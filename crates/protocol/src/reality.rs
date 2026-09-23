//! Xray-compatible REALITY authentication for the BoringSSL transport.
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use foreign_types_shared::ForeignType;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use std::{
    ffi::c_void,
    panic::AssertUnwindSafe,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const SESSION_OFFSET: usize = 39;
const SESSION_LEN: usize = 32;

struct State {
    public: [u8; 32],
    short_id: [u8; 8],
    now: u32,
    auth_key: Mutex<Option<Zeroizing<[u8; 32]>>>,
    succeeded: AtomicBool,
    failed: AtomicBool,
}

/// Keeps the callback state alive until after the associated SSL object drops.
pub struct RealityGuard {
    state: *mut State,
}
unsafe impl Send for RealityGuard {}

impl Drop for RealityGuard {
    fn drop(&mut self) {
        if !self.state.is_null() {
            // SAFETY: install creates exactly one Box and this guard is its sole owner.
            unsafe {
                drop(Box::from_raw(self.state));
            }
            self.state = std::ptr::null_mut();
        }
    }
}

impl RealityGuard {
    pub fn succeeded(&self) -> bool {
        if self.state.is_null() {
            return false;
        }
        // SAFETY: state remains owned by this guard.
        let state = unsafe { &*self.state };
        state.succeeded.load(Ordering::Acquire) && !state.failed.load(Ordering::Acquire)
    }

    pub fn verify_peer(&self, ssl: &boring::ssl::SslRef) -> Result<()> {
        ensure!(
            self.succeeded(),
            "REALITY ClientHello authentication failed"
        );
        let der = ssl
            .peer_certificate()
            .context("REALITY peer certificate missing")?
            .to_der()?;
        use x509_parser::prelude::FromDer;
        let (rest, cert) = x509_parser::certificate::X509Certificate::from_der(&der)
            .map_err(|_| anyhow::anyhow!("invalid REALITY certificate"))?;
        ensure!(rest.is_empty(), "invalid REALITY certificate encoding");
        ensure!(
            cert.public_key().algorithm.algorithm.to_id_string() == "1.3.101.112",
            "REALITY peer certificate is not Ed25519"
        );
        ensure!(
            cert.public_key().subject_public_key.data.len() == 32,
            "invalid REALITY public key"
        );
        // SAFETY: state remains owned by this guard.
        let state = unsafe { &*self.state };
        let key = state
            .auth_key
            .lock()
            .map_err(|_| anyhow::anyhow!("REALITY authentication state poisoned"))?;
        let key = key.as_ref().context("REALITY handshake key missing")?;
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key.as_ref())?;
        mac.update(cert.public_key().subject_public_key.data.as_ref());
        mac.verify_slice(cert.signature_value.data.as_ref())
            .map_err(|_| anyhow::anyhow!("REALITY server authentication rejected"))?;
        Ok(())
    }
}

extern "C" fn callback(
    ssl: *mut boring_sys::SSL,
    msg: *mut u8,
    msg_len: usize,
    arg: *mut c_void,
) -> i32 {
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        if ssl.is_null() || arg.is_null() || msg.is_null() || msg_len < SESSION_OFFSET + SESSION_LEN
        {
            return false;
        }
        // SAFETY: BoringSSL provides a mutable ClientHello buffer for this callback.
        let hello = unsafe { std::slice::from_raw_parts_mut(msg, msg_len) };
        if hello[0] != 1 || hello[38] != SESSION_LEN as u8 {
            return false;
        }
        let mut private = Zeroizing::new([0u8; 32]);
        // SAFETY: valid during this callback by the patched BoringSSL contract.
        if unsafe { boring_sys::SSL_handshake_get_x25519_private_key(ssl, private.as_mut_ptr()) }
            != 1
        {
            return false;
        }
        // SAFETY: arg points to the State owned by RealityGuard.
        let state = unsafe { &*(arg.cast::<State>()) };
        let shared = StaticSecret::from(*private).diffie_hellman(&PublicKey::from(state.public));
        if !shared.was_contributory() {
            return false;
        }
        let mut key = Zeroizing::new([0u8; 32]);
        if hkdf::Hkdf::<Sha256>::new(Some(&hello[6..26]), shared.as_bytes())
            .expand(b"REALITY", key.as_mut())
            .is_err()
        {
            return false;
        }
        let mut plain = [0u8; 16];
        plain[..3].copy_from_slice(&[1, 8, 2]);
        plain[4..8].copy_from_slice(&state.now.to_be_bytes());
        plain[8..].copy_from_slice(&state.short_id);
        let mut aad = hello.to_vec();
        aad[SESSION_OFFSET..SESSION_OFFSET + SESSION_LEN].fill(0);
        let cipher = match Aes256Gcm::new_from_slice(key.as_ref()) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let sealed = match cipher.encrypt(
            (&hello[26..38]).into(),
            Payload {
                msg: &plain,
                aad: &aad,
            },
        ) {
            Ok(v) if v.len() == SESSION_LEN => v,
            _ => return false,
        };
        hello[SESSION_OFFSET..SESSION_OFFSET + SESSION_LEN].copy_from_slice(&sealed);
        if let Ok(mut slot) = state.auth_key.lock() {
            *slot = Some(key);
        } else {
            return false;
        }
        state.succeeded.store(true, Ordering::Release);
        true
    }));
    if !matches!(result, Ok(true)) {
        if !arg.is_null() {
            // SAFETY: arg points to callback state for the lifetime of the SSL object.
            unsafe { &*(arg.cast::<State>()) }
                .failed
                .store(true, Ordering::Release);
        }
        0
    } else {
        1
    }
}

pub(crate) fn install(
    ssl: &mut boring::ssl::Ssl,
    options: &meta_config::Reality,
    clock: &Arc<crate::tls::Clock>,
) -> Result<RealityGuard> {
    let public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&options.public_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid REALITY public key"))?;
    ensure!(
        options.short_id.len() <= 16 && options.short_id.len().is_multiple_of(2),
        "invalid REALITY short id"
    );
    let mut short_id = [0u8; 8];
    for (index, chunk) in options.short_id.as_bytes().chunks(2).enumerate() {
        short_id[index] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    let now = clock.unix_seconds().context("invalid REALITY clock")? as u32;
    let state = Box::new(State {
        public,
        short_id,
        now,
        auth_key: Mutex::new(None),
        succeeded: AtomicBool::new(false),
        failed: AtomicBool::new(false),
    });
    let state = Box::into_raw(state);
    // SAFETY: ssl is live and state is retained by the returned guard.
    unsafe {
        let ctx = boring_sys::SSL_get_SSL_CTX(ssl.as_ptr());
        if ctx.is_null() {
            drop(Box::from_raw(state));
            anyhow::bail!("REALITY SSL context missing");
        }
        boring_sys::SSL_CTX_set_client_hello_cb(ctx, Some(callback), state.cast());
    }
    Ok(RealityGuard { state })
}
