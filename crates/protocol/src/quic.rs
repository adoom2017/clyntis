//! quinn's crypto on BoringSSL: the TLS 1.3 handshake through BoringSSL's
//! QUIC API (RFC 9001) with the same browser profiles, roots and clock as TCP,
//! and QUIC packet protection with BoringSSL's AEADs. This keeps one TLS stack
//! in the product and lets a QUIC ClientHello look like a browser's.

use crate::tls::{Clock, TlsFingerprint};
use boring::ssl::Ssl;
use boring_sys as ffi;
use bytes::BytesMut;
use foreign_types_shared::ForeignType;
use quinn_proto::{
    ConnectError, ConnectionId, Side, TransportError, TransportErrorCode,
    crypto::{self, CryptoError, ExportKeyingMaterialError, KeyPair, Keys, UnsupportedVersion},
    transport_parameters::TransportParameters,
};
use std::{
    any::Any,
    ffi::{c_int, c_void},
    ptr,
    sync::{Arc, OnceLock},
};
use zeroize::Zeroizing;

const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SAMPLE_LEN: usize = 16;

/// RFC 9001 §5.2 and the draft-29 salt quinn's draft versions use.
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const INITIAL_SALT_DRAFT: [u8; 20] = [
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
    0x43, 0x90, 0xa8, 0x99,
];
/// RFC 9001 §5.8.
const RETRY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];
const RETRY_KEY_DRAFT: [u8; 16] = [
    0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a, 0x6c, 0xb9, 0x6b, 0xe1,
];
const RETRY_NONCE_DRAFT: [u8; 12] = [
    0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c,
];

#[derive(Clone, Copy, Debug, PartialEq)]
enum Version {
    V1,
    /// Drafts 29 to 32, which quinn still offers.
    Draft,
}
impl Version {
    fn from_wire(version: u32) -> Result<Self, UnsupportedVersion> {
        match version {
            1 => Ok(Self::V1),
            0xff00_001d..=0xff00_0020 => Ok(Self::Draft),
            _ => Err(UnsupportedVersion),
        }
    }
    fn salt(self) -> &'static [u8] {
        match self {
            Self::V1 => &INITIAL_SALT_V1,
            Self::Draft => &INITIAL_SALT_DRAFT,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Aead {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// A TLS 1.3 cipher suite: its AEAD and its HKDF hash.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Suite {
    aead: Aead,
    sha384: bool,
}
impl Suite {
    const INITIAL: Self = Self {
        aead: Aead::Aes128Gcm,
        sha384: false,
    };
    fn from_protocol_id(id: u16) -> Option<Self> {
        Some(match id {
            0x1301 => Self::INITIAL,
            0x1302 => Self {
                aead: Aead::Aes256Gcm,
                sha384: true,
            },
            0x1303 => Self {
                aead: Aead::ChaCha20Poly1305,
                sha384: false,
            },
            _ => return None,
        })
    }
    fn digest(self) -> *const ffi::EVP_MD {
        // SAFETY: these return static digest tables.
        unsafe {
            if self.sha384 {
                ffi::EVP_sha384()
            } else {
                ffi::EVP_sha256()
            }
        }
    }
    fn hash_len(self) -> usize {
        if self.sha384 { 48 } else { 32 }
    }
    fn key_len(self) -> usize {
        match self.aead {
            Aead::Aes128Gcm => 16,
            Aead::Aes256Gcm | Aead::ChaCha20Poly1305 => 32,
        }
    }
    fn expand(self, secret: &[u8], label: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
        expand_label(self.digest(), secret, label, len)
    }
    fn packet_key(self, secret: &[u8]) -> Box<dyn crypto::PacketKey> {
        let key = self.expand(secret, b"quic key", self.key_len());
        let iv = self.expand(secret, b"quic iv", NONCE_LEN);
        Box::new(PacketKey::new(self.aead, &key, iv[..].try_into().unwrap()))
    }
    fn header_key(self, secret: &[u8]) -> Box<dyn crypto::HeaderKey> {
        let key = self.expand(secret, b"quic hp", self.key_len());
        Box::new(HeaderKey::new(self.aead, &key))
    }
    /// RFC 9001 §6.1: the next generation of a 1-RTT secret.
    fn update(self, secret: &[u8]) -> Zeroizing<Vec<u8>> {
        self.expand(secret, b"quic ku", self.hash_len())
    }
}

/// HKDF-Expand-Label (RFC 8446 §7.1) with an empty context.
fn expand_label(
    digest: *const ffi::EVP_MD,
    secret: &[u8],
    label: &[u8],
    len: usize,
) -> Zeroizing<Vec<u8>> {
    let mut info = Vec::with_capacity(4 + 6 + label.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    let mut out = Zeroizing::new(vec![0; len]);
    // SAFETY: every buffer is valid for the lengths given.
    let ok = unsafe {
        ffi::HKDF_expand(
            out.as_mut_ptr(),
            len,
            digest,
            secret.as_ptr(),
            secret.len(),
            info.as_ptr(),
            info.len(),
        )
    };
    assert_eq!(ok, 1, "HKDF-Expand-Label");
    out
}

fn initial_keys(version: Version, dst_cid: &ConnectionId, side: Side) -> Keys {
    let mut initial = Zeroizing::new([0u8; 32]);
    let mut len = 0;
    // SAFETY: every buffer is valid for the lengths given.
    let ok = unsafe {
        ffi::HKDF_extract(
            initial.as_mut_ptr(),
            &mut len,
            ffi::EVP_sha256(),
            dst_cid.as_ptr(),
            dst_cid.len(),
            version.salt().as_ptr(),
            version.salt().len(),
        )
    };
    assert!(ok == 1 && len == 32, "HKDF-Extract");
    let suite = Suite::INITIAL;
    let client = suite.expand(&initial[..], b"client in", 32);
    let server = suite.expand(&initial[..], b"server in", 32);
    let (local, remote) = match side {
        Side::Client => (client, server),
        Side::Server => (server, client),
    };
    keys(suite, &local, &remote)
}

fn keys(suite: Suite, local: &[u8], remote: &[u8]) -> Keys {
    Keys {
        header: KeyPair {
            local: suite.header_key(local),
            remote: suite.header_key(remote),
        },
        packet: KeyPair {
            local: suite.packet_key(local),
            remote: suite.packet_key(remote),
        },
    }
}

/// An AEAD key with its static IV.
struct PacketKey {
    ctx: *mut ffi::EVP_AEAD_CTX,
    iv: [u8; NONCE_LEN],
    aead: Aead,
}
// SAFETY: a BoringSSL AEAD context is immutable after creation and its seal
// and open functions take it by const pointer, so sharing it is sound.
unsafe impl Send for PacketKey {}
unsafe impl Sync for PacketKey {}
impl Drop for PacketKey {
    fn drop(&mut self) {
        // SAFETY: created by EVP_AEAD_CTX_new and freed once.
        unsafe { ffi::EVP_AEAD_CTX_free(self.ctx) };
    }
}
impl PacketKey {
    fn new(aead: Aead, key: &[u8], iv: [u8; NONCE_LEN]) -> Self {
        // SAFETY: static AEAD tables; the key buffer is valid for its length.
        let ctx = unsafe {
            let algorithm = match aead {
                Aead::Aes128Gcm => ffi::EVP_aead_aes_128_gcm(),
                Aead::Aes256Gcm => ffi::EVP_aead_aes_256_gcm(),
                Aead::ChaCha20Poly1305 => ffi::EVP_aead_chacha20_poly1305(),
            };
            ffi::EVP_AEAD_CTX_new(algorithm, key.as_ptr(), key.len(), TAG_LEN)
        };
        assert!(!ctx.is_null(), "AEAD key setup");
        Self { ctx, iv, aead }
    }
    fn nonce(&self, packet: u64) -> [u8; NONCE_LEN] {
        let mut nonce = self.iv;
        for (byte, pn) in nonce[4..].iter_mut().zip(packet.to_be_bytes()) {
            *byte ^= pn;
        }
        nonce
    }
}
impl crypto::PacketKey for PacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let nonce = self.nonce(packet);
        let (header, rest) = buf.split_at_mut(header_len);
        let (payload, tag) = rest.split_at_mut(rest.len() - TAG_LEN);
        let mut tag_len = 0;
        let data = payload.as_mut_ptr();
        // SAFETY: in-place sealing (out == in) is allowed; every buffer is
        // valid for the lengths given and the tag buffer holds TAG_LEN bytes.
        let ok = unsafe {
            ffi::EVP_AEAD_CTX_seal_scatter(
                self.ctx,
                data,
                tag.as_mut_ptr(),
                &mut tag_len,
                TAG_LEN,
                nonce.as_ptr(),
                NONCE_LEN,
                data,
                payload.len(),
                ptr::null(),
                0,
                header.as_ptr(),
                header.len(),
            )
        };
        assert!(ok == 1 && tag_len == TAG_LEN, "AEAD seal");
    }
    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        if payload.len() < TAG_LEN {
            return Err(CryptoError);
        }
        let nonce = self.nonce(packet);
        let mut out_len = 0;
        let data = payload.as_mut_ptr();
        // SAFETY: in-place opening (out == in) is allowed; every buffer is
        // valid for the lengths given.
        let ok = unsafe {
            ffi::EVP_AEAD_CTX_open(
                self.ctx,
                data,
                &mut out_len,
                payload.len(),
                nonce.as_ptr(),
                NONCE_LEN,
                data,
                payload.len(),
                header.as_ptr(),
                header.len(),
            )
        };
        if ok != 1 {
            // Forged or corrupt packets are routine; keep the error queue clean.
            // SAFETY: clears this thread's BoringSSL error queue.
            unsafe { ffi::ERR_clear_error() };
            return Err(CryptoError);
        }
        payload.truncate(out_len);
        Ok(())
    }
    fn tag_len(&self) -> usize {
        TAG_LEN
    }
    /// RFC 9001 §6.6.
    fn confidentiality_limit(&self) -> u64 {
        match self.aead {
            Aead::Aes128Gcm | Aead::Aes256Gcm => 1 << 23,
            Aead::ChaCha20Poly1305 => u64::MAX,
        }
    }
    fn integrity_limit(&self) -> u64 {
        match self.aead {
            Aead::Aes128Gcm | Aead::Aes256Gcm => 1 << 52,
            Aead::ChaCha20Poly1305 => 1 << 36,
        }
    }
}

/// Header protection (RFC 9001 §5.4): AES-ECB or ChaCha20 over a sample.
enum HeaderKey {
    Aes(Box<ffi::AES_KEY>),
    ChaCha(Zeroizing<[u8; 32]>),
}
impl HeaderKey {
    fn new(aead: Aead, key: &[u8]) -> Self {
        match aead {
            Aead::Aes128Gcm | Aead::Aes256Gcm => {
                // SAFETY: AES_KEY is plain data, filled in below.
                let mut schedule: Box<ffi::AES_KEY> = Box::new(unsafe { std::mem::zeroed() });
                // SAFETY: the key buffer holds key.len() bytes (16 or 32).
                let ok = unsafe {
                    ffi::AES_set_encrypt_key(key.as_ptr(), (key.len() * 8) as u32, &mut *schedule)
                };
                assert_eq!(ok, 0, "AES key setup");
                Self::Aes(schedule)
            }
            Aead::ChaCha20Poly1305 => Self::ChaCha(Zeroizing::new(key.try_into().unwrap())),
        }
    }
    fn mask(&self, sample: &[u8]) -> [u8; 5] {
        let mut mask = [0; 5];
        match self {
            Self::Aes(schedule) => {
                let mut block = [0; 16];
                // SAFETY: sample and block are 16 bytes each.
                unsafe { ffi::AES_encrypt(sample.as_ptr(), block.as_mut_ptr(), &**schedule) };
                mask.copy_from_slice(&block[..5]);
            }
            Self::ChaCha(key) => {
                let counter = u32::from_le_bytes(sample[..4].try_into().unwrap());
                let zeros = [0; 5];
                // SAFETY: a 32-byte key, a 12-byte nonce and 5-byte buffers.
                unsafe {
                    ffi::CRYPTO_chacha_20(
                        mask.as_mut_ptr(),
                        zeros.as_ptr(),
                        5,
                        key.as_ptr(),
                        sample[4..16].as_ptr(),
                        counter,
                    )
                };
            }
        }
        mask
    }
    /// Toggles protection; `pn_len` reads the packet number length from the
    /// first byte while it is unprotected (after unmasking, before masking).
    fn apply(&self, pn_offset: usize, packet: &mut [u8], decrypt: bool) {
        let sample = &packet[pn_offset + 4..pn_offset + 4 + SAMPLE_LEN];
        let mask = self.mask(sample);
        let bits = if packet[0] & 0x80 != 0 { 0x0f } else { 0x1f };
        let pn_len = if decrypt {
            packet[0] ^= mask[0] & bits;
            usize::from(packet[0] & 0x03) + 1
        } else {
            let pn_len = usize::from(packet[0] & 0x03) + 1;
            packet[0] ^= mask[0] & bits;
            pn_len
        };
        for (byte, mask) in packet[pn_offset..pn_offset + pn_len]
            .iter_mut()
            .zip(&mask[1..])
        {
            *byte ^= mask;
        }
    }
}
impl crypto::HeaderKey for HeaderKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.apply(pn_offset, packet, true);
    }
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.apply(pn_offset, packet, false);
    }
    fn sample_size(&self) -> usize {
        SAMPLE_LEN
    }
}

/// HMAC-SHA256 under a random key: quinn's stateless reset tokens.
pub struct ResetKey(Zeroizing<[u8; 64]>);
impl ResetKey {
    pub fn random() -> Self {
        let mut key = Zeroizing::new([0; 64]);
        // SAFETY: the buffer holds 64 bytes.
        assert_eq!(unsafe { ffi::RAND_bytes(key.as_mut_ptr(), key.len()) }, 1);
        Self(key)
    }
}
impl crypto::HmacKey for ResetKey {
    fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
        let mut len = 0;
        // SAFETY: the output buffer holds signature_len() bytes.
        let out = unsafe {
            ffi::HMAC(
                ffi::EVP_sha256(),
                self.0.as_ptr().cast(),
                self.0.len(),
                data.as_ptr(),
                data.len(),
                signature_out.as_mut_ptr(),
                &mut len,
            )
        };
        assert!(!out.is_null() && len == 32, "HMAC");
    }
    fn signature_len(&self) -> usize {
        32
    }
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let mut expected = [0; 32];
        self.sign(data, &mut expected);
        // SAFETY: both buffers hold 32 bytes when the lengths match.
        let equal = signature.len() == 32
            && unsafe {
                ffi::CRYPTO_memcmp(expected.as_ptr().cast(), signature.as_ptr().cast(), 32)
            } == 0;
        if equal { Ok(()) } else { Err(CryptoError) }
    }
}

/// What BoringSSL's QUIC callbacks hand over, by encryption level
/// (initial, early data, handshake, application).
#[derive(Default)]
struct Callbacks {
    outgoing: [Vec<u8>; 4],
    read: [Option<(Suite, Zeroizing<Vec<u8>>)>; 4],
    write: [Option<(Suite, Zeroizing<Vec<u8>>)>; 4],
    alert: Option<u8>,
}

fn ex_index() -> c_int {
    static INDEX: OnceLock<c_int> = OnceLock::new();
    // SAFETY: registers an ex_data slot with no callbacks.
    *INDEX.get_or_init(|| unsafe {
        ffi::SSL_get_ex_new_index(0, ptr::null_mut(), ptr::null_mut(), None, None)
    })
}

/// SAFETY: only from BoringSSL callbacks on an `Ssl` whose ex_data slot holds
/// its session's `Callbacks`, during a call that session made.
unsafe fn callbacks<'a>(ssl: *const ffi::SSL) -> Option<&'a mut Callbacks> {
    unsafe {
        ffi::SSL_get_ex_data(ssl, ex_index())
            .cast::<Callbacks>()
            .as_mut()
    }
}

unsafe fn secret(
    cipher: *const ffi::SSL_CIPHER,
    secret: *const u8,
    len: usize,
) -> Option<(Suite, Zeroizing<Vec<u8>>)> {
    // SAFETY: BoringSSL passes a valid cipher and a secret of `len` bytes.
    let suite = Suite::from_protocol_id(unsafe { ffi::SSL_CIPHER_get_protocol_id(cipher) })?;
    let bytes = unsafe { std::slice::from_raw_parts(secret, len) };
    Some((suite, Zeroizing::new(bytes.to_vec())))
}

unsafe extern "C" fn set_read_secret(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    cipher: *const ffi::SSL_CIPHER,
    secret_bytes: *const u8,
    len: usize,
) -> c_int {
    // SAFETY: see `callbacks` and `secret`.
    unsafe {
        let (Some(state), Some(secret)) = (callbacks(ssl), secret(cipher, secret_bytes, len))
        else {
            return 0;
        };
        state.read[level.0 as usize & 3] = Some(secret);
    }
    1
}

unsafe extern "C" fn set_write_secret(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    cipher: *const ffi::SSL_CIPHER,
    secret_bytes: *const u8,
    len: usize,
) -> c_int {
    // SAFETY: see `callbacks` and `secret`.
    unsafe {
        let (Some(state), Some(secret)) = (callbacks(ssl), secret(cipher, secret_bytes, len))
        else {
            return 0;
        };
        state.write[level.0 as usize & 3] = Some(secret);
    }
    1
}

unsafe extern "C" fn add_handshake_data(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    data: *const u8,
    len: usize,
) -> c_int {
    // SAFETY: see `callbacks`; BoringSSL passes `len` readable bytes.
    unsafe {
        let Some(state) = callbacks(ssl) else {
            return 0;
        };
        state.outgoing[level.0 as usize & 3]
            .extend_from_slice(std::slice::from_raw_parts(data, len));
    }
    1
}

unsafe extern "C" fn flush_flight(_: *mut ffi::SSL) -> c_int {
    1
}

unsafe extern "C" fn send_alert(
    ssl: *mut ffi::SSL,
    _: ffi::ssl_encryption_level_t,
    alert: u8,
) -> c_int {
    // SAFETY: see `callbacks`.
    if let Some(state) = unsafe { callbacks(ssl) } {
        state.alert = Some(alert);
    }
    1
}

static QUIC_METHOD: ffi::SSL_QUIC_METHOD = ffi::SSL_QUIC_METHOD {
    set_read_secret: Some(set_read_secret),
    set_write_secret: Some(set_write_secret),
    add_handshake_data: Some(add_handshake_data),
    flush_flight: Some(flush_flight),
    send_alert: Some(send_alert),
};

const INITIAL: usize = 0;
const HANDSHAKE: usize = 2;
const APPLICATION: usize = 3;

/// What `Connection::handshake_data` returns for these sessions.
pub struct HandshakeData {
    pub protocol: Option<Vec<u8>>,
}

pub struct Session {
    // Dropped first: BoringSSL holds a pointer to `callbacks`.
    ssl: Ssl,
    callbacks: Box<Callbacks>,
    version: Version,
    /// The level quinn writes handshake data at.
    level: usize,
    got_handshake_data: bool,
    /// The next generation of 1-RTT secrets, for key updates.
    next: Option<NextSecrets>,
}

struct NextSecrets {
    suite: Suite,
    local: Zeroizing<Vec<u8>>,
    remote: Zeroizing<Vec<u8>>,
}

impl Session {
    fn client(ssl: Ssl, version: Version, params: &TransportParameters) -> Result<Self, String> {
        let mut callbacks = Box::<Callbacks>::default();
        let mut encoded = Vec::new();
        params.write(&mut encoded);
        let raw = ssl.as_ptr();
        // SAFETY: `raw` is a live SSL; `callbacks` outlives it (field order),
        // and its heap address is stable.
        unsafe {
            ffi::SSL_set_connect_state(raw);
            if ffi::SSL_set_quic_method(raw, &QUIC_METHOD) != 1
                || ffi::SSL_set_ex_data(
                    raw,
                    ex_index(),
                    (&mut *callbacks as *mut Callbacks).cast::<c_void>(),
                ) != 1
                || ffi::SSL_set_quic_transport_params(raw, encoded.as_ptr(), encoded.len()) != 1
            {
                return Err(error_text());
            }
            ffi::SSL_set_quic_use_legacy_codepoint(raw, c_int::from(version == Version::Draft));
        }
        let mut session = Self {
            ssl,
            callbacks,
            version,
            level: INITIAL,
            got_handshake_data: false,
            next: None,
        };
        // The ClientHello, queued at the initial level.
        session.drive().map_err(|e| e.reason)?;
        Ok(session)
    }

    fn raw(&self) -> *mut ffi::SSL {
        self.ssl.as_ptr()
    }

    /// Runs the handshake as far as the data received allows.
    fn drive(&mut self) -> Result<(), TransportError> {
        // SAFETY: a live SSL with the callbacks installed.
        unsafe {
            if ffi::SSL_in_init(self.raw()) == 0 {
                if ffi::SSL_process_quic_post_handshake(self.raw()) != 1 {
                    return Err(self.failure());
                }
                return Ok(());
            }
            let result = ffi::SSL_do_handshake(self.raw());
            if result <= 0 && ffi::SSL_get_error(self.raw(), result) != ffi::SSL_ERROR_WANT_READ {
                return Err(self.failure());
            }
        }
        Ok(())
    }

    fn failure(&self) -> TransportError {
        let mut reason = error_text();
        // SAFETY: a live SSL.
        let verify = unsafe { ffi::SSL_get_verify_result(self.raw()) };
        if reason.contains("CERTIFICATE_VERIFY_FAILED") && verify != 0 {
            // SAFETY: returns a static string for any code.
            let text =
                unsafe { std::ffi::CStr::from_ptr(ffi::X509_verify_cert_error_string(verify)) };
            reason = format!(
                "certificate verification failed: {}",
                text.to_string_lossy()
            );
        }
        match self.callbacks.alert {
            Some(alert) => TransportError {
                code: TransportErrorCode::crypto(alert),
                frame: None,
                reason,
            },
            None => TransportError {
                code: TransportErrorCode::PROTOCOL_VIOLATION,
                frame: None,
                reason: format!("TLS error: {reason}"),
            },
        }
    }

    fn alpn(&self) -> Option<Vec<u8>> {
        let mut data = ptr::null();
        let mut len = 0;
        // SAFETY: BoringSSL points into the SSL, valid until it changes.
        unsafe {
            ffi::SSL_get0_alpn_selected(self.raw(), &mut data, &mut len);
            (!data.is_null() && len > 0)
                .then(|| std::slice::from_raw_parts(data, len as usize).to_vec())
        }
    }
}

/// The queued BoringSSL errors as text, emptying the queue.
fn error_text() -> String {
    let errors = boring::error::ErrorStack::get();
    if errors.errors().is_empty() {
        "unknown error".into()
    } else {
        errors.to_string()
    }
}

impl crypto::Session for Session {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        initial_keys(self.version, dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.got_handshake_data.then(|| {
            Box::new(HandshakeData {
                protocol: self.alpn(),
            }) as Box<dyn Any>
        })
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        None
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        None
    }

    fn is_handshaking(&self) -> bool {
        // SAFETY: a live SSL.
        unsafe { ffi::SSL_in_init(self.raw()) != 0 }
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        // SAFETY: a live SSL; `buf` is valid for its length.
        unsafe {
            let level = ffi::SSL_quic_read_level(self.raw());
            if ffi::SSL_provide_quic_data(self.raw(), level, buf.as_ptr(), buf.len()) != 1 {
                return Err(self.failure());
            }
        }
        self.drive()?;
        if !self.got_handshake_data && (self.alpn().is_some() || !self.is_handshaking()) {
            self.got_handshake_data = true;
            return Ok(true);
        }
        Ok(false)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        let mut data = ptr::null();
        let mut len = 0;
        // SAFETY: BoringSSL points into the SSL, valid while it lives.
        let bytes = unsafe {
            ffi::SSL_get_peer_quic_transport_params(self.raw(), &mut data, &mut len);
            if data.is_null() || len == 0 {
                return Ok(None);
            }
            std::slice::from_raw_parts(data, len)
        };
        Ok(Some(TransportParameters::read(
            Side::Client,
            &mut &bytes[..],
        )?))
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        buf.append(&mut self.callbacks.outgoing[self.level]);
        let next = match self.level {
            INITIAL => HANDSHAKE,
            HANDSHAKE => APPLICATION,
            _ => return None,
        };
        if self.callbacks.read[next].is_none() || self.callbacks.write[next].is_none() {
            return None;
        }
        let (suite, local) = self.callbacks.write[next].take()?;
        let (_, remote) = self.callbacks.read[next].take()?;
        self.level = next;
        if next == APPLICATION {
            self.next = Some(NextSecrets {
                suite,
                local: suite.update(&local),
                remote: suite.update(&remote),
            });
        }
        Some(keys(suite, &local, &remote))
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn crypto::PacketKey>>> {
        let next = self.next.as_mut()?;
        let keys = KeyPair {
            local: next.suite.packet_key(&next.local),
            remote: next.suite.packet_key(&next.remote),
        };
        next.local = next.suite.update(&next.local);
        next.remote = next.suite.update(&next.remote);
        Some(keys)
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        let Some(tag_start) = payload.len().checked_sub(TAG_LEN) else {
            return false;
        };
        // RFC 9001 §5.8: the tag authenticates a pseudo-packet.
        let mut aad = Vec::with_capacity(1 + orig_dst_cid.len() + header.len() + tag_start);
        aad.push(orig_dst_cid.len() as u8);
        aad.extend_from_slice(orig_dst_cid);
        aad.extend_from_slice(header);
        aad.extend_from_slice(&payload[..tag_start]);
        let (key, nonce) = match self.version {
            Version::V1 => (RETRY_KEY_V1, RETRY_NONCE_V1),
            Version::Draft => (RETRY_KEY_DRAFT, RETRY_NONCE_DRAFT),
        };
        let key = PacketKey::new(Aead::Aes128Gcm, &key, nonce);
        let mut tag = BytesMut::from(&payload[tag_start..]);
        // Packet number 0 leaves the nonce as is.
        crypto::PacketKey::decrypt(&key, 0, &aad, &mut tag).is_ok()
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        // SAFETY: every buffer is valid for the lengths given.
        let ok = unsafe {
            ffi::SSL_export_keying_material(
                self.raw(),
                output.as_mut_ptr(),
                output.len(),
                label.as_ptr().cast(),
                label.len(),
                context.as_ptr(),
                context.len(),
                1,
            )
        };
        if ok == 1 {
            Ok(())
        } else {
            Err(ExportKeyingMaterialError)
        }
    }
}

/// A QUIC client's TLS settings.
pub struct ClientConfig {
    pub alpn: Vec<String>,
    pub verify: bool,
    pub fingerprint: TlsFingerprint,
    pub clock: Arc<Clock>,
}

impl crypto::ClientConfig for ClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        let version = Version::from_wire(version)?;
        let invalid = |error: String| {
            tracing::debug!(server_name, "QUIC TLS setup failed: {error}");
            ConnectError::InvalidServerName(server_name.into())
        };
        let (ssl, profile) = crate::tls::quic_ssl(
            server_name,
            &self.alpn,
            self.verify,
            self.fingerprint,
            &self.clock,
        )
        .map_err(|e| invalid(format!("{e:#}")))?;
        tracing::debug!(
            tls_profile = profile.name,
            browser_version = profile.browser_version,
            "using BoringSSL QUIC profile"
        );
        Ok(Box::new(
            Session::client(ssl, version, params).map_err(invalid)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let text: String = text.split_whitespace().collect();
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 9001 Appendix A.1-A.2: the client's Initial keys for DCID
    /// 0x8394c8f03e515708 and its protected first packet's header.
    #[test]
    fn initial_keys_match_rfc_9001_vectors() {
        let cid = ConnectionId::new(&hex("8394c8f03e515708"));
        let mut initial = [0u8; 32];
        let mut len = 0;
        unsafe {
            ffi::HKDF_extract(
                initial.as_mut_ptr(),
                &mut len,
                ffi::EVP_sha256(),
                cid.as_ptr(),
                cid.len(),
                INITIAL_SALT_V1.as_ptr(),
                20,
            );
        }
        let client = Suite::INITIAL.expand(&initial, b"client in", 32);
        assert_eq!(
            &client[..],
            &hex("c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea")[..]
        );
        assert_eq!(
            &Suite::INITIAL.expand(&client, b"quic key", 16)[..],
            &hex("1f369613dd76d5467730efcbe3b1a22d")[..]
        );
        assert_eq!(
            &Suite::INITIAL.expand(&client, b"quic iv", 12)[..],
            &hex("fa044b2f42a3fd3b46fb255c")[..]
        );
        assert_eq!(
            &Suite::INITIAL.expand(&client, b"quic hp", 16)[..],
            &hex("9f50449e04a0e810283a1e9933adedd2")[..]
        );

        // A.2: header protection of the client Initial (sample from the
        // protected payload, unprotected header c300000001...).
        let keys = initial_keys(Version::V1, &cid, Side::Client);
        let mut packet = hex("c300000001088394c8f03e5157080000449e00000002");
        let pn_offset = packet.len() - 4;
        packet.extend_from_slice(&hex("d1b1c98dd7689fb8ec11d242b123dc9b"));
        keys.header.local.encrypt(pn_offset, &mut packet);
        assert_eq!(
            &packet[..pn_offset + 4],
            &hex("c000000001088394c8f03e5157080000449e7b9aec34")[..]
        );
        keys.header.local.decrypt(pn_offset, &mut packet);
        assert_eq!(
            &packet[..pn_offset + 4],
            &hex("c300000001088394c8f03e5157080000449e00000002")[..]
        );
    }

    /// RFC 9001 Appendix A.5: ChaCha20-Poly1305 short header packet.
    #[test]
    fn chacha20_packet_matches_rfc_9001_vector() {
        let secret = hex("9ac312a7f877468ebe69422748ad00a1 5443f18203a07d6060f688f30f21632b");
        let suite = Suite::from_protocol_id(0x1303).unwrap();
        assert_eq!(
            &suite.expand(&secret, b"quic key", 32)[..],
            &hex("c6d98ff3441c3fe1b2182094f69caa2e d4b716b65488960a7a984979fb23e1c8")[..]
        );
        assert_eq!(
            &suite.update(&secret)[..],
            &hex("1223504755036d556342ee9361d25342 1a826c9ecdf3c7148684b36b714881f9")[..]
        );
        let packet_key = suite.packet_key(&secret);
        let header_key = suite.header_key(&secret);
        let mut packet = hex("4200bff4");
        packet.push(0x01);
        packet.extend_from_slice(&[0; TAG_LEN]);
        packet_key.encrypt(654360564, &mut packet, 4);
        header_key.encrypt(1, &mut packet);
        assert_eq!(packet, hex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb"));
        // And back.
        header_key.decrypt(1, &mut packet);
        let mut payload = BytesMut::from(&packet[4..]);
        packet_key
            .decrypt(654360564, &packet[..4], &mut payload)
            .unwrap();
        assert_eq!(&payload[..], &[0x01]);
        // A flipped bit fails authentication.
        let mut forged = BytesMut::from(&packet[4..]);
        forged[0] ^= 1;
        assert!(
            packet_key
                .decrypt(654360564, &packet[..4], &mut forged)
                .is_err()
        );
    }

    /// Extension types and cipher suites of the ClientHello a profile sends.
    fn client_hello(fingerprint: TlsFingerprint) -> (Vec<u16>, Vec<u16>, Vec<u8>) {
        let (ssl, _) = crate::tls::quic_ssl(
            "example.com",
            &["h3".into()],
            true,
            fingerprint,
            &Clock::default(),
        )
        .unwrap_or_else(|error| panic!("{fingerprint:?} QUIC TLS setup failed: {error:#}"));
        // initial_max_data = 1 MiB; BoringSSL refuses empty parameters.
        let encoded = [0x04, 0x04, 0x80, 0x10, 0x00, 0x00];
        let params = TransportParameters::read(Side::Server, &mut &encoded[..]).unwrap();
        let session = Session::client(ssl, Version::V1, &params).unwrap();
        let hello = session.callbacks.outgoing[INITIAL].clone();
        assert_eq!(hello[0], 1, "ClientHello");
        let mut at = 4 + 2 + 32;
        let session_id = usize::from(hello[at]);
        at += 1 + session_id;
        let suites_len = usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
        let suites = hello[at + 2..at + 2 + suites_len]
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        at += 2 + suites_len;
        at += 1 + usize::from(hello[at]);
        let end = at + 2 + usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
        at += 2;
        let mut extensions = Vec::new();
        let mut alpn = Vec::new();
        while at < end {
            let kind = u16::from_be_bytes([hello[at], hello[at + 1]]);
            let len = usize::from(u16::from_be_bytes([hello[at + 2], hello[at + 3]]));
            if kind == 16 {
                alpn = hello[at + 4..at + 4 + len].to_vec();
            }
            extensions.push(kind);
            at += 4 + len;
        }
        assert_eq!(at, hello.len());
        assert_eq!(session_id, 0, "QUIC has no compatibility session ID");
        (extensions, suites, alpn)
    }

    #[test]
    fn every_profile_sends_a_tls13_quic_client_hello() {
        let grease = |v: &u16| v & 0x0f0f == 0x0a0a;
        for fingerprint in [
            TlsFingerprint::Chrome,
            TlsFingerprint::Firefox,
            TlsFingerprint::Safari,
            TlsFingerprint::Ios,
            TlsFingerprint::Android,
            TlsFingerprint::Edge,
            TlsFingerprint::Randomized,
        ] {
            let (extensions, suites, alpn) = client_hello(fingerprint);
            // quic_transport_parameters, ALPN h3, SNI and supported_versions.
            for required in [57, 16, 0, 43] {
                assert!(
                    extensions.contains(&required),
                    "{fingerprint:?} lacks {required}"
                );
            }
            assert_eq!(alpn, b"\x00\x03\x02h3", "{fingerprint:?}");
            // No TLS 1.2 leftovers: renegotiation_info or TLS 1.2 suites.
            assert!(!extensions.contains(&0xff01), "{fingerprint:?}");
            assert!(
                suites
                    .iter()
                    .all(|s| grease(s) || (0x1301..=0x1303).contains(s)),
                "{fingerprint:?}: {suites:x?}"
            );
        }
        // Chrome greases and shuffles its extensions, as Chromium's QUIC does.
        let (first, _, _) = client_hello(TlsFingerprint::Chrome);
        assert!(first.iter().any(grease));
        assert!((0..8).any(|_| client_hello(TlsFingerprint::Chrome).0 != first));
    }

    #[test]
    fn reset_tokens_verify_only_with_the_same_key() {
        use crypto::HmacKey;
        let key = ResetKey::random();
        let mut tag = [0; 32];
        key.sign(b"cid", &mut tag);
        assert!(key.verify(b"cid", &tag).is_ok());
        assert!(key.verify(b"other", &tag).is_err());
        assert!(ResetKey::random().verify(b"cid", &tag).is_err());
    }
}
