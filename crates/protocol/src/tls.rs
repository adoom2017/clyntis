//! BoringSSL-only TLS transport and browser ClientHello profiles.
use crate::{
    BoxStream,
    record::{RecordBoundedStream, RecordStream},
};
use anyhow::{Result, ensure};
use boring::{
    ssl::{
        CertificateCompressionAlgorithm, CertificateCompressor, SslConnector, SslMethod,
        SslOptions, SslSession, SslSessionCacheMode, SslVerifyMode, SslVersion,
    },
    x509::X509,
};
use foreign_types_shared::ForeignType;
use rand::seq::SliceRandom;
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Default)]
pub struct Clock {
    offset_ms: std::sync::atomic::AtomicI64,
}
impl Clock {
    pub fn set_offset(&self, millis: i64) {
        self.offset_ms
            .store(millis, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn unix_seconds(&self) -> Option<i64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis() as i128;
        let adjusted = now + i128::from(self.offset_ms.load(std::sync::atomic::Ordering::Relaxed));
        (adjusted >= 0).then_some((adjusted / 1000) as i64)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TlsFingerprint {
    Chrome,
    Firefox,
    Safari,
    Ios,
    Android,
    Edge,
    _360,
    Qq,
    Random,
    Randomized,
    Native,
}

impl TlsFingerprint {
    pub fn parse(value: &str) -> Result<Self> {
        Ok(match value.to_ascii_lowercase().as_str() {
            "" | "chrome" => Self::Chrome,
            "firefox" => Self::Firefox,
            "safari" => Self::Safari,
            "ios" => Self::Ios,
            "android" => Self::Android,
            "edge" => Self::Edge,
            "360" => Self::_360,
            "qq" => Self::Qq,
            "random" => Self::Random,
            "randomized" => Self::Randomized,
            "native" => Self::Native,
            "rustls" => {
                anyhow::bail!("TLS profile 'rustls' is unavailable; this build uses BoringSSL only")
            }
            other => anyhow::bail!("unknown TLS client fingerprint: {other}"),
        })
    }
    fn resolve(self) -> Self {
        if self != Self::Random {
            return self;
        }
        *[
            Self::Chrome,
            Self::Firefox,
            Self::Safari,
            Self::Ios,
            Self::Android,
            Self::Edge,
            Self::_360,
            Self::Qq,
        ]
        .choose(&mut rand::thread_rng())
        .unwrap()
    }
}

#[derive(Clone, Debug)]
pub struct TlsProfile {
    pub cipher_list: &'static str,
    pub curves: &'static str,
    pub sigalgs: &'static str,
    pub grease: bool,
    pub permute_extensions: bool,
    pub ech_grease: bool,
    pub key_shares: &'static [u16],
    pub extension_order: &'static [u16],
    pub certificate_compression: &'static [CertificateCompression],
    pub tls13_ciphers: &'static [u16],
    pub delegated_credential_sigalgs: &'static [u16],
    pub record_size_limit: u16,
    pub alps: bool,
    pub alps_new_codepoint: bool,
    pub empty_trust_anchors: bool,
    pub signed_cert_timestamps: bool,
    pub session_ticket: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum CertificateCompression {
    Zlib,
    Brotli,
    Zstd,
}

#[derive(Debug, Default)]
struct ZlibCertificateDecompressor;
impl CertificateCompressor for ZlibCertificateDecompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZLIB;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;
    fn decompress<W: std::io::Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        let mut decoder = flate2::read::ZlibDecoder::new(input);
        std::io::copy(&mut decoder, output)?;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct BrotliCertificateDecompressor;
impl CertificateCompressor for BrotliCertificateDecompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;
    fn decompress<W: std::io::Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        let mut decoder = brotli::Decompressor::new(input, 4096);
        std::io::copy(&mut decoder, output)?;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct ZstdCertificateDecompressor;
impl CertificateCompressor for ZstdCertificateDecompressor {
    // boring 5.2.0 exposes only the RFC 8879 ZLIB and Brotli constants even
    // though the ABI type is a single u16. Keep this pinned representation in
    // one place until the wrapper exposes ZSTD (IANA algorithm 3).
    const ALGORITHM: CertificateCompressionAlgorithm =
        unsafe { std::mem::transmute::<u16, CertificateCompressionAlgorithm>(3) };
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;
    fn decompress<W: std::io::Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        let mut decoder = zstd::stream::read::Decoder::new(input)?;
        std::io::copy(&mut decoder, output)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct BrowserProfile {
    pub name: &'static str,
    pub browser_version: &'static str,
    pub source: &'static str,
    pub fixture_sha256: &'static str,
    pub default_alpn: &'static [&'static str],
    pub tls: TlsProfile,
}

const CHROMIUM_CIPHERS: &str = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";
const FIREFOX_CIPHERS: &str = "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";
const CHROMIUM_SIGALGS: &str = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512";
const FIREFOX_SIGALGS: &str = "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512:ecdsa_sha1:rsa_pkcs1_sha1";
const KEY_SHARES_CHROME: &[u16] = &[0x11ec, 29];
const KEY_SHARES_FIREFOX: &[u16] = &[0x11ec, 29, 23];
const KEY_SHARES_CLASSIC: &[u16] = &[29, 23];
const KEY_SHARE_X25519: &[u16] = &[29];
const FIREFOX_EXTENSIONS: &[u16] = &[
    0, 23, 65281, 10, 11, 35, 16, 5, 34, 18, 51, 43, 13, 45, 28, 27, 65037,
];
const CHROMIUM_TLS13_CIPHERS: &[u16] = &[0x1301, 0x1302, 0x1303];
const FIREFOX_TLS13_CIPHERS: &[u16] = &[0x1301, 0x1303, 0x1302];
const FIREFOX_DELEGATED_CREDENTIAL_SIGALGS: &[u16] = &[0x0403, 0x0503, 0x0603, 0x0203];
const SAFARI_EXTENSIONS: &[u16] = &[0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 43, 45];
const CHROMIUM_LEGACY_EXTENSIONS: &[u16] = &[0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 43, 45];

fn profile(kind: TlsFingerprint) -> BrowserProfile {
    let kind = kind.resolve();
    let (name, version, ciphers, curves, grease, permute, ech, shares, extensions) = match kind {
        TlsFingerprint::Chrome => (
            "chrome",
            "149",
            CHROMIUM_CIPHERS,
            "X25519MLKEM768:X25519:P-256:P-384",
            true,
            true,
            true,
            KEY_SHARES_CHROME,
            &[][..],
        ),
        TlsFingerprint::Android => (
            "android",
            "Chrome 149",
            CHROMIUM_CIPHERS,
            "X25519MLKEM768:X25519:P-256:P-384",
            true,
            true,
            true,
            KEY_SHARES_CHROME,
            &[][..],
        ),
        TlsFingerprint::Edge => (
            "edge",
            "148",
            CHROMIUM_CIPHERS,
            "X25519MLKEM768:X25519:P-256:P-384",
            true,
            true,
            true,
            KEY_SHARES_CHROME,
            &[][..],
        ),
        TlsFingerprint::Firefox => (
            "firefox",
            "151",
            FIREFOX_CIPHERS,
            "X25519MLKEM768:X25519:P-256:P-384:P-521:ffdhe2048:ffdhe3072",
            false,
            false,
            true,
            KEY_SHARES_FIREFOX,
            FIREFOX_EXTENSIONS,
        ),
        TlsFingerprint::Safari => (
            "safari",
            "26.4",
            CHROMIUM_CIPHERS,
            "X25519:P-256:P-384:P-521",
            true,
            false,
            false,
            KEY_SHARES_CLASSIC,
            SAFARI_EXTENSIONS,
        ),
        TlsFingerprint::Ios => (
            "ios",
            "Safari 26.4",
            CHROMIUM_CIPHERS,
            "X25519:P-256:P-384:P-521",
            true,
            false,
            false,
            KEY_SHARES_CLASSIC,
            SAFARI_EXTENSIONS,
        ),
        TlsFingerprint::_360 => (
            "360",
            "uTLS preset",
            CHROMIUM_CIPHERS,
            "X25519:P-256:P-384",
            true,
            false,
            false,
            KEY_SHARES_CLASSIC,
            CHROMIUM_LEGACY_EXTENSIONS,
        ),
        TlsFingerprint::Qq => (
            "qq",
            "uTLS preset",
            CHROMIUM_CIPHERS,
            "X25519:P-256:P-384",
            true,
            false,
            false,
            KEY_SHARES_CLASSIC,
            CHROMIUM_LEGACY_EXTENSIONS,
        ),
        TlsFingerprint::Randomized => (
            "randomized",
            "constrained",
            CHROMIUM_CIPHERS,
            "X25519:P-256:P-384",
            true,
            true,
            false,
            KEY_SHARES_CLASSIC,
            &[][..],
        ),
        TlsFingerprint::Native => (
            "native",
            "BoringSSL 5.2.0",
            CHROMIUM_CIPHERS,
            "X25519:P-256:P-384",
            false,
            false,
            false,
            KEY_SHARES_CLASSIC,
            &[][..],
        ),
        TlsFingerprint::Random => unreachable!(),
    };
    let sigalgs = if kind == TlsFingerprint::Firefox {
        FIREFOX_SIGALGS
    } else {
        CHROMIUM_SIGALGS
    };
    let certificate_compression = match kind {
        TlsFingerprint::Firefox => &[
            CertificateCompression::Zlib,
            CertificateCompression::Brotli,
            CertificateCompression::Zstd,
        ][..],
        TlsFingerprint::Safari | TlsFingerprint::Ios => &[CertificateCompression::Zlib][..],
        TlsFingerprint::Native => &[][..],
        _ => &[CertificateCompression::Brotli][..],
    };
    let alps_new_codepoint = matches!(
        kind,
        TlsFingerprint::Chrome | TlsFingerprint::Android | TlsFingerprint::Edge
    );
    let alps = matches!(
        kind,
        TlsFingerprint::Chrome | TlsFingerprint::Android | TlsFingerprint::Edge
    );
    let empty_trust_anchors = alps;
    let tls13_ciphers = if kind == TlsFingerprint::Firefox {
        FIREFOX_TLS13_CIPHERS
    } else {
        CHROMIUM_TLS13_CIPHERS
    };
    let delegated_credential_sigalgs = if kind == TlsFingerprint::Firefox {
        FIREFOX_DELEGATED_CREDENTIAL_SIGALGS
    } else {
        &[]
    };
    let record_size_limit = if kind == TlsFingerprint::Firefox {
        0x4001
    } else {
        0
    };
    let signed_cert_timestamps = kind != TlsFingerprint::Native;
    let session_ticket = !matches!(kind, TlsFingerprint::Safari | TlsFingerprint::Ios);
    let fixture_sha256 = match kind {
        TlsFingerprint::Chrome => {
            "6c909d834bd3a689b7b7d61c52963700cb7b1f1ab0b09184261131ebac86636b"
        }
        TlsFingerprint::Android => {
            "6c909d834bd3a689b7b7d61c52963700cb7b1f1ab0b09184261131ebac86636b"
        }
        TlsFingerprint::Firefox => {
            "bbaf12e4f0e0a9dee376d9ddbdc25d259f6f714e200ab2780f71c6332ec1d261"
        }
        TlsFingerprint::Safari => {
            "c35bfbbe9a2e6922623761f28f0c2a5a7d6fef9ea7b7e9f698f13beb19a50fe2"
        }
        TlsFingerprint::Ios => "c35bfbbe9a2e6922623761f28f0c2a5a7d6fef9ea7b7e9f698f13beb19a50fe2",
        TlsFingerprint::Edge => "6c909d834bd3a689b7b7d61c52963700cb7b1f1ab0b09184261131ebac86636b",
        TlsFingerprint::_360 => "02185a57acbe8c5f282b94b81403320e0d4aa2ea9000ec7da1d54318ce41a4d0",
        TlsFingerprint::Qq => "02185a57acbe8c5f282b94b81403320e0d4aa2ea9000ec7da1d54318ce41a4d0",
        TlsFingerprint::Randomized => {
            "c3cca695dec7a0de8d218e1c2c427458a26f454254591fd67b286317121d6ef3"
        }
        TlsFingerprint::Native => {
            "b0c52a333cb193cafd5f0f90747b366fa22eb38f3c037d57e96789d7520e59ee"
        }
        TlsFingerprint::Random => unreachable!(),
    };
    let source = match kind {
        TlsFingerprint::Chrome => {
            "direct Chrome for Testing 149.0.7827.155 Win64 capture; 2026-09-20"
        }
        TlsFingerprint::Firefox => "direct Mozilla Firefox 151.0.1 Win64 capture; 2026-09-20",
        _ => "wreq-util browser profiles and Mihomo/uTLS presets; catalog 2026-09-18",
    };
    BrowserProfile {
        name,
        browser_version: version,
        source,
        fixture_sha256,
        default_alpn: if kind == TlsFingerprint::Native {
            &[]
        } else {
            &["h2", "http/1.1"]
        },
        tls: TlsProfile {
            cipher_list: ciphers,
            curves,
            sigalgs,
            grease,
            permute_extensions: permute,
            ech_grease: ech,
            key_shares: shares,
            extension_order: extensions,
            certificate_compression,
            tls13_ciphers,
            delegated_credential_sigalgs,
            record_size_limit,
            alps,
            alps_new_codepoint,
            empty_trust_anchors,
            signed_cert_timestamps,
            session_ticket,
        },
    }
}

fn randomized_profile() -> BrowserProfile {
    let mut selected = profile(TlsFingerprint::Randomized);
    selected.tls.cipher_list = *[CHROMIUM_CIPHERS, FIREFOX_CIPHERS]
        .choose(&mut rand::thread_rng())
        .unwrap();
    selected.tls.curves = *[
        "X25519:P-256:P-384",
        "X25519:P-384:P-256",
        "P-256:X25519:P-384",
    ]
    .choose(&mut rand::thread_rng())
    .unwrap();
    selected.tls.key_shares = *[KEY_SHARES_CLASSIC, KEY_SHARE_X25519]
        .choose(&mut rand::thread_rng())
        .unwrap();
    selected
}

#[derive(Clone, Debug)]
pub struct TlsConnectConfig {
    pub server_name: String,
    pub alpn: Vec<String>,
    pub verify_cert: bool,
    pub fingerprint: TlsFingerprint,
    pub reality: Option<meta_config::Reality>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ContextKey {
    profile: TlsFingerprint,
    alpn: Vec<String>,
    verify: bool,
    server_name: String,
}
static CONTEXTS: OnceLock<Mutex<HashMap<ContextKey, SslConnector>>> = OnceLock::new();
static SESSIONS: OnceLock<Mutex<VecDeque<(ContextKey, SslSession)>>> = OnceLock::new();

fn store_session(key: ContextKey, session: SslSession) {
    let mut sessions = SESSIONS.get_or_init(Default::default).lock().unwrap();
    sessions.retain(|(stored, _)| stored != &key);
    sessions.push_back((key, session));
    while sessions.len() > 256 {
        sessions.pop_front();
    }
}

fn take_session(key: &ContextKey) -> Option<SslSession> {
    let mut sessions = SESSIONS.get_or_init(Default::default).lock().unwrap();
    let index = sessions.iter().rposition(|(stored, _)| stored == key)?;
    sessions.remove(index).map(|(_, session)| session)
}

fn alpn_wire(alpn: &[String]) -> Result<Vec<u8>> {
    let mut wire = Vec::new();
    for item in alpn {
        ensure!(
            !item.is_empty() && item.len() <= 255,
            "invalid ALPN protocol"
        );
        wire.push(item.len() as u8);
        wire.extend_from_slice(item.as_bytes());
    }
    Ok(wire)
}

fn build_connector(
    profile: &BrowserProfile,
    alpn: &[String],
    verify: bool,
    reality: bool,
    session_key: Option<ContextKey>,
) -> Result<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_min_proto_version(Some(if reality {
        SslVersion::TLS1_3
    } else {
        SslVersion::TLS1_2
    }))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_cipher_list(profile.tls.cipher_list)?;
    builder.set_curves_list(profile.tls.curves)?;
    builder.set_sigalgs_list(profile.tls.sigalgs)?;
    builder.set_grease_enabled(profile.tls.grease);
    builder.set_permute_extensions(profile.tls.permute_extensions);
    builder.enable_ocsp_stapling();
    if profile.tls.signed_cert_timestamps {
        builder.enable_signed_cert_timestamps();
    }
    builder.set_alpn_protos(&alpn_wire(alpn)?)?;
    builder.set_session_cache_mode(if reality {
        SslSessionCacheMode::OFF
    } else {
        SslSessionCacheMode::CLIENT
    });
    builder.set_session_cache_size(256);
    if let Some(key) = session_key {
        builder.set_new_session_callback(move |_, session| store_session(key.clone(), session));
    }
    if !profile.tls.session_ticket {
        builder.set_options(SslOptions::NO_TICKET);
    }
    for algorithm in profile.tls.certificate_compression {
        match algorithm {
            CertificateCompression::Zlib => {
                builder.add_certificate_compression_algorithm(ZlibCertificateDecompressor)?
            }
            CertificateCompression::Brotli => {
                builder.add_certificate_compression_algorithm(BrotliCertificateDecompressor)?
            }
            CertificateCompression::Zstd => {
                builder.add_certificate_compression_algorithm(ZstdCertificateDecompressor)?
            }
        }
    }
    if verify && !reality {
        builder.set_verify(SslVerifyMode::PEER);
        for root in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
            if let Ok(cert) = X509::from_der(root.as_ref()) {
                let _ = builder.cert_store_mut().add_cert(cert);
            }
        }
    } else {
        builder.set_verify(SslVerifyMode::NONE);
    }
    Ok(builder.build())
}

fn connector(
    config: &TlsConnectConfig,
) -> Result<(
    SslConnector,
    BrowserProfile,
    Vec<String>,
    Option<ContextKey>,
)> {
    let selected = config.fingerprint.resolve();
    let profile = if selected == TlsFingerprint::Randomized {
        randomized_profile()
    } else {
        profile(selected)
    };
    let alpn = if config.alpn.is_empty() {
        profile
            .default_alpn
            .iter()
            .map(|v| (*v).to_owned())
            .collect()
    } else {
        config.alpn.clone()
    };
    if config.reality.is_some() {
        return Ok((
            build_connector(&profile, &alpn, false, true, None)?,
            profile,
            alpn,
            None,
        ));
    }
    if selected == TlsFingerprint::Randomized {
        return Ok((
            build_connector(&profile, &alpn, config.verify_cert, false, None)?,
            profile,
            alpn,
            None,
        ));
    }
    let key = ContextKey {
        profile: selected,
        alpn: alpn.clone(),
        verify: config.verify_cert,
        server_name: config.server_name.clone(),
    };
    let cache = CONTEXTS.get_or_init(Default::default);
    if let Some(found) = cache.lock().unwrap().get(&key).cloned() {
        return Ok((found, profile, alpn, Some(key)));
    }
    let built = build_connector(
        &profile,
        &alpn,
        config.verify_cert,
        false,
        Some(key.clone()),
    )?;
    let result = built.clone();
    let mut cache = cache.lock().unwrap();
    if cache.len() >= 64 {
        cache.clear();
    }
    cache.insert(key.clone(), built);
    Ok((result, profile, alpn, Some(key)))
}

fn configure_ssl(
    config: &TlsConnectConfig,
    clock: &Arc<Clock>,
) -> Result<(boring::ssl::Ssl, BrowserProfile)> {
    let (connector, profile, alpn, session_key) = connector(config)?;
    let mut configured = connector.configure()?;
    configured.set_verify_hostname(config.verify_cert && config.reality.is_none());
    let mut ssl = configured.into_ssl(&config.server_name)?;
    if let Some(key) = session_key.as_ref()
        && let Some(session) = take_session(key)
    {
        // SAFETY: the cached session came from the same server/profile/ALPN and
        // verification context. BoringSSL takes its own reference on success.
        unsafe { ssl.set_session(&session)? };
    }
    if config.reality.is_some() {
        // REALITY deliberately uses an ephemeral certificate whose Ed25519
        // signature bytes carry an HMAC. Let the handshake receive that
        // certificate, then authenticate it with RealityGuard below.
        ssl.set_custom_verify_callback(SslVerifyMode::PEER, |_| Ok(()));
        // Preserve the browser profile's exact advertised sigalg list while
        // accepting Xray's authenticated ephemeral Ed25519 CertificateVerify.
        unsafe {
            boring_sys::SSL_set_allow_unadvertised_peer_sigalg(ssl.as_ptr(), 1);
            boring_sys::SSL_set_reuse_x25519_key_share(ssl.as_ptr(), 1);
        }
    }
    if let Some(now) = clock.unix_seconds() {
        ssl.verify_param_mut().set_time(now as _);
    }
    // Keep the supported-groups list and emitted key_share entries separate.
    // SAFETY: ssl is valid and the slice lives for the duration of the call.
    unsafe {
        ensure!(
            boring_sys::SSL_set1_client_key_shares(
                ssl.as_ptr(),
                profile.tls.key_shares.as_ptr(),
                profile.tls.key_shares.len()
            ) == 1,
            "cannot configure TLS key shares"
        );
        ensure!(
            boring_sys::SSL_set1_tls13_cipher_order(
                ssl.as_ptr(),
                profile.tls.tls13_ciphers.as_ptr(),
                profile.tls.tls13_ciphers.len()
            ) == 1,
            "cannot configure TLS 1.3 cipher order"
        );
        ensure!(
            boring_sys::SSL_set1_delegated_credential_sigalgs(
                ssl.as_ptr(),
                profile.tls.delegated_credential_sigalgs.as_ptr(),
                profile.tls.delegated_credential_sigalgs.len()
            ) == 1,
            "cannot configure delegated credential algorithms"
        );
        boring_sys::SSL_set_record_size_limit(ssl.as_ptr(), profile.tls.record_size_limit);
        if !profile.tls.extension_order.is_empty() {
            ensure!(
                boring_sys::SSL_set1_extension_order(
                    ssl.as_ptr(),
                    profile.tls.extension_order.as_ptr(),
                    profile.tls.extension_order.len()
                ) == 1,
                "cannot configure ClientHello extension order"
            );
        }
    }
    ssl.set_enable_ech_grease(profile.tls.ech_grease && config.reality.is_none());
    unsafe {
        boring_sys::SSL_set_alps_use_new_codepoint(
            ssl.as_ptr(),
            i32::from(profile.tls.alps_new_codepoint),
        );
        if profile.tls.empty_trust_anchors {
            ensure!(
                boring_sys::SSL_set1_requested_trust_anchors(ssl.as_ptr(), std::ptr::null(), 0,)
                    == 1,
                "cannot configure empty trust-anchor IDs"
            );
        }
    }
    if profile.tls.alps && alpn.iter().any(|value| value == "h2") {
        // Chromium advertises ALPS for h2. The transport layer owns the
        // actual HTTP/2 SETTINGS, so the TLS setting payload is empty.
        unsafe {
            let _ = boring_sys::SSL_add_application_settings(
                ssl.as_ptr(),
                b"h2".as_ptr(),
                2,
                std::ptr::null(),
                0,
            );
        }
    }
    Ok((ssl, profile))
}

#[derive(Clone, Default)]
pub struct SecureConnector {
    clock: Arc<Clock>,
}
impl SecureConnector {
    pub fn new(clock: Arc<Clock>) -> Self {
        Self { clock }
    }
    pub fn clock(&self) -> Arc<Clock> {
        self.clock.clone()
    }

    pub async fn connect(&self, stream: BoxStream, config: &TlsConnectConfig) -> Result<BoxStream> {
        if config.reality.is_some() {
            return Ok(Box::new(self.connect_xtls(stream, config).await?));
        }
        let (ssl, selected) = configure_ssl(config, &self.clock)?;
        tracing::debug!(
            tls_profile = selected.name,
            browser_version = selected.browser_version,
            "using BoringSSL TLS profile"
        );
        let tls = tokio_boring::SslStreamBuilder::new(ssl, stream)
            .connect()
            .await
            .map_err(|error| anyhow::anyhow!("TLS handshake failed: {error}"))?;
        Ok(Box::new(tls))
    }

    pub async fn connect_xtls(
        &self,
        stream: BoxStream,
        config: &TlsConnectConfig,
    ) -> Result<RecordStream<BoxStream>> {
        let (mut ssl, selected) = configure_ssl(config, &self.clock)?;
        let guard = if let Some(options) = &config.reality {
            Some(crate::reality::install(&mut ssl, options, &self.clock)?)
        } else {
            None
        };
        tracing::debug!(
            tls_profile = selected.name,
            browser_version = selected.browser_version,
            "using BoringSSL TLS profile"
        );
        let tls = tokio_boring::SslStreamBuilder::new(ssl, RecordBoundedStream::new(stream))
            .connect()
            .await
            .map_err(|error| anyhow::anyhow!("TLS handshake failed: {error}"))?;
        if let Some(guard) = &guard {
            guard.verify_peer(tls.ssl())?;
        }
        Ok(RecordStream::tls(tls, guard))
    }
}

pub async fn connect(
    stream: BoxStream,
    config: &TlsConnectConfig,
    clock: Arc<Clock>,
) -> Result<BoxStream> {
    SecureConnector::new(clock).connect(stream, config).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring::{
        pkey::PKey,
        ssl::{SslAcceptor, SslSessionCacheMode},
    };
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncReadExt;

    #[derive(Debug)]
    struct WireHello {
        ciphers: Vec<u16>,
        extensions: Vec<(u16, Vec<u8>)>,
    }

    impl WireHello {
        fn extension(&self, kind: u16) -> &[u8] {
            self.extensions
                .iter()
                .find(|(found, _)| *found == kind)
                .map(|(_, value)| value.as_slice())
                .unwrap()
        }
    }

    fn u16s(bytes: &[u8]) -> Vec<u16> {
        bytes
            .chunks_exact(2)
            .map(|item| u16::from_be_bytes([item[0], item[1]]))
            .collect()
    }

    fn grease(value: u16) -> bool {
        value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
    }

    fn normalized_fixture(hello: &WireHello) -> String {
        let mut digest = Sha256::new();
        let mut add_u16s = |tag: u8, values: &[u16]| {
            digest.update([tag]);
            for value in values.iter().copied().filter(|value| !grease(*value)) {
                digest.update(value.to_be_bytes());
            }
        };
        add_u16s(1, &hello.ciphers);
        let mut extension_types = hello
            .extensions
            .iter()
            .map(|(kind, _)| *kind)
            .filter(|kind| !grease(*kind))
            .collect::<Vec<_>>();
        extension_types.sort_unstable();
        add_u16s(2, &extension_types);
        for (tag, kind) in [(3, 10), (4, 13), (5, 34), (6, 43)] {
            if let Some((_, bytes)) = hello.extensions.iter().find(|(found, _)| *found == kind) {
                let offset =
                    usize::from(matches!(kind, 10 | 13 | 34)) * 2 + usize::from(kind == 43);
                add_u16s(tag, &u16s(&bytes[offset..]));
            }
        }
        if let Some((_, shares)) = hello.extensions.iter().find(|(kind, _)| *kind == 51) {
            digest.update([7]);
            let mut offset = 2;
            while offset + 4 <= shares.len() {
                let group = u16::from_be_bytes([shares[offset], shares[offset + 1]]);
                let len = u16::from_be_bytes([shares[offset + 2], shares[offset + 3]]);
                if !grease(group) {
                    digest.update(group.to_be_bytes());
                    digest.update(len.to_be_bytes());
                }
                offset += 4 + len as usize;
            }
        }
        for (tag, kind) in [(8, 16), (9, 27), (10, 28), (11, 45)] {
            if let Some((_, bytes)) = hello.extensions.iter().find(|(found, _)| *found == kind) {
                digest.update([tag]);
                digest.update(bytes);
            }
        }
        digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn parse_client_hello(record: &[u8]) -> WireHello {
        assert_eq!(record[0], 22);
        assert_eq!(record[5], 1);
        let hello = &record[9..];
        let mut offset = 34;
        offset += 1 + hello[offset] as usize;
        let cipher_len = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
        offset += 2;
        let ciphers = u16s(&hello[offset..offset + cipher_len]);
        offset += cipher_len;
        offset += 1 + hello[offset] as usize;
        let extension_len = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
        offset += 2;
        let end = offset + extension_len;
        let mut extensions = Vec::new();
        while offset < end {
            let kind = u16::from_be_bytes([hello[offset], hello[offset + 1]]);
            let len = u16::from_be_bytes([hello[offset + 2], hello[offset + 3]]) as usize;
            offset += 4;
            extensions.push((kind, hello[offset..offset + len].to_vec()));
            offset += len;
        }
        WireHello {
            ciphers,
            extensions,
        }
    }

    async fn capture(fingerprint: TlsFingerprint) -> WireHello {
        capture_with_reality(fingerprint, None).await
    }

    async fn capture_with_reality(
        fingerprint: TlsFingerprint,
        reality: Option<meta_config::Reality>,
    ) -> WireHello {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0; 5];
            stream.read_exact(&mut header).await.unwrap();
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut record = header.to_vec();
            record.resize(5 + len, 0);
            stream.read_exact(&mut record[5..]).await.unwrap();
            record
        });
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let config = TlsConnectConfig {
            server_name: "example.com".into(),
            alpn: Vec::new(),
            verify_cert: false,
            fingerprint,
            reality,
        };
        let _ = SecureConnector::default()
            .connect(Box::new(stream), &config)
            .await;
        parse_client_hello(&server.await.unwrap())
    }

    #[tokio::test]
    async fn reality_reuses_x25519_without_changing_profile_sigalgs() {
        let hello = capture_with_reality(
            TlsFingerprint::Chrome,
            Some(meta_config::Reality {
                public_key: "e06Qm75__kTEZaIgA31gjuNYl9Me-XLwf3SJLLD3PxM".into(),
                short_id: "01020304".into(),
            }),
        )
        .await;
        assert!(!u16s(&hello.extension(13)[2..]).contains(&0x0807));
        let shares = hello.extension(51);
        let mut offset = 2;
        let mut hybrid = None;
        let mut classic = None;
        while offset + 4 <= shares.len() {
            let group = u16::from_be_bytes([shares[offset], shares[offset + 1]]);
            let len = u16::from_be_bytes([shares[offset + 2], shares[offset + 3]]) as usize;
            offset += 4;
            if group == 0x11ec {
                hybrid = Some(&shares[offset + len - 32..offset + len]);
            } else if group == 29 {
                classic = Some(&shares[offset..offset + len]);
            }
            offset += len;
        }
        assert_eq!(hybrid.unwrap(), classic.unwrap());
    }

    #[test]
    fn catalog_profiles_build_and_record_metadata() {
        let expected = [
            (TlsFingerprint::Chrome, "chrome", "149"),
            (TlsFingerprint::Android, "android", "Chrome 149"),
            (TlsFingerprint::Firefox, "firefox", "151"),
            (TlsFingerprint::Safari, "safari", "26.4"),
            (TlsFingerprint::Ios, "ios", "Safari 26.4"),
            (TlsFingerprint::Edge, "edge", "148"),
            (TlsFingerprint::_360, "360", "uTLS preset"),
            (TlsFingerprint::Qq, "qq", "uTLS preset"),
        ];
        let clock = Arc::new(Clock::default());
        for (fingerprint, name, version) in expected {
            let selected = profile(fingerprint);
            assert_eq!(selected.name, name);
            assert_eq!(selected.browser_version, version);
            assert!(!selected.fixture_sha256.is_empty());
            let config = TlsConnectConfig {
                server_name: "example.com".into(),
                alpn: Vec::new(),
                verify_cert: false,
                fingerprint,
                reality: None,
            };
            let (_, built) = configure_ssl(&config, &clock).unwrap();
            assert_eq!(built.name, name);
        }
    }

    #[test]
    fn fingerprint_values_match_mihomo_configuration() {
        for value in [
            "chrome",
            "firefox",
            "safari",
            "ios",
            "android",
            "edge",
            "360",
            "qq",
            "random",
            "randomized",
        ] {
            TlsFingerprint::parse(value).unwrap();
        }
        let error = TlsFingerprint::parse("rustls").unwrap_err().to_string();
        assert!(error.contains("BoringSSL only"));
    }

    #[tokio::test]
    async fn chrome_149_client_hello_matches_official_capture() {
        // Golden values were captured from the official Chrome for Testing
        // 149.0.7827.155 Win64 binary with a fresh profile on 2026-09-20.
        let hello = capture(TlsFingerprint::Chrome).await;
        assert_eq!(
            hello
                .ciphers
                .iter()
                .copied()
                .filter(|value| !grease(*value))
                .collect::<Vec<_>>(),
            [
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ]
        );
        let mut extensions = hello
            .extensions
            .iter()
            .map(|(kind, _)| *kind)
            .filter(|kind| !grease(*kind))
            .collect::<Vec<_>>();
        extensions.sort_unstable();
        assert_eq!(
            extensions,
            [
                0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 17613, 51764, 65037, 65281,
            ]
        );
        assert_eq!(
            u16s(&hello.extension(10)[2..])
                .into_iter()
                .filter(|value| !grease(*value))
                .collect::<Vec<_>>(),
            [0x11ec, 29, 23, 24]
        );
        assert_eq!(
            u16s(&hello.extension(13)[2..]),
            [
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601
            ]
        );
        assert_eq!(hello.extension(16), b"\0\x0c\x02h2\x08http/1.1");
        assert_eq!(hello.extension(27), [2, 0, 2]);
        assert_eq!(hello.extension(17613), [0, 3, 2, b'h', b'2']);
        assert_eq!(hello.extension(51764), [0, 0]);
        assert_eq!(
            normalized_fixture(&hello),
            "6c909d834bd3a689b7b7d61c52963700cb7b1f1ab0b09184261131ebac86636b"
        );
    }

    #[tokio::test]
    async fn firefox_151_client_hello_matches_catalog() {
        // Golden values were captured from the official Mozilla Firefox
        // 151.0.1 Win64 binary with a fresh profile on 2026-09-20.
        let hello = capture(TlsFingerprint::Firefox).await;
        assert_eq!(
            hello.ciphers,
            [
                0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a,
                0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ]
        );
        assert_eq!(
            hello
                .extensions
                .iter()
                .map(|(kind, _)| *kind)
                .collect::<Vec<_>>(),
            FIREFOX_EXTENSIONS
        );
        let groups = hello.extension(10);
        assert_eq!(u16s(&groups[2..]), [0x11ec, 29, 23, 24, 25, 256, 257]);
        let shares = hello.extension(51);
        let mut offset = 2;
        let mut key_shares = Vec::new();
        while offset < shares.len() {
            let group = u16::from_be_bytes([shares[offset], shares[offset + 1]]);
            let len = u16::from_be_bytes([shares[offset + 2], shares[offset + 3]]) as usize;
            key_shares.push((group, len));
            offset += 4 + len;
        }
        assert_eq!(key_shares, [(0x11ec, 1216), (29, 32), (23, 65)]);
        assert_eq!(
            u16s(&hello.extension(13)[2..]),
            [
                0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203,
                0x0201,
            ]
        );
        assert_eq!(
            u16s(&hello.extension(34)[2..]),
            [0x0403, 0x0503, 0x0603, 0x0203]
        );
        assert_eq!(hello.extension(28), [0x40, 0x01]);
        assert_eq!(hello.extension(27), [6, 0, 1, 0, 2, 0, 3]);
        assert_eq!(hello.extension(16), b"\0\x0c\x02h2\x08http/1.1");
        assert!(
            !hello
                .extensions
                .iter()
                .any(|(kind, _)| matches!(*kind, 17513 | 17613))
        );
        assert_eq!(
            normalized_fixture(&hello),
            "bbaf12e4f0e0a9dee376d9ddbdc25d259f6f714e200ab2780f71c6332ec1d261"
        );
    }

    #[tokio::test]
    async fn normalized_profile_fixtures_are_stable() {
        for fingerprint in [
            TlsFingerprint::Chrome,
            TlsFingerprint::Android,
            TlsFingerprint::Firefox,
            TlsFingerprint::Safari,
            TlsFingerprint::Ios,
            TlsFingerprint::Edge,
            TlsFingerprint::_360,
            TlsFingerprint::Qq,
        ] {
            let hello = capture(fingerprint).await;
            assert_eq!(
                normalized_fixture(&hello),
                profile(fingerprint).fixture_sha256
            );
        }
    }

    #[tokio::test]
    async fn ordinary_tls_resumes_a_cached_session() -> Result<()> {
        let cert = rcgen::generate_simple_self_signed(vec!["resume.test".into()])?;
        let certificate = X509::from_der(cert.cert.der().as_ref())?;
        let key = PKey::private_key_from_pkcs8(&cert.signing_key.serialize_der())?;
        let mut server = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        server.set_certificate(&certificate)?;
        server.set_private_key(&key)?;
        server.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        server.set_max_proto_version(Some(SslVersion::TLS1_2))?;
        server.set_session_cache_mode(SslSessionCacheMode::SERVER);
        server.set_session_id_context(b"clyntis-session-test")?;
        let server = server.build();
        let config = TlsConnectConfig {
            server_name: format!("resume-{}.test", rand::random::<u64>()),
            alpn: vec!["http/1.1".into()],
            verify_cert: false,
            fingerprint: TlsFingerprint::Native,
            reality: None,
        };
        for expected in [false, true] {
            let (client, peer) = tokio::io::duplex(64 * 1024);
            let server = server.clone();
            let task = tokio::spawn(async move {
                tokio_boring::accept(&server, peer)
                    .await
                    .map_err(|error| anyhow::anyhow!(error.to_string()))
            });
            let (ssl, _) = configure_ssl(&config, &Arc::new(Clock::default()))?;
            let stream = tokio_boring::SslStreamBuilder::new(ssl, Box::new(client) as BoxStream)
                .connect()
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            assert_eq!(stream.ssl().session_reused(), expected);
            drop(stream);
            task.await??;
        }
        Ok(())
    }
}
