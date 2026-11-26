//! HTTPS decryption for the request log: connections to the configured hosts
//! are answered with a certificate for the host signed by the user's CA, and
//! a verified TLS connection carries the requests on to the server.
use crate::{Core, Routed, observe, traffic};
use anyhow::{Context as _, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use boring::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    ssl::{AlpnError, SslAcceptor, SslMethod, SslMode},
    x509::{
        X509, X509Builder, X509NameBuilder,
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
            SubjectAlternativeName, SubjectKeyIdentifier,
        },
    },
};
use clyntis_config::mitm::Mitm;
use clyntis_protocol::{
    BoxStream, Target,
    tls::{
        ClientTlsErrorKind, SecureConnector, TlsConnectConfig, TlsFingerprint, TlsHandshakeError,
        TlsHandshakeErrorKind, accept_classified,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Per-host certificates kept; evicts the least recently used entry when full.
/// Each holds a TLS context: the iOS tunnel, within about 50 MiB, keeps few.
const LEAVES: usize = 512;
const HOSTED_LEAVES: usize = 32;
const HOSTED_INSPECTIONS: usize = 32;
/// Maximum hosts kept in the bypass cache.
const BYPASS: usize = 2048;
/// How long persisted client-certificate-refusal bypass entries live.
const BYPASS_TTL_SECS: i64 = 24 * 60 * 60;
/// How long non-persisted session bypass entries live.
const SESSION_BYPASS_TTL_SECS: i64 = 60 * 60;
/// How long HTTP/2-only ALPN bypass entries suppress QUIC fallback.
const ALPN_BYPASS_TTL_SECS: i64 = 60;
/// Maximum size accepted when loading the persisted bypass cache.
const MAX_BYPASS_FILE_BYTES: u64 = 1024 * 1024;
const BYPASS_FILE_NAME: &str = ".mitm-bypass.json";
const BYPASS_FILE_VERSION: u32 = 1;
/// How long a client may take to send its first bytes.
const FIRST_BYTES: Duration = Duration::from_secs(2);
/// How long upstream TLS handshake may take before falling back.
const UPSTREAM_HANDSHAKE: Duration = Duration::from_secs(10);
/// How long passthrough fallback redialing may take.
const PASSTHROUGH_DIAL: Duration = Duration::from_secs(10);
/// How long an idle hosted HTTP/1.1 keep-alive connection stays open between requests.
const HOSTED_KEEPALIVE_IDLE: Duration = Duration::from_secs(60);

/// The name, fingerprints and expiry of a CA certificate (PEM).
pub fn describe_authority(cert: &str) -> Option<Value> {
    X509::from_pem(cert.as_bytes())
        .ok()
        .map(|cert| describe(&cert))
}

fn describe(cert: &X509) -> Value {
    let name = cert
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok().map(|s| s.to_string()))
        .unwrap_or_default();
    let hex = |hash: MessageDigest, separator: &str| {
        cert.digest(hash)
            .map(|d| {
                d.iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(separator)
            })
            .unwrap_or_default()
    };
    json!({
        "name": name,
        "fingerprint": hex(MessageDigest::sha256(), ":"),
        // Windows names certificates in its stores by this.
        "thumbprint": hex(MessageDigest::sha1(), ""),
        "notAfter": cert.not_after().to_string(),
    })
}

/// For hosts that cannot ask the system directly whether it trusts the CA
/// for servers (iOS): the CA's description and DER, and a server
/// certificate it signs for [`CHECK_HOST`], both base64, to evaluate with the
/// system's SSL policy.
pub fn check_authority(cert: &str, key: &str) -> Result<Value> {
    let authority = Authority::load(&Mitm {
        enable: true,
        ca_cert: cert.into(),
        ca_key: key.into(),
        ..Mitm::default()
    })?;
    let leaf = authority.leaf(CHECK_HOST)?;
    Ok(json!({
        "ca": describe(&authority.cert),
        "caDer": STANDARD.encode(authority.cert.to_der()?),
        "leaf": STANDARD.encode(leaf.to_der()?),
        "host": CHECK_HOST,
    }))
}
pub const CHECK_HOST: &str = "trust-check.clyntis.invalid";

/// Makes a CA for decryption: an EC P-256 key and a self-signed certificate
/// valid for ten years. Returns the certificate and key as PEM.
pub fn generate_authority() -> Result<(String, String)> {
    let key = ec_key()?;
    let mut name = X509NameBuilder::new()?;
    let tag = uuid::Uuid::new_v4().simple().to_string();
    name.append_entry_by_nid(
        Nid::COMMONNAME,
        &format!("Clyntis Inspection CA {}", &tag[..8]),
    )?;
    name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "Clyntis")?;
    let name = name.build();
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    let value1 = serial()?.to_asn1_integer()?;
    builder.set_serial_number(&value1)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&key)?;
    let value2 = Asn1Time::from_unix(unix_now() - 86400)?;
    builder.set_not_before(&value2)?;
    let value3 = Asn1Time::days_from_now(3650)?;
    builder.set_not_after(&value3)?;
    let value4 = BasicConstraints::new().critical().ca().build()?;
    builder.append_extension(&value4)?;
    let value5 = KeyUsage::new()
        .critical()
        .key_cert_sign()
        .crl_sign()
        .digital_signature()
        .build()?;
    builder.append_extension(&value5)?;
    let identifier = SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?;
    builder.append_extension(&identifier)?;
    builder.sign(&key, MessageDigest::sha256())?;
    let cert = builder.build();
    Ok((
        String::from_utf8(cert.to_pem()?)?,
        String::from_utf8(key.private_key_to_pem_pkcs8()?)?,
    ))
}

fn ec_key() -> Result<PKey<Private>> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    Ok(PKey::from_ec_key(EcKey::generate(&group)?)?)
}

fn serial() -> Result<BigNum> {
    let mut serial = BigNum::new()?;
    serial.rand(127, MsbOption::MAYBE_ZERO, false)?;
    Ok(serial)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn cert_fingerprint(cert: &X509) -> Result<String> {
    let digest = cert.digest(MessageDigest::sha256())?;
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

fn normalize_host(host: &str) -> std::borrow::Cow<'_, str> {
    let trimmed = host.trim().trim_end_matches('.');
    if !trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
        std::borrow::Cow::Borrowed(trimmed)
    } else {
        std::borrow::Cow::Owned(trimmed.to_ascii_lowercase())
    }
}

struct Authority {
    cert: X509,
    key: PKey<Private>,
    ca_cert: String,
    ca_key: String,
    fingerprint: String,
    /// One key for every host certificate.
    leaf_key: PKey<Private>,
    leaves: RwLock<HashMap<String, (AtomicU64, Arc<SslAcceptor>)>>,
    leaf_tick: AtomicU64,
}
impl Authority {
    fn load(mitm: &Mitm) -> Result<Self> {
        ensure!(
            !mitm.ca_cert.trim().is_empty() && !mitm.ca_key.trim().is_empty(),
            "no CA certificate: create one first"
        );
        let cert = X509::from_pem(mitm.ca_cert.as_bytes()).context("invalid CA certificate")?;
        let key = PKey::private_key_from_pem(mitm.ca_key.as_bytes()).context("invalid CA key")?;
        ensure!(
            cert.public_key()?.public_eq(&key),
            "the CA key does not belong to the CA certificate"
        );
        let fingerprint = cert_fingerprint(&cert)?;
        Ok(Self {
            cert,
            key,
            ca_cert: mitm.ca_cert.clone(),
            ca_key: mitm.ca_key.clone(),
            fingerprint,
            leaf_key: ec_key()?,
            leaves: RwLock::default(),
            leaf_tick: AtomicU64::new(0),
        })
    }
    fn acceptor(&self, host: &str, limit: usize) -> Result<Arc<SslAcceptor>> {
        if let Some((used, acceptor)) = self.leaves.read().unwrap().get(host) {
            used.store(
                self.leaf_tick.fetch_add(1, Ordering::Relaxed),
                Ordering::Relaxed,
            );
            return Ok(acceptor.clone());
        }
        let leaf = self.leaf(host)?;
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        builder.set_mode(SslMode::RELEASE_BUFFERS);
        builder.set_certificate(&leaf)?;
        builder.set_private_key(&self.leaf_key)?;
        // Only HTTP/1.1 is read; a client that insists on h2 fails and the
        // host is then passed through.
        builder.set_alpn_select_callback(|_, offered| {
            let mut rest = offered;
            while let Some((&n, tail)) = rest.split_first() {
                let n = n as usize;
                if tail.len() < n {
                    break;
                }
                if &tail[..n] == b"http/1.1" {
                    return Ok(&tail[..n]);
                }
                rest = &tail[n..];
            }
            Err(AlpnError::NOACK)
        });
        let acceptor = Arc::new(builder.build());
        if limit > 0 {
            let mut leaves = self.leaves.write().unwrap();
            if let Some((used, existing)) = leaves.get(host) {
                used.store(
                    self.leaf_tick.fetch_add(1, Ordering::Relaxed),
                    Ordering::Relaxed,
                );
                return Ok(existing.clone());
            }
            if leaves.len() >= limit
                && let Some(evict) = leaves
                    .iter()
                    .min_by_key(|(_, (used, _))| used.load(Ordering::Relaxed))
                    .map(|(k, _)| k.clone())
            {
                leaves.remove(&evict);
            }
            let tick = self.leaf_tick.fetch_add(1, Ordering::Relaxed);
            leaves.insert(host.to_owned(), (AtomicU64::new(tick), acceptor.clone()));
        }
        Ok(acceptor)
    }
    fn leaf(&self, host: &str) -> Result<X509> {
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_nid(Nid::COMMONNAME, host)?;
        let name = name.build();
        let mut builder = X509Builder::new()?;
        builder.set_version(2)?;
        let value6 = serial()?.to_asn1_integer()?;
        builder.set_serial_number(&value6)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(self.cert.subject_name())?;
        builder.set_pubkey(&self.leaf_key)?;
        let value7 = Asn1Time::from_unix(unix_now() - 86400)?;
        builder.set_not_before(&value7)?;
        // Apple refuses server certificates valid for more than 398 days.
        let value8 = Asn1Time::days_from_now(365)?;
        builder.set_not_after(&value8)?;
        let value9 = BasicConstraints::new().build()?;
        builder.append_extension(&value9)?;
        let value10 = KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()?;
        builder.append_extension(&value10)?;
        let value11 = ExtendedKeyUsage::new().server_auth().build()?;
        builder.append_extension(&value11)?;
        let mut names = SubjectAlternativeName::new();
        if host.parse::<std::net::IpAddr>().is_ok() {
            names.ip(host);
        } else {
            names.dns(host);
        }
        let names = names.build(&builder.x509v3_context(Some(&self.cert), None))?;
        builder.append_extension(&names)?;
        let identifier = AuthorityKeyIdentifier::new()
            .keyid(false)
            .build(&builder.x509v3_context(Some(&self.cert), None))?;
        builder.append_extension(&identifier)?;
        builder.sign(&self.key, MessageDigest::sha256())?;
        Ok(builder.build())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum BypassReason {
    ClientCertificateRefused,
    ClientProtocolIncompatible,
    UpstreamCertificate,
    UpstreamProtocol,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BypassEntry {
    reason: BypassReason,
    expires_at: i64,
    lenient_upstream: bool,
    persisted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedBypassEntry {
    host: String,
    reason: BypassReason,
    expires_at: i64,
    #[serde(default)]
    lenient_upstream: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedBypass {
    version: u32,
    ca_fingerprint: String,
    #[serde(default)]
    entries: Vec<PersistedBypassEntry>,
}

fn with_normalized_host<R>(host: &str, f: impl FnOnce(&str) -> R) -> R {
    let host = host.trim_end_matches('.');
    if !host.bytes().any(|b| b.is_ascii_uppercase()) {
        return f(host);
    }
    if host.len() <= 256 {
        let mut buf = [0u8; 256];
        for (dst, &src) in buf[..host.len()].iter_mut().zip(host.as_bytes()) {
            *dst = src.to_ascii_lowercase();
        }
        let lower = std::str::from_utf8(&buf[..host.len()]).unwrap();
        f(lower)
    } else {
        f(&host.to_ascii_lowercase())
    }
}

fn dedup_host_patterns(hosts: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::with_capacity(hosts.len());
    let mut out = Vec::with_capacity(hosts.len());
    for host in hosts {
        let trimmed = host.trim();
        let key = if let Some(excluded) = trimmed.strip_prefix('-') {
            let excluded = excluded.trim().trim_end_matches('.');
            if excluded.is_empty() {
                continue;
            }
            (true, excluded.to_ascii_lowercase())
        } else {
            let included = trimmed.trim_end_matches('.');
            if included.is_empty() {
                continue;
            }
            (false, included.to_ascii_lowercase())
        };
        if seen.insert(key) {
            out.push(host);
        }
    }
    out
}

#[derive(Default)]
struct PatternGroup {
    match_all: bool,
    exact: HashSet<Box<str>>,
    dot_suffix: HashSet<Box<str>>,
    wildcards: Vec<Box<str>>,
}

impl PatternGroup {
    fn insert(&mut self, pattern: &str) {
        let pattern = pattern.trim_end_matches('.');
        if pattern.is_empty() {
            return;
        }
        if pattern.bytes().all(|b| b == b'*') {
            self.match_all = true;
            return;
        }
        let lower = pattern.to_ascii_lowercase();
        if !lower.contains('*') && !lower.contains('?') {
            self.exact.insert(lower.into_boxed_str());
        } else if let Some(suffix) = lower.strip_prefix("*.")
            && !suffix.is_empty()
            && !suffix.contains('*')
            && !suffix.contains('?')
        {
            self.dot_suffix.insert(suffix.into());
        } else if !self
            .wildcards
            .iter()
            .any(|existing| existing.as_ref() == lower.as_str())
        {
            self.wildcards.push(lower.into_boxed_str());
        }
    }

    fn matches(&self, lower_host: &str) -> bool {
        if self.match_all {
            return true;
        }
        if self.exact.contains(lower_host) {
            return true;
        }
        if !self.dot_suffix.is_empty() {
            for (idx, &b) in lower_host.as_bytes().iter().enumerate() {
                if b == b'.' && self.dot_suffix.contains(&lower_host[idx + 1..]) {
                    return true;
                }
            }
        }
        self.wildcards
            .iter()
            .any(|pattern| clyntis_config::mitm::wildcard(pattern, lower_host))
    }

    fn is_empty(&self) -> bool {
        !self.match_all
            && self.exact.is_empty()
            && self.dot_suffix.is_empty()
            && self.wildcards.is_empty()
    }
}

/// Pre-compiled MITM hostname matcher combining user settings and module hosts.
#[derive(Default)]
struct HostMatcher {
    user_include: PatternGroup,
    user_exclude: PatternGroup,
    module_include: PatternGroup,
    module_exclude: PatternGroup,
}

impl HostMatcher {
    fn new(user: &[String], modules: &[String]) -> Self {
        let mut out = Self::default();
        for pattern in user {
            let pattern = pattern.trim();
            if let Some(excluded) = pattern.strip_prefix('-') {
                out.user_exclude.insert(excluded.trim());
            } else if !pattern.is_empty() {
                out.user_include.insert(pattern);
            }
        }
        for pattern in modules {
            let pattern = pattern.trim();
            if let Some(excluded) = pattern.strip_prefix('-') {
                out.module_exclude.insert(excluded.trim());
            } else if !pattern.is_empty() {
                out.module_include.insert(pattern);
            }
        }
        out
    }

    /// Listed by the user or a module; the user's exclusions win, and the
    /// user's explicit inclusions override module exclusions.
    fn listed(&self, host: &str) -> bool {
        with_normalized_host(host, |lower| {
            if self.user_exclude.matches(lower) {
                return false;
            }
            if self.user_include.matches(lower) {
                return true;
            }
            if self.module_exclude.matches(lower) {
                return false;
            }
            self.module_include.matches(lower)
        })
    }

    /// Listed by a module and not excluded by either the user or a module.
    fn matches_module(&self, host: &str) -> bool {
        if self.module_include.is_empty() {
            return false;
        }
        with_normalized_host(host, |lower| {
            !self.user_exclude.matches(lower)
                && !self.module_exclude.matches(lower)
                && self.module_include.matches(lower)
        })
    }
}

/// The decryption settings and state of a running core.
pub(crate) struct Interceptor {
    settings: RwLock<Mitm>,
    /// Hosts the rewrite modules decrypt, besides the user's.
    module_hosts: RwLock<Vec<String>>,
    /// Pre-compiled combined matcher updated whenever `settings` or `module_hosts` changes.
    host_matcher: RwLock<HostMatcher>,
    authority: RwLock<Option<Arc<Authority>>>,
    /// Fingerprint of the active/most recent CA authority for detecting CA changes.
    active_fingerprint: RwLock<Option<String>>,
    /// Why decryption is on but not working.
    error: RwLock<Option<String>>,
    /// Hosts temporarily bypassed for client certificate refusal, upstream
    /// verification failure, or protocol incompatibility.
    bypass: Mutex<HashMap<String, BypassEntry>>,
    /// Hosts that had HTTP/2-only (non-HTTP/1.1 ALPN) connections passed
    /// through without decryption or rewrite, mapped to their expiry timestamp.
    alpn_bypass: Mutex<HashMap<String, i64>>,
    storage_path: Option<PathBuf>,
    persist_lock: Mutex<()>,
    /// Tests talk to servers with their own certificates.
    verify_upstream: AtomicBool,
    enable: AtomicBool,
    quic_fallback: AtomicBool,
    hosted: bool,
    leaf_limit: usize,
    inspection_limit: usize,
    inspection_slots: Arc<Semaphore>,
    rewrite_slot: Arc<Semaphore>,
    memory_limited: AtomicBool,
    upstream_handshake_ms: AtomicU64,
    passthrough_dial_ms: AtomicU64,
    first_bytes_ms: AtomicU64,
    pub(crate) hosted_keepalive_idle_ms: AtomicU64,
}
impl Interceptor {
    pub(crate) fn new(mitm: &Mitm, directory: &Path, hosted: bool) -> Self {
        let inspection_limit = if hosted {
            HOSTED_INSPECTIONS
        } else {
            Semaphore::MAX_PERMITS
        };
        let interceptor = Self {
            settings: RwLock::default(),
            module_hosts: RwLock::default(),
            host_matcher: RwLock::default(),
            authority: RwLock::default(),
            active_fingerprint: RwLock::default(),
            error: RwLock::default(),
            bypass: Mutex::default(),
            alpn_bypass: Mutex::default(),
            storage_path: Some(directory.join(BYPASS_FILE_NAME)),
            persist_lock: Mutex::default(),
            verify_upstream: true.into(),
            enable: false.into(),
            quic_fallback: false.into(),
            hosted,
            leaf_limit: if hosted { HOSTED_LEAVES } else { LEAVES },
            inspection_limit,
            inspection_slots: Arc::new(Semaphore::new(inspection_limit)),
            rewrite_slot: Arc::new(Semaphore::new(1)),
            memory_limited: false.into(),
            upstream_handshake_ms: AtomicU64::new(UPSTREAM_HANDSHAKE.as_millis() as u64),
            passthrough_dial_ms: AtomicU64::new(PASSTHROUGH_DIAL.as_millis() as u64),
            first_bytes_ms: AtomicU64::new(FIRST_BYTES.as_millis() as u64),
            hosted_keepalive_idle_ms: AtomicU64::new(HOSTED_KEEPALIVE_IDLE.as_millis() as u64),
        };
        if let Err(error) = interceptor.set(mitm.clone()) {
            tracing::warn!("HTTPS decryption is off: {error:#}");
        }
        interceptor
    }
    fn load_persisted(&self, ca_fingerprint: &str) -> HashMap<String, BypassEntry> {
        let Some(path) = &self.storage_path else {
            return HashMap::new();
        };
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HashMap::new(),
            Err(e) => {
                tracing::warn!("[MITM] cannot inspect bypass cache {}: {e}", path.display());
                return HashMap::new();
            }
        };
        if metadata.len() > MAX_BYPASS_FILE_BYTES {
            tracing::warn!("[MITM] ignoring oversized bypass cache {}", path.display());
            return HashMap::new();
        }
        let Ok(bytes) = std::fs::read(path) else {
            return HashMap::new();
        };
        let persisted: PersistedBypass = match serde_json::from_slice(&bytes) {
            Ok(parsed) => parsed,
            Err(error) => {
                tracing::warn!(
                    "[MITM] ignoring malformed bypass cache {}: {error}",
                    path.display()
                );
                return HashMap::new();
            }
        };
        if persisted.version != BYPASS_FILE_VERSION || persisted.ca_fingerprint != ca_fingerprint {
            return HashMap::new();
        }
        let now = unix_now();
        let mut out = HashMap::new();
        for entry in persisted.entries {
            if out.len() >= BYPASS {
                break;
            }
            if entry.expires_at <= now {
                continue;
            }
            // Only downstream client certificate refusal requires persistence across
            // restarts; upstream failures fall back seamlessly via raw TLS passthrough.
            if entry.reason != BypassReason::ClientCertificateRefused {
                continue;
            }
            let host = normalize_host(&entry.host).into_owned();
            if host.is_empty() {
                continue;
            }
            out.insert(
                host,
                BypassEntry {
                    reason: entry.reason,
                    expires_at: entry.expires_at,
                    lenient_upstream: entry.lenient_upstream,
                    persisted: true,
                },
            );
        }
        out
    }
    fn save_persisted(&self) {
        let Some(path) = &self.storage_path else {
            return;
        };
        let _guard = self.persist_lock.lock().unwrap();
        let ca_fingerprint = self.active_fingerprint.read().unwrap().clone();
        let entries: Vec<PersistedBypassEntry> = {
            let now = unix_now();
            let mut bypass = self.bypass.lock().unwrap();
            bypass.retain(|_, entry| entry.expires_at > now);
            let mut list: Vec<_> = bypass
                .iter()
                .filter(|(_, entry)| entry.persisted)
                .map(|(host, entry)| PersistedBypassEntry {
                    host: host.clone(),
                    reason: entry.reason,
                    expires_at: entry.expires_at,
                    lenient_upstream: entry.lenient_upstream,
                })
                .collect();
            list.sort_by(|a, b| a.host.cmp(&b.host));
            list
        };
        if entries.is_empty() {
            let _ = std::fs::remove_file(path);
            return;
        }
        let Some(ca_fingerprint) = ca_fingerprint else {
            return;
        };
        let payload = PersistedBypass {
            version: BYPASS_FILE_VERSION,
            ca_fingerprint,
            entries,
        };
        match serde_json::to_vec_pretty(&payload) {
            Ok(bytes) => {
                if let Err(error) = crate::resources::atomic_write(path, &bytes) {
                    tracing::warn!(
                        "[MITM] cannot save bypass cache {}: {error:#}",
                        path.display()
                    );
                }
            }
            Err(error) => {
                tracing::warn!("[MITM] cannot encode bypass cache: {error:#}");
            }
        }
    }
    fn remove_persisted(&self) {
        let Some(path) = &self.storage_path else {
            return;
        };
        let _guard = self.persist_lock.lock().unwrap();
        let _ = std::fs::remove_file(path);
    }
    /// Applies new settings; the CA is loaded again only when it changed.
    pub(crate) fn set(&self, mitm: Mitm) -> Result<()> {
        let prev_authority = self.authority.read().unwrap().clone();
        let prev_lenient = self.settings.read().unwrap().lenient_upstream;
        let same_loaded_ca = prev_authority
            .as_ref()
            .is_some_and(|a| a.ca_cert == mitm.ca_cert && a.ca_key == mitm.ca_key);
        let result = if !mitm.enable {
            if let Some(authority) = &prev_authority {
                authority.leaves.write().unwrap().clear();
            }
            if !same_loaded_ca {
                *self.authority.write().unwrap() = None;
            }
            Ok(())
        } else if same_loaded_ca {
            Ok(())
        } else {
            match Authority::load(&mitm) {
                Ok(authority) => {
                    let prev_fp = self.active_fingerprint.read().unwrap().clone();
                    let new_fp = authority.fingerprint.clone();
                    if prev_fp.as_ref().is_some_and(|fp| fp != &new_fp) {
                        self.bypass.lock().unwrap().clear();
                        self.alpn_bypass.lock().unwrap().clear();
                        self.remove_persisted();
                    } else if prev_fp.is_none() {
                        let loaded = self.load_persisted(&new_fp);
                        if !loaded.is_empty() {
                            let mut bypass = self.bypass.lock().unwrap();
                            for (host, entry) in loaded {
                                if bypass.len() >= BYPASS && !bypass.contains_key(&host) {
                                    break;
                                }
                                bypass.entry(host).or_insert(entry);
                            }
                        }
                    }
                    *self.active_fingerprint.write().unwrap() = Some(new_fp);
                    *self.authority.write().unwrap() = Some(Arc::new(authority));
                    Ok(())
                }
                Err(error) => {
                    *self.authority.write().unwrap() = None;
                    Err(error)
                }
            }
        };
        if mitm.lenient_upstream && !prev_lenient {
            let mut bypass = self.bypass.lock().unwrap();
            bypass.retain(|_, entry| {
                entry.reason != BypassReason::UpstreamCertificate || entry.lenient_upstream
            });
        }
        *self.error.write().unwrap() = result.as_ref().err().map(|e| format!("{e:#}"));
        {
            let mut settings = self.settings.write().unwrap();
            self.enable.store(mitm.enable, Ordering::Release);
            self.quic_fallback
                .store(mitm.quic_fallback, Ordering::Release);
            *settings = mitm;
            let modules = self.module_hosts.read().unwrap();
            *self.host_matcher.write().unwrap() = HostMatcher::new(&settings.hostname, &modules);
        }
        result
    }
    fn active(&self) -> Option<Arc<Authority>> {
        if !self.enable.load(Ordering::Acquire) {
            return None;
        }
        self.authority.read().unwrap().clone()
    }
    /// Whether servers whose names only loosely cover the host are decrypted.
    fn lenient(&self) -> bool {
        self.settings.read().unwrap().lenient_upstream
    }
    fn upstream_handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.upstream_handshake_ms.load(Ordering::Relaxed))
    }
    fn passthrough_dial_timeout(&self) -> Duration {
        Duration::from_millis(self.passthrough_dial_ms.load(Ordering::Relaxed))
    }
    fn first_bytes_timeout(&self) -> Duration {
        Duration::from_millis(self.first_bytes_ms.load(Ordering::Relaxed))
    }
    pub(crate) fn hosted_keepalive_idle(&self) -> Option<Duration> {
        self.hosted
            .then(|| Duration::from_millis(self.hosted_keepalive_idle_ms.load(Ordering::Relaxed)))
    }
    /// Whether decryption is on and working.
    pub(crate) fn is_active(&self) -> bool {
        self.active().is_some()
    }
    fn is_bypassed(&self, host: &str) -> bool {
        let key = normalize_host(host);
        let now = unix_now();
        let mut bypass = self.bypass.lock().unwrap();
        if let Some(entry) = bypass.get(key.as_ref()) {
            if entry.expires_at > now {
                return true;
            }
            bypass.remove(key.as_ref());
        }
        false
    }
    /// Whether connections to `host` are decrypted now.
    pub(crate) fn intercepts(&self, host: &str) -> bool {
        self.active().is_some() && self.listed(host) && !self.is_bypassed(host)
    }
    pub(crate) fn memory_limited(&self) -> bool {
        self.memory_limited.load(Ordering::Relaxed)
    }
    pub(crate) fn set_memory_limited(&self, limited: bool) {
        self.memory_limited.store(limited, Ordering::Relaxed);
    }
    pub(crate) fn active_inspections(&self) -> usize {
        self.inspection_limit - self.inspection_slots.available_permits()
    }
    fn can_inspect(&self) -> bool {
        !self.memory_limited() && self.inspection_slots.available_permits() != 0
    }
    pub(crate) fn try_inspect(&self) -> Option<OwnedSemaphorePermit> {
        if self.memory_limited() {
            return None;
        }
        let slot = self.inspection_slots.clone().try_acquire_owned().ok()?;
        (!self.memory_limited()).then_some(slot)
    }
    #[cfg(test)]
    pub(crate) fn try_rewrite(&self) -> Option<Arc<OwnedSemaphorePermit>> {
        if self.memory_limited() {
            return None;
        }
        self.rewrite_slot
            .clone()
            .try_acquire_owned()
            .ok()
            .map(Arc::new)
    }
    pub(crate) async fn acquire_rewrite(
        &self,
        timeout: Duration,
    ) -> Option<Arc<OwnedSemaphorePermit>> {
        if self.memory_limited() {
            return None;
        }
        let permit = tokio::time::timeout(timeout, self.rewrite_slot.clone().acquire_owned())
            .await
            .ok()?
            .ok()?;
        (!self.memory_limited()).then(|| Arc::new(permit))
    }
    /// Whether UDP 443 (QUIC) to `host` should be rejected to induce TCP fallback.
    pub(crate) fn blocks_quic(&self, host: &str) -> bool {
        if !self.can_inspect()
            || !self.enable.load(Ordering::Acquire)
            || !self.quic_fallback.load(Ordering::Acquire)
        {
            return false;
        }
        if !self.intercepts(host) {
            return false;
        }
        let key = normalize_host(host);
        let mut skipped = self.alpn_bypass.lock().unwrap();
        let Some(&expires_at) = skipped.get(key.as_ref()) else {
            return true;
        };
        let now = unix_now();
        if expires_at > now {
            false
        } else {
            skipped.remove(key.as_ref());
            true
        }
    }
    /// Listed by the user or a module; the user's exclusions win.
    fn listed(&self, host: &str) -> bool {
        self.host_matcher.read().unwrap().listed(host)
    }
    pub(crate) fn set_module_hosts(&self, hosts: Vec<String>) {
        let hosts = dedup_host_patterns(hosts);
        let settings = self.settings.read().unwrap();
        let mut modules = self.module_hosts.write().unwrap();
        *modules = hosts;
        *self.host_matcher.write().unwrap() = HostMatcher::new(&settings.hostname, &modules);
    }
    fn filter_module_hosts(&self, hosts: impl IntoIterator<Item = String>) -> Vec<String> {
        let matcher = self.host_matcher.read().unwrap();
        if matcher.module_include.is_empty() {
            return vec![];
        }
        let mut out: Vec<String> = hosts
            .into_iter()
            .filter(|host| matcher.matches_module(host))
            .collect();
        out.sort();
        out
    }
    fn current_bypass_hosts(&self) -> Vec<String> {
        let now = unix_now();
        let mut bypass = self.bypass.lock().unwrap();
        bypass.retain(|_, entry| entry.expires_at > now);
        let mut out: Vec<String> = bypass.keys().cloned().collect();
        out.sort();
        out
    }
    /// Bypassed hosts that belong to loaded rewrite modules' `[MITM] hostname` rules.
    pub(crate) fn bypassed_module_hosts(&self) -> Vec<String> {
        self.filter_module_hosts(self.current_bypass_hosts())
    }
    fn current_alpn_bypass_hosts(&self) -> Vec<String> {
        let now = unix_now();
        let mut skipped = self.alpn_bypass.lock().unwrap();
        skipped.retain(|_, expires_at| *expires_at > now);
        let mut out: Vec<String> = skipped.keys().cloned().collect();
        out.sort();
        out
    }
    /// Hosts from rewrite modules that had HTTP/2-only connections passed through.
    pub(crate) fn skipped_alpn_module_hosts(&self) -> Vec<String> {
        self.filter_module_hosts(self.current_alpn_bypass_hosts())
    }
    fn record_bypass(&self, host: &str, reason: BypassReason, ttl_secs: i64, persisted: bool) {
        let key = normalize_host(host);
        if key.is_empty() {
            return;
        }
        let now = unix_now();
        let lenient_upstream = self.lenient();
        let inserted = {
            let mut bypass = self.bypass.lock().unwrap();
            bypass.retain(|_, entry| entry.expires_at > now);
            if bypass.len() < BYPASS || bypass.contains_key(key.as_ref()) {
                bypass.insert(
                    key.into_owned(),
                    BypassEntry {
                        reason,
                        expires_at: now + ttl_secs,
                        lenient_upstream,
                        persisted,
                    },
                );
                true
            } else {
                false
            }
        };
        if inserted && persisted {
            self.save_persisted();
        }
    }
    fn record_client_cert_refused(&self, host: &str) {
        self.record_bypass(
            host,
            BypassReason::ClientCertificateRefused,
            BYPASS_TTL_SECS,
            true,
        );
    }
    fn record_client_protocol_incompatible(&self, host: &str) {
        self.record_bypass(
            host,
            BypassReason::ClientProtocolIncompatible,
            SESSION_BYPASS_TTL_SECS,
            false,
        );
    }
    fn record_upstream_bypass(&self, host: &str, reason: BypassReason) {
        self.record_bypass(host, reason, SESSION_BYPASS_TTL_SECS, false);
    }
    fn skipped_alpn(&self, host: &str) {
        let key = normalize_host(host);
        if key.is_empty() {
            return;
        }
        let now = unix_now();
        let mut skipped = self.alpn_bypass.lock().unwrap();
        skipped.retain(|_, expires_at| *expires_at > now);
        let is_new = !skipped.contains_key(key.as_ref());
        if is_new && skipped.len() < BYPASS {
            skipped.insert(key.into_owned(), now + ALPN_BYPASS_TTL_SECS);
            tracing::warn!(
                "[MITM] {host}: client ALPN does not offer http/1.1 (e.g. HTTP/2 or gRPC); passing connection through without decryption or rewrite"
            );
        } else if !is_new {
            skipped.insert(key.into_owned(), now + ALPN_BYPASS_TTL_SECS);
        }
    }
    pub(crate) fn clear_bypass(&self) {
        self.bypass.lock().unwrap().clear();
        self.alpn_bypass.lock().unwrap().clear();
        self.remove_persisted();
    }
    /// Drops cached per-host TLS acceptors under memory pressure.
    pub(crate) fn relieve_memory(&self) {
        if let Some(authority) = self.authority.read().unwrap().as_ref() {
            let mut leaves = authority.leaves.write().unwrap();
            leaves.clear();
            leaves.shrink_to_fit();
        }
    }
    pub(crate) fn status(&self) -> Value {
        let settings = self.settings.read().unwrap();
        // A configured CA is described even while decryption is off.
        let cert = self
            .authority
            .read()
            .unwrap()
            .as_ref()
            .map(|a| a.cert.clone())
            .or_else(|| X509::from_pem(settings.ca_cert.as_bytes()).ok());
        let ca = cert.map(|cert| describe(&cert));
        let bypassed = self.current_bypass_hosts();
        let skipped_alpn = self.current_alpn_bypass_hosts();
        json!({
            "enable": settings.enable,
            "hostname": settings.hostname,
            "moduleHostnames": self.module_hosts.read().unwrap().len(),
            "lenientUpstream": settings.lenient_upstream,
            "quicFallback": settings.quic_fallback,
            "active": settings.enable && self.authority.read().unwrap().is_some(),
            "ca": ca,
            "error": *self.error.read().unwrap(),
            "bypassed": bypassed,
            "skippedAlpn": skipped_alpn,
        })
    }
}

#[derive(Debug)]
enum UpstreamHandshakeFailure {
    Cancelled,
    TimedOut,
    CertificateInvalid(String),
    ProtocolIncompatible(String),
    NetworkIo(String),
    Setup(String),
}

/// Bytes already read from a stream, served again before the rest of it.
struct Prefixed<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}
impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.offset < this.prefix.len() {
            let n = buf.remaining().min(this.prefix.len() - this.offset);
            buf.put_slice(&this.prefix[this.offset..this.offset + n]);
            this.offset += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Core {
    /// Whether a TCP connection goes through [`Core::inspect_tcp`]: decryption
    /// is on, and the target names a host to decrypt or is an address whose
    /// host only the client's first bytes tell.
    pub(crate) fn inspects(&self, target: &Target) -> bool {
        if !self.mitm.can_inspect() || self.mitm.active().is_none() {
            return false;
        }
        let target = self.restore_target(target);
        match target.ip() {
            Some(_) => matches!(target.port, 80 | 443 | 8080 | 8443),
            None => self.mitm.intercepts(&target.host),
        }
    }
    /// HTTPS decryption status for the apps.
    pub fn mitm_status(&self) -> Value {
        self.mitm.status()
    }
    pub fn set_mitm(&self, mitm: Mitm) -> Result<()> {
        let disabling = !mitm.enable;
        let result = self.mitm.set(mitm);
        if disabling && let Some(rewriter) = self.rewriter() {
            rewriter.relieve_memory();
        }
        result
    }
    pub fn clear_mitm_bypass(&self) {
        self.mitm.clear_bypass();
    }
    /// Relays a client's TCP connection, decrypting it (or reading its plain
    /// HTTP) when its host is one to decrypt. The client has been told the
    /// connection is open.
    pub(crate) async fn inspect_tcp<S>(
        self: &Arc<Self>,
        mut stream: S,
        target: Target,
        source: String,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let restored = self.restore_target(&target);
        let wants_sniff = self.wants_sniff(&restored);
        let (mut route, destination, mut prefix) = if wants_sniff {
            self.sniff_target(&mut stream, &target).await?
        } else {
            (restored.clone(), restored.clone(), vec![])
        };
        crate::sniff::read_first_bytes(&mut stream, &mut prefix, self.mitm.first_bytes_timeout())
            .await?;
        let tls = prefix.first() == Some(&22);
        let mut hello_status = tls.then(|| crate::sniff::parse_client_hello(&prefix));
        let http_host = (!tls).then(|| crate::sniff::http(&prefix)).flatten();
        let sniffed_host = route.ip().and_then(|_| {
            if tls {
                match &mut hello_status {
                    Some(crate::sniff::ClientHelloStatus::Complete(hello)) => hello.sni.take(),
                    _ => None,
                }
            } else {
                http_host.clone()
            }
        });
        if wants_sniff && let Some(host) = sniffed_host.as_ref() {
            route.host = host.clone();
        }
        let inspect_host = sniffed_host.as_deref().unwrap_or(&route.host).to_owned();
        let (mut outbound, routed) = if route != restored {
            self.dial_sniffed(&route, &destination, &target, &source)
                .await?
        } else {
            self.dial_logged(&target, None, &source).await?
        };
        let http = http_host.is_some();
        let tls_http1 = match hello_status {
            Some(crate::sniff::ClientHelloStatus::Complete(hello)) => match hello.alpn {
                crate::sniff::ClientHelloAlpn::Absent
                | crate::sniff::ClientHelloAlpn::SupportsHttp1 => true,
                crate::sniff::ClientHelloAlpn::NonHttp1Only => {
                    if self.mitm.intercepts(&inspect_host) {
                        self.mitm.skipped_alpn(&inspect_host);
                    }
                    false
                }
                crate::sniff::ClientHelloAlpn::Malformed => {
                    if self.mitm.intercepts(&inspect_host) {
                        tracing::warn!(
                            "[MITM] {}: malformed ALPN extension in ClientHello; passing connection through without decryption",
                            inspect_host
                        );
                    }
                    false
                }
            },
            Some(crate::sniff::ClientHelloStatus::Incomplete) => {
                if self.mitm.intercepts(&inspect_host) {
                    tracing::warn!(
                        "[MITM] {}: incomplete TLS ClientHello before timeout; passing connection through without decryption",
                        inspect_host
                    );
                }
                false
            }
            Some(crate::sniff::ClientHelloStatus::Invalid) | None => false,
        };
        if !self.mitm.intercepts(&inspect_host) || !(tls_http1 || http) {
            outbound.write_all(&prefix).await?;
            return self.relay_io(stream, route, outbound, routed).await;
        }
        let Some(slot) = self.mitm.try_inspect() else {
            outbound.write_all(&prefix).await?;
            return self.relay_io(stream, route, outbound, routed).await;
        };
        let client = Prefixed {
            prefix,
            offset: 0,
            inner: stream,
        };
        let observe_target = Target {
            host: inspect_host,
            port: route.port,
        };
        let outcome = self
            .observe(client, observe_target, outbound, routed, tls, slot)
            .await;
        let Some(client) = outcome? else {
            return Ok(());
        };
        // Upstream handshake fell back before anything was sent to the client:
        // relay the client's own untouched TLS within a bounded dial timeout.
        let dial = async {
            if route != restored {
                self.dial_sniffed(&route, &destination, &target, &source)
                    .await
            } else {
                self.dial_logged(&target, None, &source).await
            }
        };
        let (outbound, routed) = tokio::select! {
            biased;
            _ = self.stop.cancelled() => anyhow::bail!("cancelled"),
            result = tokio::time::timeout(self.mitm.passthrough_dial_timeout(), dial) => {
                match result {
                    Ok(inner) => inner?,
                    Err(_) => anyhow::bail!("passthrough dial timed out for {route}"),
                }
            }
        };
        self.relay_io(client, route, outbound, routed).await
    }

    /// Decrypts and relays a connection. Returns the client untouched when an
    /// eligible upstream TLS handshake fails before anything is sent to the
    /// client, for the caller to pass it through as raw TLS instead.
    pub(crate) async fn observe<S>(
        self: &Arc<Self>,
        client: S,
        route: Target,
        outbound: BoxStream,
        routed: Routed,
        tls: bool,
        slot: OwnedSemaphorePermit,
    ) -> Result<Option<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let _slot = slot;
        let host = route.host.clone();
        let default_port = if tls { 443 } else { 80 };
        let authority = if route.port == default_port {
            host.clone()
        } else {
            route.to_string()
        };
        let tracker = traffic::Tracker::new(self.clone(), route, routed, "tcp")?;
        let cancel = tracker.cancel();
        let state = tracker.state.clone();
        let mut upstream: BoxStream = Box::new(traffic::Stream {
            inner: outbound,
            tracker,
        });
        if tls {
            let connector = SecureConnector::new(self.clock.clone());
            let config = TlsConnectConfig {
                server_name: host.clone(),
                alpn: vec!["http/1.1".into()],
                verify_cert: self.mitm.verify_upstream.load(Ordering::Relaxed),
                fingerprint: TlsFingerprint::Native,
                reality: None,
            };
            // Lenient: the chain must verify; the names are judged here.
            let handshake = async {
                if config.verify_cert && self.mitm.lenient() {
                    connector
                        .connect_with_names(upstream, &config, |names| {
                            clyntis_config::mitm::loosely_covers(names, &host)
                        })
                        .await
                } else {
                    connector.connect(upstream, &config).await
                }
            };
            let connected = tokio::select! {
                biased;
                _ = cancel.cancelled() => Err(UpstreamHandshakeFailure::Cancelled),
                result = tokio::time::timeout(self.mitm.upstream_handshake_timeout(), handshake) => {
                    match result {
                        Ok(Ok(stream)) => Ok(stream),
                        Ok(Err(error)) => {
                            let message = format!("{error:#}");
                            if let Some(tls_err) = error.downcast_ref::<TlsHandshakeError>() {
                                Err(match tls_err.kind {
                                    TlsHandshakeErrorKind::CertificateInvalid => {
                                        UpstreamHandshakeFailure::CertificateInvalid(message)
                                    }
                                    TlsHandshakeErrorKind::ProtocolIncompatible => {
                                        UpstreamHandshakeFailure::ProtocolIncompatible(message)
                                    }
                                    TlsHandshakeErrorKind::NetworkIo => {
                                        UpstreamHandshakeFailure::NetworkIo(message)
                                    }
                                    TlsHandshakeErrorKind::Setup => {
                                        UpstreamHandshakeFailure::Setup(message)
                                    }
                                })
                            } else {
                                Err(UpstreamHandshakeFailure::Setup(message))
                            }
                        }
                        Err(_) => Err(UpstreamHandshakeFailure::TimedOut),
                    }
                }
            };
            match connected {
                Ok(stream) => upstream = stream,
                Err(failure) => {
                    if cancel.is_cancelled()
                        || self.stop.is_cancelled()
                        || matches!(failure, UpstreamHandshakeFailure::Cancelled)
                    {
                        crate::log_close(&state, &Ok("cancelled"));
                        return Err(anyhow::anyhow!("cancelled"));
                    }
                    match failure {
                        UpstreamHandshakeFailure::Cancelled => unreachable!(),
                        UpstreamHandshakeFailure::Setup(error) => {
                            let error = std::io::Error::other(format!("{host}: {error}"));
                            crate::log_close(
                                &state,
                                &Err(std::io::Error::other(error.to_string())),
                            );
                            return Err(error.into());
                        }
                        UpstreamHandshakeFailure::CertificateInvalid(error) => {
                            self.mitm
                                .record_upstream_bypass(&host, BypassReason::UpstreamCertificate);
                            tracing::warn!(
                                "[MITM] the certificate of {host} does not verify ({error}); passing it through from now on"
                            );
                            crate::log_close(
                                &state,
                                &Ok("server certificate not verified; passed through"),
                            );
                            return Ok(Some(client));
                        }
                        UpstreamHandshakeFailure::ProtocolIncompatible(error) => {
                            self.mitm
                                .record_upstream_bypass(&host, BypassReason::UpstreamProtocol);
                            tracing::warn!(
                                "[MITM] upstream TLS handshake for {host} is incompatible ({error}); passing it through from now on"
                            );
                            crate::log_close(
                                &state,
                                &Ok("upstream TLS incompatible; passed through"),
                            );
                            return Ok(Some(client));
                        }
                        UpstreamHandshakeFailure::TimedOut => {
                            tracing::warn!(
                                "[MITM] upstream TLS handshake for {host} timed out; passing connection through without adding bypass"
                            );
                            crate::log_close(
                                &state,
                                &Ok("upstream TLS handshake failed; passed through"),
                            );
                            return Ok(Some(client));
                        }
                        UpstreamHandshakeFailure::NetworkIo(error) => {
                            tracing::warn!(
                                "[MITM] upstream TLS handshake for {host} failed ({error}); passing connection through without adding bypass"
                            );
                            crate::log_close(
                                &state,
                                &Ok("upstream TLS handshake failed; passed through"),
                            );
                            return Ok(Some(client));
                        }
                    }
                }
            }
        }
        let context = observe::Context {
            core: self.clone(),
            state: state.clone(),
            scheme: if tls { "https" } else { "http" },
            authority,
        };
        let limits = self.relay_limits();
        let expired = async {
            match limits {
                Some(limits) => traffic::idle_expired(&state, limits).await,
                None => std::future::pending().await,
            }
        };
        let relay = async {
            if !tls {
                return observe::relay(client, upstream, &context).await;
            }
            let acceptor = self
                .mitm
                .active()
                .ok_or_else(|| std::io::Error::other("decryption turned off"))?
                .acceptor(&host, self.mitm.leaf_limit)
                .map_err(std::io::Error::other)?;
            let client = match accept_classified(&acceptor, client).await {
                Ok(client) => client,
                Err(error) => {
                    let message = match error.kind {
                        ClientTlsErrorKind::CertificateRefused => {
                            self.mitm.record_client_cert_refused(&host);
                            tracing::warn!(
                                "[MITM] client refused the certificate for {host} ({error}); passing it through from now on"
                            );
                            format!("client refused the certificate: {error}")
                        }
                        ClientTlsErrorKind::ProtocolIncompatible => {
                            self.mitm.record_client_protocol_incompatible(&host);
                            tracing::warn!(
                                "[MITM] client TLS handshake for {host} is incompatible ({error}); passing it through for this session"
                            );
                            format!("client TLS handshake incompatible: {error}")
                        }
                        ClientTlsErrorKind::IoOrDisconnect => {
                            tracing::debug!(
                                "[MITM] client TLS handshake for {host} ended ({error})"
                            );
                            format!("client TLS handshake failed: {error}")
                        }
                    };
                    return Err(std::io::Error::other(message));
                }
            };
            observe::relay(client, upstream, &context).await
        };
        let outcome = tokio::select! {
            _ = cancel.cancelled() => Ok("cancelled"),
            reason = expired => Ok(reason),
            result = relay => result.map(|_| "closed"),
        };
        crate::log_close(&state, &outcome);
        outcome.map(|_| None).map_err(Into::into)
    }
}

#[cfg(test)]
pub(crate) fn test_settings(hosts: &[&str]) -> Mitm {
    let (ca_cert, ca_key) = generate_authority().unwrap();
    Mitm {
        enable: true,
        hostname: hosts.iter().map(|h| h.to_string()).collect(),
        ca_cert,
        ca_key,
        ..Mitm::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    struct TestDir(PathBuf);
    impl TestDir {
        fn new(prefix: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct TestCore {
        core: Arc<Core>,
        dir: TestDir,
    }
    impl std::ops::Deref for TestCore {
        type Target = Arc<Core>;
        fn deref(&self) -> &Self::Target {
            &self.core
        }
    }

    #[test]
    fn issues_certificates_for_hosts() {
        let dir = TestDir::new("clyntis-mitm-cert");
        let settings = test_settings(&["*.ads.test"]);
        let interceptor = Interceptor::new(&settings, dir.path(), false);
        assert!(interceptor.intercepts("x.ads.test"));
        assert!(!interceptor.intercepts("ads.test"));
        let authority = interceptor.active().unwrap();
        let leaf = authority.leaf("x.ads.test").unwrap();
        assert!(leaf.verify(&authority.key).unwrap());
        authority.acceptor("x.ads.test", LEAVES).unwrap();
        // A host certificate the iOS app checks the system trust with.
        let check = check_authority(&settings.ca_cert, &settings.ca_key).unwrap();
        let leaf =
            X509::from_der(&STANDARD.decode(check["leaf"].as_str().unwrap()).unwrap()).unwrap();
        assert!(leaf.verify(&authority.key).unwrap());
        assert!(check["ca"]["thumbprint"].is_string());
        assert!(check_authority(&settings.ca_cert, "nope").is_err());
        interceptor.record_client_cert_refused("x.ads.test");
        assert!(!interceptor.intercepts("x.ads.test"));
        assert_eq!(interceptor.status()["bypassed"][0], "x.ads.test");
        // Turning it off keeps the CA described.
        interceptor
            .set(Mitm {
                enable: false,
                ..settings
            })
            .unwrap();
        assert!(!interceptor.intercepts("y.ads.test"));
        assert!(interceptor.status()["ca"]["fingerprint"].is_string());
        // A broken CA reports why.
        let broken = Mitm {
            enable: true,
            ca_cert: "x".into(),
            ..Mitm::default()
        };
        assert!(interceptor.set(broken).is_err());
        assert!(interceptor.status()["error"].is_string());
    }

    use boring::ssl::{SslConnector, SslVerifyMode};
    use std::io::Write;
    use tokio::net::TcpListener;

    const RESPONSE_2: &[u8] =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n";

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }
    fn response_1() -> Vec<u8> {
        let body = gzip(b"ad payload");
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(&body);
        response
    }

    async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
        head
    }

    /// An HTTPS server for `ads.test` answering two requests, then closing.
    async fn server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (cert, key) = generate_authority().unwrap();
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        builder
            .set_certificate(&X509::from_pem(cert.as_bytes()).unwrap())
            .unwrap();
        builder
            .set_private_key(&PKey::private_key_from_pem(key.as_bytes()).unwrap())
            .unwrap();
        let acceptor = builder.build();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = tokio_boring::accept(&acceptor, tcp).await.unwrap();
            read_head(&mut tls).await;
            tls.write_all(&response_1()).await.unwrap();
            let head = read_head(&mut tls).await;
            assert!(head.starts_with(b"POST /track HTTP/1.1"));
            let mut body = [0u8; 3];
            tls.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"k=v");
            tls.write_all(RESPONSE_2).await.unwrap();
            tls.shutdown().await.unwrap();
        });
        port
    }

    fn core_in(dir: &Path, settings: Mitm) -> Arc<Core> {
        let mut config = clyntis_config::Config::parse(b"hosts: {ads.test: 127.0.0.1}\n").unwrap();
        config.directory = dir.to_path_buf();
        config.mitm = settings;
        let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        core.mitm
            .verify_upstream
            .store(false, std::sync::atomic::Ordering::Relaxed);
        core
    }

    fn core(settings: Mitm) -> TestCore {
        let dir = TestDir::new("clyntis-mitm-core");
        let core = core_in(dir.path(), settings);
        TestCore { core, dir }
    }

    fn client(trusted: Option<&str>) -> boring::ssl::ConnectConfiguration {
        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        builder.set_alpn_protos(b"\x02h2\x08http/1.1").unwrap();
        match trusted {
            Some(ca) => {
                builder
                    .cert_store_mut()
                    .add_cert(X509::from_pem(ca.as_bytes()).unwrap())
                    .unwrap();
                builder.set_verify(SslVerifyMode::PEER);
            }
            None => builder.set_verify(SslVerifyMode::PEER),
        }
        builder.build().configure().unwrap()
    }

    #[tokio::test]
    async fn decrypts_and_records_requests_byte_for_byte() {
        let settings = test_settings(&["*.test"]);
        let core = core(settings.clone());
        let port = server().await;
        let target = Target::new("ads.test", port).unwrap();
        assert!(core.inspects(&target));
        let (app, inbound) = tokio::io::duplex(1 << 16);
        let relay = {
            let core = core.clone();
            tokio::spawn(async move { core.inspect_tcp(inbound, target, "app".into()).await })
        };
        let mut tls = tokio_boring::connect(client(Some(&settings.ca_cert)), "ads.test", app)
            .await
            .unwrap();
        assert_eq!(tls.ssl().selected_alpn_protocol(), Some(&b"http/1.1"[..]));
        tls.write_all(b"GET /ad.js HTTP/1.1\r\nHost: ads.test\r\n\r\n")
            .await
            .unwrap();
        let expected = response_1();
        let mut received = vec![0u8; expected.len()];
        tls.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
        tls.write_all(b"POST /track HTTP/1.1\r\nHost: ads.test\r\nContent-Length: 3\r\n\r\nk=v")
            .await
            .unwrap();
        let mut rest = Vec::new();
        tls.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, RESPONSE_2);
        drop(tls);
        relay.await.unwrap().unwrap();

        let (entries, _) = core.requests.list(0, 100);
        let http: Vec<_> = entries.iter().filter(|e| e.status == "http").collect();
        assert_eq!(http.len(), 2, "{entries:?}");
        let first = http[0].http.as_ref().unwrap();
        assert_eq!(first.url, "https://ads.test/ad.js");
        assert_eq!((first.method.as_str(), first.status), ("GET", Some(200)));
        assert!(first.decrypted);
        let detail = core.requests.detail(http[0].id).unwrap();
        assert_eq!(detail["responseBody"]["text"], "ad payload");
        let second = core.requests.detail(http[1].id).unwrap();
        assert_eq!(second["requestBody"]["text"], "k=v");
        assert_eq!(second["responseBody"]["text"], "helloworld");
        assert_eq!(second["http"]["url"], "https://ads.test/track");
        let closed = entries.iter().find(|e| e.status == "closed").unwrap();
        assert_eq!((closed.requests, closed.source.as_str()), (2, "app"));
        assert_eq!(closed.reason.as_deref(), Some("closed"));
        assert_eq!(closed.host, "ads.test");
    }

    #[tokio::test]
    async fn a_client_refusing_the_certificate_bypasses_the_host() {
        let core = core(test_settings(&["ads.test"]));
        let port = server().await;
        let target = Target::new("ads.test", port).unwrap();
        let (app, inbound) = tokio::io::duplex(1 << 16);
        let relay = {
            let core = core.clone();
            tokio::spawn(async move { core.inspect_tcp(inbound, target, "app".into()).await })
        };
        // A pinned app: trusts nothing the core can sign.
        assert!(
            tokio_boring::connect(client(None), "ads.test", app)
                .await
                .is_err()
        );
        assert!(relay.await.unwrap().is_err());
        let (entries, _) = core.requests.list(0, 10);
        assert!(
            entries[0]
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("refused the certificate")),
            "{entries:?}"
        );
        assert!(!core.mitm.intercepts("ads.test"));
        assert_eq!(core.mitm_status()["bypassed"][0], "ads.test");
        core.mitm.set_module_hosts(vec!["ads.test".into()]);
        assert_eq!(core.mitm.bypassed_module_hosts(), ["ads.test"]);
        core.clear_mitm_bypass();
        assert!(core.mitm.intercepts("ads.test"));
        assert!(core.mitm.bypassed_module_hosts().is_empty());
    }

    #[tokio::test]
    async fn a_server_certificate_that_does_not_verify_passes_through() {
        // The server's certificate is self-signed: it does not verify.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (cert, key) = generate_authority().unwrap();
        let server_cert = X509::from_pem(cert.as_bytes()).unwrap();
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        builder.set_certificate(&server_cert).unwrap();
        builder
            .set_private_key(&PKey::private_key_from_pem(key.as_bytes()).unwrap())
            .unwrap();
        let acceptor = builder.build();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                // The core's own attempt fails; the client's own TLS follows.
                let Ok(mut tls) = tokio_boring::accept(&acceptor, tcp).await else {
                    continue;
                };
                read_head(&mut tls).await;
                tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await
                    .unwrap();
                tls.shutdown().await.unwrap();
                break;
            }
        });

        // Leniency covers names, never an untrusted chain.
        let core = core(Mitm {
            lenient_upstream: true,
            ..test_settings(&["ads.test"])
        });
        core.mitm
            .verify_upstream
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let target = Target::new("ads.test", port).unwrap();
        assert!(core.inspects(&target));
        let (app, inbound) = tokio::io::duplex(1 << 16);
        let relay = {
            let core = core.clone();
            tokio::spawn(async move { core.inspect_tcp(inbound, target, "app".into()).await })
        };
        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        builder.set_verify(SslVerifyMode::NONE);
        let config = builder.build().configure().unwrap();
        let mut tls = tokio_boring::connect(config, "ads.test", app)
            .await
            .unwrap();
        // The client sees the server's own certificate, not one the core made.
        assert_eq!(
            tls.ssl().peer_certificate().unwrap().to_der().unwrap(),
            server_cert.to_der().unwrap()
        );
        tls.write_all(b"GET / HTTP/1.1\r\nHost: ads.test\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tls.read_to_end(&mut response).await.unwrap();
        assert!(response.ends_with(b"\r\n\r\nok"));
        drop(tls);
        let _ = relay.await.unwrap();
        assert!(!core.mitm.intercepts("ads.test"));
        assert_eq!(core.mitm_status()["bypassed"][0], "ads.test");
        let (entries, _) = core.requests.list(0, 10);
        assert!(
            entries
                .iter()
                .any(|e| e.reason.as_deref()
                    == Some("server certificate not verified; passed through")),
            "{entries:?}"
        );
    }

    /// Reads one response: its head and a Content-Length body.
    async fn read_response<S: AsyncRead + Unpin>(stream: &mut S) -> (String, Vec<u8>) {
        let head = String::from_utf8(read_head(stream).await).unwrap();
        let length = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .map_or(0, |v| v.trim().parse().unwrap());
        let mut body = vec![0u8; length];
        stream.read_exact(&mut body).await.unwrap();
        (head, body)
    }

    #[tokio::test]
    async fn keep_alive_uses_request_snapshots_and_preserves_http_boundaries() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir(&dir).unwrap();
        let script = dir.join("rule.js");
        std::fs::write(
            &script,
            r#"
            if ($request.url.endsWith("/stop")) $done({response: {status: 403, body:"stop"}});
            else if ($request.url.endsWith("/generate")) $done({body:"new"});
            else $done({headers: {"X-Rule":"yes"}});
        "#,
        )
        .unwrap();
        let core = core(test_settings(&["ads.test"]));
        let install = |version: &str| {
            let text = format!(
                r#"[Script]
up = type=http-request,pattern=/(local|upload)$,requires-body=1,script-path=https://s.test/r
generate = type=http-request,pattern=/generate$,script-path=https://s.test/r
generated = type=http-response,pattern=/generate$,script-path=https://s.test/r
stop = type=http-request,pattern=/stop$,script-path=https://s.test/r
[URL Rewrite]
/local$ - reject-dict
[Header Rewrite]
http-response /upload$ header-add X-Version {version}
"#
            );
            let module = clyntis_config::rewrite::parse_module(&text);
            assert!(module.skipped.is_empty());
            let loaded = crate::rewrite::Loaded {
                name: version.into(),
                module,
                updated: None,
                missing: vec![],
                files: [(
                    "https://s.test/r".into(),
                    crate::rewrite::RewriteFile::pin(&script).unwrap(),
                )]
                .into(),
            };
            let mut resources = crate::resources::Resources::default();
            resources.rewrite = Some(Arc::new(crate::rewrite::Rewriter::new(
                vec![loaded],
                vec![],
            )));
            *core.resources.write().unwrap() = Arc::new(resources);
        };
        install("first");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = Target::new("ads.test", listener.local_addr().unwrap().port()).unwrap();
        let (mut app, inbound) = tokio::io::duplex(4096);
        let relay = {
            let core = core.clone();
            tokio::spawn(async move { core.inspect_tcp(inbound, target, "app".into()).await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(8), async {
            app.write_all(b"HEAD /local HTTP/1.1\r\nHost: ads.test\r\n\r\n").await.unwrap();
            let (mut server, _) = listener.accept().await.unwrap();
            let head = String::from_utf8(read_head(&mut app).await).unwrap();
            assert!(head.starts_with("HTTP/1.1 200") && head.contains("Content-Length: 2"));
            app.write_all(b"POST /local HTTP/1.1\r\nHost: ads.test\r\nContent-Length: 4\r\n\r\ndata").await.unwrap();
            let (head, body) = read_response(&mut app).await;
            assert!(head.starts_with("HTTP/1.1 200"));
            assert_eq!(body, b"{}");
            app.write_all(b"POST /upload HTTP/1.1\r\nHost: ads.test\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n").await.unwrap();
            assert!(read_head(&mut app).await.starts_with(b"HTTP/1.1 100 Continue"));
            app.write_all(b"data").await.unwrap();
            let head = String::from_utf8(read_head(&mut server).await).unwrap();
            assert!(head.starts_with("POST /upload") && head.contains("Content-Length: 4"));
            assert!(!head.to_ascii_lowercase().contains("expect:"));
            let mut upload = [0; 4];
            server.read_exact(&mut upload).await.unwrap();
            assert_eq!(&upload, b"data");
            install("second");
            server.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await.unwrap();
            assert!(read_response(&mut app).await.0.contains("X-Version: first"));
            app.write_all(b"POST /upload HTTP/1.1\r\nHost: ads.test\r\nContent-Length: 0\r\n\r\n").await.unwrap();
            read_head(&mut server).await;
            server.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await.unwrap();
            assert!(read_response(&mut app).await.0.contains("X-Version: second"));
            app.write_all(b"POST /generate HTTP/1.1\r\nHost: ads.test\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\n\r\ndata").await.unwrap();
            let head = String::from_utf8(read_head(&mut server).await).unwrap();
            assert!(head.contains("Content-Length: 3"));
            assert!(!head.to_ascii_lowercase().contains("content-encoding"));
            let mut generated = [0; 3];
            server.read_exact(&mut generated).await.unwrap();
            assert_eq!(&generated, b"new");
            server.write_all(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\n\r\ndata").await.unwrap();
            let (head, body) = read_response(&mut app).await;
            assert!(!head.to_ascii_lowercase().contains("content-encoding"));
            assert_eq!(body, b"new");
            let entry = core.requests.list(0, 20).0.into_iter()
                .find(|entry| entry.http.as_ref().is_some_and(|http| http.url.ends_with("/generate")))
                .unwrap();
            let detail = core.requests.detail(entry.id).unwrap();
            for key in ["requestHeaders", "responseHeaders"] {
                let headers = detail[key].as_array().unwrap();
                assert!(headers.contains(&json!(["Content-Length", "3"])));
                assert!(!headers.iter().any(|h| h[0].as_str().unwrap().eq_ignore_ascii_case("content-encoding")));
            }
            assert_eq!(detail["requestBody"]["text"], "new");
            assert_eq!(detail["responseBody"]["text"], "new");
            app.write_all(b"POST /stop HTTP/1.1\r\nHost: ads.test\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n").await.unwrap();
            let (head, body) = read_response(&mut app).await;
            assert!(head.starts_with("HTTP/1.1 403") && head.contains("Connection: close"));
            assert_eq!(body, b"stop");
            assert_eq!(app.read(&mut [0]).await.unwrap(), 0);
            drop(server);
            drop(app);
            relay.await.unwrap().unwrap();
        }).await.unwrap();

        // A client that closes before sending the full body can still read the answer.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = Target::new("ads.test", listener.local_addr().unwrap().port()).unwrap();
        let (mut app, inbound) = tokio::io::duplex(4096);
        let relay = {
            let core = core.clone();
            tokio::spawn(async move { core.inspect_tcp(inbound, target, "app".into()).await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(8), async {
            app.write_all(b"POST /stop HTTP/1.1\r\nHost: ads.test\r\nContent-Length: 4\r\n\r\nx")
                .await
                .unwrap();
            app.shutdown().await.unwrap();
            let (_server, _) = listener.accept().await.unwrap();
            let (head, body) = read_response(&mut app).await;
            assert!(head.starts_with("HTTP/1.1 403") && head.contains("Connection: close"));
            assert_eq!(body, b"stop");
            assert_eq!(app.read(&mut [0]).await.unwrap(), 0);
            relay.await.unwrap().unwrap();
        })
        .await
        .unwrap();
        drop(core);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn rewrites_decrypted_http_with_modules_and_scripts() {
        let directory =
            std::env::temp_dir().join(format!("clyntis-rewrite-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let feed = directory.join("feed.js");
        std::fs::write(
            &feed,
            r#"const b = JSON.parse($response.body);
b.arg = $argument;
b.stored = $persistentStore.read("k");
$persistentStore.write("v1", "k");
const headers = Object.assign({}, $response.headers, {"X-Script": String($response.status)});
setTimeout(() => $done({body: JSON.stringify(b), headers}), 1);"#,
        )
        .unwrap();
        let up = directory.join("up.js");
        std::fs::write(
            &up,
            r#"if ($request.body !== "orig") throw new Error("body " + $request.body);
Promise.resolve().then(() => $done({body: new TextEncoder().encode("changed")}));"#,
        )
        .unwrap();
        let module = clyntis_config::rewrite::parse_module(
            r#"[URL Rewrite]
^http://ads\.test/ad - reject-dict
[Header Rewrite]
http-request ^http://ads\.test/up header-add X-Flag 1
[Body Rewrite]
http-response-jq ^http://ads\.test/feed 'del(.list[].ad)'
[Script]
feed = type=http-response,pattern=^http://ads\.test/feed,requires-body=1,script-path=https://s.test/feed.js,argument=hello
up = type=http-request,pattern=^http://ads\.test/up,requires-body=1,script-path=https://s.test/up.js
[MITM]
hostname = ads.test
"#,
        );
        assert!(module.skipped.is_empty(), "{:?}", module.skipped);
        let rewriter = crate::rewrite::Rewriter::new(
            vec![crate::rewrite::Loaded {
                name: "ads".into(),
                module,
                files: [
                    (
                        "https://s.test/feed.js".to_owned(),
                        crate::rewrite::RewriteFile::pin(&feed).unwrap(),
                    ),
                    (
                        "https://s.test/up.js".to_owned(),
                        crate::rewrite::RewriteFile::pin(&up).unwrap(),
                    ),
                ]
                .into(),
                missing: vec![],
                updated: None,
            }],
            vec![],
        );
        assert_eq!(rewriter.rule_count(), 5);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            // The rejected request never arrives.
            let head = String::from_utf8(read_head(&mut tcp).await).unwrap();
            assert!(head.starts_with("GET /feed HTTP/1.1"), "{head}");
            let body = gzip(br#"{"list":[{"ad":1,"id":1}],"ok":true}"#);
            let mut response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes();
            response.extend_from_slice(&body);
            tcp.write_all(&response).await.unwrap();
            let head = String::from_utf8(read_head(&mut tcp).await).unwrap();
            assert!(head.starts_with("POST /up HTTP/1.1"), "{head}");
            assert!(head.contains("X-Flag: 1\r\n"), "{head}");
            assert!(head.contains("Content-Length: 7\r\n"), "{head}");
            let mut body = [0u8; 7];
            tcp.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"changed");
            tcp.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            tcp.shutdown().await.unwrap();
        });

        let mut config = clyntis_config::Config::parse(b"hosts: {ads.test: 127.0.0.1}\n").unwrap();
        config.mitm = test_settings(&[]);
        config.directory = directory.clone();
        let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        core.mitm.set_module_hosts(rewriter.hostnames.clone());
        {
            let mut resources = crate::resources::Resources::default();
            resources.rewrite = Some(Arc::new(rewriter));
            *core.resources.write().unwrap() = Arc::new(resources);
        }
        let target = Target::new("ads.test", port).unwrap();
        assert!(core.inspects(&target));
        let (mut app, inbound) = tokio::io::duplex(1 << 16);
        let relay = {
            let core = core.clone();
            tokio::spawn(async move { core.inspect_tcp(inbound, target, "app".into()).await })
        };
        app.write_all(b"GET /ad HTTP/1.1\r\nHost: ads.test\r\n\r\n")
            .await
            .unwrap();
        let (head, body) = read_response(&mut app).await;
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        assert_eq!(body, b"{}");
        app.write_all(b"GET /feed HTTP/1.1\r\nHost: ads.test\r\n\r\n")
            .await
            .unwrap();
        let (head, body) = read_response(&mut app).await;
        assert!(head.contains("X-Script: 200\r\n"), "{head}");
        assert!(!head.contains("Content-Encoding"), "{head}");
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"list": [{"id": 1}], "ok": true, "arg": "hello", "stored": null})
        );
        app.write_all(b"POST /up HTTP/1.1\r\nHost: ads.test\r\nContent-Length: 4\r\n\r\norig")
            .await
            .unwrap();
        let (_, body) = read_response(&mut app).await;
        assert_eq!(body, b"ok");
        drop(app);
        server.await.unwrap();
        let _ = relay.await.unwrap();

        let (entries, _) = core.requests.list(0, 100);
        let http: Vec<_> = entries.iter().filter_map(|e| e.http.as_ref()).collect();
        assert_eq!(http.len(), 3, "{entries:?}");
        assert_eq!(http[0].rewrite.as_deref(), Some("reject-dict (ads)"));
        assert_eq!(http[0].rewrite_actions, ["reject-dict"]);
        assert!(http[0].answered);
        assert_eq!(
            http[1].rewrite.as_deref(),
            Some("jq (ads), script feed (ads)")
        );
        assert_eq!(http[1].rewrite_actions, ["jq", "script feed"]);
        assert!(!http[1].answered);
        assert_eq!(
            http[2].rewrite.as_deref(),
            Some("header (ads), script up (ads)")
        );
        assert_eq!(http[2].rewrite_actions, ["header", "script up"]);
        assert!(!http[2].answered);
        let status = core.rewrite_status();
        assert_eq!(status["total"], 5);
        assert_eq!(status["rejects"], 1);
        assert_eq!(status["rewrites"], 4);
        assert_eq!(status["rejectRules"], 0);
        assert_eq!(status["bypassed"], json!([]));
        assert_eq!(status["modules"][0]["rules"], 5);
        // The script's store persisted.
        let store = std::fs::read_to_string(directory.join("rewrite/store.json")).unwrap();
        assert_eq!(store, r#"{"k":"v1"}"#);
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[tokio::test]
    async fn hosted_inspection_limits_pass_through_the_original_handshake() {
        let dir = TestDir::new("clyntis-mitm-budget");
        let mut config = clyntis_config::Config::parse(b"hosts: {ads.test: 127.0.0.1}\n").unwrap();
        config.directory = dir.path().to_path_buf();
        config.internal_host_packet_io = true;
        config.mitm = test_settings(&["ads.test"]);
        config.mitm.quic_fallback = true;
        let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = Target::new("ads.test", listener.local_addr().unwrap().port()).unwrap();
        assert!(core.inspects(&target));
        assert!(core.mitm.blocks_quic(&target.host));
        let mut permits: Vec<_> = (0..HOSTED_INSPECTIONS)
            .map(|_| core.mitm.try_inspect().unwrap())
            .collect();

        tokio::time::timeout(Duration::from_secs(5), async {
            for paused in [false, true] {
                if paused {
                    // The next connection will exercise the pressure gate instead.
                    permits.clear();
                    core.mitm.set_memory_limited(true);
                }
                assert!(!core.inspects(&target));
                assert!(!core.mitm.blocks_quic(&target.host));
                let hello =
                    crate::sniff::tests::client_hello_with_alpn(&target.host, &[b"http/1.1"]);
                let (mut app, inbound) = tokio::io::duplex(4096);
                let relay = {
                    let (core, target) = (core.clone(), target.clone());
                    // A connection that entered the inspector just before the gate closed.
                    tokio::spawn(
                        async move { core.inspect_tcp(inbound, target, "app".into()).await },
                    )
                };
                app.write_all(&hello).await.unwrap();
                let (mut server, _) = listener.accept().await.unwrap();
                let mut received = vec![0; hello.len()];
                server.read_exact(&mut received).await.unwrap();
                assert_eq!(received, hello);
                server.write_all(b"original server").await.unwrap();
                let mut reply = [0; 15];
                app.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"original server");
                app.shutdown().await.unwrap();
                server.shutdown().await.unwrap();
                relay.await.unwrap().unwrap();
            }
        })
        .await
        .unwrap();
        assert!(!core.inspects(&target));
        core.mitm.set_memory_limited(false);
        assert!(core.inspects(&target));
        assert!(core.mitm.blocks_quic(&target.host));
        assert!(!core.mitm.is_bypassed(&target.host));
    }

    #[tokio::test]
    async fn hosted_relay_keeps_shipping_bodies_when_rewrite_and_capture_are_limited() {
        let dir = TestDir::new("clyntis-mitm-body-budget");
        let mut config = clyntis_config::Config::parse(b"hosts: {ads.test: 127.0.0.1}\n").unwrap();
        config.directory = dir.path().to_path_buf();
        config.internal_host_packet_io = true;
        config.mitm = test_settings(&["ads.test"]);
        let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        let module = clyntis_config::rewrite::parse_module(
            r#"[Body Rewrite]
http-response-jq ^http://ads\.test.*/feed 'del(.ad)'
[Header Rewrite]
http-response ^http://ads\.test.*/feed header-add X-Handled 1
"#,
        );
        assert!(module.skipped.is_empty(), "{:?}", module.skipped);
        let rewriter = crate::rewrite::Rewriter::new(
            vec![crate::rewrite::Loaded {
                name: "ads".into(),
                module,
                files: Default::default(),
                missing: vec![],
                updated: None,
            }],
            vec![],
        );
        let mut resources = crate::resources::Resources::default();
        resources.rewrite = Some(Arc::new(rewriter));
        *core.resources.write().unwrap() = Arc::new(resources);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = Target::new("ads.test", listener.local_addr().unwrap().port()).unwrap();
        let (mut app, inbound) = tokio::io::duplex(4096);
        let relay = {
            let core = core.clone();
            tokio::spawn(async move { core.inspect_tcp(inbound, target, "app".into()).await })
        };

        tokio::time::timeout(Duration::from_secs(5), async {
            let busy = core.mitm.try_rewrite().unwrap();
            app.write_all(b"GET /feed HTTP/1.1\r\nHost: ads.test\r\n\r\n").await.unwrap();
            let (mut server, _) = listener.accept().await.unwrap();
            read_head(&mut server).await;
            let original = br#"{"ad":1,"keep":2}"#;
            server.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n").await.unwrap();
            server.write_all(original).await.unwrap();
            let (head, body) = read_response(&mut app).await;
            assert!(head.contains("X-Handled: 1\r\n"));
            assert_eq!(body, original);
            drop(busy);

            app.write_all(b"GET /picture HTTP/1.1\r\nHost: ads.test\r\n\r\n").await.unwrap();
            read_head(&mut server).await;
            server.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: image/webp\r\nContent-Length: 5\r\n\r\nimage").await.unwrap();
            assert_eq!(read_response(&mut app).await.1, b"image");

            // The same stream is usable after both downgrades.
            app.write_all(b"GET /feed HTTP/1.1\r\nHost: ads.test\r\n\r\n").await.unwrap();
            read_head(&mut server).await;
            server.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n").await.unwrap();
            server.write_all(original).await.unwrap();
            assert_eq!(read_response(&mut app).await.1, br#"{"keep":2}"#);

            app.shutdown().await.unwrap();
            server.shutdown().await.unwrap();
            relay.await.unwrap().unwrap();
        }).await.unwrap();
        let picture = core
            .requests
            .list(0, 20)
            .0
            .into_iter()
            .find(|entry| {
                entry
                    .http
                    .as_ref()
                    .is_some_and(|http| http.url.ends_with("/picture"))
            })
            .unwrap();
        let detail = core.requests.detail(picture.id).unwrap();
        assert_eq!(detail["responseBody"]["size"], 5);
        assert_eq!(detail["responseBody"]["truncated"], true);
        assert_eq!(detail["responseBody"]["text"], "");
    }

    #[tokio::test]
    async fn h2_only_client_hello_passes_through_without_mitm_downgrade() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let n = tokio::io::AsyncReadExt::read(&mut tcp, &mut buf)
                .await
                .unwrap();
            assert_eq!(
                crate::sniff::tls(&buf[..n]).as_deref(),
                Some("grpc.ads.test")
            );
            assert!(!crate::sniff::tls_supports_http1(&buf[..n]));
            tcp.write_all(b"RAW-PASSTHROUGH").await.unwrap();
        });

        let dir = TestDir::new("clyntis-mitm-h2");
        let mut config =
            clyntis_config::Config::parse(b"hosts: {grpc.ads.test: 127.0.0.1}\n").unwrap();
        config.directory = dir.path().to_path_buf();
        config.mitm = test_settings(&["*.ads.test"]);
        let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        let target = Target::new("grpc.ads.test", port).unwrap();
        assert!(core.inspects(&target));
        let (mut app, inbound) = tokio::io::duplex(4096);
        let relay = {
            let core = core.clone();
            tokio::spawn(async move { core.inspect_tcp(inbound, target, "app".into()).await })
        };
        let hello = crate::sniff::tests::client_hello_with_alpn("grpc.ads.test", &[b"h2"]);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            app.write_all(&hello).await.unwrap();
            let mut reply = [0u8; 15];
            tokio::io::AsyncReadExt::read_exact(&mut app, &mut reply)
                .await
                .unwrap();
            assert_eq!(&reply, b"RAW-PASSTHROUGH");
            drop(app);
            server.await.unwrap();
            let _ = relay.await.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(core.mitm_status()["skippedAlpn"], json!(["grpc.ads.test"]));
    }

    #[tokio::test]
    async fn dsl_url_replace_conditions_pipes_and_reject_status_work_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let dir = TestDir::new("clyntis-mitm-dsl");
        let mut config = clyntis_config::Config::parse(b"hosts: {ads.test: 127.0.0.1}\n").unwrap();
        config.directory = dir.path().to_path_buf();
        config.mitm = test_settings(&["ads.test"]);
        let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        let module = clyntis_config::rewrite::parse_module(&format!(
            r#"
[Rewrite]
request if ${{url}} ~= /^http:\/\/ads\.test:{port}\/old\/(.*)$/ as m then url.replace("http://ads.test:{port}/new/${{m.1}}") | header.set("X-Added", "1") | header.del("X-Remove")
request if ${{url}} ~= /^http:\/\/ads\.test:{port}\/pipe$/ && ${{request.header["X-Mode"]}} == "old" then header.set("X-Mode", "new") | header.del("Cookie")
request if ${{url}} ~= /^http:\/\/ads\.test:{port}\/cross$/ then url.replace("http://other.test:{port}/x")
request if ${{url}} ~= /^http:\/\/ads\.test:{port}\/blocked$/ then reject(451, "blocked")
request if ${{url}} ~= /^http:\/\/ads\.test:{port}\/dict403$/ then reject_dict(403)
response if ${{url}} ~= /^http:\/\/ads\.test:{port}\/new\/ok$/ && ${{response.status}} == 200 then response.header.set("X-Resp", "matched")
response if ${{url}} ~= /^http:\/\/ads\.test:{port}\/lazy$/ then response.header.set("X-Mode", "clean")
response if ${{url}} ~= /^http:\/\/ads\.test:{port}\/lazy$/ && ${{response.header["X-Mode"]}} == "clean" then response.json.delete("ad")
[MITM]
hostname = ads.test
"#
        ));
        assert!(module.skipped.is_empty(), "{:?}", module.skipped);
        let rewriter = crate::rewrite::Rewriter::new(
            vec![crate::rewrite::Loaded {
                name: "dsl".into(),
                module,
                updated: None,
                missing: vec![],
                files: Default::default(),
            }],
            vec![],
        );
        {
            let mut resources = crate::resources::Resources::default();
            resources.rewrite = Some(Arc::new(rewriter));
            *core.resources.write().unwrap() = Arc::new(resources);
        }
        let target = Target::new("ads.test", port).unwrap();
        let (mut app, inbound) = tokio::io::duplex(8192);
        let relay = {
            let core = core.clone();
            tokio::spawn(async move { core.inspect_tcp(inbound, target, "app".into()).await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            app.write_all(
                format!(
                    "GET /old/ok HTTP/1.1\r\nHost: ads.test:{port}\r\nX-Remove: yes\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            let (mut server, _) = listener.accept().await.unwrap();
            let head = String::from_utf8(read_head(&mut server).await).unwrap();
            assert!(head.starts_with("GET /new/ok HTTP/1.1\r\n"), "{head}");
            assert!(head.contains("X-Added: 1\r\n"), "{head}");
            assert!(!head.contains("X-Remove"), "{head}");
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            let (head, body) = read_response(&mut app).await;
            assert!(head.contains("X-Resp: matched\r\n"), "{head}");
            assert_eq!(body, b"ok");

            // Piped rule mutating its own condition header still runs subsequent stages.
            app.write_all(
                format!(
                    "GET /pipe HTTP/1.1\r\nHost: ads.test:{port}\r\nX-Mode: old\r\nCookie: s=1\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            let head = String::from_utf8(read_head(&mut server).await).unwrap();
            assert!(head.contains("X-Mode: new\r\n"), "{head}");
            assert!(!head.contains("Cookie:"), "{head}");
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            let _ = read_response(&mut app).await;

            // Earlier header rule activates a later body rule's condition, which
            // must lazily read and rewrite the body.
            app.write_all(
                format!("GET /lazy HTTP/1.1\r\nHost: ads.test:{port}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
            let head = String::from_utf8(read_head(&mut server).await).unwrap();
            assert!(head.starts_with("GET /lazy HTTP/1.1\r\n"), "{head}");
            let json = br#"{"ad":1,"ok":2}"#;
            server
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                        json.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            server.write_all(json).await.unwrap();
            let (head, body) = read_response(&mut app).await;
            assert!(head.contains("X-Mode: clean\r\n"), "{head}");
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap(),
                json!({"ok": 2})
            );

            // Cross-origin url.replace is ignored and forwarded unchanged.
            app.write_all(
                format!("GET /cross HTTP/1.1\r\nHost: ads.test:{port}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
            let head = String::from_utf8(read_head(&mut server).await).unwrap();
            assert!(head.starts_with("GET /cross HTTP/1.1\r\n"), "{head}");
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            let _ = read_response(&mut app).await;

            // reject(451, "blocked") and reject_dict(403) preserve status and body.
            app.write_all(
                format!("GET /blocked HTTP/1.1\r\nHost: ads.test:{port}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
            let (head, body) = read_response(&mut app).await;
            assert!(head.starts_with("HTTP/1.1 451 "), "{head}");
            assert_eq!(body, b"blocked");

            app.write_all(
                format!("GET /dict403 HTTP/1.1\r\nHost: ads.test:{port}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
            let (head, body) = read_response(&mut app).await;
            assert!(head.starts_with("HTTP/1.1 403 "), "{head}");
            assert_eq!(body, b"{}");

            drop(server);
            drop(app);
            relay.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn script_without_body_then_json_delete_preserves_script_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let dir = std::env::temp_dir().join(format!("meta-mitm-script-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("gen.js");
        std::fs::write(
            &script,
            br#"$done({body: JSON.stringify({ad: 1, keep: "from-script"})});"#,
        )
        .unwrap();

        let module = clyntis_config::rewrite::parse_module(&format!(
            r#"
[Script]
gen = type=http-response,pattern=^http://ads\.test:{port}/script-json$,requires-body=0,script-path=https://s.test/gen.js
[Rewrite]
response if ${{url}} ~= /^http:\/\/ads\.test:{port}\/script-json$/ then response.json.delete("ad")
[MITM]
hostname = ads.test
"#
        ));
        assert!(module.skipped.is_empty(), "{:?}", module.skipped);
        let rewriter = crate::rewrite::Rewriter::new(
            vec![crate::rewrite::Loaded {
                name: "script-json".into(),
                module,
                updated: None,
                missing: vec![],
                files: [(
                    "https://s.test/gen.js".to_owned(),
                    crate::rewrite::RewriteFile::pin(&script).unwrap(),
                )]
                .into(),
            }],
            vec![],
        );

        let mut config = clyntis_config::Config::parse(b"hosts: {ads.test: 127.0.0.1}\n").unwrap();
        config.mitm = test_settings(&["ads.test"]);
        config.directory = dir.clone();
        let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        {
            let mut resources = crate::resources::Resources::default();
            resources.rewrite = Some(Arc::new(rewriter));
            *core.resources.write().unwrap() = Arc::new(resources);
        }

        let target = Target::new("ads.test", port).unwrap();
        let (mut app, inbound) = tokio::io::duplex(8192);
        let relay = {
            let core = core.clone();
            tokio::spawn(async move { core.inspect_tcp(inbound, target, "app".into()).await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            app.write_all(
                format!("GET /script-json HTTP/1.1\r\nHost: ads.test:{port}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
            let (mut server, _) = listener.accept().await.unwrap();
            let head = String::from_utf8(read_head(&mut server).await).unwrap();
            assert!(head.starts_with("GET /script-json HTTP/1.1\r\n"), "{head}");
            let upstream = br#"{"ad":9,"keep":"from-server"}"#;
            server
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                        upstream.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            server.write_all(upstream).await.unwrap();

            let (_, body) = read_response(&mut app).await;
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap(),
                json!({"keep": "from-script"})
            );

            // Unread upstream wire body must have been drained cleanly for keep-alive.
            app.write_all(format!("GET /ok HTTP/1.1\r\nHost: ads.test:{port}\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let head = String::from_utf8(read_head(&mut server).await).unwrap();
            assert!(head.starts_with("GET /ok HTTP/1.1\r\n"), "{head}");
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            let (_, body) = read_response(&mut app).await;
            assert_eq!(body, b"ok");

            drop(server);
            drop(app);
            relay.await.unwrap().unwrap();
        })
        .await
        .unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn bypass_persists_across_restart_respects_ca_ttl_and_clear() {
        let dir = TestDir::new("clyntis-mitm-persist");
        let settings1 = test_settings(&["ads.test"]);
        let core1 = core_in(dir.path(), settings1.clone());
        let (_cert, acceptor) = raw_tls_acceptor_for_ads().await;
        let listener1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener1.local_addr().unwrap().port();
        let server1 = tokio::spawn(async move {
            let (tcp, _) = listener1.accept().await.unwrap();
            let mut tls = tokio_boring::accept(&acceptor, tcp).await.unwrap();
            let mut buf = [0u8; 64];
            let _ = tls.read(&mut buf).await;
        });
        let target = Target::new("ads.test", port).unwrap();
        let (app, inbound) = tokio::io::duplex(1 << 16);
        let relay = {
            let core = core1.clone();
            tokio::spawn(async move { core.inspect_tcp(inbound, target, "app".into()).await })
        };
        assert!(
            tokio_boring::connect(client(None), "ads.test", app)
                .await
                .is_err()
        );
        assert!(relay.await.unwrap().is_err());
        server1.await.unwrap();
        assert!(!core1.mitm.intercepts("ads.test"));
        let bypass_file = dir.path().join(BYPASS_FILE_NAME);
        assert!(bypass_file.exists());
        drop(core1);

        // Restart with the same directory and CA: ads.test starts bypassed immediately
        // so the very first connection passes directly to the upstream server without failing.
        let core2 = core_in(dir.path(), settings1.clone());
        assert!(!core2.mitm.intercepts("ads.test"));
        assert_eq!(core2.mitm_status()["bypassed"], json!(["ads.test"]));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let raw_port = listener.local_addr().unwrap().port();
        let raw_server = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = tcp.read(&mut buf).await.unwrap();
            assert!(n > 0);
            tcp.write_all(b"RAW-AFTER-RESTART").await.unwrap();
        });
        let (mut app, inbound) = tokio::io::duplex(4096);
        let target2 = Target::new("ads.test", raw_port).unwrap();
        let relay2 = {
            let core = core2.clone();
            tokio::spawn(async move { core.inspect_tcp(inbound, target2, "app".into()).await })
        };
        app.write_all(b"GET / HTTP/1.1\r\nHost: ads.test\r\n\r\n")
            .await
            .unwrap();
        let mut got = [0u8; 17];
        app.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"RAW-AFTER-RESTART");
        drop(app);
        raw_server.await.unwrap();
        relay2.await.unwrap().unwrap();

        // Switching to a new CA clears persisted bypass entries and removes the file.
        let settings2 = test_settings(&["ads.test"]);
        core2.set_mitm(settings2.clone()).unwrap();
        assert!(core2.mitm.intercepts("ads.test"));
        assert!(!bypass_file.exists());
        drop(core2);

        // Expired persisted entries are ignored on load.
        let fp2 = Authority::load(&settings2).unwrap().fingerprint;
        let expired = PersistedBypass {
            version: BYPASS_FILE_VERSION,
            ca_fingerprint: fp2,
            entries: vec![PersistedBypassEntry {
                host: "ads.test".into(),
                reason: BypassReason::ClientCertificateRefused,
                expires_at: unix_now() - 10,
                lenient_upstream: false,
            }],
        };
        std::fs::write(&bypass_file, serde_json::to_vec(&expired).unwrap()).unwrap();
        let core3 = core_in(dir.path(), settings2);
        assert!(core3.mitm.intercepts("ads.test"));

        // Recording a new refusal creates the file; clear_mitm_bypass deletes it.
        core3.mitm.record_client_cert_refused("ads.test");
        assert!(bypass_file.exists());
        core3.clear_mitm_bypass();
        assert!(!bypass_file.exists());
        assert!(core3.mitm.intercepts("ads.test"));
    }

    #[tokio::test]
    async fn client_disconnect_without_cert_alert_does_not_bypass() {
        let core = core(test_settings(&["ads.test"]));
        let port = server().await;
        let target = Target::new("ads.test", port).unwrap();
        let (mut app, inbound) = tokio::io::duplex(4096);
        let relay = {
            let core = core.clone();
            tokio::spawn(async move { core.inspect_tcp(inbound, target, "app".into()).await })
        };
        // Send a complete ClientHello so observe enters accept_classified, then drop immediately.
        let hello = crate::sniff::tests::client_hello_with_alpn("ads.test", &[b"http/1.1"]);
        app.write_all(&hello).await.unwrap();
        drop(app);
        let err = relay.await.unwrap().unwrap_err();
        let msg = format!("{err:#}");
        assert!(!msg.contains("refused the certificate"), "{msg}");
        assert!(core.mitm.intercepts("ads.test"));
        assert_eq!(core.mitm_status()["bypassed"], json!([]));
        assert!(!core.dir.path().join(BYPASS_FILE_NAME).exists());
    }

    #[tokio::test]
    async fn enabling_lenient_upstream_evicts_strict_upstream_certificate_bypass() {
        let dir = TestDir::new("clyntis-mitm-lenient");
        let settings = test_settings(&["*.example.test"]);
        let core = core_in(dir.path(), settings.clone());
        core.mitm
            .record_upstream_bypass("a.b.example.test", BypassReason::UpstreamCertificate);
        core.mitm.record_client_cert_refused("pinned.example.test");
        assert!(!core.mitm.intercepts("a.b.example.test"));
        assert!(!core.mitm.intercepts("pinned.example.test"));

        core.set_mitm(Mitm {
            lenient_upstream: true,
            ..settings.clone()
        })
        .unwrap();
        assert!(core.mitm.intercepts("a.b.example.test"));
        assert!(!core.mitm.intercepts("pinned.example.test"));

        // Persisted strict UpstreamCertificate entries are also skipped on restart under lenient_upstream=true.
        drop(core);
        let fp = Authority::load(&settings).unwrap().fingerprint;
        let persisted = PersistedBypass {
            version: BYPASS_FILE_VERSION,
            ca_fingerprint: fp,
            entries: vec![
                PersistedBypassEntry {
                    host: "strict-only.example.test".into(),
                    reason: BypassReason::UpstreamCertificate,
                    expires_at: unix_now() + 3600,
                    lenient_upstream: false,
                },
                PersistedBypassEntry {
                    host: "pinned.example.test".into(),
                    reason: BypassReason::ClientCertificateRefused,
                    expires_at: unix_now() + 3600,
                    lenient_upstream: false,
                },
            ],
        };
        std::fs::write(
            dir.path().join(BYPASS_FILE_NAME),
            serde_json::to_vec(&persisted).unwrap(),
        )
        .unwrap();
        let core2 = core_in(
            dir.path(),
            Mitm {
                lenient_upstream: true,
                ..settings
            },
        );
        assert!(core2.mitm.intercepts("strict-only.example.test"));
        assert!(!core2.mitm.intercepts("pinned.example.test"));
    }

    #[tokio::test]
    async fn quic_policy_is_independent_and_preserves_prior_reject_reasons() {
        let dir = TestDir::new("clyntis-mitm-quic");
        let mut config = clyntis_config::Config::parse(
            b"rules:\n- DOMAIN,rule.ads.test,REJECT\n- MATCH,DIRECT\n",
        )
        .unwrap();
        config.directory = dir.path().to_path_buf();
        let mut mitm = test_settings(&["*.ads.test"]);
        mitm.quic_fallback = false;
        config.mitm = mitm.clone();
        let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        let target = Target::new("ok.ads.test", 443).unwrap();

        // Off by default: UDP 443 is not rejected by MITM(QUIC).
        assert!(!core.mitm.blocks_quic("ok.ads.test"));
        let res = core.datagram_for_source(&target, "app").await;
        if let Err(err) = &res {
            assert!(
                err.downcast_ref::<crate::Rejected>().is_none(),
                "unexpected REJECT when quic_fallback is false: {err:#}"
            );
        }

        // Turned on: UDP 443 rejects with MITM(QUIC) unless bypassed or skipped by ALPN.
        mitm.quic_fallback = true;
        core.set_mitm(mitm.clone()).unwrap();
        assert!(core.mitm.blocks_quic("ok.ads.test"));
        let rej = core
            .datagram_for_source(&target, "app")
            .await
            .err()
            .unwrap()
            .downcast_ref::<crate::Rejected>()
            .unwrap()
            .0
            .clone();
        assert_eq!(rej.rule, "MITM(QUIC)");

        core.mitm.skipped_alpn("h2only.ads.test");
        assert!(!core.mitm.blocks_quic("h2only.ads.test"));
        core.mitm.record_client_cert_refused("bypassed.ads.test");
        assert!(!core.mitm.blocks_quic("bypassed.ads.test"));

        // Existing REJECT from user rule must NOT be overwritten by MITM(QUIC).
        let rule_rej = core
            .datagram_for_source(&Target::new("rule.ads.test", 443).unwrap(), "app")
            .await
            .err()
            .unwrap()
            .downcast_ref::<crate::Rejected>()
            .unwrap()
            .0
            .clone();
        assert_eq!(rule_rej.rule, "Domain(rule.ads.test)");

        // Existing REJECT from rewrite module domain-reject must NOT be overwritten.
        let mod_parsed = clyntis_config::rewrite::parse_module(
            "[Rule]\nDOMAIN,mod.ads.test,REJECT\n[MITM]\nhostname = mod.ads.test\n",
        );
        let rewriter = crate::rewrite::Rewriter::new(
            vec![crate::rewrite::Loaded {
                name: "m".into(),
                module: mod_parsed,
                updated: None,
                missing: vec![],
                files: Default::default(),
            }],
            vec![],
        );
        // Install both rewrite and adblock filters.
        let mut block = clyntis_config::rule::DomainSetBuilder::default();
        block.exact("adblock.ads.test");
        let filter = Arc::new(crate::adblock::Filter::new(
            block.build(),
            clyntis_config::rule::DomainSetBuilder::default().build(),
            vec![],
            &clyntis_config::adblock::Adblock::default(),
            vec![],
        ));
        let mut resources = crate::resources::Resources::default();
        resources.rewrite = Some(Arc::new(rewriter));
        resources.adblock = Some(filter);
        core.resolver
            .configure_with(&core.config.hosts, None, &resources, false)
            .unwrap();
        *core.resources.write().unwrap() = Arc::new(resources);

        let mod_rej = core
            .datagram_for_source(&Target::new("mod.ads.test", 443).unwrap(), "app")
            .await
            .err()
            .unwrap()
            .downcast_ref::<crate::Rejected>()
            .unwrap()
            .0
            .clone();
        assert_eq!(mod_rej.rule, "Module(REJECT)");

        let ad_rej = core
            .datagram_for_source(&Target::new("adblock.ads.test", 443).unwrap(), "app")
            .await
            .err()
            .unwrap()
            .downcast_ref::<crate::Rejected>()
            .unwrap()
            .0
            .clone();
        assert_eq!(ad_rej.rule, "Adblock");
    }

    async fn raw_tls_acceptor_for_ads() -> (X509, SslAcceptor) {
        let (cert, key) = generate_authority().unwrap();
        let x509 = X509::from_pem(cert.as_bytes()).unwrap();
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        builder.set_certificate(&x509).unwrap();
        builder
            .set_private_key(&PKey::private_key_from_pem(key.as_bytes()).unwrap())
            .unwrap();
        (x509, builder.build())
    }

    async fn serve_fallback_http(acceptor: SslAcceptor, stream: tokio::net::TcpStream) {
        let mut tls = tokio_boring::accept(&acceptor, stream).await.unwrap();
        read_head(&mut tls).await;
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
        tls.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn upstream_handshake_timeout_falls_back_to_passthrough_without_bypass() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (server_cert, acceptor) = raw_tls_acceptor_for_ads().await;
        let server_task = tokio::spawn(async move {
            // Connection 1: hold open silently so MITM upstream handshake times out.
            let (mut stalled, _) = listener.accept().await.unwrap();
            let mut hello = [0u8; 512];
            let _ = stalled.read(&mut hello).await;
            // Connection 2: passthrough redial succeeds with real TLS.
            let (second, _) = listener.accept().await.unwrap();
            serve_fallback_http(acceptor, second).await;
            drop(stalled);
        });

        let core = core(test_settings(&["ads.test"]));
        core.mitm.upstream_handshake_ms.store(80, Ordering::Relaxed);
        let target = Target::new("ads.test", port).unwrap();
        let (app, inbound) = tokio::io::duplex(1 << 16);
        let relay = {
            let core = core.clone();
            tokio::spawn(async move { core.inspect_tcp(inbound, target, "app".into()).await })
        };
        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        builder.set_verify(SslVerifyMode::NONE);
        let mut tls = tokio_boring::connect(builder.build().configure().unwrap(), "ads.test", app)
            .await
            .unwrap();
        assert_eq!(
            tls.ssl().peer_certificate().unwrap().to_der().unwrap(),
            server_cert.to_der().unwrap()
        );
        tls.write_all(b"GET / HTTP/1.1\r\nHost: ads.test\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tls.read_to_end(&mut response).await.unwrap();
        assert!(response.ends_with(b"\r\n\r\nok"), "{response:?}");
        drop(tls);
        server_task.await.unwrap();
        relay.await.unwrap().unwrap();
        assert!(core.mitm.intercepts("ads.test"));
        assert_eq!(core.mitm_status()["bypassed"], json!([]));
        assert!(!core.dir.path().join(BYPASS_FILE_NAME).exists());
    }

    #[tokio::test]
    async fn upstream_early_eof_falls_back_to_passthrough_without_bypass() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (server_cert, acceptor) = raw_tls_acceptor_for_ads().await;
        let server_task = tokio::spawn(async move {
            // Connection 1: accept and drop immediately before completing TLS.
            let (first, _) = listener.accept().await.unwrap();
            drop(first);
            // Connection 2: passthrough redial succeeds with real TLS.
            let (second, _) = listener.accept().await.unwrap();
            serve_fallback_http(acceptor, second).await;
        });

        let core = core(test_settings(&["ads.test"]));
        let target = Target::new("ads.test", port).unwrap();
        let (app, inbound) = tokio::io::duplex(1 << 16);
        let relay = {
            let core = core.clone();
            tokio::spawn(async move { core.inspect_tcp(inbound, target, "app".into()).await })
        };
        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        builder.set_verify(SslVerifyMode::NONE);
        let mut tls = tokio_boring::connect(builder.build().configure().unwrap(), "ads.test", app)
            .await
            .unwrap();
        assert_eq!(
            tls.ssl().peer_certificate().unwrap().to_der().unwrap(),
            server_cert.to_der().unwrap()
        );
        tls.write_all(b"GET / HTTP/1.1\r\nHost: ads.test\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tls.read_to_end(&mut response).await.unwrap();
        assert!(response.ends_with(b"\r\n\r\nok"), "{response:?}");
        drop(tls);
        server_task.await.unwrap();
        relay.await.unwrap().unwrap();
        assert!(core.mitm.intercepts("ads.test"));
        assert_eq!(core.mitm_status()["bypassed"], json!([]));
        assert!(!core.dir.path().join(BYPASS_FILE_NAME).exists());
    }

    #[tokio::test]
    async fn upstream_protocol_incompatibility_falls_back_and_records_bypass() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (cert, key) = generate_authority().unwrap();
        let x509 = X509::from_pem(cert.as_bytes()).unwrap();
        let pkey = PKey::private_key_from_pem(key.as_bytes()).unwrap();
        let mut fail_alpn = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        fail_alpn.set_certificate(&x509).unwrap();
        fail_alpn.set_private_key(&pkey).unwrap();
        fail_alpn.set_alpn_select_callback(|_, _| Err(boring::ssl::AlpnError::ALERT_FATAL));
        let fail_acceptor = fail_alpn.build();
        let mut ok_alpn = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        ok_alpn.set_certificate(&x509).unwrap();
        ok_alpn.set_private_key(&pkey).unwrap();
        let ok_acceptor = ok_alpn.build();

        let server_task = tokio::spawn(async move {
            // Connection 1 (Core MITM): fatal ALPN mismatch during upstream handshake.
            let (first, _) = listener.accept().await.unwrap();
            let _ = tokio_boring::accept(&fail_acceptor, first).await;
            // Connection 2 (passthrough): client completes TLS directly with server.
            let (second, _) = listener.accept().await.unwrap();
            serve_fallback_http(ok_acceptor, second).await;
        });

        let core = core(test_settings(&["ads.test"]));
        let target = Target::new("ads.test", port).unwrap();
        let (app, inbound) = tokio::io::duplex(1 << 16);
        let relay = {
            let core = core.clone();
            tokio::spawn(async move { core.inspect_tcp(inbound, target, "app".into()).await })
        };
        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        builder.set_verify(SslVerifyMode::NONE);
        let mut tls = tokio_boring::connect(builder.build().configure().unwrap(), "ads.test", app)
            .await
            .unwrap();
        assert_eq!(
            tls.ssl().peer_certificate().unwrap().to_der().unwrap(),
            x509.to_der().unwrap()
        );
        tls.write_all(b"GET / HTTP/1.1\r\nHost: ads.test\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tls.read_to_end(&mut response).await.unwrap();
        assert!(response.ends_with(b"\r\n\r\nok"), "{response:?}");
        drop(tls);
        server_task.await.unwrap();
        relay.await.unwrap().unwrap();
        assert!(!core.mitm.intercepts("ads.test"));
        assert_eq!(core.mitm_status()["bypassed"], json!(["ads.test"]));
        assert!(!core.dir.path().join(BYPASS_FILE_NAME).exists());
    }

    #[tokio::test]
    async fn upstream_cancellation_fails_without_passthrough_or_bypass() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepted_notify = Arc::new(tokio::sync::Notify::new());
        let server_task = tokio::spawn({
            let accepted_count = accepted_count.clone();
            let accepted_notify = accepted_notify.clone();
            async move {
                let mut held = Vec::new();
                while let Ok((stream, _)) = listener.accept().await {
                    accepted_count.fetch_add(1, Ordering::Relaxed);
                    accepted_notify.notify_one();
                    held.push(stream);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        });

        let core = core(test_settings(&["ads.test"]));
        let target = Target::new("ads.test", port).unwrap();
        let (mut app, inbound) = tokio::io::duplex(4096);
        let relay = {
            let core = core.clone();
            tokio::spawn(async move { core.inspect_tcp(inbound, target, "app".into()).await })
        };
        let hello = crate::sniff::tests::client_hello_with_alpn("ads.test", &[b"http/1.1"]);
        app.write_all(&hello).await.unwrap();
        accepted_notify.notified().await;
        assert_eq!(core.close_connections(), 1);
        let res = tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .unwrap()
            .unwrap();
        assert!(res.is_err());
        assert_eq!(accepted_count.load(Ordering::Relaxed), 1);
        assert!(core.mitm.intercepts("ads.test"));
        assert_eq!(core.mitm_status()["bypassed"], json!([]));
        server_task.abort();
    }

    #[tokio::test]
    async fn segmented_h2_only_client_hello_passes_through_without_mitm() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let expected_hello = crate::sniff::tests::client_hello_with_alpn("grpc.ads.test", &[b"h2"]);
        let expected_copy = expected_hello.clone();
        let server_task = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut got = vec![0u8; expected_copy.len()];
            tcp.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected_copy);
            tcp.write_all(b"SEGMENTED-H2-OK").await.unwrap();
        });

        let dir = TestDir::new("clyntis-mitm-seg-h2");
        let yaml = format!(
            "hosts: {{grpc.ads.test: 127.0.0.1}}\nsniffer:\n  enable: true\n  force-domain: [grpc.ads.test]\n  sniff:\n    TLS: {{ports: [{port}]}}\n"
        );
        let mut config = clyntis_config::Config::parse(yaml.as_bytes()).unwrap();
        config.directory = dir.path().to_path_buf();
        config.mitm = test_settings(&["*.ads.test"]);
        let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        let target = Target::new("grpc.ads.test", port).unwrap();
        let (mut app, inbound) = tokio::io::duplex(4096);
        let relay = {
            let core = core.clone();
            tokio::spawn(async move { core.inspect_tcp(inbound, target, "app".into()).await })
        };

        // Deliver the ClientHello in three small chunks so sniff_target / read_first_bytes
        // must accumulate across fragments.
        let p1 = expected_hello[..4].to_vec();
        let p2 = expected_hello[4..expected_hello.len() / 2].to_vec();
        let p3 = expected_hello[expected_hello.len() / 2..].to_vec();
        app.write_all(&p1).await.unwrap();
        tokio::time::sleep(Duration::from_millis(15)).await;
        app.write_all(&p2).await.unwrap();
        tokio::time::sleep(Duration::from_millis(15)).await;
        app.write_all(&p3).await.unwrap();

        let mut reply = [0u8; 15];
        app.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"SEGMENTED-H2-OK");
        drop(app);
        server_task.await.unwrap();
        relay.await.unwrap().unwrap();
        assert_eq!(core.mitm_status()["skippedAlpn"], json!(["grpc.ads.test"]));
    }

    #[tokio::test]
    async fn incomplete_client_hello_hitting_timeout_passes_through_without_decryption() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let full_hello = crate::sniff::tests::client_hello_with_alpn("grpc.ads.test", &[b"h2"]);
        let split = full_hello.len() / 2;
        let first_half = full_hello[..split].to_vec();
        let expected_first = first_half.clone();
        let server_task = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut got = vec![0u8; expected_first.len()];
            tcp.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected_first);
            tcp.write_all(b"RAW-INCOMPLETE").await.unwrap();
        });

        let dir = TestDir::new("clyntis-mitm-incomplete");
        let mut config =
            clyntis_config::Config::parse(b"hosts: {grpc.ads.test: 127.0.0.1}\n").unwrap();
        config.directory = dir.path().to_path_buf();
        config.mitm = test_settings(&["*.ads.test"]);
        let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        core.mitm.first_bytes_ms.store(60, Ordering::Relaxed);
        let target = Target::new("grpc.ads.test", port).unwrap();
        let (mut app, inbound) = tokio::io::duplex(4096);
        let relay = {
            let core = core.clone();
            tokio::spawn(async move { core.inspect_tcp(inbound, target, "app".into()).await })
        };
        app.write_all(&first_half).await.unwrap();
        // Wait past first_bytes_ms without sending the remainder of the ClientHello;
        // MITM must pass through instead of treating the partial ClientHello as HTTP/1.1.
        let mut reply = [0u8; 14];
        tokio::time::timeout(Duration::from_secs(2), app.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply, b"RAW-INCOMPLETE");
        drop(app);
        server_task.await.unwrap();
        relay.await.unwrap().unwrap();
        assert_eq!(core.mitm_status()["skippedAlpn"], json!([]));
        assert_eq!(core.mitm_status()["bypassed"], json!([]));
    }

    #[test]
    fn relieve_memory_and_disabling_mitm_clear_leaf_acceptors() {
        let dir = TestDir::new("clyntis-mitm-relieve");
        let settings = test_settings(&["*.ads.test"]);
        let interceptor = Interceptor::new(&settings, dir.path(), false);
        let authority = interceptor.active().unwrap();
        authority.acceptor("a.ads.test", LEAVES).unwrap();
        assert_eq!(authority.leaves.read().unwrap().len(), 1);

        interceptor.relieve_memory();
        assert!(authority.leaves.read().unwrap().is_empty());

        authority.acceptor("b.ads.test", LEAVES).unwrap();
        assert_eq!(authority.leaves.read().unwrap().len(), 1);
        interceptor
            .set(Mitm {
                enable: false,
                ..settings
            })
            .unwrap();
        assert!(authority.leaves.read().unwrap().is_empty());
    }

    #[tokio::test]
    async fn bare_ip_without_sniffer_keeps_ip_routing_for_non_mitm_hosts() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let expected_hello =
            crate::sniff::tests::client_hello_with_alpn("blocked-domain.test", &[b"http/1.1"]);
        let expected_copy = expected_hello.clone();
        let server_task = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut got = vec![0u8; expected_copy.len()];
            tcp.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected_copy);
            tcp.write_all(b"RAW-IP-OK").await.unwrap();
        });

        let dir = TestDir::new("clyntis-mitm-ip-route");
        let mut config = clyntis_config::Config::parse(
            b"rules:\n- DOMAIN,blocked-domain.test,REJECT\n- MATCH,DIRECT\n",
        )
        .unwrap();
        config.directory = dir.path().to_path_buf();
        config.mitm = test_settings(&["mitm-only.test"]);
        assert!(!config.sniffer.enable);
        let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();

        let target = Target::new("127.0.0.1", port).unwrap();
        let (mut app, inbound) = tokio::io::duplex(4096);
        let relay = {
            let core = core.clone();
            tokio::spawn(async move { core.inspect_tcp(inbound, target, "app".into()).await })
        };
        app.write_all(&expected_hello).await.unwrap();
        let mut reply = [0u8; 9];
        app.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"RAW-IP-OK");
        drop(app);
        server_task.await.unwrap();
        relay.await.unwrap().unwrap();
    }

    #[test]
    fn hosted_inspection_cap_is_32_and_keepalive_idle_defaults_to_60s() {
        let dir = TestDir::new("clyntis-mitm-hosted-cap");
        let settings = test_settings(&["*.ads.test"]);
        let hosted = Interceptor::new(&settings, dir.path(), true);
        assert_eq!(HOSTED_INSPECTIONS, 32);
        assert_eq!(
            hosted.hosted_keepalive_idle(),
            Some(Duration::from_secs(60))
        );
        let mut permits: Vec<_> = (0..32).map(|_| hosted.try_inspect().unwrap()).collect();
        assert_eq!(hosted.active_inspections(), 32);
        assert!(hosted.try_inspect().is_none());
        permits.pop();
        assert_eq!(hosted.active_inspections(), 31);
        assert!(hosted.try_inspect().is_some());
        drop(permits);
        assert_eq!(hosted.active_inspections(), 0);

        let desktop = Interceptor::new(&settings, dir.path(), false);
        assert_eq!(desktop.hosted_keepalive_idle(), None);
    }

    #[tokio::test]
    async fn hosted_observe_releases_slot_on_websocket_upgrade_and_idle_keepalive() {
        let dir = TestDir::new("clyntis-mitm-observe-slot");
        let config = clyntis_config::Config {
            directory: dir.path().to_path_buf(),
            internal_host_packet_io: true,
            mitm: test_settings(&["ads.test"]),
            ..Default::default()
        };
        let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        core.mitm
            .hosted_keepalive_idle_ms
            .store(60, Ordering::Relaxed);

        // 1. WebSocket upgrade keeps inspection_slot held until the upgraded connection closes.
        let slot = core.mitm.try_inspect().unwrap();
        assert_eq!(core.mitm.active_inspections(), 1);
        let (mut app, client) = tokio::io::duplex(4096);
        let (mut server, upstream) = tokio::io::duplex(4096);
        let observe_task = {
            let core = core.clone();
            tokio::spawn(async move {
                core.observe(
                    client,
                    Target::new("ads.test", 80).unwrap(),
                    Box::new(upstream),
                    Routed::from("DIRECT"),
                    false,
                    slot,
                )
                .await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            app.write_all(
                b"GET /ws HTTP/1.1\r\nHost: ads.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            )
            .await
            .unwrap();
            let req = String::from_utf8(read_head(&mut server).await).unwrap();
            assert!(req.starts_with("GET /ws HTTP/1.1"));
            server
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                )
                .await
                .unwrap();
            let resp = String::from_utf8(read_head(&mut app).await).unwrap();
            assert!(resp.starts_with("HTTP/1.1 101 "));
            app.write_all(b"\x81\x04ping").await.unwrap();
            let mut got = [0u8; 6];
            server.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"\x81\x04ping");
            assert_eq!(core.mitm.active_inspections(), 1);
            server.write_all(b"\x81\x04pong").await.unwrap();
            app.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"\x81\x04pong");
            assert_eq!(core.mitm.active_inspections(), 1);
            drop(app);
            drop(server);
            observe_task.await.unwrap().unwrap();
            assert_eq!(core.mitm.active_inspections(), 0);
        })
        .await
        .unwrap();

        // 2. Idle keep-alive closes after hosted_keepalive_idle_ms without cutting a slow response.
        let slot = core.mitm.try_inspect().unwrap();
        assert_eq!(core.mitm.active_inspections(), 1);
        let (mut app, client) = tokio::io::duplex(4096);
        let (mut server, upstream) = tokio::io::duplex(4096);
        let observe_task = {
            let core = core.clone();
            tokio::spawn(async move {
                core.observe(
                    client,
                    Target::new("ads.test", 80).unwrap(),
                    Box::new(upstream),
                    Routed::from("DIRECT"),
                    false,
                    slot,
                )
                .await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            app.write_all(b"GET /slow HTTP/1.1\r\nHost: ads.test\r\n\r\n")
                .await
                .unwrap();
            let req = String::from_utf8(read_head(&mut server).await).unwrap();
            assert!(req.starts_with("GET /slow HTTP/1.1"));
            // Wait well past hosted_keepalive_idle_ms (60 ms) while response is in flight.
            tokio::time::sleep(Duration::from_millis(160)).await;
            assert_eq!(core.mitm.active_inspections(), 1);
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nslow")
                .await
                .unwrap();
            let (_, body) = read_response(&mut app).await;
            assert_eq!(body, b"slow");
            // Keep both sides open without closing; idle timeout must close the relay and free the slot.
            let mut eof = [0u8; 1];
            assert_eq!(app.read(&mut eof).await.unwrap(), 0);
            observe_task.await.unwrap().unwrap();
            assert_eq!(core.mitm.active_inspections(), 0);
        })
        .await
        .unwrap();
    }

    #[test]
    fn host_matcher_preserves_precedence_and_deduplicates() {
        let user = vec![
            "user.test".into(),
            "*.Sub.Test.".into(),
            "-blocked.sub.test".into(),
            "-*.apple.com".into(),
        ];
        let modules = dedup_host_patterns(vec![
            "api.mod.test".into(),
            "API.MOD.TEST.".into(),
            "*.mod.test".into(),
            "*pcdn*.cdn.test".into(),
            "-user.test".into(),
            "-skip.mod.test".into(),
            "-SKIP.MOD.TEST".into(),
        ]);
        assert_eq!(
            modules,
            vec![
                "api.mod.test",
                "*.mod.test",
                "*pcdn*.cdn.test",
                "-user.test",
                "-skip.mod.test",
            ]
        );
        let matcher = HostMatcher::new(&user, &modules);
        // User inclusion beats module exclusion (`-user.test`).
        assert!(matcher.listed("USER.test."));
        assert!(!matcher.matches_module("user.test"));
        // `*.sub.test` matches subdomains but not bare `sub.test`.
        assert!(matcher.listed("a.b.sub.test"));
        assert!(!matcher.listed("sub.test"));
        // User exclusion beats both user and module inclusions.
        assert!(!matcher.listed("blocked.sub.test"));
        assert!(!matcher.listed("gs.apple.com"));
        // Module inclusions, wildcards, and module exclusions.
        assert!(matcher.listed("api.mod.test"));
        assert!(matcher.matches_module("x.mod.test"));
        assert!(!matcher.listed("mod.test"));
        assert!(!matcher.listed("skip.mod.test"));
        assert!(!matcher.matches_module("skip.mod.test"));
        assert!(matcher.listed("edge-pcdn-1.cdn.test"));
        assert!(!matcher.listed("cdn.test"));
    }

    #[test]
    fn authority_leaves_evicts_single_lru_entry() {
        let (ca_cert, ca_key) = generate_authority().unwrap();
        let authority = Authority::load(&Mitm {
            enable: true,
            ca_cert,
            ca_key,
            ..Default::default()
        })
        .unwrap();
        let a1 = authority.acceptor("a.test", 2).unwrap();
        let _b = authority.acceptor("b.test", 2).unwrap();
        // Touch `a.test` so `b.test` becomes the least recently used entry.
        let a2 = authority.acceptor("a.test", 2).unwrap();
        assert!(Arc::ptr_eq(&a1, &a2));
        // Inserting `c.test` at capacity 2 must evict only `b.test`, not clear `a.test`.
        let _c = authority.acceptor("c.test", 2).unwrap();
        let leaves = authority.leaves.read().unwrap();
        assert_eq!(leaves.len(), 2);
        assert!(leaves.contains_key("a.test"));
        assert!(leaves.contains_key("c.test"));
        assert!(!leaves.contains_key("b.test"));
    }
}
