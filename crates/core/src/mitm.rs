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
    ssl::{AlpnError, SslAcceptor, SslMethod},
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
    tls::{SecureConnector, TlsConnectConfig, TlsFingerprint},
};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Per-host certificates kept; the cache starts over when full. Each holds
/// a TLS context: the iOS tunnel, within about 50 MiB, keeps few.
const LEAVES: usize = 512;
const HOSTED_LEAVES: usize = 32;
/// Hosts remembered as refusing the certificate.
const BYPASS: usize = 2048;
/// How long a client may take to send its first bytes.
const FIRST_BYTES: Duration = Duration::from_secs(2);

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

struct Authority {
    cert: X509,
    key: PKey<Private>,
    /// One key for every host certificate.
    leaf_key: PKey<Private>,
    leaves: Mutex<HashMap<String, Arc<SslAcceptor>>>,
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
        Ok(Self {
            cert,
            key,
            leaf_key: ec_key()?,
            leaves: Mutex::default(),
        })
    }
    fn acceptor(&self, host: &str, limit: usize) -> Result<Arc<SslAcceptor>> {
        if let Some(acceptor) = self.leaves.lock().unwrap().get(host) {
            return Ok(acceptor.clone());
        }
        let leaf = self.leaf(host)?;
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
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
        let mut leaves = self.leaves.lock().unwrap();
        if leaves.len() >= limit {
            leaves.clear();
        }
        leaves.insert(host.to_owned(), acceptor.clone());
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

/// The decryption settings and state of a running core.
pub(crate) struct Interceptor {
    settings: RwLock<Mitm>,
    authority: RwLock<Option<Arc<Authority>>>,
    /// Why decryption is on but not working.
    error: RwLock<Option<String>>,
    /// Hosts whose clients refused the certificate (pinned or the CA not
    /// trusted): passed through from then on.
    bypass: Mutex<HashSet<String>>,
    /// Tests talk to servers with their own certificates.
    verify_upstream: std::sync::atomic::AtomicBool,
    leaf_limit: usize,
}
impl Interceptor {
    pub(crate) fn new(mitm: &Mitm, hosted: bool) -> Self {
        let interceptor = Self {
            settings: RwLock::default(),
            authority: RwLock::default(),
            error: RwLock::default(),
            bypass: Mutex::default(),
            verify_upstream: true.into(),
            leaf_limit: if hosted { HOSTED_LEAVES } else { LEAVES },
        };
        if let Err(error) = interceptor.set(mitm.clone()) {
            tracing::warn!("HTTPS decryption is off: {error:#}");
        }
        interceptor
    }
    /// Applies new settings; the CA is loaded again only when it changed.
    pub(crate) fn set(&self, mitm: Mitm) -> Result<()> {
        let same_ca = {
            let current = self.settings.read().unwrap();
            current.ca_cert == mitm.ca_cert && current.ca_key == mitm.ca_key
        };
        let loaded = self.authority.read().unwrap().is_some();
        let result = if !mitm.enable || (same_ca && loaded) {
            Ok(())
        } else {
            Authority::load(&mitm).map(|authority| {
                *self.authority.write().unwrap() = Some(Arc::new(authority));
                // A new CA may be trusted where the old one was not.
                self.bypass.lock().unwrap().clear();
            })
        };
        if !same_ca && result.is_err() {
            *self.authority.write().unwrap() = None;
        }
        *self.error.write().unwrap() = result.as_ref().err().map(|e| format!("{e:#}"));
        *self.settings.write().unwrap() = mitm;
        result
    }
    fn active(&self) -> Option<Arc<Authority>> {
        if !self.settings.read().unwrap().enable {
            return None;
        }
        self.authority.read().unwrap().clone()
    }
    /// Whether connections to `host` are decrypted now.
    pub(crate) fn intercepts(&self, host: &str) -> bool {
        self.active().is_some()
            && self.settings.read().unwrap().matches(host)
            && !self.bypass.lock().unwrap().contains(host)
    }
    fn refused(&self, host: &str) {
        let mut bypass = self.bypass.lock().unwrap();
        if bypass.len() < BYPASS {
            bypass.insert(host.to_owned());
        }
    }
    pub(crate) fn clear_bypass(&self) {
        self.bypass.lock().unwrap().clear();
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
        let mut bypassed: Vec<_> = self.bypass.lock().unwrap().iter().cloned().collect();
        bypassed.sort();
        json!({
            "enable": settings.enable,
            "hostname": settings.hostname,
            "active": settings.enable && self.authority.read().unwrap().is_some(),
            "ca": ca,
            "error": *self.error.read().unwrap(),
            "bypassed": bypassed,
        })
    }
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

/// Reads the client's first bytes: through a whole TLS ClientHello or HTTP
/// request head, or what came within [`FIRST_BYTES`].
async fn first_bytes<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Vec<u8>> {
    let mut prefix = Vec::new();
    let _ = tokio::time::timeout(FIRST_BYTES, async {
        loop {
            let mut buffer = [0u8; 4096];
            let n = stream.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            prefix.extend_from_slice(&buffer[..n]);
            if crate::sniff::tls(&prefix).is_some()
                || prefix.windows(4).any(|w| w == b"\r\n\r\n")
                || prefix.len() >= 32768
                || !(prefix[0] == 22 || prefix[0].is_ascii_uppercase())
            {
                break;
            }
        }
        Ok::<_, std::io::Error>(())
    })
    .await;
    Ok(prefix)
}

impl Core {
    /// Whether a TCP connection goes through [`Core::inspect_tcp`]: decryption
    /// is on, and the target names a host to decrypt or is an address whose
    /// host only the client's first bytes tell.
    pub(crate) fn inspects(&self, target: &Target) -> bool {
        if self.mitm.active().is_none() {
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
        self.mitm.set(mitm)
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
        let (mut route, destination, mut prefix) = if self.wants_sniff(&restored) {
            self.sniff_target(&mut stream, &target).await?
        } else {
            (restored.clone(), restored.clone(), vec![])
        };
        if prefix.is_empty() {
            prefix = first_bytes(&mut stream).await?;
        } else if prefix[0] == 22 && crate::sniff::tls(&prefix).is_none() {
            // The sniffer stopped early; the ClientHello must be whole.
            let more = first_bytes(&mut stream).await?;
            prefix.extend_from_slice(&more);
        }
        let tls = prefix.first() == Some(&22);
        if route.ip().is_some()
            && let Some(host) = crate::sniff::tls(&prefix).or_else(|| crate::sniff::http(&prefix))
        {
            route.host = host;
        }
        let (mut outbound, routed) = if route != restored {
            self.dial_sniffed(&route, &destination, &target, &source)
                .await?
        } else {
            self.dial_logged(&target, None, &source).await?
        };
        let http = !tls && crate::sniff::http(&prefix).is_some();
        if !self.mitm.intercepts(&route.host) || !(tls || http) {
            outbound.write_all(&prefix).await?;
            return self.relay_io(stream, route, outbound, routed).await;
        }
        let client = Prefixed {
            prefix,
            offset: 0,
            inner: stream,
        };
        self.observe(client, route, outbound, routed, tls).await
    }

    async fn observe<S>(
        self: &Arc<Self>,
        client: S,
        route: Target,
        outbound: BoxStream,
        routed: Routed,
        tls: bool,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
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
        let upstream: BoxStream = Box::new(traffic::Stream {
            inner: outbound,
            tracker,
        });
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
            // The server first: a client is never shown a certificate for a
            // server that could not be verified.
            let upstream = SecureConnector::new(self.clock.clone())
                .connect(
                    upstream,
                    &TlsConnectConfig {
                        server_name: host.clone(),
                        alpn: vec!["http/1.1".into()],
                        verify_cert: self
                            .mitm
                            .verify_upstream
                            .load(std::sync::atomic::Ordering::Relaxed),
                        fingerprint: TlsFingerprint::Native,
                        reality: None,
                    },
                )
                .await
                .map_err(|e| std::io::Error::other(format!("{host}: {e:#}")))?;
            let acceptor = self
                .mitm
                .active()
                .ok_or_else(|| std::io::Error::other("decryption turned off"))?
                .acceptor(&host, self.mitm.leaf_limit)
                .map_err(std::io::Error::other)?;
            let client = match tokio_boring::accept(&acceptor, client).await {
                Ok(client) => client,
                Err(error) => {
                    self.mitm.refused(&host);
                    tracing::warn!(
                        "[MITM] client refused the certificate for {host} ({error}); passing it through from now on"
                    );
                    return Err(std::io::Error::other(format!(
                        "client refused the certificate: {error}"
                    )));
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
        outcome.map(drop).map_err(Into::into)
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issues_certificates_for_hosts() {
        let settings = test_settings(&["*.ads.test"]);
        let interceptor = Interceptor::new(&settings, false);
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
        interceptor.refused("x.ads.test");
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

    fn core(settings: Mitm) -> Arc<Core> {
        let mut config = clyntis_config::Config::parse(b"hosts: {ads.test: 127.0.0.1}\n").unwrap();
        config.mitm = settings;
        let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        core.mitm
            .verify_upstream
            .store(false, std::sync::atomic::Ordering::Relaxed);
        core
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
        core.clear_mitm_bypass();
        assert!(core.mitm.intercepts("ads.test"));
    }
}
