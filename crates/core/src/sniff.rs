use clyntis_protocol::Target;
use std::time::Duration;
use tokio::io::AsyncReadExt;
const MAX_CLIENT_HELLO: usize = 32768;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClientHelloAlpn {
    Absent,
    SupportsHttp1,
    NonHttp1Only,
    Malformed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClientHello {
    pub(crate) sni: Option<String>,
    pub(crate) alpn: ClientHelloAlpn,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ClientHelloStatus {
    Incomplete,
    Invalid,
    Complete(ClientHello),
}

fn take<'a>(input: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if input.len() < n {
        return None;
    }
    let (head, tail) = input.split_at(n);
    *input = tail;
    Some(head)
}
fn length(input: &mut &[u8]) -> Option<usize> {
    Some(u16::from_be_bytes(take(input, 2)?.try_into().ok()?) as usize)
}
fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.')
        && !host.contains("..")
}
fn parse_sni(mut value: &[u8]) -> Option<String> {
    let n = length(&mut value)?;
    let mut names = take(&mut value, n)?;
    while !names.is_empty() {
        let kind = take(&mut names, 1)?[0];
        let n = length(&mut names)?;
        let host = take(&mut names, n)?;
        if kind == 0 {
            let host = std::str::from_utf8(host).ok()?.to_ascii_lowercase();
            return valid_host(&host).then_some(host);
        }
    }
    None
}
fn parse_alpn(mut value: &[u8]) -> ClientHelloAlpn {
    let Some(list_len) = length(&mut value) else {
        return ClientHelloAlpn::Malformed;
    };
    let Some(mut list) = take(&mut value, list_len) else {
        return ClientHelloAlpn::Malformed;
    };
    if !value.is_empty() {
        return ClientHelloAlpn::Malformed;
    }
    if list.is_empty() {
        return ClientHelloAlpn::Absent;
    }
    let mut supports_http1 = false;
    while !list.is_empty() {
        let Some(plen) = take(&mut list, 1).map(|b| b[0] as usize) else {
            return ClientHelloAlpn::Malformed;
        };
        if plen == 0 {
            return ClientHelloAlpn::Malformed;
        }
        let Some(proto) = take(&mut list, plen) else {
            return ClientHelloAlpn::Malformed;
        };
        if proto == b"http/1.1" {
            supports_http1 = true;
        }
    }
    if supports_http1 {
        ClientHelloAlpn::SupportsHttp1
    } else {
        ClientHelloAlpn::NonHttp1Only
    }
}

pub(crate) fn parse_client_hello(data: &[u8]) -> ClientHelloStatus {
    if data.is_empty() {
        return ClientHelloStatus::Incomplete;
    }
    if data[0] != 22 {
        return ClientHelloStatus::Invalid;
    }
    let mut records = data;
    let mut hello: std::borrow::Cow<'_, [u8]> = std::borrow::Cow::Borrowed(&[]);
    while !records.is_empty() {
        if records.len() < 5 {
            return ClientHelloStatus::Incomplete;
        }
        let header = &records[..5];
        if header[0] != 22 {
            return ClientHelloStatus::Invalid;
        }
        let n = u16::from_be_bytes([header[3], header[4]]) as usize;
        if n == 0 || hello.len().saturating_add(n) > MAX_CLIENT_HELLO {
            return ClientHelloStatus::Invalid;
        }
        if records.len() < 5 + n {
            return ClientHelloStatus::Incomplete;
        }
        let fragment = &records[5..5 + n];
        if hello.is_empty() {
            hello = std::borrow::Cow::Borrowed(fragment);
        } else {
            hello.to_mut().extend_from_slice(fragment);
        }
        records = &records[5 + n..];
        if hello.len() >= 4 {
            if hello[0] != 1 {
                return ClientHelloStatus::Invalid;
            }
            let size = ((hello[1] as usize) << 16) | ((hello[2] as usize) << 8) | hello[3] as usize;
            if size + 4 > MAX_CLIENT_HELLO {
                return ClientHelloStatus::Invalid;
            }
            if hello.len() >= size + 4 {
                break;
            }
        }
    }
    if hello.len() < 4 {
        return ClientHelloStatus::Incomplete;
    }
    if hello[0] != 1 {
        return ClientHelloStatus::Invalid;
    }
    let size = ((hello[1] as usize) << 16) | ((hello[2] as usize) << 8) | hello[3] as usize;
    if size + 4 > MAX_CLIENT_HELLO {
        return ClientHelloStatus::Invalid;
    }
    if hello.len() < size + 4 {
        return ClientHelloStatus::Incomplete;
    }
    let Some(mut input) = hello.get(4..4 + size) else {
        return ClientHelloStatus::Invalid;
    };
    if take(&mut input, 34).is_none() {
        return ClientHelloStatus::Invalid;
    }
    let Some(session_len) = take(&mut input, 1).map(|b| b[0] as usize) else {
        return ClientHelloStatus::Invalid;
    };
    if take(&mut input, session_len).is_none() {
        return ClientHelloStatus::Invalid;
    }
    let Some(cipher_len) = length(&mut input) else {
        return ClientHelloStatus::Invalid;
    };
    if take(&mut input, cipher_len).is_none() {
        return ClientHelloStatus::Invalid;
    }
    let Some(comp_len) = take(&mut input, 1).map(|b| b[0] as usize) else {
        return ClientHelloStatus::Invalid;
    };
    if take(&mut input, comp_len).is_none() {
        return ClientHelloStatus::Invalid;
    }
    if input.is_empty() {
        return ClientHelloStatus::Complete(ClientHello {
            sni: None,
            alpn: ClientHelloAlpn::Absent,
        });
    }
    let Some(ext_len) = length(&mut input) else {
        return ClientHelloStatus::Invalid;
    };
    let Some(mut extensions) = take(&mut input, ext_len) else {
        return ClientHelloStatus::Invalid;
    };
    let mut sni = None;
    let mut alpn = ClientHelloAlpn::Absent;
    while !extensions.is_empty() {
        let Some(kind) = length(&mut extensions) else {
            return ClientHelloStatus::Invalid;
        };
        let Some(n) = length(&mut extensions) else {
            return ClientHelloStatus::Invalid;
        };
        let Some(value) = take(&mut extensions, n) else {
            return ClientHelloStatus::Invalid;
        };
        match kind {
            0 if sni.is_none() => sni = parse_sni(value),
            16 => alpn = parse_alpn(value),
            _ => {}
        }
    }
    ClientHelloStatus::Complete(ClientHello { sni, alpn })
}

pub(crate) fn tls(data: &[u8]) -> Option<String> {
    match parse_client_hello(data) {
        ClientHelloStatus::Complete(hello) => hello.sni,
        ClientHelloStatus::Incomplete | ClientHelloStatus::Invalid => None,
    }
}

/// True only when a complete ClientHello was read and either has no ALPN
/// extension or explicitly offers `http/1.1`. Incomplete, invalid, malformed-ALPN,
/// and `h2`-only handshakes return `false` so MITM passes them through.
#[cfg(test)]
pub(crate) fn tls_supports_http1(data: &[u8]) -> bool {
    matches!(
        parse_client_hello(data),
        ClientHelloStatus::Complete(ClientHello {
            alpn: ClientHelloAlpn::Absent | ClientHelloAlpn::SupportsHttp1,
            ..
        })
    )
}

/// Appends initial client bytes into `prefix` until a complete TLS ClientHello,
/// HTTP request head, non-TLS/non-HTTP first byte, EOF, cap, or `timeout`.
pub(crate) async fn read_first_bytes<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    prefix: &mut Vec<u8>,
    timeout: Duration,
) -> std::io::Result<()> {
    let done = |buf: &[u8]| -> bool {
        if buf.is_empty() {
            return false;
        }
        if buf.len() >= MAX_CLIENT_HELLO {
            return true;
        }
        if buf[0] == 22 {
            return !matches!(parse_client_hello(buf), ClientHelloStatus::Incomplete);
        }
        if buf[0].is_ascii_uppercase() {
            return buf.windows(4).any(|w| w == b"\r\n\r\n");
        }
        true
    };
    if done(prefix) {
        return Ok(());
    }
    match tokio::time::timeout(timeout, async {
        loop {
            let mut buffer = [0u8; 4096];
            let n = stream.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            prefix.extend_from_slice(&buffer[..n]);
            if done(prefix) {
                break;
            }
        }
        Ok::<_, std::io::Error>(())
    })
    .await
    {
        Ok(result) => result,
        Err(_elapsed) => Ok(()),
    }
}
pub(crate) fn http(data: &[u8]) -> Option<String> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut r = httparse::Request::new(&mut headers);
    r.parse(data).ok()?;
    let host = std::str::from_utf8(
        r.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("host"))?
            .value,
    )
    .ok()?;
    let host = host.split(':').next()?.trim().to_ascii_lowercase();
    valid_host(&host).then_some(host)
}
impl crate::Core {
    /// `target` (already restored) is a fake-IP address without a mapping.
    pub(crate) fn stale_fake(&self, target: &Target) -> bool {
        target
            .ip()
            .is_some_and(|ip| self.resolver.is_unmapped_fake(ip))
    }
    /// Sniff configured traffic, and always try to recover the domain of a
    /// stale fake-IP connection, which cannot be dialed by address.
    pub(crate) fn wants_sniff(&self, target: &Target) -> bool {
        self.should_sniff(target) || self.stale_fake(target)
    }
    pub(crate) fn should_sniff(&self, target: &Target) -> bool {
        let s = &self.config.sniffer;
        if !s.enable {
            return false;
        }
        if s.skip_domain.iter().any(|p| domain(p, &target.host)) {
            return false;
        }
        (target.ip().is_some() || s.force_domain.iter().any(|p| domain(p, &target.host)))
            && s.sniff
                .values()
                .any(|p| p.ports.iter().any(|r| r.contains(target.port)))
    }
    pub(crate) async fn sniff_target<S: tokio::io::AsyncRead + Unpin>(
        &self,
        stream: &mut S,
        target: &Target,
    ) -> anyhow::Result<(Target, Target, Vec<u8>)> {
        let mut prefix = vec![];
        let mut route = self.restore_target(target);
        let mut destination = route.clone();
        let stale = self.stale_fake(&route);
        if !stale && !self.should_sniff(&route) {
            return Ok((route, destination, prefix));
        }
        let s = &self.config.sniffer;
        let _ = tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                let mut buffer = [0u8; 4096];
                let n = stream.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                prefix.extend_from_slice(&buffer[..n]);
                if stale {
                    // The fake IP is meaningless: take any TLS/HTTP host and
                    // dial it, whatever the sniffer's ports or override setting.
                    if let Some(host) = tls(&prefix).or_else(|| http(&prefix)) {
                        route.host = host;
                        destination = route.clone();
                        return Ok::<_, std::io::Error>(());
                    }
                    if prefix.len() >= 32768 {
                        break;
                    }
                    continue;
                }
                for (kind, settings) in &s.sniff {
                    if !settings.ports.iter().any(|p| p.contains(target.port)) {
                        continue;
                    }
                    let host = match kind.as_str() {
                        "TLS" => tls(&prefix),
                        "HTTP" => http(&prefix),
                        _ => None,
                    };
                    if let Some(host) = host {
                        if !s.skip_domain.iter().any(|p| domain(p, &host)) {
                            route.host = host;
                            if settings.override_destination {
                                destination = route.clone();
                            }
                        }
                        return Ok::<_, std::io::Error>(());
                    }
                }
                if prefix.len() >= MAX_CLIENT_HELLO
                    || (prefix.first() == Some(&22)
                        && !matches!(parse_client_hello(&prefix), ClientHelloStatus::Incomplete))
                {
                    break;
                }
            }
            Ok(())
        })
        .await;
        if stale && destination.ip().is_some() {
            anyhow::bail!(
                "fake-IP {} has no domain (cached by the client across a restart); refusing it so the client re-resolves",
                destination.host
            );
        }
        Ok((route, destination, prefix))
    }
    /// Dials a sniffed connection. `dialed` is the target the client asked
    /// for, whose address IP rules keep matching after the sniffed domain
    /// replaced it for routing.
    pub(crate) async fn dial_sniffed(
        &self,
        route: &Target,
        destination: &Target,
        dialed: &Target,
        source: &str,
    ) -> anyhow::Result<(clyntis_protocol::BoxStream, crate::Routed)> {
        let address = self.restore_target(dialed).ip();
        let decision = self
            .trace_route(route, address, "tcp", true)
            .await?
            .decision;
        if decision.node == "REJECT" {
            Self::log_connection("TCP", source, route, &decision);
            self.requests.rejected("tcp", source, route, &decision);
            anyhow::bail!(crate::Rejected(decision));
        }
        let (stream, _) = self.dial(destination, Some(&decision.node)).await?;
        Self::log_connection("TCP", source, route, &decision);
        Ok((stream, crate::Routed::new(&decision, source)))
    }
}
fn domain(pattern: &str, host: &str) -> bool {
    clyntis_config::rule::domain_pattern(pattern)
        .is_ok_and(|m| m.evaluate(&host.to_ascii_lowercase(), None, 0, "", false) == Some(true))
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    #[test]
    fn http_host_and_invalid_data() {
        assert_eq!(
            http(b"GET / HTTP/1.1\r\nHost: WWW.example.test:8080\r\n\r\n"),
            Some("www.example.test".into())
        );
        assert!(tls(&[22, 3, 3, 255, 255]).is_none());
        assert!(http(b"GET / HTTP/1.1\r\nHost: bad/name\r\n\r\n").is_none());
    }

    pub(crate) fn client_hello_with_alpn(host: &str, protos: &[&[u8]]) -> Vec<u8> {
        let mut sni = Vec::new();
        let name = host.as_bytes();
        let list_len = (1 + 2 + name.len()) as u16;
        sni.extend_from_slice(&list_len.to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);

        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni);

        if !protos.is_empty() {
            let mut proto_list = Vec::new();
            for p in protos {
                proto_list.push(p.len() as u8);
                proto_list.extend_from_slice(p);
            }
            ext.extend_from_slice(&16u16.to_be_bytes());
            ext.extend_from_slice(&((proto_list.len() + 2) as u16).to_be_bytes());
            ext.extend_from_slice(&(proto_list.len() as u16).to_be_bytes());
            ext.extend_from_slice(&proto_list);
        }

        let mut hello_body = Vec::new();
        hello_body.extend_from_slice(&[3, 3]); // TLS 1.2
        hello_body.extend_from_slice(&[0u8; 32]); // random
        hello_body.push(0); // session id len
        hello_body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        hello_body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        hello_body.push(1); // compression methods len
        hello_body.push(0); // null compression
        hello_body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello_body.extend_from_slice(&ext);

        let mut handshake = Vec::new();
        handshake.push(1); // ClientHello
        let len = hello_body.len();
        handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        handshake.extend_from_slice(&hello_body);

        let mut record = Vec::new();
        record.extend_from_slice(&[22, 3, 1]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn alpn_detects_h2_only_client_hello() {
        let h2_only = client_hello_with_alpn("grpc.example.test", &[b"h2"]);
        assert_eq!(tls(&h2_only).as_deref(), Some("grpc.example.test"));
        assert!(!tls_supports_http1(&h2_only));

        let mixed = client_hello_with_alpn("app.example.test", &[b"h2", b"http/1.1"]);
        assert_eq!(tls(&mixed).as_deref(), Some("app.example.test"));
        assert!(tls_supports_http1(&mixed));

        let no_alpn = client_hello_with_alpn("legacy.example.test", &[]);
        assert_eq!(tls(&no_alpn).as_deref(), Some("legacy.example.test"));
        assert!(tls_supports_http1(&no_alpn));
        assert_eq!(
            parse_client_hello(&no_alpn),
            ClientHelloStatus::Complete(ClientHello {
                sni: Some("legacy.example.test".into()),
                alpn: ClientHelloAlpn::Absent,
            })
        );

        // Complete ClientHello with zero extensions also has Absent ALPN.
        let mut bare_body = vec![3, 3];
        bare_body.extend_from_slice(&[0u8; 32]);
        bare_body.push(0);
        bare_body.extend_from_slice(&2u16.to_be_bytes());
        bare_body.extend_from_slice(&[0x13, 0x01]);
        bare_body.push(1);
        bare_body.push(0);
        let mut bare = vec![22, 3, 1];
        bare.extend_from_slice(&((bare_body.len() + 4) as u16).to_be_bytes());
        bare.push(1);
        bare.extend_from_slice(&[0, 0, bare_body.len() as u8]);
        bare.extend_from_slice(&bare_body);
        assert_eq!(
            parse_client_hello(&bare),
            ClientHelloStatus::Complete(ClientHello {
                sni: None,
                alpn: ClientHelloAlpn::Absent,
            })
        );
        assert!(tls_supports_http1(&bare));
    }

    #[test]
    fn incomplete_or_fragmented_client_hello_is_distinguished() {
        let h2_only = client_hello_with_alpn("grpc.example.test", &[b"h2"]);

        // Partial TLS record header and partial single record must not claim HTTP/1.1.
        assert_eq!(
            parse_client_hello(&h2_only[..3]),
            ClientHelloStatus::Incomplete
        );
        assert!(!tls_supports_http1(&h2_only[..3]));
        assert_eq!(
            parse_client_hello(&h2_only[..15]),
            ClientHelloStatus::Incomplete
        );
        assert!(!tls_supports_http1(&h2_only[..15]));

        // Multi-record ClientHello: first fragment alone is Incomplete.
        let handshake = &h2_only[5..];
        let split = handshake.len() / 2;
        let mut frag1 = vec![22, 3, 1];
        frag1.extend_from_slice(&(split as u16).to_be_bytes());
        frag1.extend_from_slice(&handshake[..split]);
        assert_eq!(parse_client_hello(&frag1), ClientHelloStatus::Incomplete);
        assert!(!tls_supports_http1(&frag1));

        // Adding the second fragment yields Complete NonHttp1Only.
        let mut two_records = frag1;
        two_records.extend_from_slice(&[22, 3, 1]);
        two_records.extend_from_slice(&((handshake.len() - split) as u16).to_be_bytes());
        two_records.extend_from_slice(&handshake[split..]);
        assert_eq!(
            parse_client_hello(&two_records),
            ClientHelloStatus::Complete(ClientHello {
                sni: Some("grpc.example.test".into()),
                alpn: ClientHelloAlpn::NonHttp1Only,
            })
        );
        assert!(!tls_supports_http1(&two_records));
    }

    #[tokio::test]
    async fn read_first_bytes_completes_partial_prefix_across_chunks() {
        let hello = client_hello_with_alpn("split.example.test", &[b"h2"]);
        let cut = hello.len() / 2;
        let mut prefix = hello[..cut].to_vec();
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            tokio::io::AsyncWriteExt::write_all(&mut writer, &hello[cut..])
                .await
                .unwrap();
        });
        read_first_bytes(&mut reader, &mut prefix, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(
            parse_client_hello(&prefix),
            ClientHelloStatus::Complete(ClientHello {
                sni: Some("split.example.test".into()),
                alpn: ClientHelloAlpn::NonHttp1Only,
            })
        );
    }

    fn fake_ip_core() -> std::sync::Arc<crate::Core> {
        let mut config = clyntis_config::Config::default();
        config.dns.enhanced_mode = "fake-ip".into();
        config.sniffer.enable = false; // recovery must not depend on the sniffer
        crate::Core::new(config, std::sync::Arc::new(clyntis_platform::DefaultHooks)).unwrap()
    }

    #[tokio::test]
    async fn stale_fake_ip_is_refused_at_once_but_mapped_ones_restore() {
        let core = fake_ip_core();
        let mapped = core.resolver.fake_address("known.test", false).unwrap();
        let known = Target::new(mapped.to_string(), 443).unwrap();
        assert!(!core.stale_fake(&core.restore_target(&known)));
        assert_eq!(core.restore_target(&known).host, "known.test");
        let stale = Target::new("198.18.200.7", 443).unwrap();
        assert!(core.stale_fake(&stale));
        // Outside the pool is a real address, never treated as stale.
        assert!(!core.stale_fake(&Target::new("203.0.113.9", 443).unwrap()));
        let started = std::time::Instant::now();
        let error = core
            .dial(&stale, None)
            .await
            .err()
            .expect("stale fake-IP must not dial");
        assert!(format!("{error:#}").contains("has no domain"), "{error:#}");
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// A sniffed domain routes the connection, but IP rules still see the
    /// address the client dialed (hosts entries, LAN services behind a VPN).
    #[tokio::test]
    async fn ip_rules_match_the_dialed_address_after_sniffing() {
        let config = clyntis_config::Config::parse(
            concat!(
                "rules:\n",
                "- IP-CIDR,192.168.2.0/24,REJECT,no-resolve\n",
                "- MATCH,DIRECT\n",
            )
            .as_bytes(),
        )
        .unwrap();
        let core =
            crate::Core::new(config, std::sync::Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        let dialed = Target::new("192.168.2.181", 443).unwrap();
        let sniffed = Target::new("nas.example", 443).unwrap();
        for destination in [&dialed, &sniffed] {
            let error = core
                .dial_sniffed(&sniffed, destination, &dialed, "test")
                .await
                .err()
                .expect("the IP rule must reject");
            assert!(
                error.downcast_ref::<crate::Rejected>().is_some(),
                "{error:#}"
            );
        }
    }

    #[tokio::test]
    async fn stale_fake_ip_recovers_the_sniffed_domain() {
        let core = fake_ip_core();
        let stale = Target::new("198.18.200.8", 80).unwrap();
        assert!(core.wants_sniff(&stale));
        let (mut client, mut server) = tokio::io::duplex(1024);
        tokio::io::AsyncWriteExt::write_all(
            &mut client,
            b"GET / HTTP/1.1\r\nHost: real.test\r\n\r\n",
        )
        .await
        .unwrap();
        let (route, destination, prefix) = core.sniff_target(&mut server, &stale).await.unwrap();
        assert_eq!(route.host, "real.test");
        assert_eq!(destination.host, "real.test");
        assert!(!prefix.is_empty());
        // Nothing recognisable: refused instead of dialing the fake address.
        let (mut client, mut server) = tokio::io::duplex(1024);
        tokio::io::AsyncWriteExt::write_all(&mut client, b"\x00\x01binary")
            .await
            .unwrap();
        drop(client);
        assert!(core.sniff_target(&mut server, &stale).await.is_err());
    }
}
