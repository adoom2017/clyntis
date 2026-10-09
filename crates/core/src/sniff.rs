use meta_protocol::Target;
use std::time::Duration;
use tokio::io::AsyncReadExt;
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
fn tls(data: &[u8]) -> Option<String> {
    let mut records = data;
    let mut hello = vec![];
    while !records.is_empty() {
        let header = take(&mut records, 5)?;
        if header[0] != 22 {
            return None;
        }
        let n = u16::from_be_bytes([header[3], header[4]]) as usize;
        hello.extend_from_slice(take(&mut records, n)?);
        if hello.len() > 32768 {
            return None;
        }
        if hello.len() >= 4 {
            let size = ((hello[1] as usize) << 16) | ((hello[2] as usize) << 8) | hello[3] as usize;
            if hello.len() >= size + 4 {
                break;
            }
        }
    }
    let mut input = hello.as_slice();
    if take(&mut input, 1)?[0] != 1 {
        return None;
    }
    let n = take(&mut input, 3)?;
    let size = ((n[0] as usize) << 16) | ((n[1] as usize) << 8) | n[2] as usize;
    input = take(&mut input, size)?;
    take(&mut input, 34)?;
    let n = take(&mut input, 1)?[0] as usize;
    take(&mut input, n)?;
    let n = length(&mut input)?;
    take(&mut input, n)?;
    let n = take(&mut input, 1)?[0] as usize;
    take(&mut input, n)?;
    let n = length(&mut input)?;
    let mut extensions = take(&mut input, n)?;
    while !extensions.is_empty() {
        let kind = length(&mut extensions)?;
        let n = length(&mut extensions)?;
        let mut value = take(&mut extensions, n)?;
        if kind != 0 {
            continue;
        }
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
    }
    None
}
fn http(data: &[u8]) -> Option<String> {
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
                if prefix.len() >= 32768 {
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
    pub(crate) async fn dial_sniffed(
        &self,
        route: &Target,
        destination: &Target,
        source: &str,
    ) -> anyhow::Result<(meta_protocol::BoxStream, String)> {
        let decision = self.route_decision(route, "tcp").await?;
        if decision.node == "REJECT" {
            Self::log_connection("TCP", source, route, &decision);
            anyhow::bail!(crate::Rejected(decision));
        }
        let (stream, _) = self.dial(destination, Some(&decision.node)).await?;
        Self::log_connection("TCP", source, route, &decision);
        Ok((stream, decision.node))
    }
}
fn domain(pattern: &str, host: &str) -> bool {
    meta_config::rule::domain_pattern(pattern)
        .is_ok_and(|m| m.evaluate(&host.to_ascii_lowercase(), None, 0, "", false) == Some(true))
}
#[cfg(test)]
mod tests {
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

    fn fake_ip_core() -> std::sync::Arc<crate::Core> {
        let mut config = meta_config::Config::default();
        config.dns.enhanced_mode = "fake-ip".into();
        config.sniffer.enable = false; // recovery must not depend on the sniffer
        crate::Core::new(config, std::sync::Arc::new(meta_platform::DefaultHooks)).unwrap()
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
