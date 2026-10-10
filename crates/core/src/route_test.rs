//! Route tests: which rule a domain or address would match and which node it
//! would leave through, without opening a connection.
use crate::{Core, Trace};
use anyhow::{Context, Result, ensure};
use meta_config::Mode;
use meta_protocol::Target;
use serde::Serialize;
use std::net::IpAddr;

/// How a connection to `host` would be routed now.
#[derive(Clone, Debug, Serialize)]
pub struct RouteTest {
    pub host: String,
    pub port: u16,
    pub network: String,
    pub mode: Mode,
    /// The address IP rules saw: the literal one, or the one resolved for the
    /// first rule that needed it. `None` when no rule needed an address or
    /// resolving failed.
    pub ip: Option<IpAddr>,
    /// The matching rule as written; `None` for ad blocking, the global and
    /// direct modes and the fallback.
    pub rule: Option<String>,
    /// Zero-based position of `rule` in the active rules.
    pub index: Option<usize>,
    /// Short form, as in the connection log: `DomainSuffix(example.com)`,
    /// `Adblock`, `Mode(Global)`, `Fallback`.
    pub matched: String,
    /// The rule's target followed by each group's selection down to `node`.
    pub chain: Vec<String>,
    /// The proxy (or DIRECT/REJECT) the connection would leave through.
    pub node: String,
    /// Whether a rule made the core resolve the name through its own
    /// upstreams before matching: with a proxy `node`, a DNS leak.
    pub resolved_locally: bool,
}

/// Parses what a person types to test: a domain or IP address, optionally with
/// a port, a scheme and a path (`https://example.com:8443/a`). `port`, when
/// given, wins; otherwise the scheme's port (80 for http, else 443).
pub fn parse_test_target(input: &str, port: Option<u16>) -> Result<Target> {
    let mut rest = input.trim();
    let mut default_port = 443;
    if let Some((scheme, tail)) = rest.split_once("://") {
        if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("ws") {
            default_port = 80;
        }
        rest = tail;
    }
    let rest = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default();
    ensure!(!rest.is_empty(), "请输入域名或 IP 地址");
    let (host, parsed_port) = if let Ok(ip) = rest.parse::<IpAddr>() {
        (ip.to_string(), None)
    } else if let Some(v6) = rest.strip_prefix('[') {
        let (address, tail) = v6.split_once(']').context("无效的 IPv6 地址")?;
        let ip: IpAddr = address.parse().context("无效的 IPv6 地址")?;
        let port = match tail.strip_prefix(':') {
            Some(port) => Some(port.parse::<u16>().context("无效的端口")?),
            None if tail.is_empty() => None,
            None => anyhow::bail!("无效的 IPv6 地址"),
        };
        (ip.to_string(), port)
    } else if let Some((host, port)) = rest.rsplit_once(':') {
        (
            host.to_owned(),
            Some(port.parse::<u16>().context("无效的端口")?),
        )
    } else {
        (rest.to_owned(), None)
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    Target::new(host, port.or(parsed_port).unwrap_or(default_port)).context("无效的域名或 IP 地址")
}

impl Core {
    /// Routes `target` as a new `network` ("tcp" or "udp") connection would be
    /// routed now, without connecting or touching the ad blocking counters.
    /// A fake-IP address is tested as the domain it stands for. Resolves the
    /// name when a rule needs an address, like a real connection.
    pub async fn test_route(&self, target: &Target, network: &str) -> Result<RouteTest> {
        ensure!(
            matches!(network, "tcp" | "udp"),
            "network must be tcp or udp"
        );
        let target = self.restore_target(target);
        let Trace {
            decision,
            ip,
            index,
            looked_up,
        } = self.trace_route(&target, network, false).await?;
        let rule = index.and_then(|i| self.policy.read().unwrap().raw_rules.get(i).cloned());
        let chain = self.chain(&decision.group)?;
        Ok(RouteTest {
            host: target.host,
            port: target.port,
            network: network.into(),
            mode: self.policy.read().unwrap().mode.clone(),
            ip,
            rule,
            index,
            matched: decision.rule,
            chain,
            node: decision.node,
            resolved_locally: looked_up,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::parse_test_target;

    #[tokio::test]
    async fn a_proxied_name_resolved_by_an_ip_rule_is_flagged() {
        let config = meta_config::Config::parse(b"hosts: {'leak.test': 10.9.9.9}\nproxy-groups:\n- {name: Proxy, type: select, proxies: [REJECT]}\nrules: ['DOMAIN,plain.test,Proxy', 'IP-CIDR,192.0.2.0/24,DIRECT', 'MATCH,Proxy']\n").unwrap();
        let core =
            crate::Core::new(config, std::sync::Arc::new(meta_platform::DefaultHooks)).unwrap();
        let test = |host: &str| {
            let core = core.clone();
            let target = parse_test_target(host, None).unwrap();
            async move { core.test_route(&target, "tcp").await.unwrap() }
        };
        let leaked = test("leak.test").await;
        assert_eq!(
            (leaked.node.as_str(), leaked.resolved_locally),
            ("REJECT", true)
        );
        assert_eq!(leaked.ip, Some("10.9.9.9".parse().unwrap()));
        assert!(!test("plain.test").await.resolved_locally);
        assert!(!test("10.9.9.9").await.resolved_locally);
    }

    #[test]
    fn typed_targets_parse_with_sensible_ports() {
        let parse = |input: &str| {
            let target = parse_test_target(input, None).unwrap();
            (target.host, target.port)
        };
        assert_eq!(parse("Example.COM."), ("example.com".into(), 443));
        assert_eq!(parse(" example.com:8080 "), ("example.com".into(), 8080));
        assert_eq!(
            parse("http://user@example.com/a?b"),
            ("example.com".into(), 80)
        );
        assert_eq!(
            parse("https://example.com:8443/"),
            ("example.com".into(), 8443)
        );
        assert_eq!(parse("1.2.3.4"), ("1.2.3.4".into(), 443));
        assert_eq!(parse("1.2.3.4:53"), ("1.2.3.4".into(), 53));
        assert_eq!(parse("2001:db8::1"), ("2001:db8::1".into(), 443));
        assert_eq!(parse("[2001:db8::1]:80"), ("2001:db8::1".into(), 80));
        assert_eq!(
            parse_test_target("example.com:80", Some(22)).unwrap().port,
            22
        );
        for bad in [
            "",
            "  ",
            "example.com:x",
            "[::1",
            "exa mple.com",
            "https://",
        ] {
            assert!(parse_test_target(bad, None).is_err(), "{bad:?} should fail");
        }
    }
}
