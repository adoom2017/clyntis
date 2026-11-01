//! DNS leak detection: an offline review of the configuration and an online
//! test against bash.ws, whose name servers record which resolvers asked for
//! random names.
use crate::Core;
use anyhow::{Context, Result, ensure};
use clyntis_config::{Mode, rule::Matcher};
use clyntis_protocol::{BoxStream, Target};
use serde::Serialize;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SERVICE: &str = "bash.ws";
/// Random names resolved per path; bash.ws's own client uses ten.
const PROBES: usize = 6;
/// Rules listed per finding; the count says how many there are in all.
const LISTED: usize = 10;

/// What the configuration reveals to DNS servers, without any network I/O.
#[derive(Clone, Debug, Serialize)]
pub struct DnsLeakAudit {
    /// Whether a `risk` finding exists: names that go through a proxy are
    /// also resolved by the core's own upstreams.
    pub leaking: bool,
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    /// `risk` (a leak), `warning` (exposure worth fixing) or `info`.
    pub level: &'static str,
    /// Stable identifier for hosts: `redir-host`, `resolving-rules`,
    /// `plain-upstream`, `system-dns`, `dns-disabled`.
    pub code: &'static str,
    pub title: String,
    pub detail: String,
    /// The rules or servers concerned.
    pub items: Vec<String>,
}

/// A resolver or exit address as bash.ws saw it.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct LeakServer {
    pub ip: String,
    pub country: String,
    pub asn: String,
}

/// Resolvers that asked bash.ws for one path's random names.
#[derive(Clone, Debug, Default, Serialize)]
pub struct LeakProbe {
    pub resolvers: Vec<LeakServer>,
    pub error: Option<String>,
}

/// Online DNS leak test.
#[derive(Clone, Debug, Serialize)]
pub struct DnsLeakTest {
    /// The address bash.ws saw this test's requests come from.
    pub exit: Vec<LeakServer>,
    /// The node and rule bash.ws traffic uses: the test reflects that route.
    pub node: String,
    pub matched: String,
    /// `leak` (a proxied name reached the core's own upstreams), `ok`,
    /// `direct` (bash.ws is not proxied: nothing to leak from) or `unknown`
    /// (a probe saw no resolvers).
    pub verdict: &'static str,
    /// Names connected to like an app would: through the matching rule, so a
    /// proxy resolves them remotely unless a rule resolves them first.
    pub routed: LeakProbe,
    /// Names resolved by the core's own upstreams: who sees the names the
    /// core resolves locally (direct connections, IP rules, redir-host).
    pub local: LeakProbe,
}

/// Whether evaluating `matcher` may make the core resolve the name: an IP
/// condition outside `no-resolve`.
fn needs_address(matcher: &Matcher) -> bool {
    match matcher {
        Matcher::Net(_) | Matcher::Nets(_) | Matcher::ExternalIp(_) | Matcher::GeoIp(_) => true,
        Matcher::NoResolve(_) => false,
        Matcher::Not(inner) => needs_address(inner),
        Matcher::And(nodes) | Matcher::Or(nodes) => nodes.iter().any(needs_address),
        _ => false,
    }
}

fn plain_server(server: &str) -> bool {
    !(server.starts_with("https://") || server.starts_with("tls://"))
}

fn listed(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let items: Vec<_> = items.into_iter().collect();
    let total = items.len();
    let mut shown: Vec<_> = items.into_iter().take(LISTED).collect();
    if total > LISTED {
        shown.push(format!("…{total} in all"));
    }
    shown
}

/// Whether names connected to through a proxy reached the core's own
/// upstreams: a routed resolver with a local resolver's address, or from its
/// network in the same country (resolvers answer from pools of addresses).
/// bash.ws's own conclusion compares resolvers with the exit instead, and so
/// flags every proxy server that uses a public resolver.
fn verdict(node: &str, routed: &LeakProbe, local: &LeakProbe) -> &'static str {
    if node == "DIRECT" {
        return "direct";
    }
    if routed.resolvers.is_empty() || local.resolvers.is_empty() {
        return "unknown";
    }
    let upstream = |server: &LeakServer| {
        local.resolvers.iter().any(|own| {
            own.ip == server.ip
                || (!own.asn.is_empty() && own.asn == server.asn && own.country == server.country)
        })
    };
    if routed.resolvers.iter().any(upstream) {
        "leak"
    } else {
        "ok"
    }
}

/// bash.ws's `?json` result: entries typed `ip` (the exit) and `dns` (a
/// resolver); its `conclusion` is not used (see `verdict`).
fn parse_result(body: &[u8]) -> Result<(Vec<LeakServer>, LeakProbe)> {
    let value: serde_json::Value =
        serde_json::from_slice(body).context("bash.ws returned an invalid result")?;
    if let Some(error) = value.get("error").and_then(|v| v.as_str()) {
        return Ok((
            Vec::new(),
            LeakProbe {
                error: Some(error.into()),
                ..Default::default()
            },
        ));
    }
    let entries = value
        .as_array()
        .context("bash.ws returned an invalid result")?;
    let text = |entry: &serde_json::Value, key: &str| {
        entry
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned()
    };
    let (mut exit, mut probe) = (Vec::new(), LeakProbe::default());
    for entry in entries {
        let server = LeakServer {
            ip: text(entry, "ip"),
            country: text(entry, "country_name"),
            asn: text(entry, "asn"),
        };
        match entry.get("type").and_then(|v| v.as_str()) {
            Some("ip") if !exit.contains(&server) => exit.push(server),
            Some("dns") if !probe.resolvers.contains(&server) => probe.resolvers.push(server),
            _ => {}
        }
    }
    Ok((exit, probe))
}

impl Core {
    /// Reviews the running configuration for DNS leaks and exposure.
    pub fn dns_leak_audit(&self) -> DnsLeakAudit {
        let dns = &self.config.dns;
        let tun = &self.config.tun;
        let mut findings = Vec::new();
        let (mode, rules, raw_rules) = {
            let policy = self.policy.read().unwrap();
            (
                policy.mode.clone(),
                policy.rules.clone(),
                policy.raw_rules.clone(),
            )
        };
        if dns.enhanced_mode == "redir-host" && (dns.enable || tun.enable) {
            findings.push(Finding {
                level: "risk",
                code: "redir-host",
                title: "redir-host mode resolves every name locally".into(),
                detail: "The core resolves every app query through the upstream DNS, so the upstream sees proxied names too. Use fake-ip mode to have proxies resolve names remotely.".into(),
                items: Vec::new(),
            });
        }
        if mode == Mode::Rule {
            // A rule that resolves leaks every name that reaches it and then
            // goes through a proxy, by that rule or a later one.
            let proxied = |target: &str| target != "DIRECT" && target != "REJECT";
            let mut later_proxy = false;
            let mut resolving = Vec::new();
            for (index, rule) in rules.iter().enumerate().rev() {
                later_proxy |= proxied(&rule.target);
                if later_proxy && !rule.no_resolve && needs_address(&rule.matcher) {
                    let raw = raw_rules.get(index).map(String::as_str).unwrap_or("?");
                    resolving.push(format!("rule {}: {raw}", index + 1));
                }
            }
            resolving.reverse();
            if !resolving.is_empty() {
                findings.push(Finding {
                    level: "risk",
                    code: "resolving-rules",
                    title: format!("{} IP rule(s) resolve names locally before matching", resolving.len()),
                    detail: "A name reaching these rules is first resolved through the upstream DNS, which then sees names that go through a proxy. Add no-resolve to these rules or move them after the domain rules.".into(),
                    items: listed(resolving),
                });
            }
        }
        let mut plain: Vec<String> = dns
            .nameserver
            .iter()
            .cloned()
            .chain(
                dns.nameserver_policy
                    .values()
                    .chain(
                        self.config
                            .network_overrides
                            .iter()
                            .flat_map(|o| o.nameserver_policy.values()),
                    )
                    .flat_map(|v| v.values()),
            )
            .filter(|server| plain_server(server))
            .collect();
        plain.sort();
        plain.dedup();
        if !plain.is_empty() {
            findings.push(Finding {
                level: "warning",
                code: "plain-upstream",
                title: "Upstream DNS uses a plaintext protocol".into(),
                detail: "Names the core resolves locally (direct connections, IP rules) go out in plaintext, which the network can see or alter. Use https:// or tls:// upstreams.".into(),
                items: listed(plain),
            });
        }
        #[cfg(target_os = "macos")]
        let system_dns_bypasses = tun.enable && tun.auto_route && !(tun.auto_dns && dns.enable);
        #[cfg(not(target_os = "macos"))]
        let system_dns_bypasses = tun.enable && tun.dns_hijack.is_empty();
        if system_dns_bypasses {
            findings.push(Finding {
                level: "warning",
                code: "system-dns",
                title: "System DNS does not go to the core".into(),
                detail: if cfg!(target_os = "macos") {
                    "In TUN mode the system may still query its original DNS servers directly. Enable DNS and automatic system DNS (tun.auto-dns)."
                } else {
                    "In TUN mode queries to port 53 are not taken over by the core. Set tun.dns-hijack (e.g. any:53)."
                }
                .into(),
                items: Vec::new(),
            });
        }
        if !dns.enable && !tun.enable {
            findings.push(Finding {
                level: "info",
                code: "dns-disabled",
                title: "The core's DNS is off".into(),
                detail: "Apps using the system proxy usually hand names to the proxy and do not leak; programs that bypass the proxy still use the system DNS.".into(),
                items: Vec::new(),
            });
        }
        DnsLeakAudit {
            leaking: findings.iter().any(|f| f.level == "risk"),
            findings,
        }
    }

    /// Runs bash.ws's DNS leak test along two paths (see `DnsLeakTest`).
    /// Takes up to about half a minute.
    pub async fn dns_leak_test(&self) -> Result<DnsLeakTest> {
        tokio::select! {
            biased;
            _ = self.stop.cancelled() => anyhow::bail!("core stopped"),
            result = tokio::time::timeout(Duration::from_secs(30), self.dns_leak_test_inner()) => {
                result.context("the DNS leak test timed out")?
            }
        }
    }

    async fn dns_leak_test_inner(&self) -> Result<DnsLeakTest> {
        let route = self.test_route(&Target::new(SERVICE, 443)?, "tcp").await?;
        ensure!(
            route.node != "REJECT",
            "a rule rejects {SERVICE}; cannot test"
        );
        let (routed_id, local_id) = tokio::try_join!(self.leak_id(), self.leak_id())?;
        let routed = futures_util::future::join_all((1..=PROBES).map(|n| {
            let id = &routed_id;
            async move {
                let host = format!("{n}.{id}.{SERVICE}");
                let _ = tokio::time::timeout(Duration::from_secs(6), self.touch(&host)).await;
            }
        }));
        let local = futures_util::future::join_all((1..=PROBES).map(|n| {
            let id = &local_id;
            async move {
                let host = format!("{n}.{id}.{SERVICE}");
                let _ =
                    tokio::time::timeout(Duration::from_secs(6), self.resolver.lookup(&host, 80))
                        .await;
            }
        }));
        tokio::join!(routed, local);
        let fetch = |id: String| async move {
            let body = self.leak_get(&format!("/dnsleak/test/{id}?json")).await?;
            parse_result(&body)
        };
        let (routed, local) = tokio::join!(fetch(routed_id), fetch(local_id));
        let failed = |error: anyhow::Error| {
            (
                Vec::new(),
                LeakProbe {
                    error: Some(format!("{error:#}")),
                    ..Default::default()
                },
            )
        };
        let (mut exit, routed) = routed.unwrap_or_else(failed);
        let (local_exit, local) = local.unwrap_or_else(failed);
        if exit.is_empty() {
            exit = local_exit;
        }
        Ok(DnsLeakTest {
            exit,
            verdict: verdict(&route.node, &routed, &local),
            node: route.node,
            matched: route.rule.unwrap_or(route.matched),
            routed,
            local,
        })
    }

    async fn leak_id(&self) -> Result<String> {
        let body = self.leak_get("/id").await?;
        let id = String::from_utf8(body)?.trim().to_owned();
        ensure!(
            !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric()),
            "{SERVICE} returned an invalid test ID"
        );
        Ok(id)
    }

    /// Connects to `host` like an app: the route decides who resolves it.
    /// A request is sent because some proxies open the remote side lazily.
    async fn touch(&self, host: &str) -> Result<()> {
        let (mut stream, _) = self.dial(&Target::new(host, 80)?, None).await?;
        stream
            .write_all(
                format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await?;
        let mut byte = [0; 1];
        let _ = stream.read(&mut byte).await;
        Ok(())
    }

    /// HTTPS GET to bash.ws through the route its traffic uses.
    async fn leak_get(&self, path: &str) -> Result<Vec<u8>> {
        use http_body_util::{BodyExt, Empty, Limited};
        let (stream, _) = self.dial(&Target::new(SERVICE, 443)?, None).await?;
        let tls: BoxStream = clyntis_protocol::tls::SecureConnector::new(self.clock.clone())
            .connect(
                stream,
                &clyntis_protocol::tls::TlsConnectConfig {
                    server_name: SERVICE.into(),
                    alpn: vec!["http/1.1".into()],
                    verify_cert: true,
                    fingerprint: clyntis_protocol::tls::TlsFingerprint::Native,
                    reality: None,
                },
            )
            .await?;
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .handshake(hyper_util::rt::TokioIo::new(tls))
            .await?;
        let _driver = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(connection));
        let request = http::Request::get(path)
            .header(http::header::HOST, SERVICE)
            .header(http::header::USER_AGENT, "clyntis")
            .body(Empty::<bytes::Bytes>::new())?;
        let response = sender.send_request(request).await?;
        ensure!(
            response.status() == http::StatusCode::OK,
            "{SERVICE} HTTP {}",
            response.status()
        );
        Ok(Limited::new(response.into_body(), 256 * 1024)
            .collect()
            .await
            .map_err(anyhow::Error::from_boxed)?
            .to_bytes()
            .to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core(yaml: &str) -> std::sync::Arc<Core> {
        let config = clyntis_config::Config::parse(yaml.as_bytes()).unwrap();
        Core::new(config, std::sync::Arc::new(clyntis_platform::DefaultHooks)).unwrap()
    }

    fn codes(audit: &DnsLeakAudit) -> Vec<&'static str> {
        audit.findings.iter().map(|f| f.code).collect()
    }

    #[test]
    fn ip_rules_before_a_proxy_are_reported_as_leaks() {
        let core = core(
            "dns: {enable: true, nameserver: ['https://1.1.1.1/dns-query']}\nproxy-groups:\n- {name: Proxy, type: select, proxies: [DIRECT]}\nrules:\n- DOMAIN-SUFFIX,cn,DIRECT\n- IP-CIDR,10.0.0.0/8,DIRECT\n- IP-CIDR,192.168.0.0/16,DIRECT,no-resolve\n- AND,((DOMAIN-KEYWORD,x),(IP-CIDR,1.0.0.0/8)),DIRECT\n- MATCH,Proxy\n- IP-CIDR,172.16.0.0/12,DIRECT\n",
        );
        let audit = core.dns_leak_audit();
        assert!(audit.leaking);
        assert_eq!(codes(&audit), ["resolving-rules"]);
        assert_eq!(
            audit.findings[0].items,
            [
                "rule 2: IP-CIDR,10.0.0.0/8,DIRECT",
                "rule 4: AND,((DOMAIN-KEYWORD,x),(IP-CIDR,1.0.0.0/8)),DIRECT"
            ]
        );
        // Global mode ignores the rules.
        core.set_mode(Mode::Global);
        assert!(!core.dns_leak_audit().leaking);
    }

    #[test]
    fn direct_only_rules_redir_host_and_plain_upstreams() {
        let audit = core(
            "dns: {enable: true, enhanced-mode: redir-host, nameserver: ['223.5.5.5', 'tls://1.1.1.1'], nameserver-policy: {'+.lan': 'udp://192.168.1.1'}}\nrules: ['GEOIP,CN,DIRECT', 'MATCH,DIRECT']\n",
        )
        .dns_leak_audit();
        assert!(audit.leaking);
        assert_eq!(codes(&audit), ["redir-host", "plain-upstream"]);
        assert_eq!(audit.findings[1].items, ["223.5.5.5", "udp://192.168.1.1"]);
        let audit = core("rules: ['MATCH,DIRECT']\n").dns_leak_audit();
        assert!(!audit.leaking);
        assert_eq!(codes(&audit), ["dns-disabled"]);
    }

    /// Live: `cargo test -p clyntis-core live_dns_leak_test -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "needs the network and bash.ws"]
    async fn live_dns_leak_test() {
        let core = core(
            "dns: {enable: true, nameserver: ['223.5.5.5', 'https://223.5.5.5/dns-query']}\nrules: ['MATCH,DIRECT']\n",
        );
        let result = core.dns_leak_test().await.unwrap();
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
        assert!(!result.exit.is_empty());
    }

    #[test]
    fn bash_ws_results_split_into_exit_resolvers_and_verdict() {
        let (exit, probe) = parse_result(br#"[
            {"ip":"203.0.113.9","country":"JP","country_name":"Japan","asn":"AS64500 Example","type":"ip"},
            {"ip":"198.51.100.53","country":"JP","country_name":"Japan","asn":"AS64501 Resolver","type":"dns"},
            {"ip":"198.51.100.53","country":"JP","country_name":"Japan","asn":"AS64501 Resolver","type":"dns"},
            {"ip":"192.0.2.1","country":"","country_name":false,"asn":false,"type":"dns"},
            {"ip":"DNS is not leaking.","country":"","country_name":false,"asn":false,"type":"conclusion"}
        ]"#).unwrap();
        assert_eq!(exit.len(), 1);
        assert_eq!(exit[0].country, "Japan");
        assert_eq!(probe.resolvers.len(), 2);
        assert_eq!(probe.resolvers[1].asn, "");
        let (_, failed) =
            parse_result(br#"{"error":"No DNS servers found. Try again..."}"#).unwrap();
        assert!(failed.error.is_some() && failed.resolvers.is_empty());
        assert!(parse_result(b"<html>").is_err());
    }

    #[test]
    fn proxied_names_leak_only_when_the_core_upstreams_see_them() {
        let server = |ip: &str, country: &str, asn: &str| LeakServer {
            ip: ip.into(),
            country: country.into(),
            asn: asn.into(),
        };
        let probe = |resolvers| LeakProbe {
            resolvers,
            error: None,
        };
        let local = probe(vec![
            server("121.196.194.72", "China", "AS37963 Alibaba"),
            server("122.228.2.4", "China", "AS134771 Wenzhou"),
        ]);
        // A proxy server's public resolver: bash.ws calls this a leak.
        let remote = probe(vec![server(
            "104.23.250.71",
            "United States",
            "AS13335 CloudFlare",
        )]);
        assert_eq!(verdict("vless", &remote, &local), "ok");
        assert_eq!(verdict("DIRECT", &local, &local), "direct");
        // Another address from an upstream's pool.
        let leaked = probe(vec![
            server("104.23.250.71", "United States", "AS13335 CloudFlare"),
            server("121.196.198.190", "China", "AS37963 Alibaba"),
        ]);
        assert_eq!(verdict("vless", &leaked, &local), "leak");
        let unnamed = probe(vec![server("122.228.2.4", "", "")]);
        assert_eq!(verdict("vless", &unnamed, &local), "leak");
        assert_eq!(verdict("vless", &remote, &probe(Vec::new())), "unknown");
    }
}
