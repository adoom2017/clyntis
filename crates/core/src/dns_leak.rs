//! DNS leak detection: an offline review of the configuration and an online
//! test against bash.ws, whose name servers record which resolvers asked for
//! random names.
use crate::Core;
use anyhow::{Context, Result, ensure};
use meta_config::{Mode, rule::Matcher};
use meta_protocol::{BoxStream, Target};
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
    /// bash.ws's verdict, comparing these resolvers with the exit address.
    pub conclusion: Option<String>,
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
        shown.push(format!("…共 {total} 项"));
    }
    shown
}

/// bash.ws's `?json` result: entries typed `ip` (the exit), `dns` (a
/// resolver) and `conclusion`.
fn parse_result(body: &[u8]) -> Result<(Vec<LeakServer>, LeakProbe)> {
    let value: serde_json::Value =
        serde_json::from_slice(body).context("bash.ws 返回了无效的结果")?;
    if let Some(error) = value.get("error").and_then(|v| v.as_str()) {
        return Ok((
            Vec::new(),
            LeakProbe {
                error: Some(error.into()),
                ..Default::default()
            },
        ));
    }
    let entries = value.as_array().context("bash.ws 返回了无效的结果")?;
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
            Some("conclusion") => {
                probe.conclusion = Some(server.ip).filter(|c| !c.is_empty());
            }
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
                title: "redir-host 模式会在本地解析所有域名".into(),
                detail: "应用的每次查询都由内核向上游 DNS 解析，走代理的域名也会被上游看到。改用 fake-ip 模式，域名会交给代理在远端解析。".into(),
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
                    resolving.push(format!("第 {} 条：{raw}", index + 1));
                }
            }
            resolving.reverse();
            if !resolving.is_empty() {
                findings.push(Finding {
                    level: "risk",
                    code: "resolving-rules",
                    title: format!("{} 条 IP 规则会在匹配前本地解析域名", resolving.len()),
                    detail: "域名经过这些规则时，内核会先向上游 DNS 解析；之后走代理的域名也因此被上游看到。给这些规则加上 no-resolve，或把它们移到域名规则之后。".into(),
                    items: listed(resolving),
                });
            }
        }
        let mut plain: Vec<String> = dns
            .nameserver
            .iter()
            .cloned()
            .chain(dns.nameserver_policy.values().flat_map(|v| v.values()))
            .filter(|server| plain_server(server))
            .collect();
        plain.sort();
        plain.dedup();
        if !plain.is_empty() {
            findings.push(Finding {
                level: "warning",
                code: "plain-upstream",
                title: "上游 DNS 使用明文协议".into(),
                detail: "内核本地解析的域名（直连连接、IP 规则）会以明文发出，运营商可以看到甚至篡改。改用 https:// 或 tls:// 上游。".into(),
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
                title: "系统 DNS 没有交给内核".into(),
                detail: if cfg!(target_os = "macos") {
                    "TUN 模式下系统仍可能直接向原来的 DNS 服务器查询。开启 DNS 和「自动设置系统 DNS」（tun.auto-dns）。"
                } else {
                    "TUN 模式下发往 53 端口的查询不会被内核接管。设置 tun.dns-hijack（例如 any:53）。"
                }
                .into(),
                items: Vec::new(),
            });
        }
        if !dns.enable && !tun.enable {
            findings.push(Finding {
                level: "info",
                code: "dns-disabled",
                title: "内核 DNS 未启用".into(),
                detail: "使用系统代理的应用通常把域名直接交给代理，不会泄露；不走代理的程序仍使用系统 DNS。".into(),
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
                result.context("DNS 泄露测试超时")?
            }
        }
    }

    async fn dns_leak_test_inner(&self) -> Result<DnsLeakTest> {
        let route = self.test_route(&Target::new(SERVICE, 443)?, "tcp").await?;
        ensure!(route.node != "REJECT", "{SERVICE} 被规则拒绝，无法测试");
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
            "{SERVICE} 返回了无效的测试编号"
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
        let tls: BoxStream = meta_protocol::tls::SecureConnector::new(self.clock.clone())
            .connect(
                stream,
                &meta_protocol::tls::TlsConnectConfig {
                    server_name: SERVICE.into(),
                    alpn: vec!["http/1.1".into()],
                    verify_cert: true,
                    fingerprint: meta_protocol::tls::TlsFingerprint::Native,
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
        let config = meta_config::Config::parse(yaml.as_bytes()).unwrap();
        Core::new(config, std::sync::Arc::new(meta_platform::DefaultHooks)).unwrap()
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
                "第 2 条：IP-CIDR,10.0.0.0/8,DIRECT",
                "第 4 条：AND,((DOMAIN-KEYWORD,x),(IP-CIDR,1.0.0.0/8)),DIRECT"
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

    /// Live: `cargo test -p meta-core live_dns_leak_test -- --ignored --nocapture`.
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
        assert_eq!(probe.conclusion.as_deref(), Some("DNS is not leaking."));
        let (_, failed) =
            parse_result(br#"{"error":"No DNS servers found. Try again..."}"#).unwrap();
        assert!(failed.error.is_some() && failed.resolvers.is_empty());
        assert!(parse_result(b"<html>").is_err());
    }
}
