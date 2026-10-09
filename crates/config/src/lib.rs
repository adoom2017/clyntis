pub mod adblock;
pub mod compat;
pub mod crypto;
pub mod custom;
pub mod overrides;
pub use compat::*;
pub mod rule;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Rule,
    Global,
    Direct,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    pub port: u16,
    pub socks_port: u16,
    pub mixed_port: u16,
    pub allow_lan: bool,
    pub bind_address: String,
    #[serde(skip_serializing)]
    pub authentication: Vec<String>,
    pub mode: Mode,
    pub ipv6: bool,
    pub log_level: String,
    pub log: Log,
    pub proxies: Vec<Proxy>,
    pub proxy_groups: Vec<Group>,
    pub rules: Vec<String>,
    pub dns: Dns,
    pub tun: Tun,
    pub external_controller: Option<String>,
    #[serde(skip_serializing)]
    pub secret: String,
    pub rule_providers: std::collections::BTreeMap<String, RuleProvider>,
    pub geodata_mode: bool,
    pub geox_url: GeoUrls,
    pub geo_auto_update: bool,
    pub geo_update_interval: u64,
    pub unified_delay: bool,
    pub tcp_concurrent: bool,
    pub external_ui: String,
    pub find_process_mode: String,
    pub keep_alive_interval: u64,
    pub global_client_fingerprint: String,
    pub hosts: std::collections::BTreeMap<String, Strings>,
    pub profile: Profile,
    pub ntp: Ntp,
    pub sniffer: Sniffer,
    pub adblock: adblock::Adblock,
    #[serde(skip)]
    pub directory: std::path::PathBuf,
    #[serde(skip)]
    pub internal_allow_native_profile: bool,
    /// Packet-tunnel hosts provide networking rather than a native interface.
    #[serde(skip)]
    pub internal_host_packet_io: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            port: 0,
            socks_port: 0,
            mixed_port: 0,
            allow_lan: false,
            bind_address: "*".into(),
            authentication: vec![],
            mode: Mode::Rule,
            ipv6: true,
            log_level: "info".into(),
            log: Log::default(),
            proxies: vec![],
            proxy_groups: vec![],
            rules: vec!["MATCH,DIRECT".into()],
            dns: Dns::default(),
            tun: Tun::default(),
            external_controller: None,
            secret: String::new(),
            rule_providers: Default::default(),
            geodata_mode: false,
            geox_url: GeoUrls::default(),
            geo_auto_update: false,
            geo_update_interval: 24,
            unified_delay: false,
            tcp_concurrent: false,
            external_ui: String::new(),
            find_process_mode: "strict".into(),
            keep_alive_interval: 30,
            global_client_fingerprint: "chrome".into(),
            hosts: Default::default(),
            profile: Profile::default(),
            ntp: Ntp::default(),
            sniffer: Sniffer::default(),
            adblock: adblock::Adblock::default(),
            directory: ".".into(),
            internal_allow_native_profile: false,
            internal_host_packet_io: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Log {
    pub log_level: String,
    pub log_path: String,
    pub max_size: u64,
    pub max_age: u64,
    pub max_backups: usize,
    pub compress: bool,
}
impl Default for Log {
    fn default() -> Self {
        Self {
            log_level: "info".into(),
            log_path: String::new(),
            max_size: 10,
            max_age: 3,
            max_backups: 0,
            compress: true,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Proxy {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ProxyKind,
    /// Required except for `tailscale`, which finds peers through its tailnet.
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default, skip_serializing, deserialize_with = "relaxed_uuid")]
    pub uuid: Option<uuid::Uuid>,
    #[serde(default, skip_serializing)]
    pub password: String,
    #[serde(default)]
    pub tls: bool,
    #[serde(default = "yes")]
    pub udp: bool,
    #[serde(default)]
    pub servername: Option<String>,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub skip_cert_verify: bool,
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(default = "tcp")]
    pub network: String,
    #[serde(default)]
    pub flow: String,
    #[serde(default)]
    pub client_fingerprint: Option<String>,
    #[serde(default)]
    pub reality_opts: Option<Reality>,
    #[serde(default)]
    pub packet_encoding: Option<String>,
    #[serde(default)]
    pub xudp: bool,
    #[serde(default)]
    pub obfs: Option<String>,
    #[serde(default, skip_serializing)]
    pub obfs_password: String,
    #[serde(default)]
    pub ports: Option<String>,
    #[serde(default = "hop", deserialize_with = "compat::string_or_number")]
    pub hop_interval: String,
    #[serde(default)]
    pub up: Option<String>,
    #[serde(default)]
    pub down: Option<String>,
    #[serde(default)]
    pub ip_version: String,
    #[serde(default)]
    pub tfo: bool,
    #[serde(default)]
    pub ws_opts: WsOptions,
    #[serde(default)]
    pub grpc_opts: GrpcOptions,
    #[serde(default)]
    pub protocol: String,
    #[serde(default, skip_serializing)]
    pub auth_str: String,
    #[serde(default, skip_serializing)]
    pub recv_window_conn: Option<serde_yaml::Value>,
    #[serde(default, skip_serializing)]
    pub recv_window: Option<serde_yaml::Value>,
    #[serde(default)]
    pub disable_mtu_discovery: bool,
    #[serde(default)]
    pub fast_open: bool,
    /// Another proxy (or group) that carries this proxy's own connections;
    /// for `tailscale`, its control-server and DERP connections.
    #[serde(default)]
    pub dialer_proxy: Option<String>,
    #[serde(flatten)]
    pub tailscale: TailscaleOptions,
}
/// mihomo's `type: tailscale` fields.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct TailscaleOptions {
    #[serde(default, skip_serializing)]
    pub auth_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_url: Option<String>,
    /// Relative to the configuration directory; default `tailscale/<name>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_dir: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ephemeral: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_routes: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_node_allow_lan_access: Option<bool>,
}
impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxy")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}
fn yes() -> bool {
    true
}
/// Xray's VLESS UUID mapping standard treats a custom non-empty string as the
/// name in UUIDv5 with the nil UUID namespace. A textual UUID remains unchanged.
fn relaxed_uuid<'de, D: serde::Deserializer<'de>>(de: D) -> Result<Option<uuid::Uuid>, D::Error> {
    use sha1::{Digest, Sha1};
    let value = Option::<String>::deserialize(de)?;
    value
        .map(|value| {
            if value.is_empty() {
                return Err(serde::de::Error::custom("VLESS uuid must not be empty"));
            }
            if let Ok(id) = uuid::Uuid::parse_str(&value) {
                return Ok(id);
            }
            let mut digest = Sha1::new();
            digest.update([0; 16]);
            digest.update(value.as_bytes());
            let mut bytes: [u8; 16] = digest.finalize()[..16].try_into().unwrap();
            bytes[6] = (bytes[6] & 0x0f) | 0x50;
            bytes[8] = (bytes[8] & 0x3f) | 0x80;
            Ok(uuid::Uuid::from_bytes(bytes))
        })
        .transpose()
}
fn tcp() -> String {
    "tcp".into()
}
fn hop() -> String {
    "30s".into()
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    Vless,
    #[serde(alias = "hy2")]
    Hysteria2,
    Trojan,
    Tailscale,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Reality {
    pub public_key: String,
    /// Optional, as in mihomo; empty means an all-zero short ID.
    #[serde(default)]
    pub short_id: String,
    /// mihomo's switch for the X25519MLKEM768 key share. Absent keeps the
    /// browser profile's shares (the patched BoringSSL reuses the X25519 secret
    /// so old and new servers authenticate); `false` removes the hybrid share.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_x25519mlkem768: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Group {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: GroupKind,
    pub proxies: Vec<String>,
    #[serde(default = "test_url")]
    pub url: String,
    #[serde(default = "interval")]
    pub interval: u64,
    #[serde(default = "tolerance")]
    pub tolerance: u64,
}
fn test_url() -> String {
    "https://www.gstatic.com/generate_204".into()
}
fn interval() -> u64 {
    300
}
fn tolerance() -> u64 {
    50
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GroupKind {
    Select,
    UrlTest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Dns {
    pub enable: bool,
    pub listen: String,
    pub nameserver: Vec<String>,
    pub default_nameserver: Vec<String>,
    pub enhanced_mode: String,
    pub fake_ip_range: ipnet::Ipv4Net,
    pub fake_ip_range6: ipnet::Ipv6Net,
    pub fake_ip_filter: Vec<String>,
    pub ipv6: bool,
    pub proxy_server_nameserver: Vec<String>,
    pub nameserver_policy: std::collections::BTreeMap<String, Strings>,
}
impl Default for Dns {
    fn default() -> Self {
        Self {
            enable: false,
            listen: "127.0.0.1:1053".into(),
            nameserver: vec!["https://1.1.1.1/dns-query".into()],
            default_nameserver: vec!["1.1.1.1".into()],
            enhanced_mode: "fake-ip".into(),
            fake_ip_range: "198.18.0.0/16".parse().unwrap(),
            fake_ip_range6: "fdfe:dcba:9876::/64".parse().unwrap(),
            fake_ip_filter: vec!["localhost".into(), "*.local".into()],
            ipv6: true,
            proxy_server_nameserver: vec![],
            nameserver_policy: Default::default(),
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Tun {
    pub enable: bool,
    pub stack: String,
    pub device: String,
    pub auto_route: bool,
    pub auto_dns: bool,
    pub auto_detect_interface: bool,
    pub interface: Option<String>,
    pub mtu: u16,
    pub route_exclude_address: Vec<ipnet::IpNet>,
    pub dns_hijack: Vec<String>,
    /// TCP congestion control for TUN connections: cubic, reno, bbr or bbr3.
    /// cubic/reno apply to the smoltcp stack; bbr/bbr3 are accepted for mihomo
    /// compatibility but have no smoltcp implementation. Absent: none.
    pub congestion_controller: Option<String>,
}
impl Default for Tun {
    fn default() -> Self {
        Self {
            enable: false,
            stack: "gvisor".into(),
            device: "clyntis".into(),
            auto_route: true,
            auto_dns: false,
            auto_detect_interface: true,
            interface: None,
            mtu: 1500,
            route_exclude_address: vec![],
            dns_hijack: vec!["any:53".into()],
            congestion_controller: None,
        }
    }
}

impl Config {
    /// Keeps the implemented outbounds (VLESS and Tailscale).
    pub fn retain_vless(&mut self) -> Result<()> {
        let supported = |p: &Proxy| matches!(p.kind, ProxyKind::Vless | ProxyKind::Tailscale);
        let removed: HashSet<_> = self
            .proxies
            .iter()
            .filter(|p| !supported(p))
            .map(|p| p.name.clone())
            .collect();
        self.proxies.retain(supported);
        for group in &mut self.proxy_groups {
            group.proxies.retain(|p| !removed.contains(p));
            if group.proxies.is_empty() {
                group.proxies.push("REJECT".into());
            }
        }
        for raw in &mut self.rules {
            let r = rule::Rule::parse(raw)?;
            if removed.contains(&r.target) {
                let suffix = if r.no_resolve { ",no-resolve" } else { "" };
                let end = raw.len() - suffix.len() - r.target.len();
                *raw = format!("{}REJECT{suffix}", &raw[..end]);
            }
        }
        self.validate()
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= 16 * 1024 * 1024,
            "configuration exceeds 16 MiB"
        );
        let de = serde_yaml::Deserializer::from_slice(bytes);
        let mut cfg: Self = serde_path_to_error::deserialize(de)
            .context("invalid or unsupported configuration field")?;
        fn listen(value: &str) -> String {
            if value.starts_with(':') {
                format!("0.0.0.0{value}")
            } else if let Some(port) = value.strip_prefix("localhost:") {
                format!("127.0.0.1:{port}")
            } else if let Some(port) = value.strip_prefix("*:") {
                format!("0.0.0.0:{port}")
            } else {
                value.into()
            }
        }
        cfg.external_controller = cfg.external_controller.as_deref().map(listen);
        cfg.dns.listen = listen(&cfg.dns.listen);
        // The top-level Clash option wins when explicitly present, including
        // `info`; otherwise the nested logging option remains supported.
        let document: serde_yaml::Value = serde_yaml::from_slice(bytes)?;
        if document
            .as_mapping()
            .is_some_and(|mapping| mapping.contains_key(serde_yaml::Value::from("log-level")))
        {
            cfg.log.log_level.clone_from(&cfg.log_level);
        } else {
            cfg.log_level.clone_from(&cfg.log.log_level);
        }
        cfg.validate()?;
        Ok(cfg)
    }
    pub fn validate(&self) -> Result<()> {
        self.adblock.validate()?;
        ensure!(
            self.internal_allow_native_profile && self.global_client_fingerprint == "native"
                || [
                    "chrome",
                    "firefox",
                    "safari",
                    "ios",
                    "android",
                    "edge",
                    "360",
                    "qq",
                    "random",
                    "randomized"
                ]
                .contains(&self.global_client_fingerprint.as_str()),
            if self.global_client_fingerprint == "rustls" {
                "global-client-fingerprint 'rustls' is unavailable; use a BoringSSL browser profile"
            } else {
                "unknown global-client-fingerprint"
            }
        );
        ensure!(
            ["debug", "info", "warning", "error", "silent"].contains(&self.log_level.as_str()),
            "invalid log-level"
        );
        ensure!(self.log.max_size > 0, "log.max-size must be positive");
        let mut names: HashSet<&str> = HashSet::from(["DIRECT", "REJECT", "GLOBAL"]);
        for (index, p) in self.proxies.iter().enumerate() {
            ensure!(
                !p.name.is_empty() && names.insert(&p.name),
                "duplicate/reserved proxy name: {}",
                p.name
            );
            ensure!(
                p.kind == ProxyKind::Tailscale || (!p.server.is_empty() && p.port != 0),
                "proxy {}: server/port required",
                p.name
            );
            ensure!(
                p.kind == ProxyKind::Tailscale || p.tailscale == TailscaleOptions::default(),
                "proxy {}: tailscale options require type: tailscale",
                p.name
            );
            ensure!(
                p.kind != ProxyKind::Vless || ["tcp", "ws", "grpc"].contains(&p.network.as_str()),
                "proxy {}: VLESS network must be tcp, ws, or grpc",
                p.name
            );
            match p.kind {
                ProxyKind::Vless => {
                    ensure!(
                        p.client_fingerprint.as_deref().is_none_or(|v| (self
                            .internal_allow_native_profile
                            && v == "native")
                            || [
                                "firefox",
                                "chrome",
                                "safari",
                                "ios",
                                "android",
                                "edge",
                                "360",
                                "qq",
                                "random",
                                "randomized"
                            ]
                            .contains(&v)),
                        "proxies[{index}].client-fingerprint: unknown TLS profile"
                    );
                    ensure!(
                        p.alpn.iter().all(|v| !v.is_empty() && v.len() <= 255),
                        "proxies[{index}].alpn: entries must be 1..255 bytes"
                    );
                    ensure!(p.uuid.is_some(), "proxy {}: uuid required", p.name);
                    ensure!(
                        p.flow.is_empty() || p.flow == "xtls-rprx-vision",
                        "unsupported flow for {}",
                        p.name
                    );
                    ensure!(
                        p.flow.is_empty() || p.network == "tcp",
                        "Vision only supports network tcp"
                    );
                    ensure!(
                        p.ws_opts.max_early_data <= 65535,
                        "proxies[{index}].ws-opts.max-early-data is too large"
                    );
                    ensure!(
                        !p.ws_opts.v2ray_http_upgrade_fast_open || p.ws_opts.v2ray_http_upgrade,
                        "proxies[{index}].ws-opts fast-open requires v2ray-http-upgrade"
                    );
                    ensure!(
                        p.network == "ws" || p.ws_opts == WsOptions::default(),
                        "proxies[{index}].ws-opts requires network: ws"
                    );
                    ensure!(
                        p.grpc_opts.max_connections <= 1024,
                        "proxies[{index}].grpc-opts.max-connections is too large"
                    );
                    ensure!(
                        p.grpc_opts.min_streams <= 65535,
                        "proxies[{index}].grpc-opts.min-streams is too large"
                    );
                    ensure!(
                        p.grpc_opts.max_streams <= 65535,
                        "proxies[{index}].grpc-opts.max-streams is too large"
                    );
                    ensure!(
                        p.grpc_opts.max_streams == 0
                            || (p.grpc_opts.max_connections == 0 && p.grpc_opts.min_streams == 0),
                        "proxies[{index}].grpc-opts.max-streams conflicts with max-connections/min-streams"
                    );
                    ensure!(
                        p.grpc_opts.min_streams == 0 || p.grpc_opts.max_connections > 0,
                        "proxies[{index}].grpc-opts.min-streams requires max-connections"
                    );
                    ensure!(
                        p.network == "grpc" || p.grpc_opts == GrpcOptions::default(),
                        "proxies[{index}].grpc-opts requires network: grpc"
                    );
                    ensure!(
                        p.flow.is_empty() || p.tls || p.reality_opts.is_some(),
                        "Vision requires TLS 1.3"
                    );
                    if let Some(r) = &p.reality_opts {
                        use base64::Engine;
                        ensure!(
                            base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(&r.public_key)?
                                .len()
                                == 32,
                            "reality public-key must be 32 bytes"
                        );
                        ensure!(
                            r.short_id.len() <= 16
                                && r.short_id.len() % 2 == 0
                                && r.short_id.bytes().all(|b| b.is_ascii_hexdigit()),
                            "invalid reality short-id"
                        );
                    }
                    if let Some(enc) = &p.packet_encoding {
                        ensure!(
                            enc == "xudp" || enc.is_empty(),
                            "unsupported packet-encoding"
                        );
                    }
                }
                ProxyKind::Hysteria2 => {
                    if !p.auth_str.is_empty() && p.password.is_empty() {
                        continue;
                    }
                    ensure!(
                        !p.password.is_empty(),
                        "proxy {}: password required",
                        p.name
                    );
                    ensure!(
                        p.obfs.as_deref().is_none_or(|v| v == "salamander"),
                        "only salamander obfs supported"
                    );
                    ensure!(
                        p.obfs.is_none() || !p.obfs_password.is_empty(),
                        "obfs-password required"
                    );
                    port_list(p)?;
                    duration_seconds(&p.hop_interval)?;
                    for value in [&p.up, &p.down].into_iter().flatten() {
                        bandwidth(value)?;
                    }
                }
                ProxyKind::Trojan => {}
                ProxyKind::Tailscale => {
                    let t = &p.tailscale;
                    if let Some(url) = &t.control_url {
                        ensure!(
                            url.starts_with("https://") || url.starts_with("http://"),
                            "proxy {}: control-url must be http(s)",
                            p.name
                        );
                    }
                    if let Some(dir) = &t.state_dir {
                        // Downloaded profiles run as root in TUN mode: keep the
                        // node state inside the configuration directory.
                        ensure!(
                            !dir.is_empty()
                                && !std::path::Path::new(dir).is_absolute()
                                && !dir.starts_with(['/', '\\', '~'])
                                && !dir.contains(':')
                                && !dir.split(['/', '\\']).any(|part| part == ".."),
                            "proxy {}: state-dir must be a relative path inside the configuration directory",
                            p.name
                        );
                    }
                    if let Some(hostname) = &t.hostname {
                        ensure!(
                            !hostname.is_empty()
                                && hostname.len() <= 63
                                && hostname
                                    .bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
                            "proxy {}: hostname must be a DNS label",
                            p.name
                        );
                    }
                }
            }
        }
        for g in &self.proxy_groups {
            ensure!(
                !g.name.is_empty() && names.insert(&g.name),
                "duplicate/reserved group name: {}",
                g.name
            );
            ensure!(!g.proxies.is_empty(), "empty group {}", g.name);
            ensure!(g.interval > 0, "group interval must be positive");
        }
        for p in &self.proxies {
            if let Some(via) = &p.dialer_proxy {
                ensure!(
                    via != &p.name && via != "GLOBAL" && names.contains(via.as_str()),
                    "proxy {}: unknown dialer-proxy {via}",
                    p.name
                );
            }
        }
        let groups: HashMap<&str, &Group> = self
            .proxy_groups
            .iter()
            .map(|g| (g.name.as_str(), g))
            .collect();
        fn visit<'a>(
            name: &'a str,
            groups: &HashMap<&'a str, &'a Group>,
            names: &HashSet<&str>,
            path: &mut HashSet<&'a str>,
        ) -> Result<()> {
            ensure!(
                names.contains(name) && name != "GLOBAL",
                "unknown or invalid group target: {name}"
            );
            if let Some(g) = groups.get(name) {
                ensure!(path.insert(name), "cyclic group: {name}");
                for child in &g.proxies {
                    visit(child, groups, names, path)?;
                }
                path.remove(name);
            }
            Ok(())
        }
        for g in &self.proxy_groups {
            visit(&g.name, &groups, &names, &mut HashSet::new())?;
        }
        for (i, raw) in self.rules.iter().enumerate() {
            let rule = rule::Rule::parse(raw).with_context(|| format!("rules[{i}]"))?;
            ensure!(
                names.contains(rule.target.as_str()),
                "rules[{i}]: unknown target {}",
                rule.target
            );
            let mut refs = vec![];
            rule.matcher.references(&mut refs);
            for (kind, name) in refs {
                if kind == "rule-set" {
                    ensure!(
                        self.rule_providers.contains_key(&name),
                        "rules[{i}]: unknown rule provider"
                    );
                }
            }
        }
        for p in self.rule_providers.values() {
            ensure!(
                ["http", "file", "inline"].contains(&p.kind.as_str()),
                "invalid rule provider type"
            );
            ensure!(
                ["domain", "ipcidr", "classical"].contains(&p.behavior.as_str()),
                "invalid rule provider behavior"
            );
            ensure!(
                ["yaml", "text"].contains(&p.format.as_str()),
                "invalid rule provider format"
            );
            ensure!(
                p.kind == "inline" || !p.path.is_empty(),
                "rule provider path is required"
            );
            ensure!(
                p.kind != "http" || p.url.starts_with("https://") || p.url.starts_with("http://"),
                "HTTP rule provider URL is required"
            );
        }
        ensure!(
            self.geo_update_interval > 0 && self.geo_update_interval <= 8760,
            "invalid geo-update-interval"
        );
        ensure!(
            ["strict", "always", "off"].contains(&self.find_process_mode.as_str()),
            "invalid find-process-mode"
        );
        // Labels only: every stack name runs the native smoltcp stack. mihomo
        // 1.19.32 made `mips` its default.
        ensure!(
            ["gvisor", "system", "mixed", "mips"].contains(&self.tun.stack.as_str()),
            "invalid tun.stack"
        );
        if let Some(controller) = &self.tun.congestion_controller {
            ensure!(
                ["cubic", "reno", "bbr", "bbr3"].contains(&controller.as_str()),
                "invalid tun.congestion-controller (cubic, reno, bbr or bbr3)"
            );
        }
        ensure!(
            self.ntp.interval > 0 && self.ntp.port > 0,
            "invalid NTP interval/port"
        );
        for (protocol, sniff) in &self.sniffer.sniff {
            ensure!(
                ["HTTP", "TLS"].contains(&protocol.as_str()),
                "only HTTP/TLS sniffing is supported"
            );
            for port in &sniff.ports {
                port.bounds()?;
            }
        }
        for value in self.dns.nameserver_policy.values() {
            ensure!(!value.values().is_empty(), "empty DNS policy upstreams");
            ensure!(
                value.values().iter().all(|server| dns_upstream(server)),
                "unsupported DNS policy upstream"
            );
        }
        ensure!(
            ["fake-ip", "redir-host"].contains(&self.dns.enhanced_mode.as_str()),
            "unsupported dns.enhanced-mode"
        );
        ensure!(
            !self.dns.nameserver.is_empty(),
            "dns.nameserver cannot be empty"
        );
        ensure!(
            self.dns
                .nameserver
                .iter()
                .chain(&self.dns.default_nameserver)
                .chain(&self.dns.proxy_server_nameserver)
                .all(|server| dns_upstream(server)),
            "unsupported DNS upstream scheme"
        );
        ensure!(
            (1280..=9000).contains(&self.tun.mtu),
            "tun.mtu must be 1280..9000"
        );
        ensure!(
            self.internal_host_packet_io
                || !self.tun.enable
                || self.tun.auto_detect_interface
                || self.tun.interface.is_some(),
            "tun.interface is required when auto-detect-interface is disabled"
        );
        ensure!(
            !self.tun.device.is_empty()
                && self.tun.device.len() <= 128
                && !self.tun.device.chars().any(char::is_control),
            "invalid tun.device"
        );
        ensure!(
            self.tun.route_exclude_address.len() <= 1024,
            "tun.route-exclude-address limit is 1024"
        );
        for (index, value) in self.tun.dns_hijack.iter().enumerate() {
            let value = value
                .strip_prefix("tcp://")
                .or_else(|| value.strip_prefix("udp://"))
                .unwrap_or(value);
            let valid = if let Some(port) = value.strip_prefix("any:") {
                port.parse::<u16>().is_ok_and(|p| p != 0)
            } else {
                value
                    .parse::<std::net::SocketAddr>()
                    .is_ok_and(|a| a.port() != 0)
            };
            ensure!(valid, "tun.dns-hijack[{index}] must be any:port or IP:port");
        }
        for auth in &self.authentication {
            ensure!(
                auth.split_once(':')
                    .is_some_and(|(u, p)| !u.is_empty() && !p.is_empty()),
                "authentication must be user:password"
            );
        }
        if let Some(addr) = &self.external_controller {
            let addr: std::net::SocketAddr = addr
                .parse()
                .context("external-controller must be IP:port")?;
            ensure!(
                addr.ip().is_loopback() || !self.secret.is_empty(),
                "non-loopback controller requires secret"
            );
        }
        if self.bind_address != "*" {
            self.bind_address
                .parse::<IpAddr>()
                .context("bind-address must be an IP address or *")?;
        }
        Ok(())
    }
}

fn dns_upstream(value: &str) -> bool {
    !value.is_empty()
        && (!value.contains("://")
            || ["udp://", "tcp://", "tls://", "https://"]
                .iter()
                .any(|prefix| value.starts_with(prefix)))
}

pub fn duration_seconds(value: &str) -> Result<u64> {
    let (digits, mul) = if let Some(s) = value.strip_suffix('s') {
        (s, 1)
    } else if let Some(s) = value.strip_suffix('m') {
        (s, 60)
    } else {
        (value, 1)
    };
    let n = digits
        .parse::<u64>()?
        .checked_mul(mul)
        .context("duration overflow")?;
    ensure!(n >= 5, "hop interval must be at least 5s");
    Ok(n)
}
pub fn bandwidth(value: &str) -> Result<u64> {
    let v = value.trim().to_ascii_lowercase();
    let (number, scale) = if let Some(n) = v.strip_suffix("gbps") {
        (n, 1_000_000_000.0)
    } else if let Some(n) = v.strip_suffix("mbps") {
        (n, 1_000_000.0)
    } else if let Some(n) = v.strip_suffix("kbps") {
        (n, 1_000.0)
    } else {
        (v.as_str(), 1_000_000.0)
    };
    let rate = number.trim().parse::<f64>()? * scale / 8.0;
    ensure!(
        rate.is_finite() && (1.0..=1e12).contains(&rate),
        "invalid bandwidth"
    );
    Ok(rate as u64)
}
pub fn port_list(proxy: &Proxy) -> Result<Vec<u16>> {
    let Some(ports) = &proxy.ports else {
        return Ok(vec![proxy.port]);
    };
    let mut output = Vec::new();
    for part in ports.split(',') {
        let (lo, hi) = if let Some((a, b)) = part.trim().split_once('-') {
            (a.parse::<u16>()?, b.parse::<u16>()?)
        } else {
            let n = part.trim().parse::<u16>()?;
            (n, n)
        };
        ensure!(lo > 0 && lo <= hi, "invalid port range");
        output.extend(lo..=hi);
        ensure!(output.len() <= 65535, "too many hopping ports");
    }
    if output.is_empty() {
        bail!("empty port list");
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    #[test]
    fn accepts_mihomo_1_19_31_and_1_19_32_options() {
        let yaml = br#"
tun:
  stack: mips
  congestion-controller: cubic
proxies:
  - name: r
    type: vless
    server: example.com
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    network: tcp
    tls: true
    servername: example.com
    reality-opts:
      public-key: e06Qm75__kTEZaIgA31gjuNYl9Me-XLwf3SJLLD3PxM
      support-x25519mlkem768: false
rules: ['MATCH,DIRECT']
"#;
        let config = Config::parse(yaml).unwrap();
        assert_eq!(config.tun.congestion_controller.as_deref(), Some("cubic"));
        let reality = config.proxies[0].reality_opts.as_ref().unwrap();
        assert_eq!(reality.short_id, "");
        assert_eq!(reality.support_x25519mlkem768, Some(false));
        let bad = String::from_utf8_lossy(yaml).replace("cubic", "vegas");
        assert!(Config::parse(bad.as_bytes()).is_err());
    }

    use super::*;
    #[test]
    fn packet_host_interface_exemption_cannot_be_enabled_by_yaml() {
        assert!(Config::parse(b"internal-host-packet-io: true\n").is_err());
        assert!(Config::parse(b"tun: {enable: true, auto-detect-interface: false}\n").is_err());
        let config = Config::parse(b"{}\n").unwrap();
        assert!(!config.internal_host_packet_io);
        assert!(
            serde_json::to_value(config)
                .unwrap()
                .get("internal-host-packet-io")
                .is_none()
        );
    }
    #[test]
    fn defaults_and_logging() {
        let cfg = Config::parse(b"log:\n  log-level: debug\n  log-path: logs/meta.log\n").unwrap();
        assert_eq!(cfg.log_level, "debug");
        assert_eq!(cfg.log.max_size, 10);
        let cfg = Config::parse(b"log-level: warning\nlog:\n  log-level: debug\n").unwrap();
        assert_eq!(cfg.log.log_level, "warning");
        let cfg = Config::parse(b"log-level: info\nlog:\n  log-level: debug\n").unwrap();
        assert_eq!(cfg.log.log_level, "info");
        assert!(Config::parse(b"dns:\n  nameserver: [tls://1.1.1.1]\n").is_ok());
        assert!(Config::parse(b"dns:\n  nameserver: [quic://1.1.1.1]\n").is_err());
    }
    #[test]
    fn reject_unknown_and_cycles() {
        assert!(Config::parse(b"proxy-providers: {}\n").is_err());
        assert!(Config::parse(b"proxy-groups:\n- {name: a, type: select, proxies: [b]}\n- {name: b, type: select, proxies: [a]}\n").is_err());
        assert!(Config::parse(b"rules: [MATCH,missing]\n").is_err());
    }
    #[test]
    fn vless_options_are_explicit() {
        let base = "proxies:\n- name: test\n  type: vless\n  server: localhost\n  port: 443\n  uuid: 11223344-5566-7788-99aa-bbccddeeff00\n";
        let config = Config::parse(format!("{base}  packet-encoding: xudp\n").as_bytes()).unwrap();
        assert_eq!(config.proxies[0].packet_encoding.as_deref(), Some("xudp"));
        assert!(Config::parse(format!("{base}  client-fingerprint: firefox\n").as_bytes()).is_ok());
        let err =
            Config::parse(format!("{base}  client-fingerprint: invalid-profile\n").as_bytes())
                .unwrap_err();
        assert!(err.to_string().contains("proxies[0].client-fingerprint"));
        assert!(Config::parse(format!("{base}  flow: xtls-rprx-vision\n").as_bytes()).is_err());
        assert!(
            Config::parse(format!("{base}  packet-encoding: packetaddr\n").as_bytes()).is_err()
        );
        assert!(Config::parse(format!("{base}  ws-opts: {{path: /ws}}\n").as_bytes()).is_err());
        assert!(
            Config::parse(
                format!(
                    "{base}  network: grpc\n  grpc-opts: {{max-connections: 2, min-streams: 1, max-streams: 4}}\n"
                )
                .as_bytes()
            )
            .is_err()
        );
        assert!(
            Config::parse(
                format!("{base}  network: grpc\n  grpc-opts: {{min-streams: 1}}\n").as_bytes()
            )
            .is_err()
        );
        assert!(
            Config::parse(
                format!(
                    "{base}  network: grpc\n  grpc-opts: {{max-connections: 2, min-streams: 1}}\n"
                )
                .as_bytes()
            )
            .is_ok()
        );
        let mapped = Config::parse(
            b"proxies:\n- name: test\n  type: vless\n  server: localhost\n  port: 443\n  uuid: example\n",
        )
        .unwrap();
        assert_eq!(
            mapped.proxies[0].uuid.unwrap().to_string(),
            "feb54431-301b-52bb-a6dd-e1e93e81bb9e"
        );
        assert!(Config::parse(b"proxies:\n- name: test\n  type: vless\n  server: localhost\n  port: 443\n  uuid: ''\n").is_err());
    }
}

#[cfg(test)]
mod tailscale_tests {
    use super::*;

    #[test]
    fn parses_mihomo_tailscale_proxies() {
        let config = Config::parse(
            b"proxies:\n  - {name: ts, type: tailscale, auth-key: tskey-auth-x, hostname: clyntis-mac, exit-node: us-exit, accept-routes: true, ephemeral: true}\n  - {name: node, type: vless, server: example.com, port: 443, uuid: 11111111-1111-4111-8111-111111111111}\n  - {name: ts2, type: tailscale, dialer-proxy: node, control-url: 'https://headscale.example'}\nrules: ['IP-CIDR,100.64.0.0/10,ts,no-resolve', 'DOMAIN-SUFFIX,ts.net,ts', 'MATCH,DIRECT']\n",
        )
        .unwrap();
        let ts = &config.proxies[0];
        assert_eq!(ts.kind, ProxyKind::Tailscale);
        assert_eq!(ts.tailscale.auth_key.as_deref(), Some("tskey-auth-x"));
        assert_eq!(ts.tailscale.exit_node.as_deref(), Some("us-exit"));
        assert!(ts.tailscale.ephemeral);
        assert_eq!(config.proxies[2].dialer_proxy.as_deref(), Some("node"));
        // Unknown keys are still rejected, and tailscale keys need the type.
        assert!(Config::parse(b"proxies:\n  - {name: ts, type: tailscale, bogus: 1}\n").is_err());
        assert!(Config::parse(b"proxies:\n  - {name: v, type: vless, server: a.b, port: 1, uuid: 11111111-1111-4111-8111-111111111111, auth-key: x}\n").is_err());
        assert!(Config::parse(b"proxies:\n  - {name: v, type: vless, uuid: 11111111-1111-4111-8111-111111111111}\n").is_err());
        assert!(
            Config::parse(b"proxies:\n  - {name: ts, type: tailscale, dialer-proxy: missing}\n")
                .is_err()
        );
        assert!(
            Config::parse(b"proxies:\n  - {name: ts, type: tailscale, dialer-proxy: ts}\n")
                .is_err()
        );
        for dir in ["/etc/x", "../x", "a/../../x", "~/x", "C:\\\\x"] {
            let yaml = format!("proxies:\n  - {{name: ts, type: tailscale, state-dir: '{dir}'}}\n");
            assert!(Config::parse(yaml.as_bytes()).is_err(), "{dir}");
        }
        assert!(
            Config::parse(b"proxies:\n  - {name: ts, type: tailscale, state-dir: nodes/home}\n")
                .is_ok()
        );
        // The auth key never leaves through serialization.
        assert!(!serde_json::to_string(&config).unwrap().contains("tskey"));
    }
}
