//! Zero-boilerplate GeoIP/GeoSite auto-routing for node-only profiles.
//!
//! When a YAML profile defines `proxies:` (with at least one VLESS or Hysteria2
//! node) and omits `rules:`, Clyntis synthesizes a minimal `Proxy` / `Auto`
//! group, GeoIP/GeoSite rules, China-friendly Fake-IP DNS, and TLS/HTTP sniffer
//! defaults so users never have to hand-write routing rules.

use crate::{Config, Group, GroupKind, Proxy, ProxyKind, SniffProtocol};
use anyhow::Result;
use serde::{Deserialize, Serialize, de::IgnoredAny};
use serde_yaml::{Mapping, Value};
use std::collections::HashSet;

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct Presence {
    pub log_level: Option<IgnoredAny>,
    pub rules: Option<IgnoredAny>,
    pub geodata_mode: Option<IgnoredAny>,
    pub geo_auto_update: Option<IgnoredAny>,
    pub proxy_groups: Option<IgnoredAny>,
    pub dns: Option<DnsPresence>,
    pub sniffer: Option<SnifferPresence>,
    pub tun: Option<TunPresence>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct DnsPresence {
    pub enable: Option<IgnoredAny>,
    pub enhanced_mode: Option<IgnoredAny>,
    pub fake_ip_range: Option<IgnoredAny>,
    pub nameserver: Option<IgnoredAny>,
    pub default_nameserver: Option<IgnoredAny>,
    pub fake_ip_filter: Option<IgnoredAny>,
    pub ipv6: Option<IgnoredAny>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct SnifferPresence {
    pub enable: Option<IgnoredAny>,
    pub sniff: Option<IgnoredAny>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct TunPresence {
    pub auto_dns: Option<IgnoredAny>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AutoRouting {
    #[default]
    Whitelist,
    Blacklist,
}

impl AutoRouting {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Whitelist => "whitelist",
            Self::Blacklist => "blacklist",
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "whitelist" => Ok(Self::Whitelist),
            "blacklist" => Ok(Self::Blacklist),
            other => anyhow::bail!(
                "unsupported auto-routing mode {:?} (expected whitelist or blacklist)",
                other
            ),
        }
    }
}

pub fn is_routable(proxy: &Proxy) -> bool {
    matches!(proxy.kind, ProxyKind::Vless | ProxyKind::Hysteria2)
}

pub fn should_auto_route(map: &Mapping, proxies: &[Proxy]) -> bool {
    !map.contains_key(Value::from("rules")) && proxies.iter().any(is_routable)
}

fn pick_group_name(preferred: &str, fallback: &str, taken: &HashSet<String>) -> String {
    if !taken.contains(preferred) {
        return preferred.to_owned();
    }
    if !taken.contains(fallback) {
        return fallback.to_owned();
    }
    for idx in 2.. {
        let candidate = format!("{preferred} {idx}");
        if !taken.contains(&candidate) {
            return candidate;
        }
    }
    unreachable!()
}

/// Builds minimalist proxy groups (`Proxy`, plus `Auto` url-test when >=2
/// routable nodes exist), excluding Tailscale proxies from general internet groups.
pub fn build_groups(proxies: &[Proxy]) -> (Vec<Group>, String) {
    let nodes: Vec<String> = proxies
        .iter()
        .filter(|p| is_routable(p))
        .map(|p| p.name.clone())
        .collect();
    let mut taken: HashSet<String> = proxies.iter().map(|p| p.name.clone()).collect();
    taken.insert("DIRECT".into());
    taken.insert("REJECT".into());
    taken.insert("GLOBAL".into());

    let proxy_name = pick_group_name("Proxy", "AutoProxy", &taken);
    if nodes.len() <= 1 {
        let mut list = nodes;
        list.push("DIRECT".into());
        let group = Group {
            name: proxy_name.clone(),
            kind: GroupKind::Select,
            proxies: list,
            url: "https://www.gstatic.com/generate_204".into(),
            interval: 300,
            tolerance: 50,
        };
        return (vec![group], proxy_name);
    }

    taken.insert(proxy_name.clone());
    let auto_name = pick_group_name("Auto", "AutoTest", &taken);
    let mut select_list = Vec::with_capacity(nodes.len() + 2);
    select_list.push(auto_name.clone());
    select_list.extend(nodes.iter().cloned());
    select_list.push("DIRECT".into());

    let select_group = Group {
        name: proxy_name.clone(),
        kind: GroupKind::Select,
        proxies: select_list,
        url: "https://www.gstatic.com/generate_204".into(),
        interval: 300,
        tolerance: 50,
    };
    let auto_group = Group {
        name: auto_name,
        kind: GroupKind::UrlTest,
        proxies: nodes,
        url: "https://www.gstatic.com/generate_204".into(),
        interval: 300,
        tolerance: 50,
    };
    (vec![select_group, auto_group], proxy_name)
}

pub fn build_rules(mode: AutoRouting, target: &str) -> Vec<String> {
    let mut rules = vec![
        "GEOSITE,private,DIRECT".into(),
        "GEOIP,private,DIRECT,no-resolve".into(),
        "DOMAIN,connectivitycheck.gstatic.com,DIRECT".into(),
        "AND,((DST-PORT,443),(NETWORK,UDP),(NOT,((GEOSITE,cn)))),REJECT".into(),
    ];
    match mode {
        AutoRouting::Whitelist => {
            rules.push("GEOSITE,apple-cn,DIRECT".into());
            rules.push("GEOSITE,cn,DIRECT".into());
            rules.push("GEOIP,cn,DIRECT".into());
            rules.push(format!("MATCH,{target}"));
        }
        AutoRouting::Blacklist => {
            rules.push(format!("GEOSITE,geolocation-!cn,{target}"));
            rules.push("MATCH,DIRECT".into());
        }
    }
    rules
}

pub fn default_dns_nameservers() -> Vec<String> {
    vec!["223.5.5.5".into(), "119.29.29.29".into()]
}

pub fn default_fake_ip_filter() -> Vec<String> {
    vec![
        "localhost".into(),
        "*.local".into(),
        "*.lan".into(),
        "*.home.arpa".into(),
        "time.*.com".into(),
        "time.*.gov".into(),
        "time.*.apple.com".into(),
        "ntp.*.com".into(),
        "+.pool.ntp.org".into(),
        "connectivitycheck.gstatic.com".into(),
    ]
}

fn default_sniff_protocols() -> std::collections::BTreeMap<String, SniffProtocol> {
    let mut sniff = std::collections::BTreeMap::new();
    sniff.insert(
        "HTTP".into(),
        SniffProtocol {
            ports: vec![
                crate::PortRange::Number(80),
                crate::PortRange::Range("8080-8880".into()),
            ],
            override_destination: true,
        },
    );
    sniff.insert(
        "TLS".into(),
        SniffProtocol {
            ports: vec![
                crate::PortRange::Number(443),
                crate::PortRange::Number(8443),
            ],
            override_destination: true,
        },
    );
    sniff
}

fn ensure_submap<'a>(map: &'a mut Mapping, key: &str) -> &'a mut Mapping {
    let k = Value::from(key);
    let is_mapping = map.get(&k).is_some_and(Value::is_mapping);
    if !is_mapping {
        map.insert(k.clone(), Value::Mapping(Mapping::new()));
    }
    map.get_mut(&k)
        .and_then(Value::as_mapping_mut)
        .expect("inserted mapping")
}

fn insert_if_missing(map: &mut Mapping, key: &str, value: Value) {
    let k = Value::from(key);
    if !map.contains_key(&k) {
        map.insert(k, value);
    }
}

fn has_key(map: Option<&Mapping>, key: &str) -> bool {
    map.is_some_and(|m| m.contains_key(Value::from(key)))
}

fn pick_existing_target(cfg: &Config) -> String {
    if let Some(g) = cfg.proxy_groups.iter().find(|g| g.name == "Proxy") {
        return g.name.clone();
    }
    if let Some(g) = cfg.proxy_groups.first() {
        return g.name.clone();
    }
    cfg.proxies
        .iter()
        .find(|p| is_routable(p))
        .map(|p| p.name.clone())
        .unwrap_or_else(|| "DIRECT".into())
}

/// Fills automatic GeoIP/GeoSite groups, rules, DNS, sniffer, and TUN defaults
/// when a profile omits `rules:` and defines at least one routable node.
pub fn apply_defaults(cfg: &mut Config, map: &Mapping) {
    if !should_auto_route(map, &cfg.proxies) {
        return;
    }
    let key = |k: &str| map.contains_key(Value::from(k)).then_some(IgnoredAny);
    let dns_map = map.get(Value::from("dns")).and_then(Value::as_mapping);
    let sniffer_map = map.get(Value::from("sniffer")).and_then(Value::as_mapping);
    let tun_map = map.get(Value::from("tun")).and_then(Value::as_mapping);
    let presence = Presence {
        log_level: key("log-level"),
        rules: key("rules"),
        geodata_mode: key("geodata-mode"),
        geo_auto_update: key("geo-auto-update"),
        proxy_groups: key("proxy-groups"),
        dns: dns_map.map(|m| DnsPresence {
            enable: has_key(Some(m), "enable").then_some(IgnoredAny),
            enhanced_mode: has_key(Some(m), "enhanced-mode").then_some(IgnoredAny),
            fake_ip_range: has_key(Some(m), "fake-ip-range").then_some(IgnoredAny),
            nameserver: has_key(Some(m), "nameserver").then_some(IgnoredAny),
            default_nameserver: has_key(Some(m), "default-nameserver").then_some(IgnoredAny),
            fake_ip_filter: has_key(Some(m), "fake-ip-filter").then_some(IgnoredAny),
            ipv6: has_key(Some(m), "ipv6").then_some(IgnoredAny),
        }),
        sniffer: sniffer_map.map(|m| SnifferPresence {
            enable: has_key(Some(m), "enable").then_some(IgnoredAny),
            sniff: has_key(Some(m), "sniff").then_some(IgnoredAny),
        }),
        tun: tun_map.map(|m| TunPresence {
            auto_dns: has_key(Some(m), "auto-dns").then_some(IgnoredAny),
        }),
    };
    apply_defaults_inner(cfg, &presence);
}

/// Fills automatic GeoIP/GeoSite groups, rules, DNS, sniffer, and TUN defaults
/// from a lightweight key-presence pass without building a full YAML DOM.
pub fn apply_defaults_from_presence(cfg: &mut Config, presence: &Presence) {
    if presence.rules.is_some() || !cfg.proxies.iter().any(is_routable) {
        return;
    }
    apply_defaults_inner(cfg, presence);
}

fn apply_defaults_inner(cfg: &mut Config, presence: &Presence) {
    if presence.geodata_mode.is_none() {
        cfg.geodata_mode = true;
    }
    if presence.geo_auto_update.is_none() {
        cfg.geo_auto_update = true;
    }

    let target = if presence.proxy_groups.is_none() {
        let (groups, target) = build_groups(&cfg.proxies);
        cfg.proxy_groups = groups;
        target
    } else {
        pick_existing_target(cfg)
    };

    cfg.rules = build_rules(cfg.auto_routing, &target);

    let dns = presence.dns.as_ref();
    if dns.is_none_or(|d| d.enable.is_none()) {
        cfg.dns.enable = true;
    }
    if dns.is_none_or(|d| d.enhanced_mode.is_none()) {
        cfg.dns.enhanced_mode = "fake-ip".into();
    }
    if dns.is_none_or(|d| d.fake_ip_range.is_none()) {
        cfg.dns.fake_ip_range = "28.0.0.0/16".parse().unwrap();
    }
    if dns.is_none_or(|d| d.nameserver.is_none()) {
        cfg.dns.nameserver = default_dns_nameservers();
    }
    if dns.is_none_or(|d| d.default_nameserver.is_none()) {
        cfg.dns.default_nameserver = default_dns_nameservers();
    }
    if dns.is_none_or(|d| d.fake_ip_filter.is_none()) {
        cfg.dns.fake_ip_filter = default_fake_ip_filter();
    }
    if dns.is_none_or(|d| d.ipv6.is_none()) {
        cfg.dns.ipv6 = cfg.ipv6;
    }

    let sniffer = presence.sniffer.as_ref();
    if sniffer.is_none_or(|s| s.enable.is_none()) {
        cfg.sniffer.enable = true;
    }
    if sniffer.is_none_or(|s| s.sniff.is_none()) {
        cfg.sniffer.sniff = default_sniff_protocols();
    }

    let tun = presence.tun.as_ref();
    if tun.is_none_or(|t| t.auto_dns.is_none()) {
        cfg.tun.auto_dns = true;
    }
}

/// Returns auto-generated group names for a raw YAML mapping when `rules:` and
/// `proxy-groups:` are omitted, so custom rules can target `Proxy` / `Auto`.
pub fn auto_targets(map: &Mapping) -> Vec<String> {
    if map.contains_key(Value::from("rules")) || map.contains_key(Value::from("proxy-groups")) {
        return Vec::new();
    }
    let Some(proxies_val) = map.get(Value::from("proxies")) else {
        return Vec::new();
    };
    let Ok(proxies) = serde_yaml::from_value::<Vec<Proxy>>(proxies_val.clone()) else {
        return Vec::new();
    };
    if !proxies.iter().any(is_routable) {
        return Vec::new();
    }
    let (groups, _) = build_groups(&proxies);
    groups.into_iter().map(|g| g.name).collect()
}

/// Materializes auto-generated groups, rules, and baseline settings into `map`
/// before custom rules are prepended to `map["rules"]`, so adding a custom rule
/// never disables auto-routing or drops the `MATCH` rule.
pub fn materialize_for_custom_rules(map: &mut Mapping) -> Result<()> {
    if map.contains_key(Value::from("rules")) {
        return Ok(());
    }
    let Some(proxies_val) = map.get(Value::from("proxies")) else {
        return Ok(());
    };
    let Ok(proxies) = serde_yaml::from_value::<Vec<Proxy>>(proxies_val.clone()) else {
        return Ok(());
    };
    if !proxies.iter().any(is_routable) {
        return Ok(());
    }

    let mode = map
        .get(Value::from("auto-routing"))
        .and_then(|v| serde_yaml::from_value::<AutoRouting>(v.clone()).ok())
        .unwrap_or_default();

    let first_routable = || {
        proxies
            .iter()
            .find(|p| is_routable(p))
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "DIRECT".into())
    };
    let target = if !map.contains_key(Value::from("proxy-groups")) {
        let (groups, target) = build_groups(&proxies);
        map.insert(Value::from("proxy-groups"), serde_yaml::to_value(&groups)?);
        target
    } else if let Some(groups) = map
        .get(Value::from("proxy-groups"))
        .and_then(|v| serde_yaml::from_value::<Vec<Group>>(v.clone()).ok())
    {
        groups
            .iter()
            .find(|g| g.name == "Proxy")
            .or_else(|| groups.first())
            .map(|g| g.name.clone())
            .unwrap_or_else(first_routable)
    } else {
        first_routable()
    };

    if !map.contains_key(Value::from("geodata-mode")) {
        map.insert(Value::from("geodata-mode"), Value::from(true));
    }
    if !map.contains_key(Value::from("geo-auto-update")) {
        map.insert(Value::from("geo-auto-update"), Value::from(true));
    }

    let ipv6 = map
        .get(Value::from("ipv6"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    {
        let dns_map = ensure_submap(map, "dns");
        insert_if_missing(dns_map, "enable", Value::from(true));
        insert_if_missing(dns_map, "enhanced-mode", Value::from("fake-ip"));
        insert_if_missing(dns_map, "fake-ip-range", Value::from("28.0.0.0/16"));
        insert_if_missing(
            dns_map,
            "nameserver",
            serde_yaml::to_value(default_dns_nameservers())?,
        );
        insert_if_missing(
            dns_map,
            "default-nameserver",
            serde_yaml::to_value(default_dns_nameservers())?,
        );
        insert_if_missing(
            dns_map,
            "fake-ip-filter",
            serde_yaml::to_value(default_fake_ip_filter())?,
        );
        insert_if_missing(dns_map, "ipv6", Value::from(ipv6));
    }
    {
        let sniffer_map = ensure_submap(map, "sniffer");
        insert_if_missing(sniffer_map, "enable", Value::from(true));
        insert_if_missing(
            sniffer_map,
            "sniff",
            serde_yaml::to_value(default_sniff_protocols())?,
        );
    }
    {
        let tun_map = ensure_submap(map, "tun");
        insert_if_missing(tun_map, "auto-dns", Value::from(true));
    }

    map.insert(
        Value::from("rules"),
        serde_yaml::to_value(build_rules(mode, &target))?,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SINGLE_NODE: &str = "proxies:\n  - {name: Tokyo, type: vless, server: 1.2.3.4, port: 443, uuid: 11111111-1111-4111-8111-111111111111}\n";
    const TWO_NODES: &str = "proxies:\n  - {name: Tokyo, type: vless, server: 1.2.3.4, port: 443, uuid: 11111111-1111-4111-8111-111111111111}\n  - {name: SG, type: hysteria2, server: 5.6.7.8, port: 443, password: pass}\n";

    #[test]
    fn minimal_single_node_defaults_to_whitelist_auto_routing() {
        let cfg = Config::parse(SINGLE_NODE.as_bytes()).unwrap();
        assert_eq!(cfg.auto_routing, AutoRouting::Whitelist);
        assert!(cfg.geodata_mode);
        assert!(cfg.geo_auto_update);
        assert!(cfg.dns.enable);
        assert_eq!(cfg.dns.enhanced_mode, "fake-ip");
        assert_eq!(
            cfg.dns.fake_ip_range,
            "28.0.0.0/16".parse::<ipnet::Ipv4Net>().unwrap()
        );
        assert_eq!(cfg.dns.nameserver, ["223.5.5.5", "119.29.29.29"]);
        assert!(cfg.sniffer.enable);
        assert!(cfg.sniffer.sniff["TLS"].override_destination);
        assert_eq!(cfg.proxy_groups.len(), 1);
        assert_eq!(cfg.proxy_groups[0].name, "Proxy");
        assert_eq!(cfg.proxy_groups[0].kind, GroupKind::Select);
        assert_eq!(cfg.proxy_groups[0].proxies, ["Tokyo", "DIRECT"]);
        assert_eq!(cfg.rules.last().map(String::as_str), Some("MATCH,Proxy"));
        assert!(cfg.rules.iter().any(|r| r == "GEOSITE,cn,DIRECT"));
        assert!(cfg.rules.iter().any(|r| r == "GEOIP,cn,DIRECT"));
    }

    #[test]
    fn multi_node_generates_select_and_urltest_groups() {
        let cfg = Config::parse(TWO_NODES.as_bytes()).unwrap();
        assert_eq!(cfg.proxy_groups.len(), 2);
        assert_eq!(cfg.proxy_groups[0].name, "Proxy");
        assert_eq!(cfg.proxy_groups[0].kind, GroupKind::Select);
        assert_eq!(
            cfg.proxy_groups[0].proxies,
            ["Auto", "Tokyo", "SG", "DIRECT"]
        );
        assert_eq!(cfg.proxy_groups[1].name, "Auto");
        assert_eq!(cfg.proxy_groups[1].kind, GroupKind::UrlTest);
        assert_eq!(cfg.proxy_groups[1].proxies, ["Tokyo", "SG"]);
    }

    #[test]
    fn blacklist_mode_uses_geolocation_not_cn_and_match_direct() {
        let yaml = format!("auto-routing: blacklist\n{SINGLE_NODE}");
        let cfg = Config::parse(yaml.as_bytes()).unwrap();
        assert_eq!(cfg.auto_routing, AutoRouting::Blacklist);
        assert!(
            cfg.rules
                .iter()
                .any(|r| r == "GEOSITE,geolocation-!cn,Proxy")
        );
        assert_eq!(cfg.rules.last().map(String::as_str), Some("MATCH,DIRECT"));
    }

    #[test]
    fn proxy_named_proxy_or_auto_does_not_collide_with_generated_groups() {
        let yaml = "proxies:\n  - {name: Proxy, type: vless, server: 1.2.3.4, port: 443, uuid: 11111111-1111-4111-8111-111111111111}\n  - {name: Auto, type: hysteria2, server: 5.6.7.8, port: 443, password: pass}\n";
        let cfg = Config::parse(yaml.as_bytes()).unwrap();
        assert_eq!(cfg.proxy_groups[0].name, "AutoProxy");
        assert_eq!(cfg.proxy_groups[1].name, "AutoTest");
        assert_eq!(
            cfg.rules.last().map(String::as_str),
            Some("MATCH,AutoProxy")
        );
    }

    #[test]
    fn null_and_empty_sections_receive_auto_routing_defaults() {
        let presence =
            serde_yaml::from_slice::<Option<Presence>>(b"dns: null\nsniffer:\ntun: null\n")
                .unwrap()
                .unwrap_or_default();
        assert!(presence.dns.is_none());
        assert!(presence.sniffer.is_none());
        assert!(presence.tun.is_none());

        let yaml = format!("dns: {{}}\nsniffer: {{}}\ntun: {{}}\n{SINGLE_NODE}");
        let cfg = Config::parse(yaml.as_bytes()).unwrap();
        assert!(cfg.dns.enable);
        assert_eq!(cfg.dns.enhanced_mode, "fake-ip");
        assert!(cfg.sniffer.enable);
        assert_eq!(cfg.sniffer.sniff.len(), 2);
        assert!(cfg.tun.auto_dns);
    }

    #[test]
    fn explicit_rules_preserve_legacy_profile_behavior() {
        let yaml = format!("{SINGLE_NODE}rules:\n  - MATCH,Tokyo\n");
        let cfg = Config::parse(yaml.as_bytes()).unwrap();
        assert!(!cfg.geodata_mode);
        assert!(!cfg.dns.enable);
        assert!(cfg.proxy_groups.is_empty());
        assert_eq!(cfg.rules, ["MATCH,Tokyo"]);
    }

    #[test]
    fn tailscale_only_profile_does_not_trigger_auto_routing() {
        let yaml = "proxies:\n  - {name: ts, type: tailscale}\n";
        let cfg = Config::parse(yaml.as_bytes()).unwrap();
        assert!(cfg.proxy_groups.is_empty());
        assert_eq!(cfg.rules, ["MATCH,DIRECT"]);
    }

    #[test]
    fn overrides_do_not_suppress_auto_dns_defaults() {
        let overridden = crate::overrides::Overrides {
            ipv6: Some(false),
            ..Default::default()
        }
        .apply(SINGLE_NODE)
        .unwrap();
        let cfg = Config::parse(overridden.as_bytes()).unwrap();
        assert!(!cfg.ipv6);
        assert!(!cfg.dns.ipv6);
        assert!(cfg.dns.enable);
        assert_eq!(cfg.dns.enhanced_mode, "fake-ip");
        assert_eq!(cfg.dns.nameserver, ["223.5.5.5", "119.29.29.29"]);
    }
}
