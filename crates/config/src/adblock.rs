//! Ad blocking: lists of ad, tracking and analytics domains (and addresses)
//! that DNS refuses and connections reject, ahead of every rule. Apps that
//! skip the system resolver are pushed back to it: HTTPDNS and DNS-over-HTTPS
//! endpoints are refused, and QUIC to a bare address falls back to TCP,
//! where the name can be sniffed. The apps write the `adblock` section from
//! their settings (see `overrides`).
use crate::rule::DomainSetBuilder;
use anyhow::{Result, bail, ensure};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// The configuration section.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Adblock {
    pub enable: bool,
    pub lists: Vec<List>,
    /// Domains never blocked: a plain domain also covers its subdomains;
    /// `+.`, `.` and `*` patterns work as in rules.
    pub allow: Vec<String>,
    /// Seconds between list updates.
    pub interval: u64,
    /// Refuse the built-in HTTPDNS and encrypted-DNS endpoints, so apps fall
    /// back to the system resolver, which the lists filter.
    pub block_httpdns: bool,
    /// Reject QUIC (UDP 443) whose destination has no known name: the app
    /// retries over TCP, where TLS sniffing finds the name.
    pub quic_fallback: bool,
    /// How DNS refuses a blocked name: `nxdomain`, or `null` (0.0.0.0 / ::)
    /// for apps that retry on NXDOMAIN.
    pub dns_answer: String,
}
impl Default for Adblock {
    fn default() -> Self {
        Self {
            enable: false,
            lists: Vec::new(),
            allow: Vec::new(),
            interval: 86_400,
            block_httpdns: true,
            quic_fallback: true,
            dns_answer: "nxdomain".into(),
        }
    }
}

pub const DNS_ANSWERS: [&str; 2] = ["nxdomain", "null"];

/// Ports on which the HTTPDNS addresses below serve lookups: HTTP, HTTPS and
/// DNS over TLS / QUIC. Port 53 stays open: plain DNS reaches the core anyway.
pub const HTTPDNS_PORTS: [u16; 6] = [80, 443, 853, 4433, 8080, 8443];
/// Addresses that answer lookups over HTTP(S) or TLS for apps that bypass the
/// system resolver: Chinese HTTPDNS services and public DoH/DoT resolvers.
pub const HTTPDNS_ADDRESSES: [&str; 28] = [
    // Alibaba Cloud HTTPDNS.
    "203.107.1.0/24",
    // Tencent Cloud HTTPDNS and DNSPod (HTTP `/d`, DoH, DoT): Xiaohongshu
    // asks 119.29.29.88 and .90 over HTTP; Enterprise Edition uses 43.132.x.
    "119.29.29.0/24",
    "119.28.28.28/32",
    "43.132.43.43/32",
    "43.132.55.55/32",
    "1.12.12.12/32",
    "120.53.53.53/32",
    // Baidu HTTPDNS.
    "180.76.76.112/32",
    // AliDNS DoH / DoT.
    "223.5.5.5/32",
    "223.6.6.6/32",
    // 360 DoH.
    "101.198.198.198/32",
    // Public resolvers' DoH / DoT.
    "1.1.1.1/32",
    "1.0.0.1/32",
    "8.8.8.8/32",
    "8.8.4.4/32",
    "9.9.9.9/32",
    "149.112.112.112/32",
    // IPv6 DoH / DoT / HTTPDNS endpoints.
    "2400:3200::1/128",
    "2400:3200:baba::1/128",
    "2402:4e00::/128",
    "2402:4e00:1::/128",
    "2400:da00::6666/128",
    "2606:4700:4700::1111/128",
    "2606:4700:4700::1001/128",
    "2001:4860:4860::8888/128",
    "2001:4860:4860::8844/128",
    "2620:fe::fe/128",
    "2620:fe::9/128",
];
/// Names of the same kind of endpoints, refused at DNS and on connection.
/// Each covers its subdomains.
pub const HTTPDNS_DOMAINS: [&str; 28] = [
    "httpdns.aliyuncs.com",
    "httpdns-api.aliyuncs.com",
    "httpdns.alicdn.com",
    "dns.alidns.com",
    "doh.pub",
    "dot.pub",
    "doh.360.cn",
    "httpdns.n.netease.com",
    "hdns.ksyun.com",
    "dig.bdurl.net",
    "dns.jd.com",
    "httpdns.bilivideo.com",
    "httpdns.baidubce.com",
    "httpsdns.baidu.com",
    "httpdns.push.heytapmobi.com",
    "dns.weixin.qq.com",
    "dns.weixin.qq.com.cn",
    "dns.google",
    "dns.google.com",
    "cloudflare-dns.com",
    "one.one.one.one",
    "dns.quad9.net",
    "dns.adguard-dns.com",
    "doh.opendns.com",
    "dns.nextdns.io",
    // Firefox turns its own DoH off when this name does not resolve.
    "use-application-dns.net",
    // iCloud Private Relay, which Apple disables on NXDOMAIN for these.
    "mask.icloud.com",
    "mask-h2.icloud.com",
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct List {
    pub name: String,
    pub url: String,
    /// `clash` (rule-provider yaml or text, domain behavior), `hosts` or
    /// `adguard` (`||domain^` rules; `@@` exceptions allow).
    #[serde(default = "clash")]
    pub format: String,
}
fn clash() -> String {
    "clash".into()
}

pub const FORMATS: [&str; 3] = ["clash", "hosts", "adguard"];

/// Lists the apps offer by default.
pub struct Preset {
    pub id: &'static str,
    pub name: &'static str,
    pub url: &'static str,
    pub format: &'static str,
    pub description: &'static str,
}
pub const PRESETS: [Preset; 3] = [
    Preset {
        id: "awavenue",
        name: "AWAvenue-Ads",
        url: "https://cdn.jsdelivr.net/gh/TG-Twilight/AWAvenue-Ads-Rule@main/Filters/AWAvenue-Ads-Rule-Clash.yaml",
        format: "clash",
        description: "Ad endpoints of Chinese apps, about 1,000 entries, few false positives",
    },
    Preset {
        id: "anti-ad",
        name: "anti-AD",
        url: "https://anti-ad.net/clash.yaml",
        format: "clash",
        description: "Broad, mostly Chinese, about 100,000 entries",
    },
    Preset {
        id: "adguard-dns",
        name: "AdGuard DNS filter",
        url: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        format: "adguard",
        description: "Mostly international ads and tracking, about 180,000 entries; uses more memory",
    },
];

impl Adblock {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.interval >= 3600,
            "adblock.interval must be at least 3600 seconds"
        );
        let mut names = std::collections::HashSet::new();
        for list in &self.lists {
            ensure!(
                !list.name.trim().is_empty()
                    && list.name.len() <= 64
                    && names.insert(list.file_name()),
                "adblock list names must be non-empty, unique and at most 64 bytes"
            );
            ensure!(
                list.url.starts_with("https://") || list.url.starts_with("http://"),
                "adblock list {}: url must be http(s)",
                list.name
            );
            ensure!(
                FORMATS.contains(&list.format.as_str()),
                "adblock list {}: format must be clash, hosts or adguard",
                list.name
            );
        }
        ensure!(
            DNS_ANSWERS.contains(&self.dns_answer.as_str()),
            "adblock.dns-answer must be nxdomain or null"
        );
        ensure!(
            self.allow.len() <= 10_000,
            "adblock.allow has too many entries"
        );
        let mut builder = DomainSetBuilder::default();
        for pattern in &self.allow {
            allow_pattern(&mut builder, pattern)?;
        }
        Ok(())
    }
}
impl List {
    /// The cache file, inside the configuration directory: never a path from
    /// the configuration.
    pub fn file_name(&self) -> String {
        let name: String = self
            .name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect();
        format!("adblock/{name}.list")
    }
}

/// An allowlist entry: plain domains cover their subdomains.
pub fn allow_pattern(builder: &mut DomainSetBuilder, pattern: &str) -> Result<()> {
    let pattern = pattern.trim().trim_end_matches('.');
    ensure!(!pattern.is_empty(), "empty adblock allow entry");
    if pattern.starts_with("+.") || pattern.starts_with('.') || pattern.contains('*') {
        builder.pattern(pattern)
    } else {
        builder.suffix(pattern);
        Ok(())
    }
}

/// Destination for parsed domain rules; implemented by [`DomainSetBuilder`]
/// and by streaming cache writers.
pub trait DomainTarget {
    fn exact(&mut self, domain: &str);
    fn suffix(&mut self, domain: &str);
    fn subdomain(&mut self, domain: &str);
    fn keyword(&mut self, keyword: &str);
    fn pattern(&mut self, pattern: &str) -> Result<()>;
}

impl DomainTarget for DomainSetBuilder {
    fn exact(&mut self, domain: &str) {
        DomainSetBuilder::exact(self, domain);
    }
    fn suffix(&mut self, domain: &str) {
        DomainSetBuilder::suffix(self, domain);
    }
    fn subdomain(&mut self, domain: &str) {
        DomainSetBuilder::subdomain(self, domain);
    }
    fn keyword(&mut self, keyword: &str) {
        DomainSetBuilder::keyword(self, keyword);
    }
    fn pattern(&mut self, pattern: &str) -> Result<()> {
        DomainSetBuilder::pattern(self, pattern)
    }
}

/// Feeds one downloaded list into the block and allow sets and the blocked
/// addresses; returns the number of entries taken. Lines that need the
/// request itself (cosmetic, URL-path, regex or modifier rules) are skipped.
pub fn parse_list(
    data: &[u8],
    format: &str,
    block: &mut DomainSetBuilder,
    allow: &mut DomainSetBuilder,
    addresses: &mut Vec<IpNet>,
) -> Result<usize> {
    parse_list_into(data, format, block, allow, addresses)
}

/// Generic variant of [`parse_list`] writing into any [`DomainTarget`].
pub fn parse_list_into(
    data: &[u8],
    format: &str,
    block: &mut impl DomainTarget,
    allow: &mut impl DomainTarget,
    addresses: &mut Vec<IpNet>,
) -> Result<usize> {
    ensure!(
        FORMATS.contains(&format),
        "unsupported adblock list format {format}"
    );
    if format == "adguard" {
        let mut meta = AdguardMeta::default();
        for raw_line in data.split(|&b| b == b'\n') {
            let line = String::from_utf8_lossy(raw_line);
            if let Some(entry) = parse_adguard_line(&line) {
                meta.record(&entry);
            }
        }
        let mut taken = 0;
        for raw_line in data.split(|&b| b == b'\n') {
            let line = String::from_utf8_lossy(raw_line);
            if let Some(entry) = parse_adguard_line(&line) {
                taken += apply_adguard_entry(&entry, &meta, block, allow);
            }
        }
        return Ok(taken);
    }
    let mut taken = 0;
    for raw_line in data.split(|&b| b == b'\n') {
        let line = String::from_utf8_lossy(raw_line);
        taken += parse_list_line(&line, format, block, addresses);
    }
    Ok(taken)
}

/// Streaming variant of [`parse_list`] that reads line-by-line from `reader`
/// into a single reusable line buffer without buffering the full file.
pub fn parse_list_reader(
    reader: impl std::io::BufRead,
    format: &str,
    block: &mut DomainSetBuilder,
    allow: &mut DomainSetBuilder,
    addresses: &mut Vec<IpNet>,
    limit: usize,
) -> Result<usize> {
    parse_list_reader_into(reader, format, block, allow, addresses, limit)
}

/// Generic variant of [`parse_list_reader`] writing into any [`DomainTarget`].
pub fn parse_list_reader_into(
    mut reader: impl std::io::BufRead,
    format: &str,
    block: &mut impl DomainTarget,
    allow: &mut impl DomainTarget,
    addresses: &mut Vec<IpNet>,
    limit: usize,
) -> Result<usize> {
    ensure!(
        FORMATS.contains(&format),
        "unsupported adblock list format {format}"
    );
    let mut buf = Vec::with_capacity(256);
    let mut read_bytes = 0usize;
    let mut taken = 0usize;
    if format == "adguard" {
        let mut meta = AdguardMeta::default();
        let mut pending_allows: Vec<(String, bool, bool)> = Vec::new();
        loop {
            buf.clear();
            let n = reader.read_until(b'\n', &mut buf)?;
            if n == 0 {
                break;
            }
            read_bytes = read_bytes.saturating_add(n);
            ensure!(read_bytes <= limit, "resource exceeds size limit");
            let line = String::from_utf8_lossy(&buf);
            let Some(entry) = parse_adguard_line(&line) else {
                continue;
            };
            if entry.badfilter || entry.important {
                meta.record(&entry);
            }
            if entry.badfilter {
                continue;
            }
            if entry.exception {
                if !meta.is_badfiltered(true, entry.domain) {
                    pending_allows.push((
                        entry.domain.to_ascii_lowercase(),
                        entry.is_pattern,
                        entry.important,
                    ));
                }
            } else if !meta.is_badfiltered(false, entry.domain) {
                taken += push_adguard_rule(block, entry.domain, entry.is_pattern);
            }
        }
        for (domain, is_pattern, important) in pending_allows {
            if meta.is_badfiltered(true, &domain) {
                continue;
            }
            if !important && meta.is_important_block(&domain) && !meta.is_important_allow(&domain) {
                continue;
            }
            taken += push_adguard_rule(allow, &domain, is_pattern);
        }
        return Ok(taken);
    }
    loop {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        read_bytes = read_bytes.saturating_add(n);
        ensure!(read_bytes <= limit, "resource exceeds size limit");
        let line = String::from_utf8_lossy(&buf);
        taken += parse_list_line(&line, format, block, addresses);
    }
    Ok(taken)
}

/// Two-pass streaming parser for a file on disk: for `adguard` lists, pass 1
/// collects only `$badfilter`/`$important` metadata and pass 2 streams rules
/// directly into `block` and `allow` with zero `AdguardEntry` buffering.
pub fn parse_list_file_into(
    path: &std::path::Path,
    format: &str,
    block: &mut impl DomainTarget,
    allow: &mut impl DomainTarget,
    addresses: &mut Vec<IpNet>,
    limit: usize,
) -> Result<usize> {
    ensure!(
        FORMATS.contains(&format),
        "unsupported adblock list format {format}"
    );
    if format != "adguard" {
        let reader = std::io::BufReader::with_capacity(64 * 1024, std::fs::File::open(path)?);
        return parse_list_reader_into(reader, format, block, allow, addresses, limit);
    }
    use std::io::BufRead;
    let mut buf = Vec::with_capacity(256);
    let mut meta = AdguardMeta::default();
    let mut read_bytes = 0usize;
    let mut reader = std::io::BufReader::with_capacity(64 * 1024, std::fs::File::open(path)?);
    loop {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        read_bytes = read_bytes.saturating_add(n);
        ensure!(read_bytes <= limit, "resource exceeds size limit");
        let line = String::from_utf8_lossy(&buf);
        if let Some(entry) = parse_adguard_line(&line) {
            meta.record(&entry);
        }
    }
    let mut taken = 0usize;
    let mut reader = std::io::BufReader::with_capacity(64 * 1024, std::fs::File::open(path)?);
    loop {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        let line = String::from_utf8_lossy(&buf);
        if let Some(entry) = parse_adguard_line(&line) {
            taken += apply_adguard_entry(&entry, &meta, block, allow);
        }
    }
    Ok(taken)
}

struct AdguardParsed<'a> {
    domain: &'a str,
    is_pattern: bool,
    exception: bool,
    important: bool,
    badfilter: bool,
}

#[derive(Default)]
struct AdguardMeta {
    badfilters: std::collections::HashSet<(bool, String)>,
    important_blocks: std::collections::HashSet<String>,
    important_allows: std::collections::HashSet<String>,
}

impl AdguardMeta {
    fn record(&mut self, entry: &AdguardParsed<'_>) {
        if entry.badfilter {
            self.badfilters
                .insert((entry.exception, entry.domain.to_ascii_lowercase()));
        } else if entry.important {
            let lower = entry.domain.to_ascii_lowercase();
            if entry.exception {
                self.important_allows.insert(lower);
            } else {
                self.important_blocks.insert(lower);
            }
        }
    }

    fn with_lower<R>(domain: &str, f: impl FnOnce(&str) -> R) -> R {
        if !domain.bytes().any(|b| b.is_ascii_uppercase()) {
            return f(domain);
        }
        if domain.len() <= 256 && domain.is_ascii() {
            let mut buf = [0u8; 256];
            let len = domain.len();
            buf[..len].copy_from_slice(domain.as_bytes());
            buf[..len].make_ascii_lowercase();
            if let Ok(s) = std::str::from_utf8(&buf[..len]) {
                return f(s);
            }
        }
        f(&domain.to_ascii_lowercase())
    }

    fn is_badfiltered(&self, exception: bool, domain: &str) -> bool {
        if self.badfilters.is_empty() {
            return false;
        }
        Self::with_lower(domain, |lower| {
            self.badfilters
                .iter()
                .any(|(ex, d)| *ex == exception && d == lower)
        })
    }

    fn is_important_block(&self, domain: &str) -> bool {
        if self.important_blocks.is_empty() {
            return false;
        }
        Self::with_lower(domain, |lower| {
            self.important_blocks.contains(lower) && !self.is_badfiltered(false, lower)
        })
    }

    fn is_important_allow(&self, domain: &str) -> bool {
        if self.important_allows.is_empty() {
            return false;
        }
        Self::with_lower(domain, |lower| {
            self.important_allows.contains(lower) && !self.is_badfiltered(true, lower)
        })
    }
}

fn parse_adguard_line(line: &str) -> Option<AdguardParsed<'_>> {
    let line = line.trim();
    let (exception, rule) = match line.strip_prefix("@@") {
        Some(rest) => (true, rest),
        None => (false, line),
    };
    let rule = rule.strip_prefix("||")?;
    let (domain, modifiers) = rule.split_once('$').unwrap_or((rule, ""));
    let mut important = false;
    let mut badfilter = false;
    if !modifiers.is_empty() {
        for modifier in modifiers.split(',') {
            match modifier.trim() {
                "important" => important = true,
                "badfilter" => badfilter = true,
                _ => return None,
            }
        }
    }
    let domain = domain.strip_suffix('^')?;
    if domain.is_empty()
        || domain.ends_with('.')
        || !domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'*')
    {
        return None;
    }
    Some(AdguardParsed {
        domain,
        is_pattern: domain.contains('*'),
        exception,
        important,
        badfilter,
    })
}

fn push_adguard_rule(target: &mut impl DomainTarget, domain: &str, is_pattern: bool) -> usize {
    if is_pattern {
        if target.pattern(domain).is_err() {
            return 0;
        }
    } else {
        target.suffix(domain);
    }
    1
}

fn apply_adguard_entry(
    entry: &AdguardParsed<'_>,
    meta: &AdguardMeta,
    block: &mut impl DomainTarget,
    allow: &mut impl DomainTarget,
) -> usize {
    if entry.badfilter || meta.is_badfiltered(entry.exception, entry.domain) {
        return 0;
    }
    if entry.exception
        && !entry.important
        && meta.is_important_block(entry.domain)
        && !meta.is_important_allow(entry.domain)
    {
        return 0;
    }
    if entry.exception {
        push_adguard_rule(allow, entry.domain, entry.is_pattern)
    } else {
        push_adguard_rule(block, entry.domain, entry.is_pattern)
    }
}

fn parse_list_line(
    line: &str,
    format: &str,
    block: &mut impl DomainTarget,
    addresses: &mut Vec<IpNet>,
) -> usize {
    match format {
        "clash" => {
            let line = line.trim();
            // yaml `payload:` items and plain text lines alike.
            let entry = line
                .strip_prefix("- ")
                .unwrap_or(line)
                .trim()
                .trim_matches(|c| c == '\'' || c == '"');
            if entry.is_empty() || entry.starts_with('#') || entry == "payload:" {
                return 0;
            }
            if let Some(rule) = entry.split_once(',') {
                // A classical line: DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD.
                let value = rule.1.split(',').next().unwrap_or("").trim();
                match rule.0.trim() {
                    "DOMAIN" => block.exact(value),
                    "DOMAIN-SUFFIX" => block.suffix(value),
                    "DOMAIN-KEYWORD" => block.keyword(value),
                    "IP-CIDR" | "IP-CIDR6" => match value.parse() {
                        Ok(net) => addresses.push(net),
                        Err(_) => return 0,
                    },
                    _ => return 0,
                }
            } else if let Ok(net) = entry.parse::<IpNet>() {
                // An `ipcidr` rule provider: bare networks.
                addresses.push(net);
            } else if block.pattern(entry).is_err() {
                return 0;
            }
            1
        }
        "hosts" => {
            let line = line.split('#').next().unwrap_or("").trim();
            let mut fields = line.split_whitespace();
            let (Some(address), Some(_)) = (fields.next(), fields.clone().next()) else {
                return 0;
            };
            if !matches!(address, "0.0.0.0" | "127.0.0.1" | "::" | "::1") {
                return 0;
            }
            let mut taken = 0;
            for domain in fields {
                if !matches!(
                    domain,
                    "localhost" | "localhost.localdomain" | "local" | "broadcasthost" | "0.0.0.0"
                ) && domain.contains('.')
                {
                    block.exact(domain);
                    taken += 1;
                }
            }
            taken
        }
        _ => 0,
    }
}

/// What the apps store: which presets are on, extra lists and the allowlist.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    /// Preset ids (see [`PRESETS`]).
    pub presets: Vec<String>,
    pub custom: Vec<List>,
    pub allow: Vec<String>,
    pub block_httpdns: bool,
    pub quic_fallback: bool,
    pub dns_answer: String,
}
impl Default for Settings {
    /// Settings saved before an option existed take the option's default.
    fn default() -> Self {
        let config = Adblock::default();
        Self {
            enabled: false,
            presets: Vec::new(),
            custom: Vec::new(),
            allow: Vec::new(),
            block_httpdns: config.block_httpdns,
            quic_fallback: config.quic_fallback,
            dns_answer: config.dns_answer,
        }
    }
}
impl Settings {
    pub fn to_config(&self) -> Result<Adblock> {
        let mut lists = Vec::new();
        for id in &self.presets {
            let Some(preset) = PRESETS.iter().find(|p| p.id == id) else {
                bail!("unknown adblock list {id}");
            };
            lists.push(List {
                name: preset.name.into(),
                url: preset.url.into(),
                format: preset.format.into(),
            });
        }
        lists.extend(self.custom.iter().cloned());
        let adblock = Adblock {
            enable: self.enabled,
            lists,
            allow: self.allow.clone(),
            block_httpdns: self.block_httpdns,
            quic_fallback: self.quic_fallback,
            dns_answer: self.dns_answer.clone(),
            ..Adblock::default()
        };
        adblock.validate()?;
        Ok(adblock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(data: &str, format: &str) -> (crate::rule::DomainSet, crate::rule::DomainSet, usize) {
        let (mut block, mut allow) = (DomainSetBuilder::default(), DomainSetBuilder::default());
        let taken = parse_list(
            data.as_bytes(),
            format,
            &mut block,
            &mut allow,
            &mut Vec::new(),
        )
        .unwrap();
        (block.build(), allow.build(), taken)
    }

    #[test]
    fn parses_clash_yaml_text_and_classical_lists() {
        let (block, _, taken) = parse(
            "#Title: x\npayload:\n  - 'ad.example.com'\n  - '+.tracker.test'\n  - \"*.wild.test\"\n",
            "clash",
        );
        assert_eq!(taken, 3);
        assert!(block.matches("ad.example.com") && !block.matches("x.ad.example.com"));
        assert!(block.matches("tracker.test") && block.matches("a.tracker.test"));
        assert!(block.matches("x.wild.test"));
        let (block, _, taken) = parse(
            "DOMAIN-SUFFIX,ads.test\nDOMAIN,one.test\nIP-CIDR,1.2.3.0/24,no-resolve\nIP-CIDR6,2001:db8::/32\nIP-CIDR,bad\nPROCESS-NAME,x\n",
            "clash",
        );
        assert_eq!(taken, 4);
        assert!(block.matches("x.ads.test") && block.matches("one.test"));
    }

    #[test]
    fn takes_addresses_from_classical_and_ipcidr_lists() {
        let (mut block, mut allow, mut addresses) = (
            DomainSetBuilder::default(),
            DomainSetBuilder::default(),
            Vec::new(),
        );
        let data =
            "payload:\n  - IP-CIDR,1.2.3.0/24,no-resolve\n  - '10.0.0.0/8'\n  - '2001:db8::/32'\n";
        let taken = parse_list(
            data.as_bytes(),
            "clash",
            &mut block,
            &mut allow,
            &mut addresses,
        )
        .unwrap();
        assert_eq!(taken, 3);
        let nets: Vec<String> = addresses.iter().map(ToString::to_string).collect();
        assert_eq!(nets, ["1.2.3.0/24", "10.0.0.0/8", "2001:db8::/32"]);
        assert_eq!(block.build().len(), 0);
    }

    #[test]
    fn built_in_endpoints_parse_and_settings_default_on() {
        for net in HTTPDNS_ADDRESSES {
            net.parse::<IpNet>().unwrap();
        }
        let mut builder = DomainSetBuilder::default();
        for domain in HTTPDNS_DOMAINS {
            allow_pattern(&mut builder, domain).unwrap();
        }
        // Stored settings from before these options keep them on.
        let old: Settings =
            serde_json::from_str(r#"{"enabled":true,"presets":[],"custom":[],"allow":[]}"#)
                .unwrap();
        let config = old.to_config().unwrap();
        assert!(config.block_httpdns && config.quic_fallback && config.dns_answer == "nxdomain");
        assert!(
            Adblock {
                dns_answer: "zero".into(),
                ..Adblock::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn parses_hosts_and_adguard_with_exceptions() {
        let (block, _, taken) = parse(
            "# c\n0.0.0.0 ad.test b.test\n127.0.0.1 localhost\n10.0.0.1 lan.test\n",
            "hosts",
        );
        assert_eq!(taken, 2);
        assert!(block.matches("ad.test") && block.matches("b.test") && !block.matches("lan.test"));
        let rules = "! comment\n||ads.test^\n||imp.test^$important\n||bad.test^$badfilter\n@@||ok.ads.test^\n/^1\\.2/\n||partial.\n.cosmetic.test^\n";
        let (block, allow, taken) = parse(rules, "adguard");
        assert_eq!(taken, 3);
        assert!(
            block.matches("x.ads.test") && block.matches("imp.test") && !block.matches("bad.test")
        );
        assert!(allow.matches("ok.ads.test"));

        // `$badfilter` disables matching rules and `$important` overrides non-important `@@`.
        let (block2, allow2, taken2) = parse(
            "||cancelled.test^\n||cancelled.test^$badfilter\n||forced.test^$important\n@@||forced.test^\n||overridden.test^$important\n@@||overridden.test^$important\n",
            "adguard",
        );
        assert_eq!(taken2, 3);
        assert!(!block2.matches("cancelled.test"));
        assert!(block2.matches("forced.test") && !allow2.matches("forced.test"));
        assert!(block2.matches("overridden.test") && allow2.matches("overridden.test"));
    }

    #[test]
    fn settings_expand_presets_and_validate() {
        let settings = Settings {
            enabled: true,
            presets: vec!["awavenue".into()],
            custom: vec![List {
                name: "Mine".into(),
                url: "https://example.com/l.txt".into(),
                format: "hosts".into(),
            }],
            allow: vec!["wechat.com".into()],
            dns_answer: "null".into(),
            ..Settings::default()
        };
        let config = settings.to_config().unwrap();
        assert_eq!(config.dns_answer, "null");
        assert_eq!(config.lists.len(), 2);
        assert_eq!(config.lists[1].file_name(), "adblock/mine.list");
        let unknown = Settings {
            presets: vec!["nope".into()],
            ..Settings::default()
        };
        assert!(unknown.to_config().is_err());
        let bad = Settings {
            custom: vec![List {
                name: "x".into(),
                url: "ftp://x".into(),
                format: "clash".into(),
            }],
            ..Settings::default()
        };
        assert!(bad.to_config().is_err());
    }

    #[test]
    fn streams_adguard_reader_and_file_without_buffering() {
        let rules = concat!(
            "! comment\n",
            "||ads.test^\n",
            "||wild.*.test^\n",
            "||bad.test^$badfilter\n",
            "||bad.test^\n",
            "@@||ok.ads.test^\n",
            "@@||forced.test^\n",
            "||forced.test^$important\n",
            "||overridden.test^$important\n",
            "@@||overridden.test^$important\n",
        );
        let mut block = DomainSetBuilder::default();
        let mut allow = DomainSetBuilder::default();
        let mut addrs = Vec::new();
        let taken = parse_list_reader(
            std::io::Cursor::new(rules.as_bytes()),
            "adguard",
            &mut block,
            &mut allow,
            &mut addrs,
            1024 * 1024,
        )
        .unwrap();
        let (block, allow) = (block.build(), allow.build());
        assert_eq!(taken, 6);
        assert!(block.matches("sub.ads.test"));
        assert!(block.matches("wild.foo.test"));
        assert!(!block.matches("bad.test"));
        assert!(allow.matches("ok.ads.test"));
        assert!(block.matches("forced.test") && !allow.matches("forced.test"));
        assert!(block.matches("overridden.test") && allow.matches("overridden.test"));

        // Two-pass file streaming also cancels rules whose `$badfilter` appears later.
        let dir = std::env::temp_dir().join(format!("adguard-stream-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("list.txt");
        let out_of_order =
            format!("||cancelled-late.test^\n{rules}||cancelled-late.test^$badfilter\n");
        std::fs::write(&file_path, out_of_order).unwrap();
        let mut f_block = DomainSetBuilder::default();
        let mut f_allow = DomainSetBuilder::default();
        let mut f_addrs = Vec::new();
        let f_taken = parse_list_file_into(
            &file_path,
            "adguard",
            &mut f_block,
            &mut f_allow,
            &mut f_addrs,
            1024 * 1024,
        )
        .unwrap();
        let (f_block, f_allow) = (f_block.build(), f_allow.build());
        assert_eq!(f_taken, 6);
        assert!(!f_block.matches("cancelled-late.test"));
        assert!(f_allow.matches("ok.ads.test"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
