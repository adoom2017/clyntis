use anyhow::{Result, bail, ensure};
use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Clone, Debug)]
pub enum Matcher {
    Domain(String),
    /// The domain and all of its subdomains (`+.example.com`, DOMAIN-SUFFIX).
    Suffix(String),
    /// Subdomains only, not the domain itself (`.example.com`).
    Subdomain(String),
    Keyword(String),
    Regex(regex::Regex),
    Net(ipnet::IpNet),
    Port(u16),
    Ports(Vec<(u16, u16)>),
    Network(String),
    /// `NETWORK-NAME,home`: the device is on that `networks` entry.
    OnNetwork(Arc<OnNetwork>),
    GeoIp(String),
    GeoSite(String),
    RuleSet(String),
    And(Arc<[Matcher]>),
    Or(Arc<[Matcher]>),
    Not(Arc<Matcher>),
    NoResolve(Arc<Matcher>),
    Domains(Arc<DomainSet>),
    Nets(Arc<IpSet>),
    ExternalIp(Arc<dyn IpMatcher>),
    All,
}
/// A named network's state, set by the core as the device network changes
/// (see [`Matcher::networks`]); off until then.
#[derive(Debug)]
pub struct OnNetwork {
    pub name: String,
    on: AtomicBool,
}
impl OnNetwork {
    pub fn set(&self, on: bool) {
        self.on.store(on, Ordering::Relaxed);
    }
    pub fn get(&self) -> bool {
        self.on.load(Ordering::Relaxed)
    }
}
pub trait IpMatcher: std::fmt::Debug + Send + Sync {
    fn matches(&self, ip: IpAddr) -> bool;
}
pub fn compile_regex(pattern: &str) -> Result<regex::Regex> {
    Ok(regex::RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(2 * 1024 * 1024)
        .build()?)
}
/// Keyed 64-bit hash of a domain. One random key per process: sets are built
/// and searched in the same process, a hash is computed once per label for all
/// lists, and nobody can craft a name that collides with a listed one.
fn domain_hash(domain: &str) -> u64 {
    use std::{hash::BuildHasher, sync::OnceLock};
    static KEY: OnceLock<std::collections::hash_map::RandomState> = OnceLock::new();
    KEY.get_or_init(Default::default)
        .hash_one(domain.as_bytes())
}

/// Sorted, deduplicated domain hashes, looked up by binary search: 8 bytes per
/// entry whatever the domain's length, against ~24 for the packed strings this
/// replaces. Large geosite, rule-provider and ad-blocking sets dominate memory
/// inside the iOS tunnel extension. With a 64-bit keyed hash a lookup of a few
/// labels against a million entries wrongly matches about once in 10^12.
#[derive(Clone, Default)]
struct DomainList {
    hashes: Box<[u64]>,
}
impl DomainList {
    fn contains(&self, hash: u64) -> bool {
        self.hashes.binary_search(&hash).is_ok()
    }
    fn len(&self) -> usize {
        self.hashes.len()
    }
    fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }
}
#[derive(Default)]
struct ListBuilder {
    hashes: Vec<u64>,
}
impl ListBuilder {
    fn push(&mut self, domain: &str) {
        self.hashes.push(domain_hash(domain));
    }
    fn build(mut self) -> DomainList {
        self.hashes.sort_unstable();
        self.hashes.dedup();
        DomainList {
            hashes: self.hashes.into_boxed_slice(),
        }
    }
}

/// Domain patterns with `*` (one label, or part of one: `*` never spans a
/// dot), indexed by the hash of the labels after the last `*`, so a lookup
/// only tries the patterns that end like the host. The index narrows
/// candidates; every candidate is still matched in full, so a hash collision
/// costs one extra comparison, never a wrong match.
#[derive(Clone, Default)]
struct Globs {
    /// (suffix hash, label count, pattern), sorted. A pattern only matches a
    /// host with as many labels: a cheap check before the glob.
    anchored: Box<[(u64, usize, Box<str>)]>,
    /// Patterns whose last label has a `*`: tried for every host.
    loose: Box<[Box<str>]>,
}
impl Globs {
    fn new(patterns: Vec<Box<str>>) -> Self {
        let mut anchored = Vec::new();
        let mut loose = Vec::new();
        for pattern in patterns {
            match fixed_suffix(&pattern) {
                Some(suffix) => {
                    let labels = pattern.split('.').count();
                    anchored.push((domain_hash(suffix), labels, pattern));
                }
                None => loose.push(pattern),
            }
        }
        anchored.sort_unstable();
        anchored.dedup();
        loose.sort_unstable();
        loose.dedup();
        Self {
            anchored: anchored.into_boxed_slice(),
            loose: loose.into_boxed_slice(),
        }
    }
    /// Patterns whose fixed suffix hashes to `suffix`, against `host` of `labels` labels.
    fn anchored_at(&self, suffix: u64, labels: usize, host: &str) -> bool {
        let start = self.anchored.partition_point(|(hash, ..)| *hash < suffix);
        self.anchored[start..]
            .iter()
            .take_while(|(hash, ..)| *hash == suffix)
            .any(|(_, count, pattern)| *count == labels && glob_matches(pattern, host))
    }
    fn loose_matches(&self, host: &str) -> bool {
        self.loose.iter().any(|pattern| glob_matches(pattern, host))
    }
    fn len(&self) -> usize {
        self.anchored.len() + self.loose.len()
    }
}
/// The labels after the last one that holds a `*`, if any.
fn fixed_suffix(pattern: &str) -> Option<&str> {
    let star = pattern.rfind('*')?;
    let dot = star + pattern[star..].find('.')?;
    Some(&pattern[dot + 1..])
}
/// `pattern` against the whole host, label by label; `*` matches any run of
/// characters within a label (the `[^.]*` of [`domain_pattern`]).
fn glob_matches(pattern: &str, host: &str) -> bool {
    let mut labels = host.split('.');
    for part in pattern.split('.') {
        match labels.next() {
            Some(label) if label_matches(part.as_bytes(), label.as_bytes()) => {}
            _ => return false,
        }
    }
    labels.next().is_none()
}
fn label_matches(pattern: &[u8], label: &[u8]) -> bool {
    // Greedy match with backtracking to the last `*`: linear for one `*`,
    // O(n·m) at worst, on labels of at most 63 bytes.
    let (mut p, mut l) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while l < label.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p, l));
            p += 1;
        } else if p < pattern.len() && pattern[p].eq_ignore_ascii_case(&label[l]) {
            p += 1;
            l += 1;
        } else if let Some((sp, sl)) = star {
            p = sp + 1;
            l = sl + 1;
            star = Some((sp, sl + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

/// Immutable set of domain conditions, built with [`DomainSetBuilder`].
#[derive(Clone, Default)]
pub struct DomainSet {
    exact: DomainList,
    suffix: DomainList,
    subdomain: DomainList,
    globs: Globs,
    keywords: Box<[Box<str>]>,
    regex: Box<[regex::Regex]>,
}
impl DomainSet {
    pub fn matches(&self, host: &str) -> bool {
        let lists = !(self.exact.is_empty() && self.suffix.is_empty() && self.subdomain.is_empty());
        let globs = !self.globs.anchored.is_empty();
        if lists || globs {
            // One hash per label serves every list and the glob index.
            let labels = if globs { host.split('.').count() } else { 0 };
            let mut label = host;
            let mut first = true;
            loop {
                let hash = domain_hash(label);
                if lists
                    && ((first && self.exact.contains(hash))
                        || self.suffix.contains(hash)
                        || (!first && self.subdomain.contains(hash)))
                {
                    return true;
                }
                // A glob has a `*` label before its suffix: never the whole host.
                if globs && !first && self.globs.anchored_at(hash, labels, host) {
                    return true;
                }
                match label.split_once('.') {
                    Some((_, rest)) => label = rest,
                    None => break,
                }
                first = false;
            }
        }
        self.globs.loose_matches(host)
            || self.keywords.iter().any(|v| host.contains(&**v))
            || self.regex.iter().any(|r| r.is_match(host))
    }
    /// Number of distinct entries; combined regexes count as one.
    pub fn len(&self) -> usize {
        self.exact.len()
            + self.suffix.len()
            + self.subdomain.len()
            + self.globs.len()
            + self.keywords.len()
            + self.regex.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl std::fmt::Debug for DomainSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DomainSet({} entries)", self.len())
    }
}

/// Collects domain conditions, then packs them into a [`DomainSet`].
#[derive(Default)]
pub struct DomainSetBuilder {
    exact: ListBuilder,
    suffix: ListBuilder,
    subdomain: ListBuilder,
    globs: Vec<Box<str>>,
    keywords: Vec<Box<str>>,
    /// Sources only; compiled once in `build` (see `compile_regexes`).
    regex: Vec<String>,
}
impl DomainSetBuilder {
    pub fn exact(&mut self, domain: &str) {
        self.exact.push(&normalize(domain));
    }
    /// The domain and its subdomains.
    pub fn suffix(&mut self, domain: &str) {
        self.suffix.push(&normalize(domain));
    }
    /// Subdomains only.
    pub fn subdomain(&mut self, domain: &str) {
        self.subdomain.push(&normalize(domain));
    }
    pub fn keyword(&mut self, keyword: &str) {
        self.keywords.push(keyword.to_ascii_lowercase().into());
    }
    /// A case-insensitive regex source, as accepted by [`compile_regex`].
    pub fn regex(&mut self, source: &str) -> Result<()> {
        compile_regex(source)?; // reject invalid patterns where they are added
        self.regex.push(source.to_owned());
        Ok(())
    }
    /// Adds a Clash-style pattern: `+.x` (x and subdomains), `.x` (subdomains),
    /// `*` within labels (never across a dot), or a plain domain.
    pub fn pattern(&mut self, pattern: &str) -> Result<()> {
        match domain_pattern(pattern)? {
            Matcher::Domain(d) => self.exact.push(&d),
            Matcher::Suffix(d) => self.suffix.push(&d),
            Matcher::Subdomain(d) => self.subdomain.push(&d),
            // Validated by `domain_pattern`; matched as a glob, not a regex.
            Matcher::Regex(_) => self.globs.push(pattern.trim().to_ascii_lowercase().into()),
            _ => unreachable!("domain_pattern returns only domain matchers"),
        }
        Ok(())
    }
    /// Takes a domain condition into the set; returns other matchers unchanged.
    pub fn absorb(&mut self, matcher: Matcher) -> Option<Matcher> {
        match matcher {
            Matcher::Domain(d) => self.exact(&d),
            Matcher::Suffix(d) => self.suffix(&d),
            Matcher::Subdomain(d) => self.subdomain(&d),
            Matcher::Keyword(k) => self.keyword(&k),
            Matcher::Regex(r) => self.regex.push(r.as_str().to_owned()),
            other => return Some(other),
        }
        None
    }
    pub fn build(self) -> DomainSet {
        DomainSet {
            exact: self.exact.build(),
            suffix: self.suffix.build(),
            subdomain: self.subdomain.build(),
            globs: Globs::new(self.globs),
            keywords: self.keywords.into_boxed_slice(),
            regex: compile_regexes(self.regex),
        }
    }
}
/// Every compiled `Regex` carries its own engines and caches, so the set's
/// patterns compile once, as one alternation; if that exceeds the size limit
/// they compile separately.
fn compile_regexes(sources: Vec<String>) -> Box<[regex::Regex]> {
    if sources.len() > 1 {
        let combined = sources
            .iter()
            .map(|s| format!("(?:{s})"))
            .collect::<Vec<_>>()
            .join("|");
        if let Ok(regex) = regex::RegexBuilder::new(&combined)
            .case_insensitive(true)
            .size_limit(8 * 1024 * 1024)
            .build()
        {
            return Box::new([regex]);
        }
    }
    // Each source was validated when it was added.
    sources
        .iter()
        .filter_map(|s| compile_regex(s).ok())
        .collect()
}
fn normalize(domain: &str) -> String {
    domain.trim().trim_matches('.').to_ascii_lowercase()
}
#[derive(Clone, Debug, Default)]
pub struct IpSet {
    v4: Vec<(u128, u128)>,
    v6: Vec<(u128, u128)>,
    pub inverse: bool,
}
impl IpSet {
    pub fn new(nets: impl IntoIterator<Item = ipnet::IpNet>, inverse: bool) -> Self {
        let mut s = Self {
            inverse,
            ..Self::default()
        };
        for n in nets {
            match n {
                ipnet::IpNet::V4(n) => s.v4.push((
                    u32::from(n.network()) as u128,
                    u32::from(n.broadcast()) as u128,
                )),
                ipnet::IpNet::V6(n) => {
                    s.v6.push((u128::from(n.network()), u128::from(n.broadcast())))
                }
            }
        }
        for ranges in [&mut s.v4, &mut s.v6] {
            ranges.sort_unstable();
            let mut merged: Vec<(u128, u128)> = vec![];
            for &(a, b) in ranges.iter() {
                if let Some(last) = merged.last_mut()
                    && a <= last.1.saturating_add(1)
                {
                    last.1 = last.1.max(b);
                } else {
                    merged.push((a, b));
                }
            }
            *ranges = merged;
        }
        s
    }
    pub fn matches(&self, ip: IpAddr) -> bool {
        let (ranges, n) = match ip {
            IpAddr::V4(ip) => (&self.v4, u32::from(ip) as u128),
            IpAddr::V6(ip) => (&self.v6, u128::from(ip)),
        };
        let i = ranges.partition_point(|r| r.0 <= n);
        (i > 0 && n <= ranges[i - 1].1) ^ self.inverse
    }
}
#[derive(Clone, Debug)]
pub struct Rule {
    pub matcher: Matcher,
    pub target: String,
    pub no_resolve: bool,
}

fn fields(raw: &str) -> Result<Vec<&str>> {
    ensure!(raw.len() <= 65536, "rule too long");
    let (mut depth, mut start) = (0usize, 0);
    let mut out = vec![];
    for (i, c) in raw.char_indices() {
        match c {
            '(' => {
                depth += 1;
                ensure!(depth <= 32, "rule nesting limit");
            }
            ')' => {
                ensure!(depth > 0, "unbalanced rule");
                depth -= 1;
            }
            ',' if depth == 0 => {
                out.push(raw[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    ensure!(depth == 0, "unbalanced rule");
    out.push(raw[start..].trim());
    Ok(out)
}
fn unwrap(raw: &str) -> Result<&str> {
    raw.strip_prefix('(')
        .and_then(|v| v.strip_suffix(')'))
        .ok_or_else(|| anyhow::anyhow!("logical rule requires parentheses"))
}
impl Matcher {
    pub fn parse_condition(raw: &str) -> Result<Self> {
        Self::parse_depth(raw, 0)
    }
    fn parse_depth(raw: &str, depth: usize) -> Result<Self> {
        ensure!(depth < 32, "rule nesting limit");
        let mut f = fields(raw)?;
        let no_resolve = f.last() == Some(&"no-resolve");
        if no_resolve {
            f.pop();
        }
        ensure!(f.len() >= 2, "invalid condition fields");
        let kind = f[0];
        ensure!(
            matches!(kind, "AND" | "OR" | "NOT") || f.len() == 2,
            "invalid condition fields"
        );
        let value = f[1].to_ascii_lowercase();
        ensure!(!value.is_empty(), "empty rule value");
        let m = match kind {
            "AND" | "OR" | "NOT" => {
                let parts = if f.len() == 2 && unwrap(f[1])?.starts_with('(') {
                    fields(unwrap(f[1])?)?
                } else {
                    f[1..].to_vec()
                };
                ensure!(!parts.is_empty(), "empty logical rule");
                let nodes = parts
                    .into_iter()
                    .map(|p| Self::parse_depth(unwrap(p)?, depth + 1))
                    .collect::<Result<Vec<_>>>()?;
                match kind {
                    "AND" => Self::And(nodes.into()),
                    "OR" => Self::Or(nodes.into()),
                    _ => {
                        ensure!(nodes.len() == 1, "NOT requires one condition");
                        Self::Not(Arc::new(nodes.into_iter().next().unwrap()))
                    }
                }
            }
            "DOMAIN" => Self::Domain(value.trim_end_matches('.').into()),
            "DOMAIN-SUFFIX" => Self::Suffix(value.trim_matches('.').into()),
            "DOMAIN-KEYWORD" => Self::Keyword(value),
            "DOMAIN-REGEX" => Self::Regex(compile_regex(f[1])?),
            "IP-CIDR" | "IP-CIDR6" => {
                let n: ipnet::IpNet = value.parse()?;
                ensure!(
                    n.addr().is_ipv4() == (kind == "IP-CIDR"),
                    "rule IP family mismatch"
                );
                Self::Net(n)
            }
            "GEOIP" => Self::GeoIp(value),
            "GEOSITE" => Self::GeoSite(value),
            "RULE-SET" => Self::RuleSet(f[1].into()),
            "DST-PORT" => {
                let mut ports = vec![];
                for part in value.split('/') {
                    ports.push(crate::PortRange::Range(part.into()).bounds()?);
                }
                Self::Ports(ports)
            }
            "NETWORK" => {
                ensure!(value == "tcp" || value == "udp", "invalid network");
                Self::Network(value)
            }
            // Names in `networks` are case-sensitive.
            "NETWORK-NAME" => Self::OnNetwork(Arc::new(OnNetwork {
                name: f[1].into(),
                on: AtomicBool::new(false),
            })),
            _ => bail!("unsupported rule type {kind}"),
        };
        if no_resolve {
            Ok(Self::NoResolve(Arc::new(m)))
        } else {
            Ok(m)
        }
    }
    pub fn bind(&self, resolve: &impl Fn(&Self) -> Result<Self>) -> Result<Self> {
        Ok(match self {
            Self::GeoIp(_) | Self::GeoSite(_) | Self::RuleSet(_) => resolve(self)?,
            Self::And(v) => Self::And(
                v.iter()
                    .map(|m| m.bind(resolve))
                    .collect::<Result<Vec<_>>>()?
                    .into(),
            ),
            Self::Or(v) => Self::Or(
                v.iter()
                    .map(|m| m.bind(resolve))
                    .collect::<Result<Vec<_>>>()?
                    .into(),
            ),
            Self::Not(v) => Self::Not(Arc::new(v.bind(resolve)?)),
            Self::NoResolve(v) => Self::NoResolve(Arc::new(v.bind(resolve)?)),
            m => m.clone(),
        })
    }
    pub fn references(&self, out: &mut Vec<(String, String)>) {
        match self {
            Self::GeoIp(v) => out.push(("geoip".into(), v.clone())),
            Self::GeoSite(v) => out.push(("geosite".into(), v.clone())),
            Self::RuleSet(v) => out.push(("rule-set".into(), v.clone())),
            Self::And(v) | Self::Or(v) => {
                for m in v.iter() {
                    m.references(out)
                }
            }
            Self::Not(v) | Self::NoResolve(v) => v.references(out),
            _ => {}
        }
    }
    /// Every `NETWORK-NAME` condition inside, for the core to set.
    pub fn networks(&self, out: &mut impl FnMut(&OnNetwork)) {
        match self {
            Self::OnNetwork(network) => out(network),
            Self::And(v) | Self::Or(v) => {
                for m in v.iter() {
                    m.networks(out)
                }
            }
            Self::Not(v) | Self::NoResolve(v) => v.networks(out),
            _ => {}
        }
    }
    /// None requests DNS only when a still-relevant IP condition needs it.
    pub fn evaluate(
        &self,
        host: &str,
        ip: Option<IpAddr>,
        port: u16,
        network: &str,
        can_resolve: bool,
    ) -> Option<bool> {
        Some(match self {
            Self::Domain(d) => host == d,
            Self::Suffix(d) => host == d || host.strip_suffix(d).is_some_and(|p| p.ends_with('.')),
            Self::Subdomain(d) => host
                .strip_suffix(d)
                .is_some_and(|p| p.len() > 1 && p.ends_with('.')),
            Self::Keyword(k) => host.contains(k),
            Self::Regex(r) => r.is_match(host),
            Self::Domains(s) => s.matches(host),
            Self::Net(n) => match ip {
                Some(ip) => n.contains(&ip),
                None if can_resolve => return None,
                None => false,
            },
            Self::Nets(n) => match ip {
                Some(ip) => n.matches(ip),
                None if can_resolve => return None,
                None => false,
            },
            Self::ExternalIp(n) => match ip {
                Some(ip) => n.matches(ip),
                None if can_resolve => return None,
                None => false,
            },
            Self::Port(p) => *p == port,
            Self::Ports(r) => r.iter().any(|(a, b)| *a <= port && port <= *b),
            Self::Network(n) => n == network,
            Self::OnNetwork(n) => n.get(),
            Self::All => true,
            Self::Not(m) => return m.evaluate(host, ip, port, network, can_resolve).map(|v| !v),
            Self::NoResolve(m) => return m.evaluate(host, ip, port, network, false),
            Self::And(nodes) | Self::Or(nodes) => {
                let and = matches!(self, Self::And(_));
                let mut unknown = false;
                for m in nodes.iter() {
                    match m.evaluate(host, ip, port, network, can_resolve) {
                        Some(v) if v != and => return Some(v),
                        None => unknown = true,
                        _ => {}
                    }
                }
                if unknown {
                    return None;
                }
                and
            }
            Self::GeoIp(_) | Self::GeoSite(_) | Self::RuleSet(_) => false,
        })
    }
}
impl Rule {
    pub fn parse(raw: &str) -> Result<Self> {
        let mut f = fields(raw)?;
        ensure!(f.len() >= 2, "rule needs type and target");
        let no_resolve = f.last() == Some(&"no-resolve");
        if no_resolve {
            f.pop();
        }
        ensure!(f.len() >= 2, "missing rule target");
        let target = f.pop().unwrap().to_string();
        ensure!(!target.is_empty(), "empty rule target");
        let matcher = if f[0] == "MATCH" {
            ensure!(f.len() == 1, "MATCH takes one target");
            Matcher::All
        } else {
            Matcher::parse_condition(&f.join(","))?
        };
        Ok(Self {
            matcher,
            target,
            no_resolve,
        })
    }
    pub fn matches(&self, host: &str, ip: Option<IpAddr>, port: u16, network: &str) -> bool {
        self.matcher.evaluate(
            &host.trim_end_matches('.').to_ascii_lowercase(),
            ip,
            port,
            network,
            false,
        ) == Some(true)
    }
}
pub fn domain_pattern(pattern: &str) -> Result<Matcher> {
    let p = pattern.trim().to_ascii_lowercase();
    ensure!(!p.is_empty(), "empty domain pattern");
    if let Some(s) = p.strip_prefix("+.") {
        return Ok(Matcher::Suffix(s.into()));
    }
    if let Some(s) = p.strip_prefix('.') {
        return Ok(Matcher::Subdomain(s.into()));
    }
    if !p.contains('*') {
        return Ok(Matcher::Domain(p));
    }
    let re = format!("^{}$", regex::escape(&p).replace("\\*", "[^.]*"));
    Ok(Matcher::Regex(regex::Regex::new(&re)?))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dot_prefix_matches_subdomains_only_like_mihomo() {
        let m = |p: &str, host: &str| {
            domain_pattern(p)
                .unwrap()
                .evaluate(host, None, 0, "", false)
        };
        assert_eq!(m(".example.com", "a.example.com"), Some(true));
        assert_eq!(m(".example.com", "b.a.example.com"), Some(true));
        assert_eq!(m(".example.com", "example.com"), Some(false));
        assert_eq!(m(".example.com", "badexample.com"), Some(false));
        assert_eq!(m("+.example.com", "example.com"), Some(true));
        assert_eq!(m("+.example.com", "a.example.com"), Some(true));
        assert_eq!(m("example.com", "a.example.com"), Some(false));
    }

    #[test]
    fn compact_domain_set_matches_every_kind() {
        let mut b = DomainSetBuilder::default();
        for p in [
            "Exact.test",
            "+.suffix.test",
            ".sub.test",
            "*.one.test",
            "*.*.two.test",
            "x*y.glob.test",
        ] {
            b.pattern(p).unwrap();
        }
        b.exact("exact.test"); // duplicate after normalisation
        b.keyword("KeyWord");
        b.regex("^re[0-9]+\\.test$").unwrap();
        let set = b.build();
        assert_eq!(set.len(), 8);
        for (host, expected) in [
            ("exact.test", true),
            ("a.exact.test", false),
            ("suffix.test", true),
            ("deep.a.suffix.test", true),
            ("sub.test", false),
            ("a.sub.test", true),
            ("a.one.test", true),
            ("one.test", false),
            ("b.a.one.test", false),
            ("b.a.two.test", true),
            ("a.two.test", false),
            ("xay.glob.test", true),
            ("has-keyword-inside.test", true),
            ("re42.test", true),
            ("unrelated.test", false),
        ] {
            assert_eq!(set.matches(host), expected, "{host}");
        }
        assert!(DomainSetBuilder::default().build().is_empty());
    }

    #[test]
    fn glob_index_narrows_candidates_without_changing_matches() {
        assert_eq!(
            fixed_suffix("ad-host-backup-*.aliyuncs.com"),
            Some("aliyuncs.com")
        );
        assert_eq!(
            fixed_suffix("reachableads-av.*.amazonaws.com"),
            Some("amazonaws.com")
        );
        assert_eq!(fixed_suffix("ads.livetv*.me"), Some("me"));
        assert_eq!(fixed_suffix("ads.example.*"), None);
        assert_eq!(fixed_suffix("*.*"), None);
        let patterns = [
            "ad-host-backup-*.aliyuncs.com",
            "reachableads-av.*.amazonaws.com",
            "ads.livetv*.me",
            "st-n.ads*-adnow.com",
            "counter*.stat.ovh",
            "*.one.test",
            "*.*.two.test",
            "a*b*c.test",
            "*x*.test",
            "ads.example.*",
            "*.ads.*",
            "**.test",
        ];
        let mut builder = DomainSetBuilder::default();
        for pattern in patterns {
            builder.pattern(pattern).unwrap();
        }
        let set = builder.build();
        let reference: Vec<_> = patterns
            .iter()
            .map(|p| domain_pattern(p).unwrap())
            .collect();
        let labels = [
            "ad-host-backup-3",
            "ad-host-backup-",
            "oss-cn-hangzhou",
            "reachableads-av",
            "eu",
            "ads",
            "livetv7",
            "livetv",
            "st-n",
            "ads1-adnow",
            "adsx-adnow",
            "counter",
            "counter9",
            "stat",
            "ovh",
            "aliyuncs",
            "amazonaws",
            "com",
            "me",
            "test",
            "one",
            "two",
            "a",
            "b",
            "abc",
            "aXbYc",
            "acb",
            "x",
            "yxy",
            "example",
            "net",
            "",
        ];
        // Every host of up to four labels drawn from the list above.
        let mut hosts = Vec::new();
        for a in labels {
            for b in labels {
                hosts.push(format!("{a}.{b}"));
                for c in [
                    "com",
                    "test",
                    "me",
                    "ovh",
                    "aliyuncs.com",
                    "amazonaws.com",
                    "x.test",
                ] {
                    hosts.push(format!("{a}.{b}.{c}"));
                }
            }
        }
        let mut matched = 0;
        for host in &hosts {
            let expected = reference
                .iter()
                .any(|m| m.evaluate(host, None, 0, "", false) == Some(true));
            assert_eq!(set.matches(host), expected, "{host}");
            matched += expected as usize;
        }
        assert!(matched > 50, "the hosts exercise the patterns ({matched})");
        // The suffix alone never matches: the rest of the pattern still has to.
        assert!(set.matches("ad-host-backup-3.aliyuncs.com"));
        assert!(!set.matches("oss-cn-hangzhou.aliyuncs.com"));
        assert!(!set.matches("x.ad-host-backup-3.aliyuncs.com"));
        assert!(set.matches("AD-HOST-BACKUP-3.aliyuncs.com"));
    }

    #[test]
    fn hashed_lists_keep_exact_suffix_and_subdomain_semantics() {
        let mut b = DomainSetBuilder::default();
        b.exact("only.test");
        b.suffix("tree.test");
        b.subdomain("kids.test");
        for i in 0..10_000 {
            b.suffix(&format!("filler{i}.example"));
        }
        let set = b.build();
        assert_eq!(set.len(), 10_003);
        for (host, expected) in [
            ("only.test", true),
            ("a.only.test", false),
            ("tree.test", true),
            ("a.b.tree.test", true),
            ("atree.test", false),
            ("kids.test", false),
            ("a.kids.test", true),
            ("filler9999.example", true),
            ("x.filler0.example", true),
            ("filler10000.example", false),
            ("test", false),
        ] {
            assert_eq!(set.matches(host), expected, "{host}");
        }
    }

    #[test]
    fn overlapping_wildcards_from_mihomo_regression() {
        // mihomo 5f951098: these returned false in its trie.
        for (host, patterns) in [
            (
                "a.example.com",
                &["*.example.com", "dead.a.example.com"][..],
            ),
            (
                "b.a.example.com",
                &[
                    "*.*.example.com",
                    "dead.*.a.example.com",
                    "dead.b.a.example.com",
                ],
            ),
            (
                "b.c.a.example.com",
                &["*.*.*.example.com", "*.a.example.com"],
            ),
        ] {
            let mut b = DomainSetBuilder::default();
            for p in patterns {
                b.pattern(p).unwrap();
            }
            assert!(b.build().matches(host), "{host}");
        }
    }

    #[test]
    fn builder_absorbs_domain_conditions_only() {
        let mut b = DomainSetBuilder::default();
        assert!(
            b.absorb(Matcher::parse_condition("DOMAIN-SUFFIX,ads.test").unwrap())
                .is_none()
        );
        assert!(
            b.absorb(Matcher::parse_condition("DOMAIN,exact.test").unwrap())
                .is_none()
        );
        assert!(
            b.absorb(Matcher::parse_condition("DST-PORT,443").unwrap())
                .is_some()
        );
        let set = b.build();
        assert!(
            set.matches("x.ads.test") && set.matches("exact.test") && !set.matches("x.exact.test")
        );
    }
    #[test]
    fn logical_and_lazy_dns() {
        let alternate =
            Rule::parse("AND,(AND,(DST-PORT,443),(NETWORK,UDP)),(NOT,((GEOSITE,cn))),REJECT")
                .unwrap();
        let bound = alternate
            .matcher
            .bind(&|_| Ok(Matcher::Suffix("cn.test".into())))
            .unwrap();
        assert_eq!(
            bound.evaluate("other.test", None, 443, "udp", false),
            Some(true)
        );
        assert_eq!(
            bound.evaluate("cn.test", None, 443, "udp", false),
            Some(false)
        );
        let r = Rule::parse("AND,((NETWORK,UDP),(OR,((GEOIP,CN),(DST-PORT,443)))),REJECT").unwrap();
        let m = r
            .matcher
            .bind(&|_| Ok(Matcher::Net("10.0.0.0/8".parse().unwrap())))
            .unwrap();
        assert_eq!(m.evaluate("a", None, 80, "tcp", true), Some(false));
        assert_eq!(m.evaluate("a", None, 443, "udp", true), Some(true));
        assert_eq!(m.evaluate("a", None, 80, "udp", true), None);
        assert!(Rule::parse("NOT,((NETWORK,tcp),(NETWORK,udp)),DIRECT").is_err());
        assert!(Rule::parse("AND,((NETWORK,tcp),DIRECT").is_err());
    }
    #[test]
    fn suffix_label_boundary() {
        let r = Rule::parse("DOMAIN-SUFFIX,example.org,DIRECT").unwrap();
        assert!(r.matches("WWW.Example.org.", None, 443, "tcp"));
        assert!(!r.matches("notexample.org", None, 443, "tcp"));
    }
    #[test]
    fn no_resolve_and_ranges() {
        assert!(
            Rule::parse("GEOIP,CN,DIRECT,no-resolve")
                .unwrap()
                .no_resolve
        );
        let r = Rule::parse("DST-PORT,80/443/8000-9000,DIRECT").unwrap();
        assert!(r.matches("a", None, 8443, "tcp"));
        assert!(!r.matches("a", None, 79, "tcp"));
    }
    #[test]
    fn interval_family() {
        let s = IpSet::new(
            [
                "10.0.0.0/24".parse().unwrap(),
                "10.0.1.0/24".parse().unwrap(),
                "2001:db8::/32".parse().unwrap(),
            ],
            false,
        );
        assert!(s.matches("10.0.1.255".parse().unwrap()));
        assert!(!s.matches("10.0.2.0".parse().unwrap()));
        assert!(s.matches("2001:db8::1".parse().unwrap()));
    }
}
