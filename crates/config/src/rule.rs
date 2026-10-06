use anyhow::{Result, bail, ensure};
use std::{net::IpAddr, sync::Arc};

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
pub trait IpMatcher: std::fmt::Debug + Send + Sync {
    fn matches(&self, ip: IpAddr) -> bool;
}
pub fn compile_regex(pattern: &str) -> Result<regex::Regex> {
    Ok(regex::RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(2 * 1024 * 1024)
        .build()?)
}
/// Sorted, deduplicated domains packed into one byte buffer and looked up by
/// binary search: about 4 bytes of overhead per entry, instead of a `String`
/// plus a hash-table slot (~80 bytes for a typical domain). Large geosite and
/// rule-provider sets dominate memory inside the iOS tunnel extension.
#[derive(Clone, Default)]
struct DomainList {
    bytes: Box<[u8]>,
    ends: Box<[u32]>,
}
impl DomainList {
    fn get(&self, index: usize) -> &[u8] {
        let start = index.checked_sub(1).map_or(0, |i| self.ends[i] as usize);
        &self.bytes[start..self.ends[index] as usize]
    }
    fn contains(&self, domain: &str) -> bool {
        let (mut low, mut high) = (0, self.ends.len());
        while low < high {
            let middle = (low + high) / 2;
            match self.get(middle).cmp(domain.as_bytes()) {
                std::cmp::Ordering::Less => low = middle + 1,
                std::cmp::Ordering::Greater => high = middle,
                std::cmp::Ordering::Equal => return true,
            }
        }
        false
    }
    fn len(&self) -> usize {
        self.ends.len()
    }
}
#[derive(Default)]
struct ListBuilder {
    bytes: Vec<u8>,
    spans: Vec<(u32, u32)>,
}
impl ListBuilder {
    fn push(&mut self, domain: &str) {
        let start = self.bytes.len();
        self.bytes.extend_from_slice(domain.as_bytes());
        // Sets are bounded far below 4 GiB by the 128 MiB resource limit.
        self.spans.push((start as u32, domain.len() as u32));
    }
    fn build(self) -> DomainList {
        let Self { bytes, mut spans } = self;
        let text = |&(start, len): &(u32, u32)| &bytes[start as usize..(start + len) as usize];
        spans.sort_unstable_by(|a, b| text(a).cmp(text(b)));
        spans.dedup_by(|a, b| text(a) == text(b));
        let mut packed = Vec::with_capacity(spans.iter().map(|s| s.1 as usize).sum());
        let mut ends = Vec::with_capacity(spans.len());
        for span in &spans {
            packed.extend_from_slice(text(span));
            ends.push(packed.len() as u32);
        }
        DomainList {
            bytes: packed.into_boxed_slice(),
            ends: ends.into_boxed_slice(),
        }
    }
}

/// Immutable set of domain conditions, built with [`DomainSetBuilder`].
#[derive(Clone, Default)]
pub struct DomainSet {
    exact: DomainList,
    suffix: DomainList,
    subdomain: DomainList,
    /// Patterns whose `*` labels each match exactly one label.
    wildcard: Box<[Box<str>]>,
    keywords: Box<[Box<str>]>,
    regex: Box<[regex::Regex]>,
}
impl DomainSet {
    pub fn matches(&self, host: &str) -> bool {
        if self.exact.contains(host) {
            return true;
        }
        let mut label = host;
        let mut first = true;
        loop {
            if self.suffix.contains(label) || (!first && self.subdomain.contains(label)) {
                return true;
            }
            match label.split_once('.') {
                Some((_, rest)) => label = rest,
                None => break,
            }
            first = false;
        }
        self.wildcard.iter().any(|p| wildcard_matches(p, host))
            || self.keywords.iter().any(|v| host.contains(&**v))
            || self.regex.iter().any(|r| r.is_match(host))
    }
    /// Number of distinct entries; combined regexes count as one.
    pub fn len(&self) -> usize {
        self.exact.len()
            + self.suffix.len()
            + self.subdomain.len()
            + self.wildcard.len()
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

fn wildcard_matches(pattern: &str, host: &str) -> bool {
    let mut labels = host.rsplit('.');
    for part in pattern.rsplit('.') {
        match labels.next() {
            Some(label) if part == "*" || part == label => {}
            _ => return false,
        }
    }
    labels.next().is_none()
}

/// Collects domain conditions, then packs them into a [`DomainSet`].
#[derive(Default)]
pub struct DomainSetBuilder {
    exact: ListBuilder,
    suffix: ListBuilder,
    subdomain: ListBuilder,
    wildcard: Vec<Box<str>>,
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
    /// `*` labels (one label each), or a plain domain.
    pub fn pattern(&mut self, pattern: &str) -> Result<()> {
        match domain_pattern(pattern)? {
            Matcher::Domain(d) => self.exact.push(&d),
            Matcher::Suffix(d) => self.suffix.push(&d),
            Matcher::Subdomain(d) => self.subdomain.push(&d),
            Matcher::Regex(r) => {
                let p = pattern.trim().to_ascii_lowercase();
                if p.split('.')
                    .all(|label| label == "*" || !label.contains('*'))
                {
                    self.wildcard.push(p.into());
                } else {
                    // `*` inside a label: keep the existing glob behaviour.
                    self.regex.push(r.as_str().to_owned());
                }
            }
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
            wildcard: self.wildcard.into_boxed_slice(),
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
        assert_eq!(set.len(), 7); // the glob and the regex share one alternation
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
