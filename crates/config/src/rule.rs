use anyhow::{Result, bail, ensure};
use std::{net::IpAddr, sync::Arc};

#[derive(Clone, Debug)]
pub enum Matcher {
    Domain(String),
    Suffix(String),
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
#[derive(Clone, Debug, Default)]
pub struct DomainSet {
    pub exact: std::collections::HashSet<String>,
    pub suffix: std::collections::HashSet<String>,
    pub keywords: Vec<String>,
    pub regex: Vec<regex::Regex>,
}
impl DomainSet {
    pub fn matches(&self, host: &str) -> bool {
        if self.exact.contains(host) {
            return true;
        }
        let mut label = host;
        loop {
            if self.suffix.contains(label) {
                return true;
            }
            match label.split_once('.') {
                Some((_, rest)) => label = rest,
                None => break,
            }
        }
        self.keywords.iter().any(|v| host.contains(v))
            || self.regex.iter().any(|r| r.is_match(host))
    }
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
        return Ok(Matcher::Suffix(s.into()));
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
