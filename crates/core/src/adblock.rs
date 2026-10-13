//! Ad blocking at run time: the compiled lists, the allowlist, the endpoints
//! of resolvers that bypass DNS filtering, and counters.
use clyntis_config::{
    adblock::{Adblock, HTTPDNS_ADDRESSES, HTTPDNS_DOMAINS, HTTPDNS_PORTS},
    rule::{DomainSet, DomainSetBuilder},
};
use ipnet::IpNet;
use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

/// One loaded list, for status displays.
#[derive(Clone, Debug, Serialize)]
pub struct ListInfo {
    pub name: String,
    pub entries: usize,
    /// When the cached file was downloaded (Unix seconds).
    pub updated: Option<u64>,
    pub error: Option<String>,
}

/// Why a connection was refused, as the route trace and log show it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Block {
    /// A listed domain.
    List,
    /// An HTTPDNS or encrypted-DNS endpoint.
    Endpoint,
    /// A listed address.
    Address,
    /// QUIC to an address without a name, so the app retries over TCP.
    Quic,
}
impl Block {
    pub fn matched(self) -> &'static str {
        match self {
            Block::List => "Adblock",
            Block::Endpoint => "Adblock(HTTPDNS)",
            Block::Address => "Adblock(IP)",
            Block::Quic => "Adblock(QUIC)",
        }
    }
}

/// Compiled block and allow sets. The user's allowlist can change while
/// running; the lists' own exceptions come with them.
pub struct Filter {
    block: Arc<DomainSet>,
    list_allow: Arc<DomainSet>,
    user_allow: RwLock<DomainSet>,
    /// Addresses from the lists.
    addresses: Arc<Vec<IpNet>>,
    endpoints: Arc<Endpoints>,
    block_httpdns: bool,
    quic_fallback: bool,
    /// Answer blocked names with 0.0.0.0 / :: instead of NXDOMAIN.
    pub null_answer: bool,
    pub lists: Vec<ListInfo>,
}
/// The built-in HTTPDNS and encrypted-DNS endpoints.
struct Endpoints {
    domains: DomainSet,
    addresses: Vec<IpNet>,
}
impl Endpoints {
    fn new() -> Self {
        let mut domains = DomainSetBuilder::default();
        for domain in HTTPDNS_DOMAINS {
            domains.suffix(domain);
        }
        Self {
            domains: domains.build(),
            // Checked by clyntis-config's tests.
            addresses: HTTPDNS_ADDRESSES
                .iter()
                .filter_map(|net| net.parse().ok())
                .collect(),
        }
    }
}
impl Filter {
    pub fn new(
        block: DomainSet,
        list_allow: DomainSet,
        addresses: Vec<IpNet>,
        settings: &Adblock,
        lists: Vec<ListInfo>,
    ) -> Self {
        Self {
            block: Arc::new(block),
            list_allow: Arc::new(list_allow),
            user_allow: RwLock::new(allow_set(&settings.allow)),
            addresses: Arc::new(addresses),
            endpoints: Arc::new(Endpoints::new()),
            block_httpdns: settings.block_httpdns,
            quic_fallback: settings.quic_fallback,
            null_answer: settings.dns_answer == "null",
            lists,
        }
    }
    /// The same compiled lists with new status, allowlist and options.
    pub fn with_lists(&self, settings: &Adblock, lists: Vec<ListInfo>) -> Self {
        Self {
            block: self.block.clone(),
            list_allow: self.list_allow.clone(),
            user_allow: RwLock::new(allow_set(&settings.allow)),
            addresses: self.addresses.clone(),
            endpoints: self.endpoints.clone(),
            block_httpdns: settings.block_httpdns,
            quic_fallback: settings.quic_fallback,
            null_answer: settings.dns_answer == "null",
            lists,
        }
    }
    /// Whether a listed domain is blocked.
    pub fn blocks(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.');
        if host.parse::<IpAddr>().is_ok() || !self.block.matches(host) {
            return false;
        }
        !(self.list_allow.matches(host) || self.user_allow.read().unwrap().matches(host))
    }
    /// Whether DNS refuses `host`: a listed domain or an encrypted-DNS name.
    pub fn refuses_name(&self, host: &str) -> Option<Block> {
        if self.blocks(host) {
            return Some(Block::List);
        }
        self.endpoint_name(host).then_some(Block::Endpoint)
    }
    fn endpoint_name(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.');
        self.block_httpdns
            && self.endpoints.domains.matches(host)
            && !self.user_allow.read().unwrap().matches(host)
    }
    /// Whether a connection to `host` (a name, or an address the core could
    /// not name) is refused, and why. Names are never resolved here.
    pub fn refuses(&self, host: &str, port: u16, network: &str) -> Option<Block> {
        let Ok(ip) = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
        else {
            return self.refuses_name(host);
        };
        let ip = ip.to_canonical();
        if self.block_httpdns
            && HTTPDNS_PORTS.contains(&port)
            && self.endpoints.addresses.iter().any(|net| net.contains(&ip))
        {
            return Some(Block::Endpoint);
        }
        if self.addresses.iter().any(|net| net.contains(&ip)) {
            return Some(Block::Address);
        }
        (self.quic_fallback && network == "udp" && port == 443).then_some(Block::Quic)
    }
    pub fn set_allow(&self, patterns: &[String]) {
        *self.user_allow.write().unwrap() = allow_set(patterns);
    }
    #[cfg(test)]
    pub fn shares_lists(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.block, &other.block)
    }
    /// Listed domains and addresses.
    pub fn entries(&self) -> usize {
        self.block.len() + self.addresses.len()
    }
}
fn allow_set(patterns: &[String]) -> DomainSet {
    let mut builder = DomainSetBuilder::default();
    for pattern in patterns {
        // Validated with the configuration; skip anything else defensively.
        let _ = clyntis_config::adblock::allow_pattern(&mut builder, pattern);
    }
    builder.build()
}

const RECENT: usize = 100;
const TRACKED_DOMAINS: usize = 2000;

#[derive(Clone, Debug, Serialize)]
pub struct Blocked {
    pub time: u64,
    pub domain: String,
    /// "dns" or "connection".
    pub via: &'static str,
}

/// Counters since the core started.
pub struct Stats {
    pub since: u64,
    dns: AtomicU64,
    connections: AtomicU64,
    domains: Mutex<HashMap<String, u64>>,
    recent: Mutex<VecDeque<Blocked>>,
    /// Blocks since the last log summary: the total and per-target counts.
    window: Mutex<(u64, HashMap<String, u64>)>,
}
impl Default for Stats {
    fn default() -> Self {
        Self {
            since: now(),
            dns: AtomicU64::new(0),
            connections: AtomicU64::new(0),
            domains: Mutex::default(),
            recent: Mutex::default(),
            window: Mutex::default(),
        }
    }
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
impl Stats {
    pub fn record(&self, domain: &str, via: &'static str) {
        let counter = if via == "dns" {
            &self.dns
        } else {
            &self.connections
        };
        counter.fetch_add(1, Ordering::Relaxed);
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        {
            let mut window = self.window.lock().unwrap();
            window.0 += 1;
            if let Some(count) = window.1.get_mut(&domain) {
                *count += 1;
            } else if window.1.len() < TRACKED_DOMAINS {
                window.1.insert(domain.clone(), 1);
            }
        }
        {
            let mut domains = self.domains.lock().unwrap();
            if let Some(count) = domains.get_mut(&domain) {
                *count += 1;
            } else if domains.len() < TRACKED_DOMAINS {
                domains.insert(domain.clone(), 1);
            }
        }
        let mut recent = self.recent.lock().unwrap();
        if recent.len() == RECENT {
            recent.pop_back();
        }
        recent.push_front(Blocked {
            time: now(),
            domain,
            via,
        });
    }

    /// One line for the blocks since the last call, most blocked targets
    /// first, so the info log shows ad blocking without a line per block.
    pub fn take_summary(&self, top: usize) -> Option<String> {
        let (total, targets) = std::mem::take(&mut *self.window.lock().unwrap());
        if total == 0 {
            return None;
        }
        let mut targets: Vec<_> = targets.into_iter().collect();
        targets.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let mut line = targets
            .iter()
            .take(top)
            .map(|(target, count)| format!("{target} ×{count}"))
            .collect::<Vec<_>>()
            .join(", ");
        if targets.len() > top {
            line += &format!(" (+{} more)", targets.len() - top);
        }
        Some(format!("blocked {total}: {line}"))
    }

    /// Totals, the most blocked domains and the latest blocks, newest first.
    pub fn snapshot(&self, top: usize) -> serde_json::Value {
        let mut domains: Vec<(String, u64)> = self
            .domains
            .lock()
            .unwrap()
            .iter()
            .map(|(d, c)| (d.clone(), *c))
            .collect();
        domains.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        domains.truncate(top);
        let (dns, connections) = (
            self.dns.load(Ordering::Relaxed),
            self.connections.load(Ordering::Relaxed),
        );
        serde_json::json!({
            "since": self.since,
            "total": dns + connections,
            "dns": dns,
            "connections": connections,
            "domains": self.domains.lock().unwrap().len(),
            "top": domains.into_iter().map(|(domain, count)| serde_json::json!({"domain": domain, "count": count})).collect::<Vec<_>>(),
            "recent": self.recent.lock().unwrap().iter().cloned().collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlists_win_and_counters_track_domains() {
        let mut block = DomainSetBuilder::default();
        block.suffix("ads.test");
        let mut list_allow = DomainSetBuilder::default();
        list_allow.suffix("ok.ads.test");
        let filter = Filter::new(
            block.build(),
            list_allow.build(),
            vec![],
            &Adblock {
                allow: vec!["keep.ads.test".into()],
                ..Adblock::default()
            },
            vec![],
        );
        assert!(
            filter.blocks("x.ads.test") && filter.blocks("ADS.test.".to_ascii_lowercase().as_str())
        );
        assert!(!filter.blocks("ok.ads.test") && !filter.blocks("a.keep.ads.test"));
        assert!(!filter.blocks("1.2.3.4") && !filter.blocks("other.test"));
        filter.set_allow(&["ads.test".into()]);
        assert!(!filter.blocks("x.ads.test"));

        let stats = Stats::default();
        stats.record("x.ads.test", "dns");
        stats.record("x.ads.test.", "connection");
        stats.record("y.ads.test", "dns");
        assert_eq!(
            stats.take_summary(1).as_deref(),
            Some("blocked 3: x.ads.test ×2 (+1 more)")
        );
        assert_eq!(stats.take_summary(1), None);
        let snapshot = stats.snapshot(10);
        assert_eq!(snapshot["total"], 3);
        assert_eq!(snapshot["dns"], 2);
        assert_eq!(snapshot["top"][0]["domain"], "x.ads.test");
        assert_eq!(snapshot["top"][0]["count"], 2);
        assert_eq!(snapshot["recent"][0]["domain"], "y.ads.test");
    }
}
