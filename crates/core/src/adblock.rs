//! Ad blocking at run time: the compiled lists, the allowlist and counters.
use meta_config::rule::{DomainSet, DomainSetBuilder};
use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque},
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

/// Compiled block and allow sets. The user's allowlist can change while
/// running; the lists' own exceptions come with them.
pub struct Filter {
    block: Arc<DomainSet>,
    list_allow: Arc<DomainSet>,
    user_allow: RwLock<DomainSet>,
    pub lists: Vec<ListInfo>,
}
impl Filter {
    pub fn new(
        block: DomainSet,
        list_allow: DomainSet,
        user_allow: &[String],
        lists: Vec<ListInfo>,
    ) -> Self {
        Self {
            block: Arc::new(block),
            list_allow: Arc::new(list_allow),
            user_allow: RwLock::new(allow_set(user_allow)),
            lists,
        }
    }
    /// The same compiled lists with new status and allowlist.
    pub fn with_lists(&self, user_allow: &[String], lists: Vec<ListInfo>) -> Self {
        Self {
            block: self.block.clone(),
            list_allow: self.list_allow.clone(),
            user_allow: RwLock::new(allow_set(user_allow)),
            lists,
        }
    }
    pub fn blocks(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.');
        if host.parse::<std::net::IpAddr>().is_ok() || !self.block.matches(host) {
            return false;
        }
        !(self.list_allow.matches(host) || self.user_allow.read().unwrap().matches(host))
    }
    pub fn set_allow(&self, patterns: &[String]) {
        *self.user_allow.write().unwrap() = allow_set(patterns);
    }
    #[cfg(test)]
    pub fn shares_lists(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.block, &other.block)
    }
    pub fn entries(&self) -> usize {
        self.block.len()
    }
}
fn allow_set(patterns: &[String]) -> DomainSet {
    let mut builder = DomainSetBuilder::default();
    for pattern in patterns {
        // Validated with the configuration; skip anything else defensively.
        let _ = meta_config::adblock::allow_pattern(&mut builder, pattern);
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
}
impl Default for Stats {
    fn default() -> Self {
        Self {
            since: now(),
            dns: AtomicU64::new(0),
            connections: AtomicU64::new(0),
            domains: Mutex::default(),
            recent: Mutex::default(),
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
            &["keep.ads.test".into()],
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
        let snapshot = stats.snapshot(10);
        assert_eq!(snapshot["total"], 3);
        assert_eq!(snapshot["dns"], 2);
        assert_eq!(snapshot["top"][0]["domain"], "x.ads.test");
        assert_eq!(snapshot["top"][0]["count"], 2);
        assert_eq!(snapshot["recent"][0]["domain"], "y.ads.test");
    }
}
