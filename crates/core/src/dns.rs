use anyhow::{Context, Result, ensure};
use clyntis_config::Dns;
use clyntis_platform::Hooks;
use clyntis_protocol::Target;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        DNSClass, Name, RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(test)]
#[path = "dns_tests.rs"]
mod tests;

/// A cached response in wire form: decoded messages took ~25 times the
/// space, 16 MiB for a full cache, which the iOS tunnel cannot afford.
struct CacheEntry {
    response: Vec<u8>,
    inserted: Instant,
    expires: Instant,
    size: usize,
}
const CACHE_ENTRIES: usize = 4096;
const CACHE_BYTES: usize = 1024 * 1024;
/// Per-entry allocator and table overhead beyond the key and response bytes.
const CACHE_OVERHEAD: usize = 256;
/// Fallback negative cache TTL (seconds) for NODATA/NXDOMAIN responses that
/// omit an authority SOA record, so IPv4-only hosts cache negative AAAA answers.
const NEGATIVE_FALLBACK_TTL: u32 = 30;
/// How long nameserver-policy servers not yet heard from on this network
/// answer alone before the plain nameservers are asked too.
const POLICY_HEAD_START: Duration = Duration::from_millis(500);
/// How long a lookup that already has IPv4 addresses waits for the AAAA
/// query sent alongside (RFC 8305's resolution delay). An AAAA query that
/// is never answered must not hold back a usable IPv4 result.
const AAAA_GRACE: Duration = Duration::from_millis(50);
/// NOERROR and NXDOMAIN settle a name; other codes say only that this
/// server could not or would not answer.
fn answered(response: &Message) -> bool {
    matches!(
        response.response_code(),
        ResponseCode::NoError | ResponseCode::NXDomain
    )
}
fn cache_key(request: &Message) -> Result<Vec<u8>> {
    // Keep EDNS, DNSSEC, recursion flags and query class in the cache key.
    let mut key_request = request.clone();
    key_request.set_id(0);
    Ok(key_request.to_vec()?)
}
fn cache_ttl(response: &Message) -> u32 {
    if !answered(response) || response.truncated() {
        return 0;
    }
    let negative =
        response.response_code() == ResponseCode::NXDomain || response.answers().is_empty();
    let ttl = if negative {
        response
            .name_servers()
            .iter()
            .filter_map(|r| match r.data() {
                RData::SOA(soa) => Some(r.ttl().min(soa.minimum())),
                _ => None,
            })
            .min()
            .unwrap_or_else(|| {
                if response.answers().is_empty() {
                    NEGATIVE_FALLBACK_TTL
                } else {
                    0
                }
            })
    } else {
        response
            .answers()
            .iter()
            .chain(response.name_servers())
            .chain(response.additionals())
            .map(Record::ttl)
            .min()
            .unwrap_or(0)
    };
    ttl.min(3600)
}
#[derive(Default)]
struct Cache {
    entries: HashMap<Vec<u8>, CacheEntry>,
    total_bytes: usize,
}
impl Cache {
    fn get(&mut self, key: &[u8], id: u16) -> Option<Message> {
        let now = Instant::now();
        let expired = match self.entries.get(key) {
            Some(entry) if entry.expires > now => {
                if let Ok(mut response) = Message::from_vec(&entry.response) {
                    response.set_id(id);
                    let elapsed = now
                        .saturating_duration_since(entry.inserted)
                        .as_secs()
                        .min(u32::MAX as u64) as u32;
                    for record in response.answers_mut().iter_mut() {
                        record.set_ttl(record.ttl().saturating_sub(elapsed));
                    }
                    for record in response.name_servers_mut().iter_mut() {
                        record.set_ttl(record.ttl().saturating_sub(elapsed));
                    }
                    for record in response.additionals_mut().iter_mut() {
                        record.set_ttl(record.ttl().saturating_sub(elapsed));
                    }
                    return Some(response);
                }
                false
            }
            Some(_) => true,
            None => false,
        };
        if expired && let Some(prev) = self.entries.remove(key) {
            self.total_bytes = self.total_bytes.saturating_sub(prev.size);
        }
        None
    }
    fn prune_expired(&mut self, now: Instant) {
        let mut removed_bytes = 0usize;
        self.entries.retain(|_, entry| {
            if entry.expires > now {
                true
            } else {
                removed_bytes += entry.size;
                false
            }
        });
        self.total_bytes = self.total_bytes.saturating_sub(removed_bytes);
    }
    fn insert(&mut self, mut key: Vec<u8>, mut bytes: Vec<u8>, ttl: u32) {
        bytes.shrink_to_fit();
        key.shrink_to_fit();
        let size = key.len() + bytes.len() + CACHE_OVERHEAD;
        if let Some(prev) = self.entries.remove(&key) {
            self.total_bytes = self.total_bytes.saturating_sub(prev.size);
        }
        if size > CACHE_BYTES {
            return;
        }
        let now = Instant::now();
        if self.entries.len() >= CACHE_ENTRIES || self.total_bytes + size > CACHE_BYTES {
            self.prune_expired(now);
        }
        while self.entries.len() >= CACHE_ENTRIES || self.total_bytes + size > CACHE_BYTES {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.inserted)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            if let Some(removed) = self.entries.remove(&oldest) {
                self.total_bytes = self.total_bytes.saturating_sub(removed.size);
            }
        }
        self.entries.insert(
            key,
            CacheEntry {
                response: bytes,
                inserted: now,
                expires: now + Duration::from_secs(ttl as u64),
                size,
            },
        );
        self.total_bytes += size;
    }
}

type InflightResult = std::result::Result<Message, String>;
type InflightSlot = tokio::sync::watch::Receiver<Option<InflightResult>>;

struct InflightGuard<'a> {
    map: &'a Mutex<HashMap<(bool, Vec<u8>), InflightSlot>>,
    key: Option<(bool, Vec<u8>)>,
    tx: Option<tokio::sync::watch::Sender<Option<InflightResult>>>,
}
impl InflightGuard<'_> {
    fn finish_ok(mut self, response: &Message) {
        if let Some(key) = self.key.take() {
            self.map.lock().unwrap().remove(&key);
        }
        if let Some(tx) = self.tx.take()
            && tx.receiver_count() > 0
        {
            let _ = tx.send(Some(Ok(response.clone())));
        }
    }
    fn finish_err(mut self, error: &anyhow::Error) {
        if let Some(key) = self.key.take() {
            self.map.lock().unwrap().remove(&key);
        }
        if let Some(tx) = self.tx.take()
            && tx.receiver_count() > 0
        {
            let _ = tx.send(Some(Err(format!("{error:#}"))));
        }
    }
}
impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        if let Some(key) = self.key.take()
            && let Ok(mut map) = self.map.lock()
        {
            map.remove(&key);
        }
    }
}

/// Fake-IP mappings up to `capacity` names; past it the least recently
/// queried name gives up its mapping. Addresses advance through the whole
/// pool before any is reused, so a client still holding an evicted address
/// reaches nothing rather than an unrelated name.
struct FakeMap {
    /// Address and the use stamp of its latest query, indexed by
    /// `usize::from(v6)` so lookups borrow `&str` directly without allocating.
    by_name: [HashMap<Arc<str>, (IpAddr, u64)>; 2],
    by_ip: HashMap<IpAddr, Arc<str>>,
    /// (address, stamp) in use order, oldest first; an entry whose stamp is
    /// no longer the name's latest is stale and skipped.
    order: VecDeque<(IpAddr, u64)>,
    stamp: u64,
    next4: u64,
    next6: u128,
    capacity: usize,
    /// Changes whenever a mapping is added or dropped, so unchanged mappings
    /// are not saved again.
    generation: u64,
}
pub const FAKE_CAPACITY: usize = 32768;
impl FakeMap {
    fn new(capacity: usize) -> Self {
        Self {
            by_name: [HashMap::new(), HashMap::new()],
            by_ip: HashMap::new(),
            order: VecDeque::new(),
            stamp: 0,
            next4: 2,
            next6: 2,
            capacity,
            generation: 0,
        }
    }
    fn len(&self) -> usize {
        self.by_name[0].len() + self.by_name[1].len()
    }
    fn contains_name(&self, name: &str, v6: bool) -> bool {
        self.by_name[usize::from(v6)].contains_key(name)
    }
    fn get(&mut self, name: &str, v6: bool) -> Option<IpAddr> {
        let (ip, stamp) = self.by_name[usize::from(v6)].get_mut(name)?;
        self.stamp += 1;
        *stamp = self.stamp;
        let ip = *ip;
        self.order.push_back((ip, self.stamp));
        if self.order.len() > 2 * self.capacity.max(64) {
            self.compact();
        }
        Some(ip)
    }
    fn insert(&mut self, name: Arc<str>, ip: IpAddr) {
        self.stamp += 1;
        self.generation += 1;
        self.order.push_back((ip, self.stamp));
        self.by_ip.insert(ip, Arc::clone(&name));
        self.by_name[usize::from(ip.is_ipv6())].insert(name, (ip, self.stamp));
    }
    /// Drops the least recently queried mapping.
    fn evict(&mut self) {
        while let Some((ip, stamp)) = self.order.pop_front() {
            let Some(name) = self.by_ip.get(&ip) else {
                continue;
            };
            let table = &mut self.by_name[usize::from(ip.is_ipv6())];
            if table
                .get(name.as_ref())
                .is_some_and(|entry| entry.1 == stamp)
            {
                table.remove(name.as_ref());
                self.by_ip.remove(&ip);
                self.generation += 1;
                return;
            }
        }
    }
    fn compact(&mut self) {
        let mut live: Vec<_> = self
            .by_name
            .iter()
            .flat_map(|table| table.values().copied())
            .collect();
        live.sort_by_key(|entry| entry.1);
        self.order = live.into();
    }
    /// Names and addresses, least recently queried first.
    fn export(&self) -> Vec<(String, IpAddr)> {
        let mut entries: Vec<_> = self
            .by_name
            .iter()
            .flat_map(|table| table.iter())
            .map(|(name, (ip, stamp))| (*stamp, name, *ip))
            .collect();
        entries.sort_by_key(|entry| entry.0);
        entries
            .into_iter()
            .map(|(_, name, ip)| (name.to_string(), ip))
            .collect()
    }
    /// The next unmapped address, wrapping around the pool.
    fn allocate(&mut self, net4: ipnet::Ipv4Net, net6: ipnet::Ipv6Net, v6: bool) -> Result<IpAddr> {
        for _ in 0..=self.by_ip.len() {
            let ip = if v6 {
                // Offsets 2..=size-1 (the network and the gateway are reserved).
                let last = match net6.prefix_len() {
                    0 => u128::MAX,
                    prefix => (1u128 << (128 - prefix)) - 1,
                };
                ensure!(last >= 2, "fake-IP v6 pool exhausted");
                if self.next6 > last {
                    self.next6 = 2;
                }
                let ip = std::net::Ipv6Addr::from(u128::from(net6.network()) + self.next6);
                self.next6 += 1;
                IpAddr::V6(ip)
            } else {
                // Offsets 2..=size-2, also leaving out the broadcast address.
                let last = (1u64 << (32 - net4.prefix_len())).saturating_sub(2);
                ensure!(last >= 2, "fake-IP v4 pool exhausted");
                if self.next4 > last {
                    self.next4 = 2;
                }
                let ip = std::net::Ipv4Addr::from(
                    u32::try_from(u64::from(u32::from(net4.network())) + self.next4)
                        .context("fake-IP v4 pool exhausted")?,
                );
                self.next4 += 1;
                IpAddr::V4(ip)
            };
            if !self.by_ip.contains_key(&ip) {
                return Ok(ip);
            }
        }
        anyhow::bail!("fake-IP pool exhausted")
    }
}
pub struct Resolver {
    pub config: Dns,
    hooks: Hooks,
    clock: Arc<clyntis_protocol::tls::Clock>,
    cache: Mutex<Cache>,
    proxy_cache: Mutex<Cache>,
    inflight: Mutex<HashMap<(bool, Vec<u8>), InflightSlot>>,
    fake: Mutex<FakeMap>,
    policy: RwLock<DnsPolicy>,
    /// Whether each nameserver-policy server list answered on this network;
    /// forgotten with the cache when the network changes.
    reachable: Mutex<HashMap<Vec<String>, bool>>,
    tailnet: RwLock<Option<TailnetNames>>,
    adblock: RwLock<Option<Arc<crate::adblock::Filter>>>,
    /// Kept across resource refreshes so counts survive list updates.
    pub(crate) adblock_stats: Arc<crate::adblock::Stats>,
    configured: AtomicBool,
}
/// MagicDNS names of the running Tailscale proxies.
pub type TailnetNames = Arc<dyn Fn(&str) -> Option<IpAddr> + Send + Sync>;
#[derive(Clone, Default)]
struct DnsPolicy {
    hosts: HashMap<String, clyntis_config::Strings>,
    wildcard_hosts: Vec<(clyntis_config::rule::Matcher, clyntis_config::Strings)>,
    nameservers: Vec<(clyntis_config::rule::Matcher, Vec<String>)>,
    filters: Vec<clyntis_config::rule::Matcher>,
}
fn compile_hosts(
    hosts: &std::collections::BTreeMap<String, clyntis_config::Strings>,
) -> (
    HashMap<String, clyntis_config::Strings>,
    Vec<(clyntis_config::rule::Matcher, clyntis_config::Strings)>,
) {
    let mut exact = HashMap::new();
    let mut wildcards = Vec::new();
    for (key, value) in hosts {
        if key.contains('*') || key.starts_with('+') {
            wildcards.push((key, value));
        } else {
            exact.insert(key.clone(), value.clone());
        }
    }
    // Longest pattern first (reverse lexicographical tie-break preserves
    // `BTreeMap::iter().max_by_key(|(k, _)| k.len())`).
    wildcards.sort_by(|(a, _), (b, _)| b.len().cmp(&a.len()).then_with(|| b.cmp(a)));
    let wildcard_hosts = wildcards
        .into_iter()
        .filter_map(|(key, value)| {
            clyntis_config::rule::domain_pattern(key)
                .ok()
                .map(|matcher| (matcher, value.clone()))
        })
        .collect();
    (exact, wildcard_hosts)
}
impl Resolver {
    pub fn new(config: Dns, hooks: Hooks) -> Self {
        Self::new_with_clock(
            config,
            hooks,
            Arc::new(clyntis_protocol::tls::Clock::default()),
        )
    }
    pub fn new_with_clock(
        config: Dns,
        hooks: Hooks,
        clock: Arc<clyntis_protocol::tls::Clock>,
    ) -> Self {
        let filters = config
            .fake_ip_filter
            .iter()
            .filter(|p| !p.starts_with("geosite:") && !p.starts_with("rule-set:"))
            .filter_map(|p| clyntis_config::rule::domain_pattern(p).ok())
            .collect();
        Self {
            config,
            hooks,
            clock,
            policy: RwLock::new(DnsPolicy {
                filters,
                ..DnsPolicy::default()
            }),
            reachable: Mutex::new(HashMap::new()),
            tailnet: RwLock::new(None),
            adblock: RwLock::new(None),
            adblock_stats: Default::default(),
            configured: AtomicBool::new(false),
            cache: Mutex::new(Cache::default()),
            proxy_cache: Mutex::new(Cache::default()),
            inflight: Mutex::new(HashMap::new()),
            fake: Mutex::new(FakeMap::new(FAKE_CAPACITY)),
        }
    }
    pub fn clock(&self) -> Arc<clyntis_protocol::tls::Clock> {
        self.clock.clone()
    }
    pub(crate) fn is_configured(&self) -> bool {
        self.configured.load(Ordering::Relaxed)
    }
    /// Applies hosts and nameserver-policy, with `network`'s (the override
    /// for the current network) taking precedence over the global ones.
    pub fn configure(
        &self,
        hosts: &std::collections::BTreeMap<String, clyntis_config::Strings>,
        network: Option<&clyntis_config::network::NetworkOverride>,
        resources: &crate::resources::Resources,
    ) -> Result<()> {
        self.configure_with(hosts, network, resources, true)
    }
    pub(crate) fn configure_with(
        &self,
        hosts: &std::collections::BTreeMap<String, clyntis_config::Strings>,
        network: Option<&clyntis_config::network::NetworkOverride>,
        resources: &crate::resources::Resources,
        clear_cache: bool,
    ) -> Result<()> {
        *self.adblock.write().unwrap() = resources.adblock.clone();
        fn matcher(
            pattern: &str,
            resources: &crate::resources::Resources,
        ) -> Result<clyntis_config::rule::Matcher> {
            for (prefix, kind) in [("geosite:", "GEOSITE"), ("rule-set:", "RULE-SET")] {
                if let Some(tags) = pattern.strip_prefix(prefix) {
                    let nodes = tags
                        .split(',')
                        .map(|tag| {
                            resources.bind(&clyntis_config::rule::Matcher::parse_condition(
                                &format!("{kind},{tag}"),
                            )?)
                        })
                        .collect::<Result<Vec<_>>>()?;
                    return Ok(clyntis_config::rule::Matcher::Or(nodes.into()));
                }
            }
            clyntis_config::rule::domain_pattern(pattern)
        }
        // Most specific first: exact names, then longer patterns, then sets.
        fn ordered(
            policy: &std::collections::BTreeMap<String, clyntis_config::Strings>,
        ) -> Vec<(&String, &clyntis_config::Strings)> {
            let mut entries: Vec<_> = policy.iter().collect();
            entries.sort_by_key(|(key, _)| {
                std::cmp::Reverse(
                    if key.starts_with("geosite:") || key.starts_with("rule-set:") {
                        0
                    } else {
                        key.len()
                            + if key.contains('*') || key.starts_with('+') || key.starts_with('.') {
                                0
                            } else {
                                65536
                            }
                    },
                )
            });
            entries
        }
        let nameservers = network
            .map(|network| ordered(&network.nameserver_policy))
            .unwrap_or_default()
            .into_iter()
            .chain(ordered(&self.config.nameserver_policy))
            .map(|(key, value)| Ok((matcher(key, resources)?, value.values())))
            .collect::<Result<Vec<_>>>()?;
        let mut merged_hosts = hosts.clone();
        if let Some(network) = network {
            merged_hosts.extend(network.hosts.clone());
        }
        let (hosts, wildcard_hosts) = compile_hosts(&merged_hosts);
        let filters = self
            .config
            .fake_ip_filter
            .iter()
            .map(|p| matcher(p, resources))
            .collect::<Result<Vec<_>>>()?;
        *self.policy.write().unwrap() = DnsPolicy {
            hosts,
            wildcard_hosts,
            nameservers,
            filters,
        };
        self.configured.store(true, Ordering::Relaxed);
        if clear_cache {
            self.clear_cache();
        }
        Ok(())
    }
    /// Real lookups (DIRECT dials, non-fake-ip answers) resolve tailnet names
    /// to their 100.x addresses unless hosts names the host; fake-ip answers
    /// keep the domain for rules.
    pub fn set_tailnet_names(&self, names: Option<TailnetNames>) {
        *self.tailnet.write().unwrap() = names;
    }
    pub(crate) fn adblock(&self) -> Option<Arc<crate::adblock::Filter>> {
        self.adblock.read().unwrap().clone()
    }
    pub fn set_hosts(&self, hosts: &std::collections::BTreeMap<String, clyntis_config::Strings>) {
        let (exact, wildcard_hosts) = compile_hosts(hosts);
        let mut policy = self.policy.write().unwrap();
        policy.hosts = exact;
        policy.wildcard_hosts = wildcard_hosts;
    }
    fn host_values(&self, host: &str) -> Option<Vec<String>> {
        let policy = self.policy.read().unwrap();
        if policy.hosts.is_empty() && policy.wildcard_hosts.is_empty() {
            return None;
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some(v) = policy.hosts.get(&host) {
            return Some(v.values());
        }
        policy
            .wildcard_hosts
            .iter()
            .find(|(m, _)| m.evaluate(&host, None, 0, "", false) == Some(true))
            .map(|(_, v)| v.values())
    }
    pub async fn lookup_proxy(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        let proxy = !self.config.proxy_server_nameserver.is_empty();
        self.lookup_inner(host, port, proxy).await
    }
    fn is_fake_ip(&self, ip: IpAddr) -> bool {
        self.config.enhanced_mode == "fake-ip"
            && match ip {
                IpAddr::V4(ip) => self.config.fake_ip_range.contains(&ip),
                IpAddr::V6(ip) => self.config.fake_ip_range6.contains(&ip),
            }
    }
    pub fn original(&self, ip: IpAddr) -> Option<String> {
        if !self.is_fake_ip(ip) {
            return None;
        }
        self.fake
            .lock()
            .unwrap()
            .by_ip
            .get(&ip)
            .map(|name| name.to_string())
    }
    /// An address from the fake-IP pool with no domain behind it, e.g. one a
    /// client cached before the core restarted. Dialing it can only time out.
    pub fn is_unmapped_fake(&self, ip: IpAddr) -> bool {
        self.is_fake_ip(ip) && !self.fake.lock().unwrap().by_ip.contains_key(&ip)
    }
    /// Mappings, least recently queried first.
    pub fn export_fake(&self) -> Vec<(String, IpAddr)> {
        self.fake.lock().unwrap().export()
    }
    /// Changes whenever a fake-IP mapping is added or dropped.
    pub fn fake_generation(&self) -> u64 {
        self.fake.lock().unwrap().generation
    }
    /// Keeps at most `capacity` mappings, dropping the least recently queried.
    pub fn set_fake_capacity(&self, capacity: usize) {
        let mut map = self.fake.lock().unwrap();
        map.capacity = capacity.max(1);
        while map.len() > map.capacity {
            map.evict();
        }
    }
    /// Restores exported mappings, oldest first; past the capacity only the
    /// most recent are kept, while addresses still advance past all of them.
    pub fn import_fake(&self, entries: &[(String, IpAddr)]) -> Result<()> {
        ensure!(
            entries.len() <= FAKE_CAPACITY,
            "saved fake-IP capacity exceeded"
        );
        let capacity = self.fake.lock().unwrap().capacity;
        let mut map = FakeMap::new(capacity);
        let mut skipped = 0usize;
        let mut outside = 0usize;
        for (name, ip) in entries {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            // Saved under an earlier fake-ip-range or fake-ip-range6. They
            // cannot collide with the current pool, so nothing to advance past.
            let in_pool = match ip {
                IpAddr::V4(ip) => {
                    let net = self.config.fake_ip_range;
                    net.contains(ip) && *ip != net.broadcast()
                }
                IpAddr::V6(ip) => self.config.fake_ip_range6.contains(ip),
            };
            if !in_pool {
                outside += 1;
                continue;
            }
            match ip {
                IpAddr::V4(ip) => {
                    let net = self.config.fake_ip_range;
                    let n = u64::from(u32::from(*ip)) - u64::from(u32::from(net.network()));
                    ensure!(n >= 2, "reserved fake-IP");
                    map.next4 = map.next4.max(n + 1);
                }
                IpAddr::V6(ip) => {
                    let net = self.config.fake_ip_range6;
                    let n = u128::from(*ip) - u128::from(net.network());
                    ensure!(n >= 2, "reserved fake-IP");
                    map.next6 = map
                        .next6
                        .max(n.checked_add(1).context("saved pool overflow")?);
                }
            }
            // Older versions allocated fake addresses for wire labels that
            // the upstream hostname parser cannot encode. Preserve valid
            // mappings and advance past discarded addresses so cached clients
            // cannot accidentally reach a newly assigned, unrelated hostname.
            if absolute_name(&name).is_err() {
                skipped += 1;
                continue;
            }
            ensure!(
                !map.by_ip.contains_key(ip) && !map.contains_name(&name, ip.is_ipv6()),
                "duplicate saved fake-IP"
            );
            map.insert(Arc::<str>::from(name), *ip);
        }
        while map.len() > map.capacity {
            map.evict();
        }
        map.generation = 0;
        *self.fake.lock().unwrap() = map;
        if skipped != 0 {
            tracing::warn!(
                skipped,
                "ignored unsupported hostnames in saved fake-IP cache; valid mappings retained"
            );
        }
        if outside != 0 {
            tracing::info!(
                dropped = outside,
                "dropped saved fake-IP mappings outside the configured fake-IP ranges"
            );
        }
        Ok(())
    }
    pub fn clear_cache(&self) {
        *self.cache.lock().unwrap() = Cache::default();
        *self.proxy_cache.lock().unwrap() = Cache::default();
        self.reachable.lock().unwrap().clear();
    }
    #[cfg(test)]
    pub(crate) fn seed_test_cache_entry(&self) {
        self.cache.lock().unwrap().insert(
            b"test.example".to_vec(),
            b"cached-dns-response".to_vec(),
            60,
        );
    }
    #[cfg(test)]
    pub(crate) fn cache_entry_count(&self) -> usize {
        self.cache.lock().unwrap().entries.len()
    }
    pub async fn lookup(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        self.lookup_inner(host, port, false).await
    }
    async fn lookup_inner(&self, host: &str, port: u16, proxy: bool) -> Result<Vec<SocketAddr>> {
        let mut host = host.trim_end_matches('.').to_ascii_lowercase();
        // hosts entries come first: a device's LAN address configured for one
        // network wins over its tailnet name (same short name in MagicDNS).
        for depth in 0..16 {
            let Some(values) = self.host_values(&host) else {
                break;
            };
            let ips: Vec<_> = values
                .iter()
                .filter_map(|v| v.parse::<IpAddr>().ok())
                .filter(|ip| ip.is_ipv4() || self.config.ipv6)
                .map(|ip| SocketAddr::new(ip, port))
                .collect();
            if values.iter().all(|v| v.parse::<IpAddr>().is_ok()) {
                return Ok(ips);
            }
            ensure!(
                values.len() == 1 && depth < 15,
                "invalid or cyclic hosts alias"
            );
            host = values[0].trim_end_matches('.').to_ascii_lowercase();
        }
        if !proxy {
            let tailnet = self.tailnet.read().unwrap().clone();
            if let Some(ip) = tailnet.and_then(|names| names(&host)) {
                return Ok(vec![SocketAddr::new(ip, port)]);
            }
        }
        let host = host.as_str();
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let a = self.records_in(host, RecordType::A, proxy);
        let aaaa = async {
            if self.config.ipv6 {
                self.records_in(host, RecordType::AAAA, proxy).await
            } else {
                Ok(vec![])
            }
        };
        tokio::pin!(a, aaaa);
        let (a, aaaa) = tokio::select! {
            a = &mut a => {
                let usable = a
                    .as_ref()
                    .is_ok_and(|records| records.iter().any(|r| matches!(r.data(), RData::A(_))));
                let aaaa = if usable {
                    tokio::time::timeout(AAAA_GRACE, &mut aaaa).await.unwrap_or_else(|_| {
                        tracing::debug!(%host, "AAAA lookup still pending; using the IPv4 answer");
                        Ok(vec![])
                    })
                } else {
                    aaaa.await
                };
                (a, aaaa)
            }
            aaaa = &mut aaaa => (a.await, aaaa),
        };
        let mut addresses = vec![];
        for record in [&a, &aaaa]
            .into_iter()
            .filter_map(|result| result.as_ref().ok())
            .flatten()
        {
            match record.data() {
                RData::A(ip) => addresses.push(SocketAddr::new(IpAddr::V4(ip.0), port)),
                RData::AAAA(ip) => addresses.push(SocketAddr::new(IpAddr::V6(ip.0), port)),
                _ => {}
            }
        }
        if addresses.is_empty() {
            let mut failures = Vec::new();
            if let Err(error) = a {
                failures.push(format!("A: {error:#}"));
            }
            if let Err(error) = aaaa {
                failures.push(format!("AAAA: {error:#}"));
            }
            if failures.is_empty() {
                anyhow::bail!("DNS lookup for {host} returned no addresses");
            }
            anyhow::bail!(
                "DNS lookup for {host} returned no addresses ({})",
                failures.join("; ")
            );
        }
        Ok(addresses)
    }
    async fn records_in(&self, host: &str, kind: RecordType, proxy: bool) -> Result<Vec<Record>> {
        let query = Query::query(absolute_name(host)?, kind);
        let mut request = Message::new();
        request
            .set_id(uuid::Uuid::new_v4().as_u128() as u16)
            .set_recursion_desired(true)
            .add_query(query);
        let response = self.cached_exchange_in(&request, proxy).await?;
        tracing::debug!(
            %host,
            record_type = ?kind,
            response_code = ?response.response_code(),
            answers = response.answers().len(),
            "DNS lookup response"
        );
        ensure!(
            answered(&response),
            "DNS server rejected query ({})",
            response.response_code()
        );
        Ok(response.answers().to_vec())
    }
    fn cache_store(cache: &Mutex<Cache>, key: Vec<u8>, response: &Message) -> Result<()> {
        let ttl = cache_ttl(response);
        if ttl > 0 {
            // Encoders reserve far more than a typical answer needs.
            let bytes = response.to_vec()?;
            cache.lock().unwrap().insert(key, bytes, ttl);
        }
        Ok(())
    }
    async fn cached_exchange(&self, request: &Message) -> Result<Message> {
        self.cached_exchange_in(request, false).await
    }
    async fn cached_exchange_in(&self, request: &Message, proxy: bool) -> Result<Message> {
        let cache = if proxy {
            &self.proxy_cache
        } else {
            &self.cache
        };
        let key = cache_key(request)?;
        loop {
            if let Some(response) = cache.lock().unwrap().get(&key, request.id()) {
                return Ok(response);
            }
            let inflight_key = (proxy, key.clone());
            let role = {
                let mut inflight = self.inflight.lock().unwrap();
                if let Some(rx) = inflight.get(&inflight_key) {
                    Err(rx.clone())
                } else {
                    // Re-check cache under the inflight lock so a leader that
                    // just stored into cache and removed its slot cannot race
                    // with a new caller and trigger a duplicate upstream query.
                    if let Some(response) = cache.lock().unwrap().get(&key, request.id()) {
                        return Ok(response);
                    }
                    let (tx, rx) = tokio::sync::watch::channel(None);
                    inflight.insert(inflight_key.clone(), rx);
                    Ok(InflightGuard {
                        map: &self.inflight,
                        key: Some(inflight_key),
                        tx: Some(tx),
                    })
                }
            };
            match role {
                Ok(guard) => {
                    let result = if proxy {
                        self.race(&self.config.proxy_server_nameserver, request)
                            .await
                    } else {
                        self.exchange(request).await
                    };
                    match result {
                        Ok(response) => {
                            if let Err(error) = Self::cache_store(cache, key, &response) {
                                guard.finish_err(&error);
                                return Err(error);
                            }
                            guard.finish_ok(&response);
                            return Ok(response);
                        }
                        Err(error) => {
                            guard.finish_err(&error);
                            return Err(error);
                        }
                    }
                }
                Err(mut rx) => loop {
                    if let Some(result) = rx.borrow_and_update().clone() {
                        return match result {
                            Ok(mut response) => {
                                response.set_id(request.id());
                                Ok(response)
                            }
                            Err(error) => Err(anyhow::anyhow!(error)),
                        };
                    }
                    if rx.changed().await.is_err() {
                        if let Some(result) = rx.borrow_and_update().clone() {
                            return match result {
                                Ok(mut response) => {
                                    response.set_id(request.id());
                                    Ok(response)
                                }
                                Err(error) => Err(anyhow::anyhow!(error)),
                            };
                        }
                        // Leader was cancelled before finishing; retry.
                        break;
                    }
                },
            }
        }
    }
    async fn exchange(&self, request: &Message) -> Result<Message> {
        let host = request
            .queries()
            .first()
            .map(|q| {
                q.name()
                    .to_ascii()
                    .trim_end_matches('.')
                    .to_ascii_lowercase()
            })
            .unwrap_or_default();
        let policy = self
            .policy
            .read()
            .unwrap()
            .nameservers
            .iter()
            .find(|(m, _)| m.evaluate(&host, None, 0, "", false) == Some(true))
            .map(|(_, v)| v.clone());
        let Some(servers) = policy else {
            return self.race(&self.config.nameserver, request).await;
        };
        self.exchange_policy(&host, &servers, request).await
    }
    /// A policy server is often only reachable on one network (a home LAN
    /// resolver): away from it its names must still resolve, through the
    /// plain nameservers, without waiting out its timeout on every lookup.
    /// Servers that answered on this network are waited for; unknown ones get
    /// a head start; unreachable ones race the nameservers, so they take over
    /// again as soon as they answer first. A reply, even NXDOMAIN, is final.
    async fn exchange_policy(
        &self,
        host: &str,
        servers: &[String],
        request: &Message,
    ) -> Result<Message> {
        let mark = |reachable: bool| {
            let previous = self
                .reachable
                .lock()
                .unwrap()
                .insert(servers.to_vec(), reachable);
            if !reachable && previous != Some(false) {
                tracing::info!(
                    host,
                    servers = ?servers,
                    "[DNS] policy nameservers unreachable on this network; nameserver answers too"
                );
            }
        };
        let head_start = match self.reachable.lock().unwrap().get(servers) {
            Some(true) => None,
            None => Some(POLICY_HEAD_START),
            Some(false) => Some(Duration::ZERO),
        };
        let policy = self.race(servers, request);
        tokio::pin!(policy);
        let early = match head_start {
            None => Some(policy.as_mut().await),
            Some(wait) => tokio::time::timeout(wait, policy.as_mut()).await.ok(),
        };
        let fallback = self.race(&self.config.nameserver, request);
        match early {
            Some(Ok(response)) => {
                mark(true);
                return Ok(response);
            }
            Some(Err(error)) => {
                mark(false);
                return fallback.await.map_err(|fallback| fallback.context(error));
            }
            None => {}
        }
        tokio::pin!(fallback);
        tokio::select! {
            biased;
            result = &mut policy => match result {
                Ok(response) => {
                    mark(true);
                    Ok(response)
                }
                Err(error) => {
                    mark(false);
                    fallback.await.map_err(|fallback| fallback.context(error))
                }
            },
            result = &mut fallback => match result {
                Ok(response) => {
                    mark(false);
                    Ok(response)
                }
                Err(fallback) => {
                    let result = policy.await;
                    mark(result.is_ok());
                    result.map_err(|error| error.context(fallback))
                }
            },
        }
    }
    /// Asks every upstream at once and takes the first answer: trying them
    /// in turn left a lookup waiting out each silent server first. A server
    /// that refuses or fails the query (SERVFAIL, REFUSED, ...) does not end
    /// the race: a broken upstream answers fastest and would hide the working
    /// ones. Its reply is returned only when no other upstream answers.
    async fn race(&self, servers: &[String], request: &Message) -> Result<Message> {
        let mut error = anyhow::anyhow!("no DNS upstream");
        let mut rejected = None;
        let mut pending: futures_util::stream::FuturesUnordered<_> = servers
            .iter()
            .map(|upstream| async move {
                let result = tokio::time::timeout(
                    Duration::from_secs(5),
                    self.query_upstream(upstream, request),
                )
                .await;
                (upstream, result)
            })
            .collect();
        while let Some((upstream, result)) = futures_util::StreamExt::next(&mut pending).await {
            match result {
                Ok(Ok(response)) if answered(&response) => return Ok(response),
                Ok(Ok(response)) => {
                    tracing::debug!(
                        %upstream,
                        response_code = ?response.response_code(),
                        "DNS upstream rejected query; waiting for the others"
                    );
                    error = anyhow::anyhow!(
                        "DNS upstream {upstream} answered {}",
                        response.response_code()
                    );
                    rejected.get_or_insert(response);
                }
                Ok(Err(e)) => {
                    tracing::debug!(%upstream, error = %e, "DNS upstream failed");
                    error = e.context(format!("DNS upstream {upstream}"));
                }
                Err(_) => {
                    tracing::debug!(%upstream, "DNS upstream timed out");
                    error = anyhow::anyhow!("DNS upstream {upstream} timed out");
                }
            }
        }
        rejected.ok_or(error)
    }
    fn first_bootstrap_addr(&self, response: &Message, port: u16) -> Option<SocketAddr> {
        for r in response.answers() {
            match r.data() {
                RData::A(ip) => return Some(SocketAddr::new(IpAddr::V4(ip.0), port)),
                RData::AAAA(ip) if self.config.ipv6 => {
                    return Some(SocketAddr::new(IpAddr::V6(ip.0), port));
                }
                _ => {}
            }
        }
        None
    }
    async fn bootstrap(&self, host: &str, port: u16) -> Result<SocketAddr> {
        if let Ok(ip) = host.parse() {
            return Ok(SocketAddr::new(ip, port));
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        for kind in [RecordType::A, RecordType::AAAA] {
            if kind == RecordType::AAAA && !self.config.ipv6 {
                continue;
            }
            let mut msg = Message::new();
            msg.set_id(uuid::Uuid::new_v4().as_u128() as u16)
                .set_recursion_desired(true)
                .add_query(Query::query(absolute_name(&host)?, kind));
            let key = cache_key(&msg)?;
            if let Some(cached) = self.cache.lock().unwrap().get(&key, msg.id()) {
                if let Some(addr) = self.first_bootstrap_addr(&cached, port) {
                    return Ok(addr);
                }
                continue;
            }
            let mut negative = None;
            for server in &self.config.default_nameserver {
                let (raw, default_port) = if let Some(raw) = server.strip_prefix("tls://") {
                    (raw, 853)
                } else if let Some(raw) = server.strip_prefix("tcp://") {
                    (raw, 53)
                } else {
                    (server.trim_start_matches("udp://"), 53)
                };
                let addr = parse_server(raw, default_port)?;
                let Ok(ip) = addr.host.parse::<IpAddr>() else {
                    continue;
                };
                if let Ok(response) = self.raw_udp(SocketAddr::new(ip, addr.port), &msg).await {
                    if let Some(found) = self.first_bootstrap_addr(&response, port) {
                        let _ = Self::cache_store(&self.cache, key, &response);
                        return Ok(found);
                    }
                    if answered(&response) && negative.is_none() {
                        negative = Some(response);
                    }
                }
            }
            if let Some(response) = negative {
                let _ = Self::cache_store(&self.cache, key, &response);
            }
        }
        anyhow::bail!("DNS bootstrap failed")
    }
    async fn query_upstream(&self, server: &str, request: &Message) -> Result<Message> {
        if server.starts_with("https://") {
            use http_body_util::{BodyExt, Full, Limited};
            let uri: http::Uri = server.parse()?;
            let target = Target::from_uri(&uri, 443)?;
            let addr = self.bootstrap(&target.host, target.port).await?;
            let socket = clyntis_platform::tcp_connect(addr, &*self.hooks).await?;
            let tls = clyntis_protocol::tls::SecureConnector::new(self.clock.clone())
                .connect(
                    Box::new(socket),
                    &clyntis_protocol::tls::TlsConnectConfig {
                        server_name: target.host,
                        alpn: vec!["http/1.1".into()],
                        verify_cert: true,
                        fingerprint: clyntis_protocol::tls::TlsFingerprint::Native,
                        reality: None,
                    },
                )
                .await?;
            let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
                .max_buf_size(16384)
                .handshake(hyper_util::rt::TokioIo::new(tls))
                .await?;
            let _driver = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(connection));
            let path = uri
                .path_and_query()
                .map(|v| v.as_str())
                .unwrap_or("/dns-query");
            let outgoing = http::Request::post(path)
                .header(
                    http::header::HOST,
                    uri.authority().context("DoH authority missing")?.as_str(),
                )
                .header(http::header::CONTENT_TYPE, "application/dns-message")
                .header(http::header::ACCEPT, "application/dns-message")
                .body(Full::new(bytes::Bytes::from(request.to_vec()?)))?;
            let response = sender.send_request(outgoing).await?;
            ensure!(response.status() == http::StatusCode::OK, "DoH HTTP error");
            ensure!(
                response
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v
                        .split(';')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .eq_ignore_ascii_case("application/dns-message")),
                "DoH content type mismatch"
            );
            let body = Limited::new(response.into_body(), 65535)
                .collect()
                .await
                .map_err(anyhow::Error::from_boxed)?
                .to_bytes();
            let response = Message::from_vec(&body)?;
            validate_response(request, &response)?;
            return Ok(response);
        }
        if let Some(raw) = server.strip_prefix("tls://") {
            let target = parse_server(raw, 853)?;
            let addr = self.bootstrap(&target.host, target.port).await?;
            let socket = clyntis_platform::tcp_connect(addr, &*self.hooks).await?;
            let stream = clyntis_protocol::tls::SecureConnector::new(self.clock.clone())
                .connect(
                    Box::new(socket),
                    &clyntis_protocol::tls::TlsConnectConfig {
                        server_name: target.host,
                        alpn: Vec::new(),
                        verify_cert: true,
                        fingerprint: clyntis_protocol::tls::TlsFingerprint::Native,
                        reality: None,
                    },
                )
                .await?;
            return Self::exchange_stream(stream, request).await;
        }
        let tcp = server.starts_with("tcp://");
        let raw = server
            .trim_start_matches("udp://")
            .trim_start_matches("tcp://");
        let target = parse_server(raw, 53)?;
        let addr = self.bootstrap(&target.host, target.port).await?;
        if tcp {
            self.raw_tcp(addr, request).await
        } else {
            let response = self.raw_udp(addr, request).await?;
            if response.truncated() {
                self.raw_tcp(addr, request).await
            } else {
                Ok(response)
            }
        }
    }
    async fn raw_udp(&self, addr: SocketAddr, request: &Message) -> Result<Message> {
        let bind = if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()?;
        let socket = clyntis_platform::udp_bind_for(bind, Some(addr), &*self.hooks)?;
        socket.connect(addr).await?;
        let query = request.to_vec()?;
        // A lost datagram is common on mobile networks: resend after 1 s and
        // 2 s instead of waiting out the whole 3 s on one packet.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            socket.send(&query).await?;
            let resend = (tokio::time::Instant::now() + Duration::from_secs(1)).min(deadline);
            loop {
                match tokio::time::timeout_at(resend, socket.readable()).await {
                    Ok(Ok(())) => match try_recv_dns_message(&socket, request) {
                        Ok(result) => return result,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(e) => return Err(e.into()),
                    },
                    Ok(Err(e)) => return Err(e.into()),
                    Err(_) if resend < deadline => break,
                    Err(elapsed) => return Err(elapsed.into()),
                }
            }
        }
    }
    async fn raw_tcp(&self, addr: SocketAddr, request: &Message) -> Result<Message> {
        let socket = clyntis_platform::tcp_connect(addr, &*self.hooks).await?;
        Self::exchange_stream(socket, request).await
    }
    async fn exchange_stream<S>(mut socket: S, request: &Message) -> Result<Message>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let bytes = request.to_vec()?;
        socket.write_u16(bytes.len() as u16).await?;
        socket.write_all(&bytes).await?;
        let n = socket.read_u16().await?;
        let mut bytes = vec![0; n as usize];
        socket.read_exact(&mut bytes).await?;
        let response = Message::from_vec(&bytes)?;
        validate_response(request, &response)?;
        Ok(response)
    }
    fn is_fake_ip_excluded(&self, host: &str) -> bool {
        self.policy
            .read()
            .unwrap()
            .filters
            .iter()
            .any(|m| m.evaluate(host, None, 0, "", false) == Some(true))
    }
    pub async fn answer(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let request = Message::from_vec(bytes)?;
        ensure!(
            request.message_type() == MessageType::Query
                && request.op_code() == OpCode::Query
                && request.queries().len() == 1,
            "unsupported DNS request"
        );
        let query = &request.queries()[0];
        let host = query
            .name()
            .to_ascii()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        // Ad blocking answers first: the app fails at once instead of connecting.
        if let Some(filter) = self.adblock()
            && let Some(block) = filter.refuses_name(&host)
        {
            self.adblock_stats.record(&host, "dns");
            tracing::debug!(
                host,
                matched = block.matched(),
                "[DNS] ad block refused query"
            );
            let mut response = Message::new();
            response
                .set_id(request.id())
                .set_message_type(MessageType::Response)
                .set_recursion_desired(request.recursion_desired())
                .set_recursion_available(true)
                .add_query(query.clone());
            // `null` answers an unroutable address (other types get no data):
            // some apps retry an NXDOMAIN at once, but give up on 0.0.0.0.
            // Endpoint names stay NXDOMAIN: Firefox's canary and iCloud
            // Private Relay only stand down on a negative answer.
            if !filter.null_answer || block != crate::adblock::Block::List {
                response.set_response_code(ResponseCode::NXDomain);
            } else if let Some(data) = match query.query_type() {
                RecordType::A => Some(RData::A(A(std::net::Ipv4Addr::UNSPECIFIED))),
                RecordType::AAAA => Some(RData::AAAA(AAAA(std::net::Ipv6Addr::UNSPECIFIED))),
                _ => None,
            } {
                response.add_answer(Record::from_rdata(query.name().clone(), 300, data));
            }
            return Ok(response.to_vec()?);
        }
        let mut response = Message::new();
        response
            .set_id(request.id())
            .set_message_type(MessageType::Response)
            .set_recursion_desired(request.recursion_desired())
            .set_recursion_available(true)
            .add_query(query.clone());
        if query.query_class() == DNSClass::IN
            && query.query_type() == RecordType::AAAA
            && !self.config.ipv6
        {
            return Ok(response.to_vec()?);
        }
        if self.host_values(&host).is_some()
            && matches!(query.query_type(), RecordType::A | RecordType::AAAA)
        {
            match self.lookup(&host, 0).await {
                Ok(addresses) => {
                    for addr in addresses {
                        let data = match addr.ip() {
                            IpAddr::V4(ip) if query.query_type() == RecordType::A => {
                                Some(RData::A(A(ip)))
                            }
                            IpAddr::V6(ip) if query.query_type() == RecordType::AAAA => {
                                Some(RData::AAAA(AAAA(ip)))
                            }
                            _ => None,
                        };
                        if let Some(data) = data {
                            response.add_answer(Record::from_rdata(query.name().clone(), 60, data));
                        }
                    }
                }
                Err(_) => {
                    response.set_response_code(ResponseCode::ServFail);
                }
            }
            return Ok(response.to_vec()?);
        }
        if self.config.enhanced_mode == "fake-ip"
            && query.query_class() == DNSClass::IN
            && matches!(query.query_type(), RecordType::A | RecordType::AAAA)
            && !self.is_fake_ip_excluded(&host)
        {
            if absolute_name(&host).is_err() {
                response.set_response_code(ResponseCode::FormErr);
                return Ok(response.to_vec()?);
            }
            let ip = match self.fake_address(&host, query.query_type() == RecordType::AAAA) {
                Ok(ip) => ip,
                Err(_) => {
                    response.set_response_code(ResponseCode::ServFail);
                    return Ok(response.to_vec()?);
                }
            };
            let data = match ip {
                IpAddr::V4(ip) => RData::A(A(ip)),
                IpAddr::V6(ip) => RData::AAAA(AAAA(ip)),
            };
            response.add_answer(Record::from_rdata(query.name().clone(), 60, data));
        } else {
            match self.cached_exchange(&request).await {
                Ok(upstream) => {
                    response = upstream;
                }
                Err(_) => {
                    response.set_response_code(ResponseCode::ServFail);
                }
            }
        }
        Ok(response.to_vec()?)
    }
    pub(crate) fn fake_address(&self, host: &str, v6: bool) -> Result<IpAddr> {
        absolute_name(host).context("unsupported fake-IP hostname")?;
        let mut map = self.fake.lock().unwrap();
        if let Some(ip) = map.get(host, v6) {
            return Ok(ip);
        }
        if map.len() >= map.capacity {
            map.evict();
        }
        let ip = map.allocate(self.config.fake_ip_range, self.config.fake_ip_range6, v6)?;
        map.insert(Arc::<str>::from(host), ip);
        Ok(ip)
    }
}
/// Non-async UDP receive helper keeping the 4 KiB scratch buffer off the
/// `raw_udp` async future state machine and off the heap.
fn try_recv_dns_message(
    socket: &tokio::net::UdpSocket,
    request: &Message,
) -> std::io::Result<Result<Message>> {
    let mut scratch = [std::mem::MaybeUninit::uninit(); 4096];
    let mut buf = tokio::io::ReadBuf::uninit(&mut scratch);
    socket.try_recv_buf(&mut buf)?;
    Ok((|| {
        let response = Message::from_vec(buf.filled())?;
        validate_response(request, &response)?;
        Ok(response)
    })())
}
fn parse_server(server: &str, default: u16) -> Result<Target> {
    if let Ok(ip) = server.parse::<IpAddr>() {
        Target::new(ip.to_string(), default)
    } else if let Ok(target) = Target::parse(server) {
        Ok(target)
    } else {
        Target::new(server, default)
    }
}
fn absolute_name(host: &str) -> Result<Name> {
    let mut name = Name::from_ascii(host)?;
    // Wire names are always absolute; keep the original question equivalent
    // to its decoded response even when configuration omits the final dot.
    name.set_fqdn(true);
    Ok(name)
}

fn validate_response(request: &Message, response: &Message) -> Result<()> {
    ensure!(
        response.id() == request.id()
            && response.message_type() == MessageType::Response
            && response.op_code() == request.op_code()
            && response.queries() == request.queries(),
        "DNS response mismatch"
    );
    Ok(())
}

#[cfg(test)]
mod perf_tests {
    use super::*;
    use hickory_proto::rr::rdata::SOA;
    use std::sync::atomic::AtomicUsize;

    fn make_query(name: &str, id: u16, kind: RecordType) -> Message {
        let mut msg = Message::new();
        msg.set_id(id)
            .set_recursion_desired(true)
            .add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
        msg
    }

    #[tokio::test]
    async fn singleflight_coalesces_concurrent_misses_and_recovers_on_cancel() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = udp.local_addr().unwrap().to_string();
            let hits = Arc::new(AtomicUsize::new(0));
            let hits_server = hits.clone();
            let _server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                let udp = Arc::new(udp);
                let mut buf = [0u8; 4096];
                loop {
                    let (n, peer) = udp.recv_from(&mut buf).await.unwrap();
                    let mut reply = Message::from_vec(&buf[..n]).unwrap();
                    hits_server.fetch_add(1, Ordering::SeqCst);
                    let qname = reply.queries()[0].name().clone();
                    reply
                        .set_message_type(MessageType::Response)
                        .set_recursion_available(true);
                    reply.add_answer(Record::from_rdata(
                        qname,
                        60,
                        RData::A(A("192.0.2.55".parse().unwrap())),
                    ));
                    let udp = udp.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(80)).await;
                        let _ = udp.send_to(&reply.to_vec().unwrap(), peer).await;
                    });
                }
            }));
            let resolver = Arc::new(Resolver::new(
                Dns {
                    nameserver: vec![address],
                    enhanced_mode: "redir-host".into(),
                    ipv6: false,
                    ..Dns::default()
                },
                Arc::new(clyntis_platform::DefaultHooks),
            ));

            // 4 concurrent misses with different IDs coalesce into 1 upstream query.
            let mut tasks = Vec::new();
            for id in 10..14u16 {
                let r = resolver.clone();
                tasks.push(tokio::spawn(async move {
                    let req = make_query("coalesce.test", id, RecordType::A)
                        .to_vec()
                        .unwrap();
                    let raw = r.answer(&req).await.unwrap();
                    (id, Message::from_vec(&raw).unwrap())
                }));
            }
            for task in tasks {
                let (expected_id, reply) = task.await.unwrap();
                assert_eq!(reply.id(), expected_id);
                assert_eq!(
                    reply.answers()[0].data(),
                    &RData::A(A("192.0.2.55".parse().unwrap()))
                );
            }
            assert_eq!(hits.load(Ordering::SeqCst), 1);
            assert!(resolver.inflight.lock().unwrap().is_empty());

            // Leader cancellation frees the inflight slot so follower retries and succeeds.
            let leader = {
                let r = resolver.clone();
                tokio::spawn(async move {
                    let req = make_query("cancel.test", 20, RecordType::A)
                        .to_vec()
                        .unwrap();
                    r.answer(&req).await
                })
            };
            tokio::time::sleep(Duration::from_millis(15)).await;
            let follower = {
                let r = resolver.clone();
                tokio::spawn(async move {
                    let req = make_query("cancel.test", 21, RecordType::A)
                        .to_vec()
                        .unwrap();
                    r.answer(&req).await
                })
            };
            tokio::time::sleep(Duration::from_millis(15)).await;
            leader.abort();
            let reply = Message::from_vec(&follower.await.unwrap().unwrap()).unwrap();
            assert_eq!(reply.id(), 21);
            assert_eq!(
                reply.answers()[0].data(),
                &RData::A(A("192.0.2.55".parse().unwrap()))
            );
            assert!(resolver.inflight.lock().unwrap().is_empty());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn nodata_without_soa_caches_with_fallback_ttl() {
        let mut nodata = Message::new();
        nodata
            .set_message_type(MessageType::Response)
            .set_response_code(ResponseCode::NoError);
        assert_eq!(cache_ttl(&nodata), NEGATIVE_FALLBACK_TTL);

        let mut nodata_zero_soa = nodata.clone();
        nodata_zero_soa.add_name_server(Record::from_rdata(
            Name::from_ascii("test.").unwrap(),
            60,
            RData::SOA(SOA::new(
                Name::from_ascii("ns.test.").unwrap(),
                Name::from_ascii("host.test.").unwrap(),
                1,
                60,
                60,
                60,
                0,
            )),
        ));
        assert_eq!(cache_ttl(&nodata_zero_soa), 0);

        let mut servfail = Message::new();
        servfail
            .set_message_type(MessageType::Response)
            .set_response_code(ResponseCode::ServFail);
        assert_eq!(cache_ttl(&servfail), 0);

        // End-to-end: second lookup of an IPv4-only host hits cached NODATA AAAA.
        tokio::time::timeout(Duration::from_secs(5), async {
            let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = udp.local_addr().unwrap().to_string();
            let aaaa_hits = Arc::new(AtomicUsize::new(0));
            let aaaa_server = aaaa_hits.clone();
            let _server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let (n, peer) = udp.recv_from(&mut buf).await.unwrap();
                    let mut reply = Message::from_vec(&buf[..n]).unwrap();
                    let query = reply.queries()[0].clone();
                    reply
                        .set_message_type(MessageType::Response)
                        .set_response_code(ResponseCode::NoError);
                    if query.query_type() == RecordType::A {
                        reply.add_answer(Record::from_rdata(
                            query.name().clone(),
                            60,
                            RData::A(A("192.0.2.77".parse().unwrap())),
                        ));
                    } else if query.query_type() == RecordType::AAAA {
                        aaaa_server.fetch_add(1, Ordering::SeqCst);
                        // Empty answers, no authority SOA (NODATA).
                    }
                    udp.send_to(&reply.to_vec().unwrap(), peer).await.unwrap();
                }
            }));
            let resolver = Resolver::new(
                Dns {
                    nameserver: vec![address],
                    ipv6: true,
                    ..Dns::default()
                },
                Arc::new(clyntis_platform::DefaultHooks),
            );
            for _ in 0..2 {
                assert_eq!(
                    resolver.lookup("v4only.test", 443).await.unwrap(),
                    vec!["192.0.2.77:443".parse::<SocketAddr>().unwrap()]
                );
            }
            assert_eq!(aaaa_hits.load(Ordering::SeqCst), 1);
        })
        .await
        .unwrap();
    }

    #[test]
    fn cache_tracks_total_bytes_incrementally() {
        let sum = |cache: &Cache| -> usize { cache.entries.values().map(|e| e.size).sum() };
        let mut cache = Cache::default();
        assert_eq!(cache.total_bytes, 0);

        // Insert and overwrite with different payload sizes.
        cache.insert(b"k1".to_vec(), vec![1u8; 100], 60);
        assert_eq!(cache.total_bytes, sum(&cache));
        cache.insert(b"k1".to_vec(), vec![2u8; 250], 60);
        assert_eq!(cache.total_bytes, sum(&cache));
        cache.insert(b"k2".to_vec(), vec![3u8; 150], 60);
        assert_eq!(cache.total_bytes, sum(&cache));

        // Lazy expiry on get decrements total_bytes.
        cache.entries.get_mut(b"k2".as_slice()).unwrap().expires =
            Instant::now() - Duration::from_secs(1);
        assert!(cache.get(b"k2", 1).is_none());
        assert!(!cache.entries.contains_key(b"k2".as_slice()));
        assert_eq!(cache.total_bytes, sum(&cache));

        // Prune expired and byte-limit eviction maintain exact total_bytes.
        let big = vec![0u8; 64 * 1024];
        for i in 0..24u32 {
            cache.insert(format!("big-{i}").into_bytes(), big.clone(), 60);
            assert!(cache.total_bytes <= CACHE_BYTES);
            assert_eq!(cache.total_bytes, sum(&cache));
        }
        for entry in cache.entries.values_mut() {
            entry.expires = Instant::now() - Duration::from_secs(1);
        }
        cache.prune_expired(Instant::now());
        assert_eq!(cache.entries.len(), 0);
        assert_eq!(cache.total_bytes, 0);
    }

    #[tokio::test]
    async fn lookup_proxy_and_bootstrap_use_caches() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = udp.local_addr().unwrap().to_string();
            let hits = Arc::new(AtomicUsize::new(0));
            let hits_server = hits.clone();
            let _server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let (n, peer) = udp.recv_from(&mut buf).await.unwrap();
                    let mut reply = Message::from_vec(&buf[..n]).unwrap();
                    hits_server.fetch_add(1, Ordering::SeqCst);
                    let qname = reply.queries()[0].name().clone();
                    reply.set_message_type(MessageType::Response);
                    reply.add_answer(Record::from_rdata(
                        qname,
                        60,
                        RData::A(A("192.0.2.88".parse().unwrap())),
                    ));
                    udp.send_to(&reply.to_vec().unwrap(), peer).await.unwrap();
                }
            }));
            let resolver = Resolver::new(
                Dns {
                    nameserver: vec!["127.0.0.1:1".into()],
                    proxy_server_nameserver: vec![address.clone()],
                    default_nameserver: vec![address],
                    ipv6: false,
                    ..Dns::default()
                },
                Arc::new(clyntis_platform::DefaultHooks),
            );
            for _ in 0..2 {
                assert_eq!(
                    resolver.lookup_proxy("node.proxy.test", 443).await.unwrap(),
                    vec!["192.0.2.88:443".parse::<SocketAddr>().unwrap()]
                );
            }
            assert_eq!(hits.load(Ordering::SeqCst), 1);
            assert_eq!(resolver.cache.lock().unwrap().entries.len(), 0);
            assert_eq!(resolver.proxy_cache.lock().unwrap().entries.len(), 1);

            for _ in 0..2 {
                assert_eq!(
                    resolver.bootstrap("doh.bootstrap.test", 443).await.unwrap(),
                    "192.0.2.88:443".parse::<SocketAddr>().unwrap()
                );
            }
            assert_eq!(hits.load(Ordering::SeqCst), 2);
            assert_eq!(resolver.cache.lock().unwrap().entries.len(), 1);

            resolver.clear_cache();
            assert_eq!(resolver.cache.lock().unwrap().entries.len(), 0);
            assert_eq!(resolver.proxy_cache.lock().unwrap().entries.len(), 0);
        })
        .await
        .unwrap();
    }

    #[test]
    fn wildcard_hosts_fake_map_arc_and_original_fast_path() {
        let mut config = Dns::default();
        config.enhanced_mode = "redir-host".into();
        let redir = Resolver::new(config, Arc::new(clyntis_platform::DefaultHooks));
        let ip = redir.fake_address("shared.test", false).unwrap();
        // Fast path skips fake map when enhanced_mode != "fake-ip".
        assert_eq!(redir.original(ip), None);

        let resolver = Resolver::new(Dns::default(), Arc::new(clyntis_platform::DefaultHooks));
        let fake_ip = resolver.fake_address("shared.test", false).unwrap();
        assert_eq!(
            resolver.fake_address("shared.test", false).unwrap(),
            fake_ip
        );
        assert_eq!(resolver.original(fake_ip).as_deref(), Some("shared.test"));
        assert_eq!(resolver.original("1.1.1.1".parse().unwrap()), None);
        {
            let map = resolver.fake.lock().unwrap();
            let (name_key, _) = map.by_name[0].get_key_value("shared.test").unwrap();
            let ip_val = map.by_ip.get(&fake_ip).unwrap();
            assert!(Arc::ptr_eq(name_key, ip_val));
        }

        let mut hosts = std::collections::BTreeMap::new();
        hosts.insert(
            "+.example.test".into(),
            clyntis_config::Strings::One("192.0.2.1".into()),
        );
        hosts.insert(
            "+.sub.example.test".into(),
            clyntis_config::Strings::One("192.0.2.2".into()),
        );
        hosts.insert(
            "exact.sub.example.test".into(),
            clyntis_config::Strings::One("192.0.2.3".into()),
        );
        resolver
            .configure(&hosts, None, &crate::resources::Resources::default())
            .unwrap();
        assert_eq!(
            resolver.host_values("a.example.test"),
            Some(vec!["192.0.2.1".into()])
        );
        assert_eq!(
            resolver.host_values("a.sub.example.test"),
            Some(vec!["192.0.2.2".into()])
        );
        assert_eq!(
            resolver.host_values("exact.sub.example.test"),
            Some(vec!["192.0.2.3".into()])
        );
        assert!(resolver.is_fake_ip_excluded("localhost"));
        assert!(resolver.is_fake_ip_excluded("printer.local"));
        assert!(!resolver.is_fake_ip_excluded("example.com"));
    }
}
