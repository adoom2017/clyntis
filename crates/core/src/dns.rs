use anyhow::{Context, Result, ensure};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        DNSClass, Name, RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use meta_config::Dns;
use meta_platform::Hooks;
use meta_protocol::Target;
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{Mutex, RwLock},
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
#[derive(Default)]
struct Cache {
    entries: HashMap<Vec<u8>, CacheEntry>,
    size: usize,
}

/// Fake-IP mappings up to `capacity` names; past it the least recently
/// queried name gives up its mapping. Addresses advance through the whole
/// pool before any is reused, so a client still holding an evicted address
/// reaches nothing rather than an unrelated name.
struct FakeMap {
    /// Address and the use stamp of its latest query.
    by_name: HashMap<(String, bool), (IpAddr, u64)>,
    by_ip: HashMap<IpAddr, String>,
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
            by_name: HashMap::new(),
            by_ip: HashMap::new(),
            order: VecDeque::new(),
            stamp: 0,
            next4: 2,
            next6: 2,
            capacity,
            generation: 0,
        }
    }
    fn get(&mut self, key: &(String, bool)) -> Option<IpAddr> {
        let (ip, stamp) = self.by_name.get_mut(key)?;
        self.stamp += 1;
        *stamp = self.stamp;
        let ip = *ip;
        self.order.push_back((ip, self.stamp));
        if self.order.len() > 2 * self.capacity.max(64) {
            self.compact();
        }
        Some(ip)
    }
    fn insert(&mut self, name: String, ip: IpAddr) {
        self.stamp += 1;
        self.generation += 1;
        self.order.push_back((ip, self.stamp));
        self.by_ip.insert(ip, name.clone());
        self.by_name.insert((name, ip.is_ipv6()), (ip, self.stamp));
    }
    /// Drops the least recently queried mapping.
    fn evict(&mut self) {
        while let Some((ip, stamp)) = self.order.pop_front() {
            let Some(name) = self.by_ip.get(&ip) else {
                continue;
            };
            let key = (name.clone(), ip.is_ipv6());
            if self.by_name.get(&key).is_some_and(|entry| entry.1 == stamp) {
                self.by_name.remove(&key);
                self.by_ip.remove(&ip);
                self.generation += 1;
                return;
            }
        }
    }
    fn compact(&mut self) {
        let mut live: Vec<_> = self.by_name.values().copied().collect();
        live.sort_by_key(|entry| entry.1);
        self.order = live.into();
    }
    /// Names and addresses, least recently queried first.
    fn export(&self) -> Vec<(String, IpAddr)> {
        let mut entries: Vec<_> = self
            .by_name
            .iter()
            .map(|((name, _), (ip, stamp))| (*stamp, name.clone(), *ip))
            .collect();
        entries.sort_by_key(|entry| entry.0);
        entries
            .into_iter()
            .map(|(_, name, ip)| (name, ip))
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
    clock: std::sync::Arc<meta_protocol::tls::Clock>,
    cache: Mutex<Cache>,
    fake: Mutex<FakeMap>,
    policy: RwLock<DnsPolicy>,
    tailnet: RwLock<Option<TailnetNames>>,
    adblock: RwLock<Option<std::sync::Arc<crate::adblock::Filter>>>,
    /// Kept across resource refreshes so counts survive list updates.
    pub(crate) adblock_stats: std::sync::Arc<crate::adblock::Stats>,
}
/// MagicDNS names of the running Tailscale proxies.
pub type TailnetNames = std::sync::Arc<dyn Fn(&str) -> Option<IpAddr> + Send + Sync>;
#[derive(Clone, Default)]
struct DnsPolicy {
    hosts: std::collections::BTreeMap<String, meta_config::Strings>,
    nameservers: Vec<(meta_config::rule::Matcher, Vec<String>)>,
    filters: Vec<meta_config::rule::Matcher>,
}
impl Resolver {
    pub fn new(config: Dns, hooks: Hooks) -> Self {
        Self::new_with_clock(
            config,
            hooks,
            std::sync::Arc::new(meta_protocol::tls::Clock::default()),
        )
    }
    pub fn new_with_clock(
        config: Dns,
        hooks: Hooks,
        clock: std::sync::Arc<meta_protocol::tls::Clock>,
    ) -> Self {
        Self {
            config,
            hooks,
            clock,
            policy: RwLock::new(DnsPolicy::default()),
            tailnet: RwLock::new(None),
            adblock: RwLock::new(None),
            adblock_stats: Default::default(),
            cache: Mutex::new(Cache::default()),
            fake: Mutex::new(FakeMap::new(FAKE_CAPACITY)),
        }
    }
    pub fn clock(&self) -> std::sync::Arc<meta_protocol::tls::Clock> {
        self.clock.clone()
    }
    pub fn configure(
        &self,
        hosts: &std::collections::BTreeMap<String, meta_config::Strings>,
        resources: &crate::resources::Resources,
    ) -> Result<()> {
        *self.adblock.write().unwrap() = resources.adblock.clone();
        fn matcher(
            pattern: &str,
            resources: &crate::resources::Resources,
        ) -> Result<meta_config::rule::Matcher> {
            for (prefix, kind) in [("geosite:", "GEOSITE"), ("rule-set:", "RULE-SET")] {
                if let Some(tags) = pattern.strip_prefix(prefix) {
                    let nodes = tags
                        .split(',')
                        .map(|tag| {
                            resources.bind(&meta_config::rule::Matcher::parse_condition(&format!(
                                "{kind},{tag}"
                            ))?)
                        })
                        .collect::<Result<Vec<_>>>()?;
                    return Ok(meta_config::rule::Matcher::Or(nodes.into()));
                }
            }
            meta_config::rule::domain_pattern(pattern)
        }
        let mut entries: Vec<_> = self.config.nameserver_policy.iter().collect();
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
        let nameservers = entries
            .into_iter()
            .map(|(key, value)| Ok((matcher(key, resources)?, value.values())))
            .collect::<Result<Vec<_>>>()?;
        let filters = self
            .config
            .fake_ip_filter
            .iter()
            .map(|p| matcher(p, resources))
            .collect::<Result<Vec<_>>>()?;
        *self.policy.write().unwrap() = DnsPolicy {
            hosts: hosts.clone(),
            nameservers,
            filters,
        };
        self.clear_cache();
        Ok(())
    }
    /// Real lookups (DIRECT dials, non-fake-ip answers) resolve tailnet names
    /// to their 100.x addresses; fake-ip answers keep the domain for rules.
    pub fn set_tailnet_names(&self, names: Option<TailnetNames>) {
        *self.tailnet.write().unwrap() = names;
    }
    pub(crate) fn adblock(&self) -> Option<std::sync::Arc<crate::adblock::Filter>> {
        self.adblock.read().unwrap().clone()
    }
    pub fn set_hosts(&self, hosts: &std::collections::BTreeMap<String, meta_config::Strings>) {
        self.policy.write().unwrap().hosts = hosts.clone();
    }
    fn host_values(&self, host: &str) -> Option<Vec<String>> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let policy = self.policy.read().unwrap();
        if let Some(v) = policy.hosts.get(&host) {
            return Some(v.values());
        }
        policy
            .hosts
            .iter()
            .filter(|(key, _)| key.contains('*') || key.starts_with('+'))
            .filter(|(key, _)| {
                meta_config::rule::domain_pattern(key)
                    .is_ok_and(|m| m.evaluate(&host, None, 0, "", false) == Some(true))
            })
            .max_by_key(|(key, _)| key.len())
            .map(|(_, v)| v.values())
    }
    pub async fn lookup_proxy(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        if self.config.proxy_server_nameserver.is_empty() {
            return self.lookup(host, port).await;
        }
        let mut config = self.config.clone();
        config.nameserver = config.proxy_server_nameserver.clone();
        config.nameserver_policy.clear();
        let resolver = Self::new_with_clock(config, self.hooks.clone(), self.clock.clone());
        resolver.set_hosts(&self.policy.read().unwrap().hosts);
        resolver.lookup(host, port).await
    }
    pub fn original(&self, ip: IpAddr) -> Option<String> {
        self.fake.lock().unwrap().by_ip.get(&ip).cloned()
    }
    /// An address from the fake-IP pool with no domain behind it, e.g. one a
    /// client cached before the core restarted. Dialing it can only time out.
    pub fn is_unmapped_fake(&self, ip: IpAddr) -> bool {
        self.config.enhanced_mode == "fake-ip"
            && match ip {
                IpAddr::V4(ip) => self.config.fake_ip_range.contains(&ip),
                IpAddr::V6(ip) => self.config.fake_ip_range6.contains(&ip),
            }
            && self.original(ip).is_none()
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
        while map.by_name.len() > map.capacity {
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
        for (name, ip) in entries {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            match ip {
                IpAddr::V4(ip) => {
                    let net = self.config.fake_ip_range;
                    ensure!(
                        net.contains(ip) && *ip != net.broadcast(),
                        "saved fake-IP outside pool"
                    );
                    let n = u64::from(u32::from(*ip)) - u64::from(u32::from(net.network()));
                    ensure!(n >= 2, "reserved fake-IP");
                    map.next4 = map.next4.max(n + 1);
                }
                IpAddr::V6(ip) => {
                    let net = self.config.fake_ip_range6;
                    ensure!(net.contains(ip), "saved fake-IP outside pool");
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
                !map.by_ip.contains_key(ip)
                    && !map.by_name.contains_key(&(name.clone(), ip.is_ipv6())),
                "duplicate saved fake-IP"
            );
            map.insert(name, *ip);
        }
        while map.by_name.len() > map.capacity {
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
        Ok(())
    }
    pub fn clear_cache(&self) {
        *self.cache.lock().unwrap() = Cache::default();
    }
    pub async fn lookup(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        let mut host = host.trim_end_matches('.').to_ascii_lowercase();
        let tailnet = self.tailnet.read().unwrap().clone();
        if let Some(ip) = tailnet.and_then(|names| names(&host)) {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
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
        let host = host.as_str();
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let (a, aaaa) = tokio::join!(self.records(host, RecordType::A), async {
            if self.config.ipv6 {
                self.records(host, RecordType::AAAA).await
            } else {
                Ok(vec![])
            }
        });
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
    async fn records(&self, host: &str, kind: RecordType) -> Result<Vec<Record>> {
        let query = Query::query(absolute_name(host)?, kind);
        let mut request = Message::new();
        request
            .set_id(uuid::Uuid::new_v4().as_u128() as u16)
            .set_recursion_desired(true)
            .add_query(query);
        let response = self.cached_exchange(&request).await?;
        tracing::debug!(
            %host,
            record_type = ?kind,
            response_code = ?response.response_code(),
            answers = response.answers().len(),
            "DNS lookup response"
        );
        ensure!(
            response.response_code() == ResponseCode::NoError
                || response.response_code() == ResponseCode::NXDomain,
            "DNS server rejected query"
        );
        Ok(response.answers().to_vec())
    }
    async fn cached_exchange(&self, request: &Message) -> Result<Message> {
        // Keep EDNS, DNSSEC, recursion flags and query class in the cache key.
        let mut key_request = request.clone();
        key_request.set_id(0);
        let key = key_request.to_vec()?;
        {
            let cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.entries.get(&key)
                && entry.expires > Instant::now()
                && let Ok(mut response) = Message::from_vec(&entry.response)
            {
                response.set_id(request.id());
                let elapsed = entry.inserted.elapsed().as_secs().min(u32::MAX as u64) as u32;
                for record in response.answers_mut().iter_mut() {
                    record.set_ttl(record.ttl().saturating_sub(elapsed));
                }
                for record in response.name_servers_mut().iter_mut() {
                    record.set_ttl(record.ttl().saturating_sub(elapsed));
                }
                for record in response.additionals_mut().iter_mut() {
                    record.set_ttl(record.ttl().saturating_sub(elapsed));
                }
                return Ok(response);
            }
        }
        let response = self.exchange(request).await?;
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
                .unwrap_or(0)
        } else {
            response
                .answers()
                .iter()
                .chain(response.name_servers())
                .chain(response.additionals())
                .map(Record::ttl)
                .min()
                .unwrap_or(0)
        }
        .min(3600);
        if ttl > 0
            && !response.truncated()
            && matches!(
                response.response_code(),
                ResponseCode::NoError | ResponseCode::NXDomain
            )
        {
            // Encoders reserve far more than a typical answer needs.
            let mut bytes = response.to_vec()?;
            bytes.shrink_to_fit();
            let mut key = key;
            key.shrink_to_fit();
            let size = key.len() + bytes.len() + CACHE_OVERHEAD;
            let mut cache = self.cache.lock().unwrap();
            cache
                .entries
                .retain(|_, entry| entry.expires > Instant::now());
            cache.entries.remove(&key);
            cache.size = cache.entries.values().map(|entry| entry.size).sum();
            while cache.entries.len() >= CACHE_ENTRIES || cache.size + size > CACHE_BYTES {
                let Some(oldest) = cache
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.inserted)
                    .map(|(key, _)| key.clone())
                else {
                    break;
                };
                cache.size -= cache.entries.remove(&oldest).unwrap().size;
            }
            if size <= CACHE_BYTES {
                cache.entries.insert(
                    key,
                    CacheEntry {
                        response: bytes,
                        inserted: Instant::now(),
                        expires: Instant::now() + Duration::from_secs(ttl as u64),
                        size,
                    },
                );
                cache.size += size;
            }
        }
        Ok(response)
    }
    async fn exchange(&self, request: &Message) -> Result<Message> {
        let mut error = anyhow::anyhow!("no DNS upstream");
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
        let servers = self
            .policy
            .read()
            .unwrap()
            .nameservers
            .iter()
            .find(|(m, _)| m.evaluate(&host, None, 0, "", false) == Some(true))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| self.config.nameserver.clone());
        for upstream in &servers {
            match tokio::time::timeout(
                Duration::from_secs(5),
                self.query_upstream(upstream, request),
            )
            .await
            {
                Ok(Ok(response)) => return Ok(response),
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
        Err(error)
    }
    async fn bootstrap(&self, host: &str, port: u16) -> Result<SocketAddr> {
        if let Ok(ip) = host.parse() {
            return Ok(SocketAddr::new(ip, port));
        }
        for kind in [RecordType::A, RecordType::AAAA] {
            if kind == RecordType::AAAA && !self.config.ipv6 {
                continue;
            }
            let mut msg = Message::new();
            msg.set_id(uuid::Uuid::new_v4().as_u128() as u16)
                .set_recursion_desired(true)
                .add_query(Query::query(absolute_name(host)?, kind));
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
                    for r in response.answers() {
                        match r.data() {
                            RData::A(ip) => return Ok(SocketAddr::new(IpAddr::V4(ip.0), port)),
                            RData::AAAA(ip) if self.config.ipv6 => {
                                return Ok(SocketAddr::new(IpAddr::V6(ip.0), port));
                            }
                            _ => {}
                        }
                    }
                }
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
            let socket = meta_platform::tcp_connect(addr, &*self.hooks).await?;
            let tls = meta_protocol::tls::SecureConnector::new(self.clock.clone())
                .connect(
                    Box::new(socket),
                    &meta_protocol::tls::TlsConnectConfig {
                        server_name: target.host,
                        alpn: vec!["http/1.1".into()],
                        verify_cert: true,
                        fingerprint: meta_protocol::tls::TlsFingerprint::Native,
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
            let socket = meta_platform::tcp_connect(addr, &*self.hooks).await?;
            let stream = meta_protocol::tls::SecureConnector::new(self.clock.clone())
                .connect(
                    Box::new(socket),
                    &meta_protocol::tls::TlsConnectConfig {
                        server_name: target.host,
                        alpn: Vec::new(),
                        verify_cert: true,
                        fingerprint: meta_protocol::tls::TlsFingerprint::Native,
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
        let socket = meta_platform::udp_bind_for(bind, Some(addr), &*self.hooks)?;
        socket.connect(addr).await?;
        socket.send(&request.to_vec()?).await?;
        let mut bytes = vec![0; 65535];
        let n = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut bytes)).await??;
        let response = Message::from_vec(&bytes[..n])?;
        validate_response(request, &response)?;
        Ok(response)
    }
    async fn raw_tcp(&self, addr: SocketAddr, request: &Message) -> Result<Message> {
        let socket = meta_platform::tcp_connect(addr, &*self.hooks).await?;
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
            && filter.blocks(&host)
        {
            self.adblock_stats.record(&host, "dns");
            let mut response = Message::new();
            response
                .set_id(request.id())
                .set_message_type(MessageType::Response)
                .set_recursion_desired(request.recursion_desired())
                .set_recursion_available(true)
                .set_response_code(ResponseCode::NXDomain)
                .add_query(query.clone());
            return Ok(response.to_vec()?);
        }
        let excluded = self
            .policy
            .read()
            .unwrap()
            .filters
            .iter()
            .any(|m| m.evaluate(&host, None, 0, "", false) == Some(true))
            || self.config.fake_ip_filter.iter().any(|pattern| {
                host == *pattern
                    || pattern.strip_prefix("*.").is_some_and(|suffix| {
                        host == suffix || host.ends_with(&format!(".{suffix}"))
                    })
            });
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
            && !excluded
            && query.query_class() == DNSClass::IN
            && matches!(query.query_type(), RecordType::A | RecordType::AAAA)
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
        let key = (host.to_owned(), v6);
        if let Some(ip) = map.get(&key) {
            return Ok(ip);
        }
        if map.by_name.len() >= map.capacity {
            map.evict();
        }
        let ip = map.allocate(self.config.fake_ip_range, self.config.fake_ip_range6, v6)?;
        map.insert(key.0, ip);
        Ok(ip)
    }
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
