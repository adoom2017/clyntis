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
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Mutex, RwLock},
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(test)]
#[path = "dns_tests.rs"]
mod tests;

struct CacheEntry {
    response: Message,
    inserted: Instant,
    expires: Instant,
    size: usize,
}
#[derive(Default)]
struct Cache {
    entries: HashMap<Vec<u8>, CacheEntry>,
    size: usize,
}
struct FakeMap {
    by_name: HashMap<(String, bool), IpAddr>,
    by_ip: HashMap<IpAddr, String>,
    next4: u64,
    next6: u128,
}
pub struct Resolver {
    pub config: Dns,
    hooks: Hooks,
    clock: std::sync::Arc<meta_protocol::tls::Clock>,
    cache: Mutex<Cache>,
    fake: Mutex<FakeMap>,
    policy: RwLock<DnsPolicy>,
}
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
            cache: Mutex::new(Cache::default()),
            fake: Mutex::new(FakeMap {
                by_name: HashMap::new(),
                by_ip: HashMap::new(),
                next4: 2,
                next6: 2,
            }),
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
    pub fn export_fake(&self) -> Vec<(String, IpAddr)> {
        self.fake
            .lock()
            .unwrap()
            .by_ip
            .iter()
            .map(|(ip, name)| (name.clone(), *ip))
            .collect()
    }
    pub fn import_fake(&self, entries: &[(String, IpAddr)]) -> Result<()> {
        ensure!(entries.len() <= 32768, "saved fake-IP capacity exceeded");
        let mut map = FakeMap {
            by_name: HashMap::new(),
            by_ip: HashMap::new(),
            next4: 2,
            next6: 2,
        };
        for (name, ip) in entries {
            absolute_name(name)?;
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
            ensure!(
                map.by_ip.insert(*ip, name.clone()).is_none()
                    && map.by_name.insert((name, ip.is_ipv6()), *ip).is_none(),
                "duplicate saved fake-IP"
            );
        }
        *self.fake.lock().unwrap() = map;
        Ok(())
    }
    pub fn clear_cache(&self) {
        *self.cache.lock().unwrap() = Cache::default();
    }
    pub async fn lookup(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        let mut host = host.trim_end_matches('.').to_ascii_lowercase();
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
        for r in a.into_iter().chain(aaaa).flatten() {
            match r.data() {
                RData::A(ip) => addresses.push(SocketAddr::new(IpAddr::V4(ip.0), port)),
                RData::AAAA(ip) => addresses.push(SocketAddr::new(IpAddr::V6(ip.0), port)),
                _ => {}
            }
        }
        ensure!(!addresses.is_empty(), "DNS lookup returned no addresses");
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
            {
                let mut response = entry.response.clone();
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
            let size = key.len() + response.to_vec()?.len();
            let mut cache = self.cache.lock().unwrap();
            cache
                .entries
                .retain(|_, entry| entry.expires > Instant::now());
            cache.entries.remove(&key);
            cache.size = cache.entries.values().map(|entry| entry.size).sum();
            while cache.entries.len() >= 4096 || cache.size + size > 8 * 1024 * 1024 {
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
            if size <= 8 * 1024 * 1024 {
                cache.entries.insert(
                    key,
                    CacheEntry {
                        response: response.clone(),
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
                Ok(Err(e)) => error = e,
                Err(e) => error = e.into(),
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
    fn fake_address(&self, host: &str, v6: bool) -> Result<IpAddr> {
        let mut map = self.fake.lock().unwrap();
        let key = (host.into(), v6);
        if let Some(ip) = map.by_name.get(&key) {
            return Ok(*ip);
        }
        ensure!(
            map.by_name.len() < 32768,
            "fake-IP capacity reached; refusing to reuse live mappings"
        );
        let ip = if v6 {
            let net = self.config.fake_ip_range6;
            let address = u128::from(net.network())
                .checked_add(map.next6)
                .context("fake-IP v6 pool exhausted")?;
            let ip = std::net::Ipv6Addr::from(address);
            ensure!(net.contains(&ip), "fake-IP v6 pool exhausted");
            map.next6 += 1;
            IpAddr::V6(ip)
        } else {
            let net = self.config.fake_ip_range;
            let address = u64::from(u32::from(net.network())) + map.next4;
            let ip = std::net::Ipv4Addr::from(
                u32::try_from(address).context("fake-IP v4 pool exhausted")?,
            );
            ensure!(
                net.contains(&ip) && ip != net.broadcast(),
                "fake-IP v4 pool exhausted"
            );
            map.next4 += 1;
            IpAddr::V4(ip)
        };
        map.by_name.insert(key, ip);
        map.by_ip.insert(ip, host.into());
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
