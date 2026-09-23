//! Embeddable proxy core. Runtime and OS policy belong to the host.
mod api;
pub mod dns;
mod inbound;
mod ntp;
mod packet;
mod profile;
mod resources;
mod sniff;
#[cfg(test)]
mod tests;
mod traffic;

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use meta_config::{Config, GroupKind, Mode, ProxyKind, rule::Rule};
use meta_platform::Hooks;
use meta_protocol::{BoxStream, Datagram, Target};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, RwLock, Weak, atomic::AtomicU64},
    time::{Duration, Instant},
};
use tokio::{io::AsyncWriteExt, task::JoinSet};
use tokio_util::sync::CancellationToken;

pub struct Core {
    pub config: Config,
    pub resolver: Arc<dns::Resolver>,
    hooks: Hooks,
    policy: RwLock<Policy>,
    pub stop: CancellationToken,
    connections: Mutex<HashMap<String, Arc<traffic::State>>>,
    pub upload: AtomicU64,
    pub download: AtomicU64,
    slots: Arc<tokio::sync::Semaphore>,
    lifecycle: Mutex<bool>,
    pub events: tokio::sync::broadcast::Sender<String>,
    resources: RwLock<Arc<resources::Resources>>,
    clock: Arc<meta_protocol::tls::Clock>,
    xudp_pool: tokio::sync::Mutex<HashMap<String, Weak<meta_protocol::xudp::Multiplexer>>>,
    xudp_key: [u8; 32],
}
struct Policy {
    mode: Mode,
    rules: Vec<Rule>,
    raw_rules: Vec<String>,
    selection: HashMap<String, String>,
    delay: HashMap<String, u64>,
}
#[derive(Clone, Debug)]
pub(crate) struct RouteDecision {
    pub(crate) node: String,
    pub(crate) group: String,
    pub(crate) rule: String,
}

fn without_last_rule_field<'a>(raw: &'a str, expected: &str) -> &'a str {
    let mut depth = 0usize;
    for (index, character) in raw.char_indices().rev() {
        match character {
            ')' => depth += 1,
            '(' => depth = depth.saturating_sub(1),
            ',' if depth == 0 && raw[index + 1..].trim().eq_ignore_ascii_case(expected) => {
                return raw[..index].trim_end();
            }
            _ => {}
        }
    }
    raw
}

fn describe_rule(raw: &str, target: &str) -> String {
    let raw = without_last_rule_field(raw, "no-resolve");
    let raw = without_last_rule_field(raw, target);
    let Some((kind, value)) = raw.split_once(',') else {
        return if raw.eq_ignore_ascii_case("MATCH") {
            "Match".into()
        } else {
            raw.into()
        };
    };
    let kind = kind.trim();
    let value = value.trim();
    let name = match kind.to_ascii_uppercase().as_str() {
        "DOMAIN" => "Domain",
        "DOMAIN-SUFFIX" => "DomainSuffix",
        "DOMAIN-KEYWORD" => "DomainKeyword",
        "DOMAIN-REGEX" => "DomainRegex",
        "IP-CIDR" => "IPCIDR",
        "IP-CIDR6" => "IPCIDR6",
        "GEOIP" => "GeoIP",
        "GEOSITE" => "GeoSite",
        "RULE-SET" => "RuleSet",
        "DST-PORT" => "DstPort",
        "NETWORK" => "Network",
        "AND" => "And",
        "OR" => "Or",
        "NOT" => "Not",
        _ => kind,
    };
    format!("{name}({value})")
}

#[cfg(test)]
mod connection_log_tests {
    use super::describe_rule;

    #[test]
    fn clash_style_rule_descriptions_preserve_the_match_condition() {
        assert_eq!(describe_rule("MATCH,DIRECT", "DIRECT"), "Match");
        assert_eq!(
            describe_rule("DOMAIN-SUFFIX,chatgpt.com,OpenAI", "OpenAI"),
            "DomainSuffix(chatgpt.com)"
        );
        assert_eq!(
            describe_rule("GEOIP,CN,DIRECT,no-resolve", "DIRECT"),
            "GeoIP(CN)"
        );
        assert_eq!(
            describe_rule("DOMAIN-SUFFIX, example.com, Proxy Group", "Proxy Group"),
            "DomainSuffix(example.com)"
        );
    }
}
#[derive(Clone, Serialize)]
pub struct Connection {
    pub id: String,
    pub metadata: Target,
    pub network: String,
    pub chains: Vec<String>,
    pub upload: u64,
    pub download: u64,
    pub start: String,
    #[serde(skip)]
    pub cancel: CancellationToken,
}
pub struct Running {
    core: Arc<Core>,
    tasks: JoinSet<()>,
    pub addresses: Vec<SocketAddr>,
}
impl Running {
    pub async fn shutdown(mut self) {
        if self.core.save_profile().is_err() {
            tracing::warn!("cannot save profile");
        }
        self.core.stop.cancel();
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
        *self.core.lifecycle.lock().unwrap() = false;
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.core.stop.cancel();
        self.tasks.abort_all();
    }
}
impl Core {
    pub fn new(config: Config, hooks: Hooks) -> Result<Arc<Self>> {
        config.validate()?;
        let mut dns = config.dns.clone();
        dns.ipv6 &= config.ipv6;
        let clock = Arc::new(meta_protocol::tls::Clock::default());
        let resolver = Arc::new(dns::Resolver::new_with_clock(
            dns,
            hooks.clone(),
            clock.clone(),
        ));
        resolver.set_hosts(&config.hosts);
        let mut selection = HashMap::new();
        for group in &config.proxy_groups {
            selection.insert(group.name.clone(), group.proxies[0].clone());
        }
        let rules = config
            .rules
            .iter()
            .map(|r| Rule::parse(r))
            .collect::<Result<Vec<_>>>()?;
        let policy = Policy {
            mode: config.mode.clone(),
            raw_rules: config.rules.clone(),
            rules,
            selection,
            delay: HashMap::new(),
        };
        let (events, _) = tokio::sync::broadcast::channel(256);
        let mut xudp_key = [0; 32];
        xudp_key[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        xudp_key[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        Ok(Arc::new(Self {
            config,
            resolver,
            hooks,
            policy: RwLock::new(policy),
            stop: CancellationToken::new(),
            connections: Default::default(),
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            slots: Arc::new(tokio::sync::Semaphore::new(4096)),
            lifecycle: Mutex::new(false),
            events,
            resources: RwLock::new(Arc::new(resources::Resources::default())),
            clock,
            xudp_pool: Default::default(),
            xudp_key,
        }))
    }
    pub async fn start(self: &Arc<Self>) -> Result<Running> {
        self.start_with_packets(None).await
    }
    pub async fn start_with_packets(
        self: &Arc<Self>,
        packets: Option<Arc<dyn meta_platform::PacketIo>>,
    ) -> Result<Running> {
        ensure!(
            self.config.tun.enable == packets.is_some(),
            "tun.enable requires a host PacketIo; disable TUN for listener-only operation"
        );
        {
            let mut started = self.lifecycle.lock().unwrap();
            ensure!(
                !*started && !self.stop.is_cancelled(),
                "core cannot be started twice; create a new core"
            );
            *started = true;
        }
        let result = self.start_inner(packets).await;
        if result.is_err() {
            self.stop.cancel();
            *self.lifecycle.lock().unwrap() = false;
        }
        result
    }
    async fn start_inner(
        self: &Arc<Self>,
        packets: Option<Arc<dyn meta_platform::PacketIo>>,
    ) -> Result<Running> {
        self.prepare_resources(false).await?;
        self.load_profile()?;
        let mut tasks = JoinSet::new();
        let mut addresses = vec![];
        if self.config.ntp.enable {
            let core = self.clone();
            tasks.spawn(async move{let mut interval=tokio::time::interval(Duration::from_secs(core.config.ntp.interval.saturating_mul(60)));loop{tokio::select!{_=core.stop.cancelled()=>break,_=interval.tick()=>{}}tokio::select!{_=core.stop.cancelled()=>break,result=core.sync_ntp()=>{if result.is_err(){tracing::warn!("NTP synchronization failed; retaining current clock offset");}}}}});
        }
        if self.config.profile.store_fake_ip || self.config.profile.store_selected {
            let core = self.clone();
            tasks.spawn(async move{let mut interval=tokio::time::interval(Duration::from_secs(5));loop{tokio::select!{_=core.stop.cancelled()=>break,_=interval.tick()=>{if core.save_profile().is_err(){tracing::warn!("cannot save profile");}}}}});
        }
        if self.config.geo_auto_update || !self.config.rule_providers.is_empty() {
            let core = self.clone();
            tasks.spawn(async move {
                let seconds=core.config.rule_providers.values().filter(|p|p.interval>0).map(|p|p.interval).chain(std::iter::once(if core.config.geo_auto_update{core.config.geo_update_interval.saturating_mul(3600)}else{86400})).min().unwrap_or(86400).max(1);
                let mut interval=tokio::time::interval(Duration::from_secs(seconds));interval.tick().await;
                loop {tokio::select!{_=core.stop.cancelled()=>break,_=interval.tick()=>{}};tokio::select!{_=core.stop.cancelled()=>break,result=core.prepare_resources(true)=>{if result.is_err(){tracing::warn!("routing resource refresh failed; retaining previous snapshot");}}}}
            });
        }
        if let Some(packets) = packets {
            let core = self.clone();
            tasks.spawn(async move {
                if let Err(error) = packet::run(core.clone(), packets).await {
                    tracing::error!(%error, "packet interface stopped");
                }
                core.stop.cancel();
            });
        }
        let ip = if self.config.allow_lan {
            if self.config.bind_address == "*" {
                "0.0.0.0".parse()?
            } else {
                self.config.bind_address.parse()?
            }
        } else {
            "127.0.0.1".parse()?
        };
        for (port, kind) in [
            (self.config.port, inbound::Kind::Http),
            (self.config.socks_port, inbound::Kind::Socks),
            (self.config.mixed_port, inbound::Kind::Mixed),
        ] {
            if port == 0 {
                continue;
            }
            let address = SocketAddr::new(ip, port);
            let label = match kind {
                inbound::Kind::Http => "HTTP proxy",
                inbound::Kind::Socks => "SOCKS proxy",
                inbound::Kind::Mixed => "mixed HTTP/SOCKS proxy",
            };
            let listener = tokio::net::TcpListener::bind(address)
                .await
                .with_context(|| format!("cannot bind {label} TCP listener at {address}"))?;
            addresses.push(listener.local_addr()?);
            let core = self.clone();
            tasks.spawn(async move {
                inbound::serve(core, listener, kind).await;
            });
        }
        if self.config.dns.enable {
            let address = &self.config.dns.listen;
            let udp = tokio::net::UdpSocket::bind(address)
                .await
                .with_context(|| format!("cannot bind DNS UDP listener at {address}"))?;
            let tcp = tokio::net::TcpListener::bind(address)
                .await
                .with_context(|| format!("cannot bind DNS TCP listener at {address}"))?;
            let core = self.clone();
            tasks.spawn(async move {
                inbound::dns_udp(core, udp).await;
            });
            let core = self.clone();
            tasks.spawn(async move {
                inbound::dns_tcp(core, tcp).await;
            });
        }
        if let Some(addr) = &self.config.external_controller {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("cannot bind controller TCP listener at {addr}"))?;
            let core = self.clone();
            let stop = self.stop.clone();
            tasks.spawn(async move {
                let _ = axum::serve(listener, api::router(core))
                    .with_graceful_shutdown(stop.cancelled_owned())
                    .await;
            });
        }
        for group in self
            .config
            .proxy_groups
            .iter()
            .filter(|g| g.kind == GroupKind::UrlTest)
        {
            let group = group.clone();
            let core = self.clone();
            tasks.spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(group.interval));
                loop {
                    tokio::select! {_=core.stop.cancelled()=>break,_=interval.tick()=>{}}
                    let mut best = None;
                    for target in &group.proxies {
                        if let Ok(delay) =
                            core.probe(target, &group.url, Duration::from_secs(5)).await
                            && best.as_ref().is_none_or(|(_, d)| delay < *d)
                        {
                            best = Some((target.clone(), delay));
                        }
                    }
                    if let Some((target, delay)) = best {
                        let mut policy = core.policy.write().unwrap();
                        let old = policy
                            .selection
                            .get(&group.name)
                            .and_then(|n| policy.delay.get(n))
                            .copied()
                            .unwrap_or(u64::MAX);
                        if delay.saturating_add(group.tolerance) < old {
                            policy.selection.insert(group.name.clone(), target);
                        }
                    }
                }
            });
        }
        Ok(Running {
            core: self.clone(),
            tasks,
            addresses,
        })
    }
    pub fn restore_target(&self, target: &Target) -> Target {
        if let Some(name) = target.ip().and_then(|ip| self.resolver.original(ip)) {
            Target {
                host: name,
                port: target.port,
            }
        } else {
            target.clone()
        }
    }
    pub async fn prepare_resources(&self, refresh: bool) -> Result<()> {
        let mut config = self.config.clone();
        config.rules = self.policy.read().unwrap().raw_rules.clone();
        let next = Arc::new(
            resources::Resources::load(&config, &self.resolver, &self.hooks, refresh).await?,
        );
        let mut resources = self.resources.write().unwrap();
        let mut policy = self.policy.write().unwrap();
        let rules = next.rules(&policy.raw_rules)?;
        self.resolver.configure(&config.hosts, &next)?;
        policy.rules = rules;
        *resources = next;
        Ok(())
    }
    pub(crate) async fn route_decision(
        &self,
        target: &Target,
        network: &str,
    ) -> Result<RouteDecision> {
        let (mode, rules, raw_rules) = {
            let p = self.policy.read().unwrap();
            (p.mode.clone(), p.rules.clone(), p.raw_rules.clone())
        };
        if mode == Mode::Direct {
            return Ok(RouteDecision {
                node: "DIRECT".into(),
                group: "DIRECT".into(),
                rule: "Mode(Direct)".into(),
            });
        }
        if mode == Mode::Global {
            return Ok(RouteDecision {
                node: self.leaf("GLOBAL")?,
                group: "GLOBAL".into(),
                rule: "Mode(Global)".into(),
            });
        }
        let mut ip = target.ip();
        let mut resolved = ip.is_some();
        let host = target.host.trim_end_matches('.').to_ascii_lowercase();
        for (index, rule) in rules.into_iter().enumerate() {
            let matched = rule.matcher.evaluate(
                &host,
                ip,
                target.port,
                network,
                !rule.no_resolve && !resolved,
            );
            if matched.is_none() && !rule.no_resolve && !resolved {
                ip = self
                    .resolver
                    .lookup(&target.host, target.port)
                    .await
                    .ok()
                    .and_then(|v| v.first().map(SocketAddr::ip));
                resolved = true;
            }
            if matched == Some(true)
                || (matched.is_none() && rule.matches(&host, ip, target.port, network))
            {
                return Ok(RouteDecision {
                    node: self.leaf(&rule.target)?,
                    group: rule.target.clone(),
                    rule: raw_rules
                        .get(index)
                        .map(|raw| describe_rule(raw, &rule.target))
                        .unwrap_or_else(|| "Match".into()),
                });
            }
        }
        Ok(RouteDecision {
            node: "DIRECT".into(),
            group: "DIRECT".into(),
            rule: "Fallback".into(),
        })
    }
    #[cfg(test)]
    async fn route(&self, target: &Target, network: &str) -> Result<String> {
        Ok(self.route_decision(target, network).await?.node)
    }
    fn leaf(&self, name: &str) -> Result<String> {
        let policy = self.policy.read().unwrap();
        let mut name = name.to_owned();
        if name == "GLOBAL" {
            name = self
                .config
                .proxy_groups
                .first()
                .map(|g| g.name.clone())
                .or_else(|| self.config.proxies.first().map(|p| p.name.clone()))
                .unwrap_or("DIRECT".into());
        }
        for _ in 0..=self.config.proxy_groups.len() {
            if let Some(selected) = policy.selection.get(&name) {
                name = selected.clone();
            } else {
                return Ok(name);
            }
        }
        bail!("group cycle")
    }
    pub fn select(&self, group: &str, name: &str) -> Result<()> {
        let config = self
            .config
            .proxy_groups
            .iter()
            .find(|g| g.name == group)
            .context("group not found")?;
        ensure!(
            config.proxies.iter().any(|p| p == name),
            "node not in group"
        );
        self.policy
            .write()
            .unwrap()
            .selection
            .insert(group.into(), name.into());
        self.save_profile()?;
        Ok(())
    }
    pub fn set_mode(&self, mode: Mode) {
        self.policy.write().unwrap().mode = mode;
    }
    pub fn replace_rules(&self, rules: Vec<String>) -> Result<()> {
        self.update_policy(None, Some(rules))
    }
    pub fn update_policy(&self, mode: Option<Mode>, rules: Option<Vec<String>>) -> Result<()> {
        let update_rules = rules.is_some();
        let mut cfg = self.config.clone();
        if let Some(rules) = rules {
            cfg.rules = rules;
        } else {
            cfg.rules = self.policy.read().unwrap().raw_rules.clone();
        }
        if let Some(mode) = &mode {
            cfg.mode = mode.clone();
        }
        cfg.validate()?;
        let rules = self.resources.read().unwrap().rules(&cfg.rules)?;
        let mut policy = self.policy.write().unwrap();
        if update_rules {
            policy.rules = rules;
            policy.raw_rules = cfg.rules;
        }
        if let Some(mode) = mode {
            policy.mode = mode;
        }
        Ok(())
    }
    pub fn configuration(&self) -> serde_json::Value {
        let mut config = serde_json::to_value(&self.config).unwrap();
        let policy = self.policy.read().unwrap();
        config["mode"] = serde_json::to_value(&policy.mode).unwrap();
        config["rules"] = serde_json::to_value(&policy.raw_rules).unwrap();
        config
    }
    async fn raw_tcp(&self, target: &Target) -> Result<tokio::net::TcpStream> {
        let addresses = self.resolver.lookup(&target.host, target.port).await?;
        let stream = self.connect_addresses(addresses, false, "").await?;
        if let (Ok(local), Ok(remote)) = (stream.local_addr(), stream.peer_addr()) {
            tracing::info!(
                "[OUTBOUND] {} --> {} using DIRECT for {}",
                local,
                remote,
                target
            );
        }
        Ok(stream)
    }
    async fn connect_addresses(
        &self,
        mut addresses: Vec<SocketAddr>,
        tfo: bool,
        ip_version: &str,
    ) -> Result<tokio::net::TcpStream> {
        match ip_version {
            "ipv4" => addresses.retain(SocketAddr::is_ipv4),
            "ipv6" => addresses.retain(SocketAddr::is_ipv6),
            "ipv4-prefer" => addresses.sort_by_key(|a| a.is_ipv6()),
            "ipv6-prefer" => addresses.sort_by_key(|a| a.is_ipv4()),
            _ => {}
        }
        addresses.truncate(32);
        if self.config.tcp_concurrent {
            use futures_util::{StreamExt, stream::FuturesUnordered};
            let mut attempts = FuturesUnordered::new();
            for (index, addr) in addresses.into_iter().enumerate() {
                attempts.push(async move {
                    if index > 0 {
                        tokio::time::sleep(Duration::from_millis(50 * index as u64)).await;
                    }
                    tokio::time::timeout(
                        Duration::from_secs(5),
                        meta_platform::tcp_connect_options(
                            addr,
                            &*self.hooks,
                            self.config.keep_alive_interval,
                            tfo,
                        ),
                    )
                    .await
                });
            }
            while let Some(result) = attempts.next().await {
                if let Ok(Ok(stream)) = result {
                    return Ok(stream);
                }
            }
            bail!("all concurrent connection attempts failed");
        }
        let mut last = anyhow::anyhow!("no destination address");
        for addr in addresses {
            match tokio::time::timeout(
                Duration::from_secs(5),
                meta_platform::tcp_connect_options(
                    addr,
                    &*self.hooks,
                    self.config.keep_alive_interval,
                    tfo,
                ),
            )
            .await
            {
                Ok(Ok(s)) => return Ok(s),
                Ok(Err(e)) => last = e,
                Err(e) => last = e.into(),
            }
        }
        Err(last)
    }
    async fn vless_stream(
        &self,
        proxy: &meta_config::Proxy,
        target: &Target,
        command: u8,
    ) -> Result<BoxStream> {
        let mut addresses = self
            .resolver
            .lookup_proxy(&proxy.server, proxy.port)
            .await?;
        addresses.truncate(32);
        let mut last = anyhow::anyhow!("no destination address");
        while !addresses.is_empty() {
            let socket = match self
                .connect_addresses(addresses.clone(), proxy.tfo, &proxy.ip_version)
                .await
            {
                Ok(socket) => socket,
                Err(error) => return Err(error),
            };
            let local = socket.local_addr().ok();
            let peer = socket.peer_addr().ok();
            if let (Some(local), Some(remote)) = (local, peer) {
                tracing::info!(
                    "[OUTBOUND] {} --> {} connecting {}({}:{}) for {}",
                    local,
                    remote,
                    proxy.name,
                    proxy.server,
                    proxy.port,
                    target
                );
            }
            match meta_protocol::vless::connect_with_options(
                socket,
                proxy,
                target,
                command,
                &self.config.global_client_fingerprint,
                self.clock.clone(),
            )
            .await
            {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    if let Some(remote) = peer {
                        tracing::warn!(
                            "[OUTBOUND] {} handshake failed using {} for {}: {:#}",
                            remote,
                            proxy.name,
                            target,
                            error
                        );
                    }
                    last = error;
                }
            }
            if let Some(peer) = peer {
                addresses.retain(|address| *address != peer);
            } else {
                addresses.remove(0);
            }
        }
        Err(last)
    }
    pub async fn dial(
        &self,
        target: &Target,
        selected: Option<&str>,
    ) -> Result<(BoxStream, String)> {
        let (stream, decision) = tokio::select! {
            biased;
            _ = self.stop.cancelled() => bail!("core stopped"),
            result = tokio::time::timeout(Duration::from_secs(20), self.dial_inner(target, selected, "tcp")) => result??,
        };
        Ok((stream, decision.node))
    }
    pub(crate) async fn dial_logged(
        &self,
        target: &Target,
        selected: Option<&str>,
        source: &str,
    ) -> Result<(BoxStream, String)> {
        let display_target = self.restore_target(target);
        let (stream, decision) = tokio::select! {
            biased;
            _ = self.stop.cancelled() => bail!("core stopped"),
            result = tokio::time::timeout(Duration::from_secs(20), self.dial_inner(&display_target, selected, "tcp")) => result??,
        };
        Self::log_connection("TCP", source, &display_target, &decision);
        Ok((stream, decision.node))
    }
    pub(crate) fn log_connection(
        network: &str,
        source: &str,
        target: &Target,
        decision: &RouteDecision,
    ) {
        let using = if decision.group == decision.node {
            decision.node.clone()
        } else {
            format!("{}[{}]", decision.group, decision.node)
        };
        tracing::info!(
            "[{}] {} --> {} match {} using {}",
            network,
            source,
            target,
            decision.rule,
            using
        );
    }
    async fn dial_inner(
        &self,
        target: &Target,
        selected: Option<&str>,
        network: &str,
    ) -> Result<(BoxStream, RouteDecision)> {
        let target = self.restore_target(target);
        let decision = match selected {
            Some(n) => RouteDecision {
                node: self.leaf(n)?,
                group: n.into(),
                rule: "Selected".into(),
            },
            None => self.route_decision(&target, network).await?,
        };
        let name = &decision.node;
        let stream = tokio::time::timeout(Duration::from_secs(20), async {
            if name == "DIRECT" {
                return Ok::<BoxStream, anyhow::Error>(Box::new(self.raw_tcp(&target).await?));
            }
            if name == "REJECT" {
                bail!("connection rejected");
            }
            let p = self
                .config
                .proxies
                .iter()
                .find(|p| p.name == name.as_str())
                .context("proxy not found")?;
            match p.kind {
                ProxyKind::Vless => self.vless_stream(p, &target, 1).await,
                ProxyKind::Hysteria2 | ProxyKind::Trojan => {
                    bail!("configured outbound protocol is unavailable in this build")
                }
            }
        })
        .await??;
        Ok((stream, decision))
    }
    pub async fn datagram(self: &Arc<Self>, target: &Target) -> Result<Arc<dyn Datagram>> {
        self.datagram_with_global_id(target, None, None).await
    }
    pub(crate) async fn datagram_for_source(
        self: &Arc<Self>,
        target: &Target,
        source: &str,
    ) -> Result<Arc<dyn Datagram>> {
        let mut digest = Sha256::new();
        digest.update(self.xudp_key);
        digest.update(source.as_bytes());
        let digest = digest.finalize();
        let mut global_id = [0; 8];
        global_id.copy_from_slice(&digest[..8]);
        self.datagram_with_global_id(target, Some(global_id), Some(source))
            .await
    }
    async fn datagram_with_global_id(
        self: &Arc<Self>,
        target: &Target,
        global_id: Option<[u8; 8]>,
        source: Option<&str>,
    ) -> Result<Arc<dyn Datagram>> {
        let target = self.restore_target(target);
        tokio::select! {
            biased;
            _=self.stop.cancelled()=>bail!("core stopped"),
            result=tokio::time::timeout(Duration::from_secs(20),async {
                let decision=self.route_decision(&target,"udp").await?;
                let inner=self.datagram_inner(&target,&decision.node,global_id).await?;
                if let Some(source)=source {
                    let source=source.split_once(':').map(|(_,value)|value).unwrap_or(source);
                    Self::log_connection("UDP",source,&target,&decision);
                }
                Ok::<Arc<dyn Datagram>,anyhow::Error>(Arc::new(traffic::PacketSession {
                    inner,tracker:traffic::Tracker::new(self.clone(),target,decision.node,"udp")?
                }))
            })=>result?,
        }
    }
    async fn datagram_inner(
        &self,
        target: &Target,
        name: &str,
        global_id: Option<[u8; 8]>,
    ) -> Result<Arc<dyn Datagram>> {
        if name == "REJECT" {
            bail!("UDP rejected");
        }
        if name == "DIRECT" {
            let remote = self
                .resolver
                .lookup(&target.host, target.port)
                .await?
                .into_iter()
                .next()
                .context("no UDP address")?;
            let bind = if remote.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            }
            .parse()?;
            let socket = meta_platform::udp_bind_for(bind, Some(remote), &*self.hooks)?;
            socket.connect(remote).await?;
            if let Ok(local) = socket.local_addr() {
                tracing::info!(
                    "[OUTBOUND/UDP] {} --> {} using DIRECT for {}",
                    local,
                    remote,
                    target
                );
            }
            return Ok(Arc::new(DirectUdp {
                socket,
                target: target.clone(),
            }));
        }
        let proxy = self
            .config
            .proxies
            .iter()
            .find(|p| p.name == name)
            .context("proxy not found")?;
        ensure!(proxy.udp, "UDP disabled");
        match proxy.kind {
            ProxyKind::Vless => {
                let xudp = proxy.xudp
                    || proxy.packet_encoding.as_deref() == Some("xudp")
                    || proxy.flow == "xtls-rprx-vision";
                if xudp {
                    let multiplexer = {
                        let mut pool = self.xudp_pool.lock().await;
                        pool.retain(|_, weak| weak.upgrade().is_some_and(|mux| mux.is_alive()));
                        if let Some(mux) = pool.get(name).and_then(Weak::upgrade) {
                            mux
                        } else {
                            let stream = self.vless_stream(proxy, target, 3).await?;
                            let mux = meta_protocol::xudp::Multiplexer::new(stream);
                            pool.insert(name.to_owned(), Arc::downgrade(&mux));
                            mux
                        }
                    };
                    Ok(Arc::new(multiplexer.session(target.clone(), global_id)?))
                } else {
                    let stream = self.vless_stream(proxy, target, 2).await?;
                    Ok(Arc::new(meta_protocol::vless::UdpSession::new(
                        stream,
                        target.clone(),
                    )))
                }
            }
            ProxyKind::Hysteria2 | ProxyKind::Trojan => {
                bail!("configured outbound protocol is unavailable in this build")
            }
        }
    }
    pub async fn relay(
        self: &Arc<Self>,
        inbound: BoxStream,
        target: Target,
        outbound: BoxStream,
        node: String,
    ) -> Result<()> {
        self.relay_io(inbound, target, outbound, node).await
    }
    pub(crate) async fn relay_io<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        self: &Arc<Self>,
        mut inbound: S,
        target: Target,
        outbound: BoxStream,
        node: String,
    ) -> Result<()> {
        let tracker = traffic::Tracker::new(self.clone(), target, node, "tcp")?;
        let cancel = tracker.cancel();
        let mut outbound = traffic::Stream {
            inner: outbound,
            tracker,
        };
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        let state = outbound.tracker.state.clone();
        let idle = async {
            loop {
                interval.tick().await;
                if state.idle() >= Duration::from_secs(300) {
                    break;
                }
            }
        };
        tokio::select! {
            _=cancel.cancelled()=>{},
            _=idle=>{},
            result=tokio::io::copy_bidirectional(&mut inbound,&mut outbound)=>{result?;},
        }
        Ok(())
    }
    pub fn connections(&self) -> Vec<Connection> {
        self.connections
            .lock()
            .unwrap()
            .values()
            .map(|s| s.snapshot())
            .collect()
    }
    pub fn close_connection(&self, id: &str) {
        if let Some(c) = self.connections.lock().unwrap().get(id) {
            c.snapshot().cancel.cancel();
        }
    }
    pub async fn network_changed(&self) {
        for connection in self.connections() {
            connection.cancel.cancel();
        }
        self.resolver.clear_cache();
    }
    pub async fn probe(&self, name: &str, url: &str, timeout: Duration) -> Result<u64> {
        let start = Instant::now();
        let mut measured = start;
        let operation = async {
            let uri: http::Uri = url.parse()?;
            let secure = uri.scheme_str() == Some("https");
            ensure!(
                secure || uri.scheme_str() == Some("http"),
                "test URL must use HTTP(S)"
            );
            let target = Target::from_uri(&uri, if secure { 443 } else { 80 })?;
            let (stream, _) = self.dial(&target, Some(name)).await?;
            let mut stream: BoxStream = if secure {
                meta_protocol::tls::SecureConnector::new(self.clock.clone())
                    .connect(
                        stream,
                        &meta_protocol::tls::TlsConnectConfig {
                            server_name: target.host.clone(),
                            alpn: vec!["http/1.1".into()],
                            verify_cert: true,
                            fingerprint: meta_protocol::tls::TlsFingerprint::Native,
                            reality: None,
                        },
                    )
                    .await?
            } else {
                stream
            };
            if self.config.unified_delay {
                measured = Instant::now();
            }
            let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
            stream
                .write_all(
                    format!("GET {path} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await?;
            let mut byte = [0; 12];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut byte).await?;
            ensure!(&byte[..5] == b"HTTP/", "invalid health response");
            Ok::<_, anyhow::Error>(())
        };
        tokio::select! {
            biased;
            _ = self.stop.cancelled() => bail!("core stopped"),
            result = tokio::time::timeout(timeout, operation) => result??,
        }
        let elapsed = measured.elapsed().as_millis() as u64;
        self.policy
            .write()
            .unwrap()
            .delay
            .insert(name.into(), elapsed);
        Ok(elapsed)
    }
}
struct DirectUdp {
    socket: tokio::net::UdpSocket,
    target: Target,
}
#[async_trait]
impl Datagram for DirectUdp {
    async fn send(&self, target: &Target, bytes: &[u8]) -> Result<()> {
        ensure!(target == &self.target, "UDP target changed");
        self.socket.send(bytes).await?;
        Ok(())
    }
    async fn recv(&self) -> Result<(Target, Vec<u8>)> {
        let mut bytes = vec![0; 65535];
        let n = self.socket.recv(&mut bytes).await?;
        bytes.truncate(n);
        Ok((self.target.clone(), bytes))
    }
}
