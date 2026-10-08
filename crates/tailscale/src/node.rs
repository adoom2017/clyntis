//! The node: logs in, follows the network map, and opens TCP connections to
//! tailnet addresses and MagicDNS names.
use crate::{
    Dialer,
    control::{Control, ServerUrl},
    key::{NodeKey, Private, State},
    magic::{self, Peer, Routes},
    netstack,
    tailcfg::{
        self, CAPABILITY_VERSION, DerpMap, Hostinfo, MapRequest, MapResponse, NetInfo,
        RegisterAuth, RegisterRequest,
    },
};
use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use meta_protocol::BoxStream;
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

/// The `type: tailscale` proxy options (mihomo's field names).
#[derive(Clone, Debug)]
pub struct Options {
    pub name: String,
    pub auth_key: Option<String>,
    pub hostname: String,
    pub control_url: String,
    pub state_path: PathBuf,
    pub ephemeral: bool,
    pub accept_routes: bool,
    pub exit_node: Option<String>,
    pub os: String,
}

#[derive(Default)]
struct NetMap {
    me: Option<tailcfg::Node>,
    peers: BTreeMap<i64, tailcfg::Node>,
    derp: DerpMap,
    domain: String,
}
impl NetMap {
    fn apply(&mut self, map: MapResponse) {
        if let Some(node) = map.node {
            self.me = Some(node);
        }
        if let Some(derp) = map.derp_map {
            self.derp = derp;
        }
        if !map.domain.is_empty() {
            self.domain = map.domain;
        }
        if let Some(peers) = map.peers {
            self.peers = peers.into_iter().map(|p| (p.id, p)).collect();
        }
        for peer in map.peers_changed {
            self.peers.insert(peer.id, peer);
        }
        for id in map.peers_removed {
            self.peers.remove(&id);
        }
        for patch in map.peers_changed_patch {
            if let Some(peer) = self.peers.get_mut(&patch.node_id) {
                if patch.derp_region != 0 {
                    peer.home_derp = patch.derp_region;
                }
                if let Some(key) = patch.key {
                    peer.key = key;
                }
                if let Some(key) = patch.disco_key {
                    peer.disco_key = key;
                }
                if patch.online.is_some() {
                    peer.online = patch.online;
                }
                if let Some(endpoints) = patch.endpoints {
                    peer.endpoints = endpoints;
                }
            }
        }
        for (id, online) in map.online_change {
            if let Some(peer) = id.parse().ok().and_then(|id: i64| self.peers.get_mut(&id)) {
                peer.online = Some(online);
            }
        }
    }

    fn find(&self, name: &str) -> Option<&tailcfg::Node> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        self.peers.values().chain(self.me.iter()).find(|node| {
            let fqdn = node.fqdn().to_ascii_lowercase();
            fqdn == name
                || fqdn.split('.').next() == Some(name.as_str())
                || (!node.computed_name.is_empty()
                    && node.computed_name.eq_ignore_ascii_case(&name))
        })
    }

    fn routes(&self, options: &Options, home: u32) -> Routes {
        let exit = options.exit_node.as_deref().and_then(|wanted| {
            let ip: Option<IpAddr> = wanted.parse().ok();
            self.peers.values().find(|peer| match ip {
                Some(ip) => peer.addresses.iter().any(|a| a.addr() == ip),
                None => self.find(wanted).is_some_and(|found| found.id == peer.id),
            })
        });
        let mut table = Vec::new();
        let mut peers = std::collections::HashMap::new();
        for node in self.peers.values() {
            if node.key.is_zero() || node.expired {
                continue;
            }
            let peer = Peer {
                key: node.key,
                region: node.derp_region(),
                disco: node.disco_key,
                endpoints: node
                    .endpoints
                    .iter()
                    .filter_map(|e| e.parse().ok())
                    .collect(),
            };
            peers.insert(node.key, peer.clone());
            for net in node.allowed() {
                let own = node.addresses.contains(net);
                let default = net.prefix_len() == 0;
                let exit_route = default && exit.is_some_and(|e| e.id == node.id);
                if own || exit_route || (!default && options.accept_routes) {
                    table.push((*net, peer.clone()));
                }
            }
        }
        table.sort_by_key(|(net, _)| std::cmp::Reverse(net.prefix_len()));
        Routes {
            table,
            peers,
            derp: self.derp.clone(),
            home,
        }
    }
}

struct Inner {
    options: Options,
    dialer: Arc<dyn Dialer>,
    netmap: Mutex<NetMap>,
    routes: watch::Sender<Routes>,
    ready: watch::Sender<Option<String>>,
    stack: netstack::Handle,
    disco: Private,
    endpoints: watch::Receiver<magic::Endpoints>,
}

/// A running Tailscale node. Dropping the last handle does not stop it;
/// cancel the token passed to [`Node::start`].
#[derive(Clone)]
pub struct Node {
    inner: Arc<Inner>,
}

impl Node {
    pub fn start(
        options: Options,
        dialer: Arc<dyn Dialer>,
        stop: CancellationToken,
    ) -> Result<Self> {
        ServerUrl::parse(&options.control_url)?;
        let state = State::load_or_create(&options.state_path)?;
        let (routes, routes_rx) = watch::channel(Routes::default());
        let (ready, _) = watch::channel(None);
        let (commands, commands_rx) = mpsc::channel(64);
        let (to_router, from_stack) = mpsc::channel(1024);
        let (to_stack, from_router) = mpsc::channel(1024);
        tokio::spawn(netstack::run(
            commands_rx,
            from_router,
            to_router,
            stop.clone(),
        ));
        // One disco key for the node's lifetime: peers learn it from the map.
        let disco = Private::generate();
        let (endpoints, endpoints_rx) = watch::channel(Vec::new());
        tokio::spawn(magic::run(
            state.node.clone(),
            disco.clone(),
            dialer.clone(),
            routes_rx,
            from_stack,
            to_stack,
            endpoints,
            stop.clone(),
        ));
        let node = Self {
            inner: Arc::new(Inner {
                options,
                dialer,
                netmap: Mutex::new(NetMap::default()),
                routes,
                ready,
                stack: netstack::Handle { commands },
                disco,
                endpoints: endpoints_rx,
            }),
        };
        let inner = node.inner.clone();
        tokio::spawn(async move {
            let mut state = state;
            let mut backoff = Duration::from_secs(2);
            loop {
                let result = tokio::select! {
                    _ = stop.cancelled() => return,
                    result = session(&inner, &mut state) => result,
                };
                if let Err(error) = result {
                    tracing::warn!(proxy = %inner.options.name, error = %format!("{error:#}"), "Tailscale control session failed; retrying");
                }
                tokio::select! {
                    _ = stop.cancelled() => return,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
        });
        Ok(node)
    }

    /// Waits (briefly) for the first network map.
    async fn wait_ready(&self) -> Result<()> {
        let mut ready = self.inner.ready.subscribe();
        tokio::time::timeout(Duration::from_secs(20), ready.wait_for(|r| r.is_some()))
            .await
            .context("Tailscale is not connected to its tailnet yet")??;
        Ok(())
    }

    /// The tailnet address for a peer's MagicDNS name (full or short).
    pub fn resolve(&self, name: &str) -> Option<IpAddr> {
        let netmap = self.inner.netmap.lock().unwrap();
        let node = netmap.find(name)?;
        node.addresses
            .iter()
            .map(|a| a.addr())
            .find(IpAddr::is_ipv4)
            .or_else(|| node.addresses.first().map(|a| a.addr()))
    }

    /// Whether this node routes `ip` (a peer, an accepted subnet route, or
    /// anything through the exit node).
    pub fn routes(&self, ip: IpAddr) -> bool {
        self.inner.routes.borrow().lookup(ip).is_some()
    }

    pub async fn dial(&self, host: &str, port: u16) -> Result<BoxStream> {
        self.wait_ready().await?;
        let ip = match host.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => match self.resolve(host) {
                Some(ip) => ip,
                None if self.inner.options.exit_node.is_some() => self
                    .inner
                    .dialer
                    .resolve(host)
                    .await?
                    .into_iter()
                    .find(|ip| self.routes(*ip))
                    .with_context(|| format!("{host} has no address routed by the exit node"))?,
                None => bail!("{host} is not a node in this tailnet"),
            },
        };
        if !self.routes(ip) {
            bail!("{ip} is not routed by this tailnet (no peer, subnet route or exit node)");
        }
        self.inner.stack.connect(SocketAddr::new(ip, port)).await
    }
}

fn hostinfo(options: &Options, home: u32) -> Hostinfo {
    Hostinfo {
        ipn_version: format!("clyntis-{}", env!("CARGO_PKG_VERSION")),
        os: options.os.clone(),
        hostname: options.hostname.clone(),
        net_info: (home != 0).then(|| NetInfo {
            preferred_derp: home,
            ..Default::default()
        }),
        app: Some("clyntis".into()),
    }
}

/// Picks the home DERP region with the fastest TLS handshake.
async fn choose_home(dialer: &Arc<dyn Dialer>, derp: &DerpMap) -> Option<u32> {
    let mut probes = tokio::task::JoinSet::new();
    for region in derp.regions.values() {
        if region.avoid || region.no_measure_no_home {
            continue;
        }
        let Some(node) = region.nodes.iter().find(|n| !n.stun_only).cloned() else {
            continue;
        };
        let (dialer, id) = (dialer.clone(), region.region_id);
        probes.spawn(async move {
            let started = tokio::time::Instant::now();
            let port = if node.derp_port == 0 {
                443
            } else {
                node.derp_port
            };
            tokio::time::timeout(
                Duration::from_secs(4),
                dialer.connect_tls(&node.host_name, port),
            )
            .await
            .ok()?
            .ok()?;
            Some((started.elapsed(), id))
        });
    }
    let mut best: Option<(Duration, u32)> = None;
    while let Some(result) = probes.join_next().await {
        if let Ok(Some(found)) = result
            && best.is_none_or(|b| found.0 < b.0)
        {
            best = Some(found);
        }
    }
    best.map(|(_, id)| id)
}

async fn session(inner: &Arc<Inner>, state: &mut State) -> Result<()> {
    let options = &inner.options;
    let server = ServerUrl::parse(&options.control_url)?;
    let mut control = Control::connect(inner.dialer.clone(), &server, &state.machine).await?;
    if !state.registered {
        let auth_key = options
            .auth_key
            .clone()
            .filter(|k| !k.is_empty())
            .context("auth-key is required to join the tailnet")?;
        let response = control
            .register(&RegisterRequest {
                version: CAPABILITY_VERSION,
                node_key: NodeKey(state.node.public()),
                old_node_key: NodeKey(Default::default()),
                auth: Some(RegisterAuth { auth_key }),
                hostinfo: hostinfo(options, state.home_derp),
                ephemeral: options.ephemeral,
            })
            .await?;
        if !response.error.is_empty() {
            bail!("Tailscale login refused: {}", response.error);
        }
        if !response.machine_authorized {
            if !response.auth_url.is_empty() {
                bail!("Tailscale login needs approval at {}", response.auth_url);
            }
            bail!("Tailscale node is waiting for admin approval");
        }
        state.registered = true;
        state.save(&options.state_path)?;
        tracing::info!(proxy = %options.name, "Tailscale node registered");
    }
    let disco = inner.disco.public().disco();
    let mut endpoints = inner.endpoints.clone();
    let request = |home: u32, stream: bool, endpoints: &magic::Endpoints| MapRequest {
        version: CAPABILITY_VERSION,
        compress: "zstd",
        keep_alive: true,
        node_key: NodeKey(state.node.public()),
        disco_key: disco.clone(),
        stream,
        hostinfo: hostinfo(options, home),
        omit_peers: !stream,
        endpoints: endpoints.iter().map(|(addr, _)| addr.to_string()).collect(),
        endpoint_types: endpoints.iter().map(|(_, kind)| *kind).collect(),
    };
    let mut home = state.home_derp;
    let current = endpoints.borrow_and_update().clone();
    let mut stream = match control.map(&request(home, true, &current)).await {
        Ok(stream) => stream,
        // The node key is unknown or expired (an ephemeral node removed while
        // offline, a key expiry): log in again with the auth key.
        Err(error) if format!("{error:#}").contains("HTTP 4") => {
            state.registered = false;
            state.save(&options.state_path)?;
            return Err(error.context("Tailscale node key no longer accepted; logging in again"));
        }
        Err(error) => return Err(error),
    };
    let mut announced = false;
    loop {
        let map = tokio::select! {
            map = stream.next() => match map? {
                Some(map) => map,
                None => break,
            },
            // New UDP candidates: tell control so peers can try direct paths.
            changed = endpoints.changed() => {
                if changed.is_ok() {
                    let current = endpoints.borrow_and_update().clone();
                    let mut update = control.map(&request(home, false, &current)).await?;
                    let _ = tokio::time::timeout(Duration::from_secs(10), update.next()).await;
                }
                continue;
            }
        };
        if map.keep_alive
            && map.node.is_none()
            && map.peers.is_none()
            && map.peers_changed.is_empty()
        {
            continue;
        }
        let (routes, me, peers, derp) = {
            let mut netmap = inner.netmap.lock().unwrap();
            netmap.apply(map);
            (
                netmap.routes(options, home),
                netmap.me.clone(),
                netmap.peers.len(),
                netmap.derp.clone(),
            )
        };
        if let Some(me) = &me
            && me.key != state.node.public()
        {
            bail!("control server returned another node key");
        }
        // Choose a home DERP region once the map is known, and tell control
        // so peers send to us there.
        if !announced && !derp.regions.is_empty() {
            announced = true;
            let known = derp.regions.values().any(|r| r.region_id == home);
            if !known && let Some(chosen) = choose_home(&inner.dialer, &derp).await {
                home = chosen;
                state.home_derp = chosen;
                let _ = state.save(&options.state_path);
            }
            let current = endpoints.borrow().clone();
            let mut update = control.map(&request(home, false, &current)).await?;
            let _ = tokio::time::timeout(Duration::from_secs(10), update.next()).await;
        }
        let routes = Routes { home, ..routes };
        inner.routes.send_replace(routes);
        if let Some(me) = me {
            let _ = inner
                .stack
                .commands
                .send(netstack::Command::Addresses(me.addresses.clone()))
                .await;
            let first = inner.ready.borrow().is_none();
            if first {
                tracing::info!(
                    proxy = %options.name,
                    name = %me.fqdn(),
                    addresses = ?me.addresses.iter().map(IpNet::addr).collect::<Vec<_>>(),
                    peers,
                    home_derp = home,
                    "Tailscale joined the tailnet"
                );
            }
            inner.ready.send_replace(Some(me.fqdn().to_owned()));
        }
    }
    bail!("Tailscale network map stream ended")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Public;

    fn peer(id: i64, name: &str, address: &str, allowed: &[&str]) -> tailcfg::Node {
        tailcfg::Node {
            id,
            name: format!("{name}.tail.ts.net."),
            key: Public([id as u8; 32]),
            addresses: vec![address.parse().unwrap()],
            allowed_ips: Some(allowed.iter().map(|a| a.parse().unwrap()).collect()),
            home_derp: 2,
            ..Default::default()
        }
    }

    fn options(exit: Option<&str>, accept_routes: bool) -> Options {
        Options {
            name: "ts".into(),
            auth_key: None,
            hostname: "me".into(),
            control_url: "https://controlplane.tailscale.com".into(),
            state_path: "/tmp/unused".into(),
            ephemeral: false,
            accept_routes,
            exit_node: exit.map(str::to_owned),
            os: "macOS".into(),
        }
    }

    fn netmap() -> NetMap {
        let mut map = NetMap::default();
        for node in [
            peer(
                1,
                "pi5",
                "100.104.16.87/32",
                &["100.104.16.87/32", "192.168.8.0/24"],
            ),
            peer(
                2,
                "exit",
                "100.64.0.2/32",
                &["100.64.0.2/32", "0.0.0.0/0", "::/0"],
            ),
        ] {
            map.peers.insert(node.id, node);
        }
        map
    }

    #[test]
    fn routes_peers_and_only_opted_in_subnets_and_exit_nodes() {
        let map = netmap();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let plain = map.routes(&options(None, false), 2);
        assert_eq!(
            plain.lookup(ip("100.104.16.87")).unwrap().key,
            Public([1; 32])
        );
        assert!(
            plain.lookup(ip("192.168.8.10")).is_none(),
            "subnet routes need accept-routes"
        );
        assert!(
            plain.lookup(ip("8.8.8.8")).is_none(),
            "no exit node selected"
        );
        let routed = map.routes(&options(Some("exit"), true), 2);
        assert_eq!(
            routed.lookup(ip("192.168.8.10")).unwrap().key,
            Public([1; 32])
        );
        assert_eq!(routed.lookup(ip("8.8.8.8")).unwrap().key, Public([2; 32]));
        // A peer's own address beats the exit node's default route.
        assert_eq!(
            routed.lookup(ip("100.104.16.87")).unwrap().key,
            Public([1; 32])
        );
        // The exit node can be named by its tailnet address too.
        let by_ip = map.routes(&options(Some("100.64.0.2"), false), 2);
        assert_eq!(by_ip.lookup(ip("1.1.1.1")).unwrap().key, Public([2; 32]));
    }

    #[test]
    fn finds_peers_by_full_and_short_magicdns_names() {
        let map = netmap();
        assert_eq!(map.find("pi5").unwrap().id, 1);
        assert_eq!(map.find("PI5.tail.ts.net.").unwrap().id, 1);
        assert!(map.find("pi5.example.com").is_none());
    }

    #[test]
    fn applies_incremental_map_updates() {
        let mut map = netmap();
        map.apply(MapResponse {
            peers_removed: vec![2],
            peers_changed_patch: vec![tailcfg::PeerChange {
                node_id: 1,
                derp_region: 9,
                ..Default::default()
            }],
            ..Default::default()
        });
        assert!(!map.peers.contains_key(&2));
        assert_eq!(map.peers[&1].derp_region(), 9);
    }
}
