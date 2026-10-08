//! Moves IP packets between the netstack and peers: WireGuard (boringtun)
//! per peer, sent over a direct UDP path when disco finds one, otherwise
//! relayed through each peer's home DERP region.
use crate::{
    Dialer, derp,
    disco::{self, Message, stun},
    key::{Private, Public},
    tailcfg::{DerpMap, ENDPOINT_LOCAL, ENDPOINT_STUN},
};
use boringtun::noise::{Tunn, TunnResult};
use ipnet::IpNet;
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, watch},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

const BUFFER: usize = 65536 + 256;
const PENDING_PER_REGION: usize = 64;
/// magicsock's timings: a direct path is trusted for 6.5 s after a pong,
/// refreshed by heartbeats every 3 s while the peer is in use (45 s).
const TRUST: Duration = Duration::from_millis(6500);
const HEARTBEAT: Duration = Duration::from_secs(3);
const ACTIVE: Duration = Duration::from_secs(45);
const DISCOVERY: Duration = Duration::from_secs(5);
const PING_TIMEOUT: Duration = Duration::from_secs(5);
const STUN_INTERVAL: Duration = Duration::from_secs(23);
const MAX_ENDPOINTS: usize = 8;
/// DERP-relayed pongs report this as the source (tailcfg.DerpMagicIP).
const DERP_MAGIC_IP: Ipv4Addr = Ipv4Addr::new(127, 3, 3, 40);

/// A peer reachable for the destinations in its routes.
#[derive(Clone, Debug)]
pub struct Peer {
    pub key: Public,
    pub region: u32,
    pub disco: Public,
    pub endpoints: Vec<SocketAddr>,
}

/// What the router needs from the network map.
#[derive(Clone, Debug, Default)]
pub struct Routes {
    /// Longest prefix first.
    pub table: Vec<(IpNet, Peer)>,
    pub peers: HashMap<Public, Peer>,
    pub derp: DerpMap,
    pub home: u32,
}
impl Routes {
    pub fn lookup(&self, ip: IpAddr) -> Option<&Peer> {
        self.table
            .iter()
            .find(|(net, _)| net.contains(&ip))
            .map(|(_, peer)| peer)
    }
}

/// Our UDP candidates for peers, with their tailcfg endpoint types.
pub type Endpoints = Vec<(SocketAddr, u8)>;

/// How a peer is currently reached, for status displays.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct PathStatus {
    /// The trusted direct UDP path, if any.
    pub direct: Option<SocketAddr>,
    pub rtt_ms: Option<u64>,
    /// Traffic in the last 45 s.
    pub active: bool,
}
pub type Paths = Arc<std::sync::Mutex<HashMap<Public, PathStatus>>>;

enum Region {
    Connecting(VecDeque<(Public, Vec<u8>)>),
    Up(derp::Link),
}

struct Path {
    addr: SocketAddr,
    rtt: Duration,
    trusted_until: Instant,
}

#[derive(Default)]
struct PeerState {
    best: Option<Path>,
    pings: HashMap<[u8; 12], (SocketAddr, Instant)>,
    /// Candidates learned from call-me-maybe and incoming pings.
    learned: Vec<SocketAddr>,
    last_discovery: Option<Instant>,
    last_heartbeat: Option<Instant>,
    last_send: Option<Instant>,
}
impl PeerState {
    fn trusted(&self, now: Instant) -> Option<SocketAddr> {
        self.best
            .as_ref()
            .filter(|path| path.trusted_until > now)
            .map(|path| path.addr)
    }
}

/// Where a packet came from.
#[derive(Clone, Copy)]
enum Via {
    Udp(SocketAddr),
    Derp(Public),
}

struct Router {
    key: Private,
    disco: Private,
    dialer: Arc<dyn Dialer>,
    routes: watch::Receiver<Routes>,
    regions: HashMap<u32, Region>,
    tunnels: HashMap<Public, Tunn>,
    states: HashMap<Public, PeerState>,
    by_addr: HashMap<SocketAddr, Public>,
    next_index: u32,
    to_stack: mpsc::Sender<Vec<u8>>,
    derp_in: mpsc::Sender<(Public, Vec<u8>)>,
    links: mpsc::Sender<(u32, Option<derp::Link>)>,
    udp: Option<Arc<UdpSocket>>,
    local_ip: Option<IpAddr>,
    stun_pending: HashMap<[u8; 12], Instant>,
    /// Published STUN-mapped addresses, and those seen in the current round:
    /// NATs whose mapping varies by destination answer each server differently.
    stun_addrs: Vec<SocketAddr>,
    stun_round: Vec<SocketAddr>,
    endpoints: watch::Sender<Endpoints>,
    paths: Paths,
    ticks: u32,
    buf: Vec<u8>,
}

impl Router {
    fn tunnel(&mut self, peer: &Public) -> &mut Tunn {
        if !self.tunnels.contains_key(peer) {
            self.next_index = (self.next_index + 1) & 0x00ff_ffff;
            let tunnel = Tunn::new(
                self.key.0.clone(),
                x25519_dalek::PublicKey::from(peer.0),
                None,
                None,
                self.next_index,
                None,
            );
            self.tunnels.insert(*peer, tunnel);
        }
        self.tunnels.get_mut(peer).unwrap()
    }

    fn peer(&self, key: &Public) -> Option<Peer> {
        self.routes.borrow().peers.get(key).cloned()
    }

    fn send_udp(&self, addr: SocketAddr, packet: &[u8]) -> bool {
        self.udp
            .as_ref()
            .is_some_and(|udp| udp.try_send_to(packet, addr).is_ok())
    }

    /// Relays `packet` to `peer` through its home DERP region, connecting to
    /// the region first if needed.
    fn send_derp(&mut self, peer: &Public, packet: Vec<u8>) {
        let region = match self.routes.borrow().peers.get(peer) {
            Some(peer) if peer.region != 0 => peer.region,
            _ => {
                tracing::debug!(peer = ?peer, "Tailscale peer has no home DERP region; dropping packet");
                return;
            }
        };
        match self.regions.get_mut(&region) {
            Some(Region::Up(link)) if !link.is_closed() => {
                link.send(*peer, packet);
            }
            Some(Region::Connecting(queue)) => {
                if queue.len() < PENDING_PER_REGION {
                    queue.push_back((*peer, packet));
                }
            }
            _ => {
                self.regions.insert(
                    region,
                    Region::Connecting(VecDeque::from([(*peer, packet)])),
                );
                self.connect(region);
            }
        }
    }

    /// Sends a WireGuard datagram over the trusted direct path, or DERP while
    /// discovery looks for one.
    fn send(&mut self, peer: &Public, datagram: Vec<u8>) {
        let now = Instant::now();
        let state = self.states.entry(*peer).or_default();
        state.last_send = Some(now);
        let (trusted, best) = (state.trusted(now), state.best.as_ref().map(|p| p.addr));
        if let Some(addr) = trusted
            && self.send_udp(addr, &datagram)
        {
            return;
        }
        // An untrusted best path may still work; send there too.
        if let Some(addr) = best {
            self.send_udp(addr, &datagram);
        }
        self.discover(peer, false);
        self.send_derp(peer, datagram);
    }

    fn send_disco(&mut self, peer: &Peer, via: Via, message: &Message) {
        if peer.disco.is_zero() {
            return;
        }
        let packet = disco::seal(&self.disco, &peer.disco, message);
        match via {
            Via::Udp(addr) => {
                self.send_udp(addr, &packet);
            }
            Via::Derp(key) => self.send_derp(&key, packet),
        }
    }

    fn ping(&mut self, peer: &Peer, addr: SocketAddr) {
        if self.udp.is_none() || addr.is_ipv6() || addr.ip().is_unspecified() {
            return;
        }
        let tx: [u8; 12] = rand::random();
        self.states
            .entry(peer.key)
            .or_default()
            .pings
            .insert(tx, (addr, Instant::now()));
        let node_key = Some(self.key.public());
        self.send_disco(peer, Via::Udp(addr), &Message::Ping { tx, node_key });
    }

    /// Pings every candidate of `peer` and asks it, via DERP, to ping ours, so
    /// both NATs open at once. At most every 5 s unless `force`.
    fn discover(&mut self, key: &Public, force: bool) {
        if self.udp.is_none() {
            return;
        }
        let Some(peer) = self.peer(key) else { return };
        let now = Instant::now();
        let state = self.states.entry(*key).or_default();
        if !force && state.last_discovery.is_some_and(|t| now - t < DISCOVERY) {
            return;
        }
        state.last_discovery = Some(now);
        let mut candidates = peer.endpoints.clone();
        for addr in &state.learned {
            if !candidates.contains(addr) {
                candidates.push(*addr);
            }
        }
        candidates.truncate(MAX_ENDPOINTS);
        tracing::debug!(peer = ?key, candidates = ?candidates, "disco discovery");
        for addr in candidates {
            self.ping(&peer, addr);
        }
        let ours: Vec<SocketAddr> = self.endpoints.borrow().iter().map(|(a, _)| *a).collect();
        if !ours.is_empty() {
            self.send_disco(&peer, Via::Derp(*key), &Message::CallMeMaybe(ours));
        }
    }

    fn handle_disco(&mut self, via: Via, packet: &[u8]) {
        let Some((sender, message)) = disco::open(&self.disco, packet) else {
            return;
        };
        let peer = self
            .routes
            .borrow()
            .peers
            .values()
            .find(|p| p.disco == sender)
            .cloned();
        let Some(peer) = peer else {
            tracing::debug!("disco message from a node not in the network map");
            return;
        };
        let now = Instant::now();
        tracing::debug!(
            peer = ?peer.key,
            via = %match via { Via::Udp(addr) => addr.to_string(), Via::Derp(_) => "DERP".into() },
            message = ?message,
            "disco received"
        );
        match message {
            Message::Ping { tx, .. } => {
                let src = match via {
                    Via::Udp(addr) => addr,
                    Via::Derp(_) => {
                        SocketAddr::new(DERP_MAGIC_IP.into(), self.routes.borrow().home as u16)
                    }
                };
                self.send_disco(&peer, via, &Message::Pong { tx, src });
                if let Via::Udp(addr) = via {
                    self.by_addr.insert(addr, peer.key);
                    let state = self.states.entry(peer.key).or_default();
                    if !state.learned.contains(&addr) {
                        state.learned.push(addr);
                    }
                    // They reached us: confirm the path in our direction too.
                    if state.trusted(now).is_none() {
                        self.ping(&peer, addr);
                    }
                }
            }
            Message::Pong { tx, src } => {
                let Some(state) = self.states.get_mut(&peer.key) else {
                    return;
                };
                let Some((addr, sent)) = state.pings.remove(&tx) else {
                    return;
                };
                if let Via::Udp(from) = via
                    && from != addr
                {
                    return;
                }
                let rtt = now - sent;
                let better = state.best.as_ref().is_none_or(|best| {
                    best.addr == addr
                        || best.trusted_until <= now
                        || rtt + Duration::from_millis(5) < best.rtt
                });
                if better {
                    if state.best.as_ref().is_none_or(|best| best.addr != addr) {
                        tracing::info!(peer = ?peer.key, %addr, rtt_ms = rtt.as_millis() as u64, observed = %src, "Tailscale direct path found");
                    }
                    state.best = Some(Path {
                        addr,
                        rtt,
                        trusted_until: now + TRUST,
                    });
                    self.by_addr.insert(addr, peer.key);
                }
            }
            Message::CallMeMaybe(endpoints) => {
                let state = self.states.entry(peer.key).or_default();
                for addr in &endpoints {
                    if !state.learned.contains(addr) {
                        state.learned.push(*addr);
                    }
                }
                state.learned.truncate(MAX_ENDPOINTS * 2);
                for addr in endpoints.into_iter().take(MAX_ENDPOINTS) {
                    self.ping(&peer, addr);
                }
            }
        }
    }

    fn connect(&self, region: u32) {
        let routes = self.routes.borrow().clone();
        let Some(node) = routes
            .derp
            .regions
            .values()
            .find(|r| r.region_id == region)
            .and_then(|r| r.nodes.iter().find(|n| !n.stun_only))
            .cloned()
        else {
            tracing::warn!(region, "Tailscale DERP region missing from the map");
            let links = self.links.clone();
            tokio::spawn(async move {
                let _ = links.send((region, None)).await;
            });
            return;
        };
        let (dialer, key, inbound, links) = (
            self.dialer.clone(),
            self.key.clone(),
            self.derp_in.clone(),
            self.links.clone(),
        );
        let home = region == routes.home;
        tokio::spawn(async move {
            let link = match derp::connect(&*dialer, &node, &key, home, inbound).await {
                Ok(link) => {
                    tracing::info!(region, server = %node.host_name, home, "Tailscale DERP connected");
                    Some(link)
                }
                Err(error) => {
                    tracing::warn!(region, server = %node.host_name, error = %format!("{error:#}"), "Tailscale DERP connection failed");
                    None
                }
            };
            let _ = links.send((region, link)).await;
        });
    }

    /// Feeds a WireGuard datagram from `peer` into its tunnel.
    fn wireguard(&mut self, peer: Public, datagram: &[u8]) {
        if !self.routes.borrow().peers.contains_key(&peer) {
            tracing::debug!(peer = ?peer, "WireGuard packet from a node not in the network map");
            return;
        }
        let mut network = Vec::new();
        let mut stack = Vec::new();
        let mut buf = std::mem::take(&mut self.buf);
        {
            let tunnel = self.tunnel(&peer);
            let mut input = datagram;
            loop {
                match tunnel.decapsulate(None, input, &mut buf) {
                    TunnResult::WriteToNetwork(data) => {
                        network.push(data.to_vec());
                        // Queued packets are released one call at a time.
                        input = &[];
                        continue;
                    }
                    TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                        stack.push(data.to_vec());
                    }
                    TunnResult::Err(error) => {
                        tracing::debug!(peer = ?peer, ?error, "WireGuard rejected a packet");
                    }
                    TunnResult::Done => {}
                }
                break;
            }
        }
        self.buf = buf;
        for datagram in network {
            self.send(&peer, datagram);
        }
        for packet in stack {
            if self.to_stack.try_send(packet).is_err() {
                tracing::debug!("Tailscale netstack is congested; dropping a packet");
            }
        }
    }

    fn on_derp(&mut self, peer: Public, packet: &[u8]) {
        if disco::is_disco(packet) {
            self.handle_disco(Via::Derp(peer), packet);
        } else {
            self.wireguard(peer, packet);
        }
    }

    fn on_udp(&mut self, src: SocketAddr, packet: &[u8]) {
        if stun::is_stun(packet) {
            self.stun_response(packet);
        } else if disco::is_disco(packet) {
            self.handle_disco(Via::Udp(src), packet);
        } else if let Some(peer) = self.by_addr.get(&src).copied() {
            self.wireguard(peer, packet);
        } else {
            tracing::debug!(%src, "UDP packet from an unknown address");
        }
    }

    /// Encrypts a packet from the netstack for the peer routing its destination.
    fn outbound(&mut self, packet: Vec<u8>) {
        let Some(dst) = Tunn::dst_address(&packet) else {
            return;
        };
        let Some(peer) = self.routes.borrow().lookup(dst).map(|p| p.key) else {
            tracing::debug!(%dst, "no Tailscale peer routes this destination");
            return;
        };
        let mut buf = std::mem::take(&mut self.buf);
        let datagram = match self.tunnel(&peer).encapsulate(&packet, &mut buf) {
            TunnResult::WriteToNetwork(data) => Some(data.to_vec()),
            TunnResult::Err(error) => {
                tracing::debug!(peer = ?peer, ?error, "WireGuard could not encrypt");
                None
            }
            _ => None,
        };
        self.buf = buf;
        if let Some(datagram) = datagram {
            self.send(&peer, datagram);
        }
    }

    fn timers(&mut self) {
        let now = Instant::now();
        let mut buf = std::mem::take(&mut self.buf);
        let mut out = Vec::new();
        let known: Vec<Public> = self.routes.borrow().peers.keys().copied().collect();
        self.tunnels.retain(|key, _| known.contains(key));
        self.states.retain(|key, _| known.contains(key));
        self.by_addr.retain(|_, key| known.contains(key));
        for (peer, tunnel) in &mut self.tunnels {
            if let TunnResult::WriteToNetwork(data) = tunnel.update_timers(&mut buf) {
                out.push((*peer, data.to_vec()));
            }
        }
        self.buf = buf;
        for (peer, datagram) in out {
            self.send(&peer, datagram);
        }
        // Keep paths of peers in use alive; rediscover lost ones.
        let mut heartbeat = Vec::new();
        let mut rediscover = Vec::new();
        for (key, state) in &mut self.states {
            state
                .pings
                .retain(|_, (_, sent)| now - *sent < PING_TIMEOUT);
            let active = state.last_send.is_some_and(|t| now - t < ACTIVE);
            if !active {
                continue;
            }
            match state.best.as_ref().map(|p| p.addr) {
                Some(addr) if state.last_heartbeat.is_none_or(|t| now - t >= HEARTBEAT) => {
                    state.last_heartbeat = Some(now);
                    heartbeat.push((*key, addr));
                    if state.trusted(now).is_none() {
                        rediscover.push(*key);
                    }
                }
                None => rediscover.push(*key),
                _ => {}
            }
        }
        for (key, addr) in heartbeat {
            if let Some(peer) = self.peer(&key) {
                self.ping(&peer, addr);
            }
        }
        for key in rediscover {
            self.discover(&key, false);
        }
        self.ticks = self.ticks.wrapping_add(1);
        if self.ticks.is_multiple_of(4) {
            let snapshot = self
                .states
                .iter()
                .map(|(key, state)| {
                    let trusted = state.trusted(now);
                    let status = PathStatus {
                        direct: trusted,
                        rtt_ms: trusted
                            .and(state.best.as_ref())
                            .map(|p| p.rtt.as_millis() as u64),
                        active: state.last_send.is_some_and(|t| now - t < ACTIVE),
                    };
                    (*key, status)
                })
                .collect();
            *self.paths.lock().unwrap() = snapshot;
        }
    }

    /// Asks a few DERP nodes' STUN servers for our public UDP address.
    fn stun(&mut self) {
        if self.udp.is_none() {
            return;
        }
        // Close the previous round: publish its addresses if they changed.
        let mut round = std::mem::take(&mut self.stun_round);
        round.sort();
        let mut published = self.stun_addrs.clone();
        published.sort();
        if !round.is_empty() && round != published {
            self.stun_addrs = round;
            self.publish();
        }
        let Some(udp) = &self.udp else { return };
        let now = Instant::now();
        self.stun_pending
            .retain(|_, sent| now - *sent < PING_TIMEOUT);
        let routes = self.routes.borrow();
        let mut servers: Vec<SocketAddr> = Vec::new();
        let preferred = routes
            .derp
            .regions
            .values()
            .filter(|r| r.region_id == routes.home);
        for region in preferred.chain(routes.derp.regions.values()) {
            for node in &region.nodes {
                if node.stun_port < 0 {
                    continue;
                }
                let port = if node.stun_port == 0 {
                    3478
                } else {
                    node.stun_port as u16
                };
                if let Ok(ip) = node.ipv4.parse::<Ipv4Addr>() {
                    let addr = SocketAddr::new(ip.into(), port);
                    if !servers.contains(&addr) {
                        servers.push(addr);
                    }
                }
            }
            if servers.len() >= 3 {
                break;
            }
        }
        drop(routes);
        for server in servers.into_iter().take(3) {
            let tx: [u8; 12] = rand::random();
            if udp.try_send_to(&stun::request(&tx), server).is_ok() {
                self.stun_pending.insert(tx, now);
            }
        }
    }

    fn stun_response(&mut self, packet: &[u8]) {
        let Some((tx, mapped)) = stun::response(packet) else {
            return;
        };
        if self.stun_pending.remove(&tx).is_none() || !mapped.is_ipv4() {
            return;
        }
        if !self.stun_round.contains(&mapped) {
            self.stun_round.push(mapped);
        }
        // The first answer is published at once; later rounds when they end.
        if self.stun_addrs.is_empty() {
            self.stun_addrs = self.stun_round.clone();
            self.publish();
        }
    }

    /// Reports our candidates: the STUN-mapped address when known, and the
    /// LAN address even without it (peers on the same network, or STUN
    /// blocked upstream).
    fn publish(&mut self) {
        let port = self
            .udp
            .as_ref()
            .and_then(|u| u.local_addr().ok())
            .map(|a| a.port());
        let mut endpoints: Endpoints = Vec::new();
        for mapped in &self.stun_addrs {
            endpoints.push((*mapped, ENDPOINT_STUN));
        }
        if let (Some(ip), Some(port)) = (self.local_ip, port) {
            let local = SocketAddr::new(ip, port);
            if !self.stun_addrs.contains(&local) {
                endpoints.push((local, ENDPOINT_LOCAL));
            }
        }
        if *self.endpoints.borrow() == endpoints {
            return;
        }
        tracing::info!(endpoints = ?endpoints.iter().map(|e| e.0).collect::<Vec<_>>(), "Tailscale UDP endpoints");
        self.endpoints.send_replace(endpoints);
    }
}

/// Runs until `stop`. `from_stack` carries packets to encrypt; decrypted
/// packets go to `to_stack`; discovered UDP candidates go to `endpoints`.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    key: Private,
    disco: Private,
    dialer: Arc<dyn Dialer>,
    routes: watch::Receiver<Routes>,
    mut from_stack: mpsc::Receiver<Vec<u8>>,
    to_stack: mpsc::Sender<Vec<u8>>,
    endpoints: watch::Sender<Endpoints>,
    paths: Paths,
    stop: CancellationToken,
) {
    let (derp_in, mut derp_rx) = mpsc::channel(1024);
    let (links, mut links_rx) = mpsc::channel(16);
    let (udp_in, mut udp_rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(1024);
    let udp = match dialer.bind_udp().await {
        Ok(socket) => Some(Arc::new(socket)),
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "Tailscale UDP unavailable; peers are reached through DERP only");
            None
        }
    };
    let local_ip = dialer.local_ipv4().await;
    if let Some(socket) = udp.clone() {
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; BUFFER];
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    received = socket.recv_from(&mut buf) => match received {
                        Ok((n, src)) => {
                            if udp_in.try_send((src, buf[..n].to_vec())).is_err() && udp_in.is_closed() {
                                break;
                            }
                        }
                        Err(error) => {
                            tracing::debug!(%error, "Tailscale UDP receive failed");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    },
                }
            }
        });
    }
    let mut router = Router {
        key,
        disco,
        dialer,
        routes: routes.clone(),
        regions: HashMap::new(),
        tunnels: HashMap::new(),
        states: HashMap::new(),
        by_addr: HashMap::new(),
        next_index: rand::random::<u32>() & 0x00ff_ffff,
        to_stack,
        derp_in,
        links,
        udp,
        local_ip,
        stun_pending: HashMap::new(),
        stun_addrs: Vec::new(),
        stun_round: Vec::new(),
        endpoints,
        paths,
        ticks: 0,
        buf: vec![0; BUFFER],
    };
    router.publish();
    let mut routes = routes;
    let mut timer = tokio::time::interval(Duration::from_millis(250));
    let mut home_check = tokio::time::interval(Duration::from_secs(5));
    let mut stun_timer = tokio::time::interval(STUN_INTERVAL);
    loop {
        tokio::select! {
            biased;
            _ = stop.cancelled() => break,
            Some((region, link)) = links_rx.recv() => {
                match (router.regions.remove(&region), link) {
                    (Some(Region::Connecting(queue)), Some(link)) => {
                        for (peer, packet) in queue {
                            link.send(peer, packet);
                        }
                        router.regions.insert(region, Region::Up(link));
                    }
                    (_, Some(link)) => { router.regions.insert(region, Region::Up(link)); }
                    (_, None) => {}
                }
            }
            Some((src, packet)) = udp_rx.recv() => router.on_udp(src, &packet),
            Some((peer, packet)) = derp_rx.recv() => router.on_derp(peer, &packet),
            packet = from_stack.recv() => match packet {
                Some(packet) => router.outbound(packet),
                None => break,
            },
            changed = routes.changed() => {
                if changed.is_err() { break }
                if router.stun_addrs.is_empty() { router.stun(); }
            }
            _ = timer.tick() => router.timers(),
            _ = stun_timer.tick() => router.stun(),
            // Peers reach us only through the home region: keep it connected.
            _ = home_check.tick() => {
                let home = router.routes.borrow().home;
                let up = matches!(router.regions.get(&home), Some(Region::Up(link)) if !link.is_closed())
                    || matches!(router.regions.get(&home), Some(Region::Connecting(_)));
                if home != 0 && !up {
                    router.regions.insert(home, Region::Connecting(VecDeque::new()));
                    router.connect(home);
                }
                router.regions.retain(|_, region| !matches!(region, Region::Up(link) if link.is_closed()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meta_protocol::BoxStream;

    struct Loopback;
    #[async_trait::async_trait]
    impl Dialer for Loopback {
        async fn connect_tcp(&self, _: &str, _: u16) -> anyhow::Result<BoxStream> {
            anyhow::bail!("no DERP in this test")
        }
        async fn connect_tls(&self, _: &str, _: u16) -> anyhow::Result<BoxStream> {
            anyhow::bail!("no DERP in this test")
        }
        async fn resolve(&self, _: &str) -> anyhow::Result<Vec<IpAddr>> {
            Ok(vec![])
        }
        async fn bind_udp(&self) -> anyhow::Result<UdpSocket> {
            Ok(UdpSocket::bind("127.0.0.1:0").await?)
        }
        async fn local_ipv4(&self) -> Option<IpAddr> {
            None
        }
    }

    /// An IPv4/UDP packet from 100.64.0.1 to 100.64.0.2 with `payload`.
    fn ip_packet(payload: &[u8]) -> Vec<u8> {
        let total = 20 + 8 + payload.len();
        let mut p = vec![
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            0,
            0,
            0,
            64,
            17,
            0,
            0,
        ];
        p.extend_from_slice(&[100, 64, 0, 1, 100, 64, 0, 2]);
        let mut sum: u32 = p
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]) as u32)
            .sum();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let checksum = !(sum as u16);
        p[10..12].copy_from_slice(&checksum.to_be_bytes());
        p.extend_from_slice(&[0x30, 0x39, 0x30, 0x39]);
        p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(payload);
        p
    }

    #[tokio::test]
    async fn finds_a_direct_path_and_carries_wireguard_over_it() {
        let (ours, our_disco) = (Private::generate(), Private::generate());
        let (theirs, their_disco) = (Private::generate(), Private::generate());
        let peer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = Peer {
            key: theirs.public(),
            region: 0,
            disco: their_disco.public(),
            endpoints: vec![peer_socket.local_addr().unwrap()],
        };
        let routes = Routes {
            table: vec![("100.64.0.2/32".parse().unwrap(), peer.clone())],
            peers: HashMap::from([(peer.key, peer)]),
            ..Default::default()
        };
        let (_routes_tx, routes_rx) = watch::channel(routes);
        let (to_router, from_stack) = mpsc::channel(16);
        let (to_stack, _from_router) = mpsc::channel(16);
        let (endpoints, _) = watch::channel(Vec::new());
        let stop = CancellationToken::new();
        tokio::spawn(run(
            ours.clone(),
            our_disco.clone(),
            Arc::new(Loopback),
            routes_rx,
            from_stack,
            to_stack,
            endpoints,
            Default::default(),
            stop.clone(),
        ));
        let packet = ip_packet(b"direct");
        to_router.send(packet.clone()).await.unwrap();
        let mut their_tunnel = Tunn::new(
            theirs.0.clone(),
            x25519_dalek::PublicKey::from(ours.public().0),
            None,
            None,
            7,
            None,
        );
        let mut buf = vec![0u8; BUFFER];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let mut ponged = false;
        loop {
            let (n, from) = tokio::time::timeout_at(deadline, peer_socket.recv_from(&mut buf))
                .await
                .expect("no direct traffic")
                .unwrap();
            let data = buf[..n].to_vec();
            if let Some((sender, message)) = disco::open(&their_disco, &data) {
                assert_eq!(sender, our_disco.public());
                if let Message::Ping { tx, node_key } = message {
                    assert_eq!(node_key, Some(ours.public()));
                    let pong = disco::seal(
                        &their_disco,
                        &our_disco.public(),
                        &Message::Pong { tx, src: from },
                    );
                    peer_socket.send_to(&pong, from).await.unwrap();
                    ponged = true;
                }
                continue;
            }
            // WireGuard over the direct path only after our pong.
            assert!(
                ponged,
                "WireGuard sent directly before the path was confirmed"
            );
            let mut out = vec![0u8; BUFFER];
            let mut input = data.as_slice();
            loop {
                match their_tunnel.decapsulate(None, input, &mut out) {
                    TunnResult::WriteToNetwork(reply) => {
                        peer_socket.send_to(reply, from).await.unwrap();
                        input = &[];
                    }
                    TunnResult::WriteToTunnelV4(inner, _) => {
                        assert_eq!(inner, &packet[..]);
                        stop.cancel();
                        return;
                    }
                    _ => break,
                }
            }
        }
    }
}
