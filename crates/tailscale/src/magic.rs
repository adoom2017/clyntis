//! Moves IP packets between the netstack and peers: WireGuard (boringtun)
//! per peer, carried over DERP to each peer's home region.
use crate::{
    Dialer, derp,
    key::{Private, Public},
    tailcfg::DerpMap,
};
use boringtun::noise::{Tunn, TunnResult};
use ipnet::IpNet;
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    sync::Arc,
    time::Duration,
};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

/// Disco messages (NAT traversal pings) start with this; we only relay, so
/// they are ignored and peers keep using DERP.
const DISCO_MAGIC: &[u8] = "TS💬".as_bytes();
const BUFFER: usize = 65536 + 256;
const PENDING_PER_REGION: usize = 64;

/// A peer reachable for the destinations in its routes.
#[derive(Clone, Debug)]
pub struct Peer {
    pub key: Public,
    pub region: u32,
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

enum Region {
    Connecting(VecDeque<(Public, Vec<u8>)>),
    Up(derp::Link),
}

struct Router {
    key: Private,
    dialer: Arc<dyn Dialer>,
    routes: watch::Receiver<Routes>,
    regions: HashMap<u32, Region>,
    tunnels: HashMap<Public, Tunn>,
    next_index: u32,
    to_stack: mpsc::Sender<Vec<u8>>,
    derp_in: mpsc::Sender<(Public, Vec<u8>)>,
    links: mpsc::Sender<(u32, Option<derp::Link>)>,
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

    /// Sends a WireGuard datagram to `peer` through its home DERP region,
    /// connecting to the region first if needed.
    fn send(&mut self, peer: &Public, datagram: Vec<u8>) {
        let region = match self.routes.borrow().peers.get(peer) {
            Some(peer) if peer.region != 0 => peer.region,
            _ => {
                tracing::debug!(peer = ?peer, "Tailscale peer has no home DERP region; dropping packet");
                return;
            }
        };
        match self.regions.get_mut(&region) {
            Some(Region::Up(link)) if !link.is_closed() => {
                link.send(*peer, datagram);
            }
            Some(Region::Connecting(queue)) => {
                if queue.len() < PENDING_PER_REGION {
                    queue.push_back((*peer, datagram));
                }
            }
            _ => {
                self.regions.insert(
                    region,
                    Region::Connecting(VecDeque::from([(*peer, datagram)])),
                );
                self.connect(region);
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

    /// Feeds a datagram relayed from `peer` into its tunnel.
    fn inbound(&mut self, peer: Public, datagram: &[u8]) {
        if datagram.starts_with(DISCO_MAGIC) {
            return;
        }
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
        let mut buf = std::mem::take(&mut self.buf);
        let mut out = Vec::new();
        let known: Vec<Public> = self.routes.borrow().peers.keys().copied().collect();
        self.tunnels.retain(|key, _| known.contains(key));
        for (peer, tunnel) in &mut self.tunnels {
            if let TunnResult::WriteToNetwork(data) = tunnel.update_timers(&mut buf) {
                out.push((*peer, data.to_vec()));
            }
        }
        self.buf = buf;
        for (peer, datagram) in out {
            self.send(&peer, datagram);
        }
    }
}

/// Runs until `stop`. `from_stack` carries packets to encrypt; decrypted
/// packets go to `to_stack`.
pub async fn run(
    key: Private,
    dialer: Arc<dyn Dialer>,
    routes: watch::Receiver<Routes>,
    mut from_stack: mpsc::Receiver<Vec<u8>>,
    to_stack: mpsc::Sender<Vec<u8>>,
    stop: CancellationToken,
) {
    let (derp_in, mut derp_rx) = mpsc::channel(1024);
    let (links, mut links_rx) = mpsc::channel(16);
    let mut router = Router {
        key,
        dialer,
        routes: routes.clone(),
        regions: HashMap::new(),
        tunnels: HashMap::new(),
        next_index: rand::random::<u32>() & 0x00ff_ffff,
        to_stack,
        derp_in,
        links,
        buf: vec![0; BUFFER],
    };
    let mut routes = routes;
    let mut timer = tokio::time::interval(Duration::from_millis(250));
    let mut home_check = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            biased;
            _ = stop.cancelled() => break,
            Some((region, link)) = links_rx.recv() => {
                match (router.regions.remove(&region), link) {
                    (Some(Region::Connecting(queue)), Some(link)) => {
                        for (peer, datagram) in queue {
                            link.send(peer, datagram);
                        }
                        router.regions.insert(region, Region::Up(link));
                    }
                    (_, Some(link)) => { router.regions.insert(region, Region::Up(link)); }
                    (_, None) => {}
                }
            }
            Some((peer, datagram)) = derp_rx.recv() => router.inbound(peer, &datagram),
            packet = from_stack.recv() => match packet {
                Some(packet) => router.outbound(packet),
                None => break,
            },
            changed = routes.changed() => if changed.is_err() { break },
            _ = timer.tick() => router.timers(),
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
