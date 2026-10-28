//! Userspace TCP/IP for connections from this node's tailnet addresses, and
//! to its `serve` ports. IP packets go to and come from the WireGuard router.
use anyhow::{Result, bail};
use clyntis_protocol::BoxStream;
use smoltcp::{
    iface::{Config, Interface, PollResult, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp,
    time::{Duration as NetDuration, Instant as NetInstant},
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint},
};
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Notify, mpsc, oneshot, watch},
    time::Instant,
};
use tokio_util::sync::{CancellationToken, PollSender};

/// Tailscale's MTU.
pub const MTU: usize = 1280;
const CHUNK: usize = 8192;
const BUFFER: usize = 64 * 1024;
const QUEUE: usize = 8;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Retry interval while packets wait for room in a full router queue.
const BACKLOG_RETRY: Duration = Duration::from_millis(10);

/// First local port of outbound connections; `serve` ports stay below it.
const FIRST_PORT: u16 = 49152;
const LAST_PORT: u16 = 65000;

pub enum Command {
    Connect(SocketAddr, oneshot::Sender<Result<BoxStream>>),
    Addresses(Vec<ipnet::IpNet>),
}

/// The `serve` ports and the peer addresses allowed on each (`None`: every
/// peer in the network map, which the router already enforces).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Gate {
    pub ports: BTreeMap<u16, Option<Vec<IpAddr>>>,
}
impl Gate {
    /// Whether a decrypted packet may enter the stack. Only TCP to a `serve`
    /// port is checked; everything else is the stack's own traffic. Denied
    /// packets vanish without a RST, so probes cannot tell the port is open.
    fn admits(&self, packet: &[u8]) -> Admission {
        if self.ports.is_empty() {
            return Admission::Pass;
        }
        let (source, tcp) = match packet.first().map(|b| b >> 4) {
            Some(4) if packet.len() >= 20 => {
                let header = usize::from(packet[0] & 0x0f) * 4;
                if packet[9] != 6 || header < 20 {
                    return Admission::Pass;
                }
                let source: [u8; 4] = packet[12..16].try_into().unwrap();
                (IpAddr::from(source), packet.get(header..))
            }
            Some(6) if packet.len() >= 40 => {
                match packet[6] {
                    6 => {}
                    // Extension headers could carry TCP past this check.
                    0 | 43 | 44 | 60 => return Admission::Denied { syn: false },
                    _ => return Admission::Pass,
                }
                let source: [u8; 16] = packet[8..24].try_into().unwrap();
                (IpAddr::from(source), packet.get(40..))
            }
            _ => return Admission::Pass,
        };
        let Some(tcp) = tcp.filter(|tcp| tcp.len() >= 14) else {
            return Admission::Denied { syn: false };
        };
        let port = u16::from_be_bytes([tcp[2], tcp[3]]);
        match self.ports.get(&port) {
            None => Admission::Pass,
            Some(None) => Admission::Pass,
            Some(Some(allowed)) if allowed.contains(&source) => Admission::Pass,
            Some(Some(_)) => Admission::Denied {
                syn: tcp[13] & 0x12 == 0x02,
            },
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
enum Admission {
    Pass,
    /// `syn`: a connection attempt, counted once.
    Denied {
        syn: bool,
    },
}

/// A connection a peer opened to a `serve` port.
pub struct Accepted {
    pub remote: SocketAddr,
    pub port: u16,
    pub stream: BoxStream,
}

/// Inbound counters for status displays.
#[derive(Debug, Default)]
pub struct ServeStats {
    pub active: AtomicUsize,
    pub accepted: AtomicU64,
    pub denied: AtomicU64,
}

struct PacketDevice {
    incoming: VecDeque<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
}
struct Receive(Vec<u8>);
struct Transmit(mpsc::OwnedPermit<Vec<u8>>);
impl Device for PacketDevice {
    type RxToken<'a> = Receive;
    type TxToken<'a> = Transmit;
    fn receive(&mut self, _: NetInstant) -> Option<(Receive, Transmit)> {
        if self.incoming.is_empty() {
            return None;
        }
        let permit = self.outgoing.clone().try_reserve_owned().ok()?;
        Some((Receive(self.incoming.pop_front()?), Transmit(permit)))
    }
    fn transmit(&mut self, _: NetInstant) -> Option<Transmit> {
        self.outgoing.clone().try_reserve_owned().ok().map(Transmit)
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps.max_burst_size = Some(64);
        caps
    }
}
impl RxToken for Receive {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl TxToken for Transmit {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut bytes = vec![0; len];
        let result = f(&mut bytes);
        self.0.send(bytes);
        result
    }
}

/// One TCP connection as seen by the proxy session.
struct Stream {
    input: mpsc::Receiver<Vec<u8>>,
    pending: Option<(Vec<u8>, usize)>,
    output: Option<PollSender<Vec<u8>>>,
    wake: Arc<Notify>,
}
impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.pending.is_none() {
            match this.input.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(bytes)) => {
                    this.pending = Some((bytes, 0));
                    this.wake.notify_one();
                }
            }
        }
        let (bytes, offset) = this.pending.as_mut().unwrap();
        let n = buf.remaining().min(bytes.len() - *offset);
        buf.put_slice(&bytes[*offset..*offset + n]);
        *offset += n;
        if *offset == bytes.len() {
            this.pending = None;
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let Some(output) = this.output.as_mut() else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match output.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Ready(Ok(())) => {
                let n = data.len().min(CHUNK);
                let sent = output
                    .send_item(data[..n].to_vec())
                    .map(|()| n)
                    .map_err(|_| io::ErrorKind::BrokenPipe.into());
                this.wake.notify_one();
                Poll::Ready(sent)
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.output.take();
        this.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}
impl Drop for Stream {
    // The stack only runs when woken: let it see the closed channels.
    fn drop(&mut self) {
        self.wake.notify_one();
    }
}

/// Who receives a connection once it is established.
enum Waiter {
    Dial(oneshot::Sender<Result<BoxStream>>),
    /// Accepted on this `serve` port.
    Accept(u16),
}

struct Flow {
    handle: SocketHandle,
    remote: IpAddr,
    input: Option<mpsc::Sender<Vec<u8>>>,
    output: mpsc::Receiver<Vec<u8>>,
    pending: Option<(Vec<u8>, usize)>,
    eof: bool,
    /// Until established: where to hand the stream, and when to give up.
    connecting: Option<(Waiter, Instant, Option<Stream>)>,
    inbound: bool,
}
impl Flow {
    fn new(handle: SocketHandle, remote: IpAddr, waiter: Waiter, wake: &Arc<Notify>) -> Self {
        let (input, receiver) = mpsc::channel(QUEUE);
        let (sender, output) = mpsc::channel(QUEUE);
        let stream = Stream {
            input: receiver,
            pending: None,
            output: Some(PollSender::new(sender)),
            wake: wake.clone(),
        };
        Self {
            handle,
            remote,
            input: Some(input),
            output,
            pending: None,
            eof: false,
            inbound: matches!(waiter, Waiter::Accept(_)),
            connecting: Some((waiter, Instant::now() + CONNECT_TIMEOUT, Some(stream))),
        }
    }
}

fn tcp_socket() -> tcp::Socket<'static> {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; BUFFER]),
        tcp::SocketBuffer::new(vec![0; BUFFER]),
    );
    socket.set_nagle_enabled(false);
    socket.set_ack_delay(None);
    socket.set_keep_alive(Some(NetDuration::from_secs(30)));
    socket.set_timeout(Some(NetDuration::from_secs(300)));
    socket
}

/// Keeps one listening socket per `serve` port once the node has addresses.
fn sync_listeners(
    listeners: &mut BTreeMap<u16, SocketHandle>,
    sockets: &mut SocketSet<'static>,
    gate: &Gate,
    addressed: bool,
) {
    listeners.retain(|port, handle| {
        let keep = addressed && gate.ports.contains_key(port);
        if !keep {
            sockets.remove(*handle);
        }
        keep
    });
    if !addressed {
        return;
    }
    for &port in gate.ports.keys() {
        if listeners.contains_key(&port) {
            continue;
        }
        let mut socket = tcp_socket();
        match socket.listen(port) {
            Ok(()) => {
                listeners.insert(port, sockets.add(socket));
            }
            Err(error) => tracing::warn!(port, %error, "Tailscale serve cannot listen"),
        }
    }
}

/// smoltcp sends one segment per socket per egress pass; keep transmitting
/// until nothing is left or the router queue is full.
fn poll(
    iface: &mut Interface,
    now: NetInstant,
    device: &mut PacketDevice,
    sockets: &mut SocketSet<'_>,
) {
    iface.poll(now, device, sockets);
    for _ in 0..256 {
        if iface.poll_egress(now, device, sockets) == PollResult::None {
            break;
        }
    }
}

fn admit(gate: &Gate, stats: &ServeStats, queue: &mut VecDeque<Vec<u8>>, packet: Vec<u8>) {
    match gate.admits(&packet) {
        Admission::Pass => queue.push_back(packet),
        Admission::Denied { syn: true } => {
            stats.denied.fetch_add(1, Ordering::Relaxed);
        }
        Admission::Denied { syn: false } => {}
    }
}

/// The inbound side of [`run`]: which ports to serve, where accepted
/// connections go, and the counters to update.
pub struct Inbound {
    pub gate: watch::Receiver<Gate>,
    pub accepted: mpsc::Sender<Accepted>,
    pub stats: Arc<ServeStats>,
}

/// Runs the stack until `stop`: `commands` opens connections, `incoming`
/// carries decrypted packets from peers, `outgoing` takes packets to encrypt.
/// `open` lists the peer addresses with open connections, so the router
/// keeps only their paths alive.
pub async fn run(
    mut commands: mpsc::Receiver<Command>,
    mut incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
    open: watch::Sender<Vec<IpAddr>>,
    inbound: Inbound,
    stop: CancellationToken,
) {
    let Inbound {
        mut gate,
        accepted,
        stats,
    } = inbound;
    let mut current = gate.borrow_and_update().clone();
    let mut gate_open = true;
    let mut listeners: BTreeMap<u16, SocketHandle> = BTreeMap::new();
    let started = Instant::now();
    let now = || NetInstant::from_millis(started.elapsed().as_millis() as i64);
    let mut device = PacketDevice {
        incoming: VecDeque::new(),
        outgoing,
    };
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = rand::random();
    let mut iface = Interface::new(config, &mut device, now());
    let mut sockets = SocketSet::new(vec![]);
    let mut flows: Vec<Flow> = Vec::new();
    let mut next_port: u16 = FIRST_PORT;
    let wake = Arc::new(Notify::new());
    // When smoltcp next needs to run (retransmits, keep-alives, timeouts) or
    // a pending connect expires; otherwise the stack sleeps until woken. A
    // fixed 10 ms tick woke an idle node 100 times a second.
    let mut next: Option<Instant> = None;
    loop {
        let timer = async {
            match next {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            biased;
            _ = stop.cancelled() => break,
            changed = gate.changed(), if gate_open => match changed {
                Ok(()) => {
                    current = gate.borrow_and_update().clone();
                    let addressed = !iface.ip_addrs().is_empty();
                    sync_listeners(&mut listeners, &mut sockets, &current, addressed);
                }
                Err(_) => gate_open = false,
            },
            command = commands.recv() => match command {
                None => break,
                Some(Command::Addresses(addresses)) => {
                    iface.update_ip_addrs(|list| {
                        list.clear();
                        for net in &addresses {
                            let address: IpAddress = net.addr().into();
                            let _ = list.push(IpCidr::new(address, if net.addr().is_ipv4() { 32 } else { 128 }));
                        }
                    });
                    let routes = iface.routes_mut();
                    routes.remove_default_ipv4_route();
                    routes.remove_default_ipv6_route();
                    for net in &addresses {
                        match net.addr() {
                            IpAddr::V4(v4) => { let _ = routes.add_default_ipv4_route(v4); }
                            IpAddr::V6(v6) => { let _ = routes.add_default_ipv6_route(v6); }
                        }
                    }
                    sync_listeners(&mut listeners, &mut sockets, &current, !addresses.is_empty());
                }
                Some(Command::Connect(remote, reply)) => {
                    let local = iface.ip_addrs().iter().map(|c| c.address()).find(|a| {
                        matches!((a, remote.ip()), (IpAddress::Ipv4(_), IpAddr::V4(_)) | (IpAddress::Ipv6(_), IpAddr::V6(_)))
                    });
                    let Some(local) = local else {
                        let _ = reply.send(Err(anyhow::anyhow!("this node has no tailnet address for {remote}")));
                        continue;
                    };
                    let mut socket = tcp_socket();
                    next_port = if next_port >= LAST_PORT { FIRST_PORT } else { next_port + 1 };
                    let endpoint = IpEndpoint::new(remote.ip().into(), remote.port());
                    if let Err(error) = socket.connect(iface.context(), endpoint, (local, next_port)) {
                        let _ = reply.send(Err(anyhow::anyhow!("tailnet connect: {error}")));
                        continue;
                    }
                    let handle = sockets.add(socket);
                    flows.push(Flow::new(handle, remote.ip(), Waiter::Dial(reply), &wake));
                }
            },
            packet = incoming.recv() => match packet {
                None => break,
                Some(packet) => {
                    admit(&current, &stats, &mut device.incoming, packet);
                    while device.incoming.len() < 256 {
                        let Ok(packet) = incoming.try_recv() else { break };
                        admit(&current, &stats, &mut device.incoming, packet);
                    }
                }
            },
            _ = wake.notified() => {},
            _ = timer => {},
        }
        poll(&mut iface, now(), &mut device, &mut sockets);
        // A listening socket that took a SYN carries that connection from
        // now on (smoltcp has no backlog); a fresh one takes the next.
        for (&port, handle) in listeners.iter_mut() {
            let socket = sockets.get::<tcp::Socket>(*handle);
            if socket.state() == tcp::State::Listen {
                continue;
            }
            let remote = socket
                .remote_endpoint()
                .map(|endpoint| IpAddr::from(endpoint.addr));
            let mut fresh = tcp_socket();
            if fresh.listen(port).is_err() {
                continue;
            }
            let taken = std::mem::replace(handle, sockets.add(fresh));
            match remote {
                Some(remote) => flows.push(Flow::new(taken, remote, Waiter::Accept(port), &wake)),
                None => {
                    sockets.remove(taken);
                }
            }
        }
        flows.retain_mut(|flow| {
            let socket = sockets.get_mut::<tcp::Socket>(flow.handle);
            if let Some((_, deadline, _)) = &flow.connecting {
                match socket.state() {
                    tcp::State::Established => {
                        let (waiter, _, stream) = flow.connecting.take().unwrap();
                        let stream: BoxStream = Box::new(stream.unwrap());
                        match waiter {
                            Waiter::Dial(reply) => {
                                let _ = reply.send(Ok(stream));
                            }
                            Waiter::Accept(port) => {
                                let remote = socket.remote_endpoint().map(|endpoint| {
                                    SocketAddr::new(endpoint.addr.into(), endpoint.port)
                                });
                                let handed = remote.is_some_and(|remote| {
                                    accepted
                                        .try_send(Accepted {
                                            remote,
                                            port,
                                            stream,
                                        })
                                        .is_ok()
                                });
                                if handed {
                                    stats.accepted.fetch_add(1, Ordering::Relaxed);
                                } else {
                                    socket.abort();
                                }
                            }
                        }
                    }
                    tcp::State::Closed | tcp::State::TimeWait => {
                        let (waiter, _, _) = flow.connecting.take().unwrap();
                        if let Waiter::Dial(reply) = waiter {
                            let _ = reply
                                .send(Err(anyhow::anyhow!("tailnet peer refused the connection")));
                        }
                        sockets.remove(flow.handle);
                        return false;
                    }
                    _ if Instant::now() >= *deadline => {
                        let (waiter, _, _) = flow.connecting.take().unwrap();
                        if let Waiter::Dial(reply) = waiter {
                            let _ =
                                reply.send(Err(anyhow::anyhow!("tailnet connection timed out")));
                        }
                        socket.abort();
                        return true;
                    }
                    _ => return true,
                }
            }
            while socket.can_recv() {
                let Some(input) = &flow.input else { break };
                let Ok(permit) = input.try_reserve() else {
                    if input.is_closed() {
                        socket.abort();
                    }
                    break;
                };
                let _ = socket.recv(|bytes| {
                    let n = bytes.len().min(CHUNK);
                    permit.send(bytes[..n].to_vec());
                    (n, ())
                });
            }
            if !socket.may_recv() && flow.connecting.is_none() {
                flow.input.take();
            }
            while socket.can_send() {
                if flow.pending.is_none() && !flow.eof {
                    match flow.output.try_recv() {
                        Ok(bytes) => flow.pending = Some((bytes, 0)),
                        Err(mpsc::error::TryRecvError::Disconnected) => flow.eof = true,
                        Err(mpsc::error::TryRecvError::Empty) => break,
                    }
                }
                let Some((bytes, offset)) = flow.pending.as_mut() else {
                    if flow.eof {
                        socket.close();
                    }
                    break;
                };
                let n = socket.send_slice(&bytes[*offset..]).unwrap_or(0);
                if n == 0 {
                    break;
                }
                *offset += n;
                if *offset == bytes.len() {
                    flow.pending = None;
                }
            }
            if !socket.is_open() {
                sockets.remove(flow.handle);
                false
            } else {
                true
            }
        });
        poll(&mut iface, now(), &mut device, &mut sockets);
        stats.active.store(
            flows.iter().filter(|flow| flow.inbound).count(),
            Ordering::Relaxed,
        );
        let mut remotes: Vec<IpAddr> = flows.iter().map(|flow| flow.remote).collect();
        remotes.sort();
        remotes.dedup();
        open.send_if_modified(|current| {
            let changed = *current != remotes;
            if changed {
                *current = remotes;
            }
            changed
        });
        next = next_poll(&mut iface, now(), &device, &sockets, &flows);
    }
}

/// When the loop must run again without being woken: smoltcp's own timers,
/// the earliest connect deadline, and soon while packets wait for queue room.
fn next_poll(
    iface: &mut Interface,
    now: NetInstant,
    device: &PacketDevice,
    sockets: &SocketSet<'_>,
    flows: &[Flow],
) -> Option<Instant> {
    let start = Instant::now();
    let mut next = iface
        .poll_delay(now, sockets)
        .map(|delay| start + Duration::from_micros(delay.total_micros()));
    let mut earliest = |at: Instant| next = Some(next.map_or(at, |n| n.min(at)));
    for flow in flows {
        if let Some((_, deadline, _)) = &flow.connecting {
            earliest(*deadline);
        }
    }
    if !device.incoming.is_empty() || device.outgoing.capacity() == 0 {
        earliest(start + BACKLOG_RETRY);
    }
    next
}

/// Handle used by the node to open connections.
#[derive(Clone)]
pub struct Handle {
    pub commands: mpsc::Sender<Command>,
}
impl Handle {
    pub async fn connect(&self, remote: SocketAddr) -> Result<BoxStream> {
        let (reply, result) = oneshot::channel();
        if self
            .commands
            .send(Command::Connect(remote, reply))
            .await
            .is_err()
        {
            bail!("Tailscale node stopped");
        }
        result
            .await
            .map_err(|_| anyhow::anyhow!("Tailscale node stopped"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A peer stack listening on 100.64.0.2:80 that echoes what it receives,
    /// fed by `run`'s outgoing packets and answering into its incoming ones.
    async fn echo_peer(mut from: mpsc::Receiver<Vec<u8>>, to: mpsc::Sender<Vec<u8>>) {
        let (sink, mut sent) = mpsc::channel(256);
        let mut device = PacketDevice {
            incoming: VecDeque::new(),
            outgoing: sink,
        };
        let started = Instant::now();
        let now = || NetInstant::from_millis(started.elapsed().as_millis() as i64);
        let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, now());
        iface.update_ip_addrs(|list| {
            let _ = list.push(IpCidr::new(IpAddress::v4(100, 64, 0, 2), 32));
        });
        let mut sockets = SocketSet::new(vec![]);
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; BUFFER]),
            tcp::SocketBuffer::new(vec![0; BUFFER]),
        );
        socket.listen(80).unwrap();
        let handle = sockets.add(socket);
        loop {
            while let Ok(packet) = from.try_recv() {
                device.incoming.push_back(packet);
            }
            poll(&mut iface, now(), &mut device, &mut sockets);
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            if socket.can_recv() && socket.can_send() {
                let data = socket.recv(|b| (b.len(), b.to_vec())).unwrap();
                socket.send_slice(&data).unwrap();
            }
            if socket.state() == tcp::State::CloseWait {
                socket.close();
            }
            poll(&mut iface, now(), &mut device, &mut sockets);
            while let Ok(packet) = sent.try_recv() {
                if to.send(packet).await.is_err() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    fn inbound(gate: Gate) -> (watch::Sender<Gate>, Inbound, mpsc::Receiver<Accepted>) {
        let (gate, gate_rx) = watch::channel(gate);
        let (accepted, accepted_rx) = mpsc::channel(8);
        let inbound = Inbound {
            gate: gate_rx,
            accepted,
            stats: Arc::new(ServeStats::default()),
        };
        (gate, inbound, accepted_rx)
    }

    /// A peer stack at `source` that opens `count` connections to
    /// 100.64.0.1:`port` one after another, keeping each open, and reports
    /// each echoed greeting. `states` shows every client socket's state.
    async fn dialing_peer(
        source: IpAddress,
        port: u16,
        count: usize,
        mut from: mpsc::Receiver<Vec<u8>>,
        to: mpsc::Sender<Vec<u8>>,
        echoed: mpsc::Sender<String>,
        states: watch::Sender<Vec<tcp::State>>,
    ) {
        let (sink, mut sent) = mpsc::channel(256);
        let mut device = PacketDevice {
            incoming: VecDeque::new(),
            outgoing: sink,
        };
        let started = Instant::now();
        let now = || NetInstant::from_millis(started.elapsed().as_millis() as i64);
        let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, now());
        iface.update_ip_addrs(|list| {
            let _ = list.push(IpCidr::new(source, 32));
        });
        match source {
            IpAddress::Ipv4(v4) => {
                let _ = iface.routes_mut().add_default_ipv4_route(v4);
            }
            IpAddress::Ipv6(_) => unreachable!(),
        }
        let mut sockets = SocketSet::new(vec![]);
        struct Client {
            handle: SocketHandle,
            greeted: bool,
            received: Vec<u8>,
            done: bool,
        }
        let mut clients: Vec<Client> = Vec::new();
        loop {
            if clients.len() < count && clients.iter().all(|client| client.done) {
                let mut socket = tcp_socket();
                let local = 40000 + clients.len() as u16;
                socket
                    .connect(iface.context(), (IpAddress::v4(100, 64, 0, 1), port), local)
                    .unwrap();
                clients.push(Client {
                    handle: sockets.add(socket),
                    greeted: false,
                    received: Vec::new(),
                    done: false,
                });
            }
            while let Ok(packet) = from.try_recv() {
                device.incoming.push_back(packet);
            }
            poll(&mut iface, now(), &mut device, &mut sockets);
            for (index, client) in clients.iter_mut().enumerate() {
                let socket = sockets.get_mut::<tcp::Socket>(client.handle);
                let greeting = format!("hello {index}");
                if !client.greeted && socket.can_send() {
                    socket.send_slice(greeting.as_bytes()).unwrap();
                    client.greeted = true;
                }
                if socket.can_recv() {
                    socket
                        .recv(|bytes| {
                            client.received.extend_from_slice(bytes);
                            (bytes.len(), ())
                        })
                        .unwrap();
                }
                if !client.done && client.received.len() == greeting.len() {
                    client.done = true;
                    let _ = echoed.try_send(String::from_utf8_lossy(&client.received).into_owned());
                }
            }
            states.send_replace(
                clients
                    .iter()
                    .map(|client| sockets.get::<tcp::Socket>(client.handle).state())
                    .collect(),
            );
            poll(&mut iface, now(), &mut device, &mut sockets);
            while let Ok(packet) = sent.try_recv() {
                if to.send(packet).await.is_err() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// Echoes every accepted connection.
    async fn echo_accepted(
        mut accepted: mpsc::Receiver<Accepted>,
        seen: mpsc::Sender<(SocketAddr, u16)>,
    ) {
        while let Some(Accepted {
            remote,
            port,
            stream,
        }) = accepted.recv().await
        {
            let _ = seen.send((remote, port)).await;
            tokio::spawn(async move {
                let (mut read, mut write) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    }

    fn served(port: u16, allow: Option<Vec<IpAddr>>) -> Gate {
        Gate {
            ports: BTreeMap::from([(port, allow)]),
        }
    }

    /// Starts this node's stack at 100.64.0.1 with `gate`, and a dialing
    /// peer at `source`.
    async fn serving(
        gate: Gate,
        source: IpAddress,
        port: u16,
        count: usize,
    ) -> (
        CancellationToken,
        Arc<ServeStats>,
        mpsc::Receiver<String>,
        mpsc::Receiver<(SocketAddr, u16)>,
        watch::Receiver<Vec<tcp::State>>,
    ) {
        let (commands, command_rx) = mpsc::channel(4);
        let (to_stack, incoming) = mpsc::channel(256);
        let (outgoing, from_stack) = mpsc::channel(256);
        let (open, _open_rx) = watch::channel(Vec::new());
        let stop = CancellationToken::new();
        let (gate, inbound, accepted) = inbound(gate);
        let stats = inbound.stats.clone();
        tokio::spawn(run(
            command_rx,
            incoming,
            outgoing,
            open,
            inbound,
            stop.clone(),
        ));
        commands
            .send(Command::Addresses(vec!["100.64.0.1/32".parse().unwrap()]))
            .await
            .unwrap();
        let (echoed_tx, echoed) = mpsc::channel(8);
        let (states_tx, states) = watch::channel(Vec::new());
        let (seen_tx, seen) = mpsc::channel(8);
        tokio::spawn(echo_accepted(accepted, seen_tx));
        tokio::spawn(dialing_peer(
            source, port, count, from_stack, to_stack, echoed_tx, states_tx,
        ));
        tokio::spawn(async move {
            // Keep the gate's sender (and the stack's commands) alive.
            let _keep = (gate, commands);
            std::future::pending::<()>().await;
        });
        (stop, stats, echoed, seen, states)
    }

    #[tokio::test]
    async fn accepts_peer_connections_on_serve_ports_one_after_another() {
        let peer = IpAddress::v4(100, 64, 0, 2);
        let (stop, stats, mut echoed, mut seen, _) =
            serving(served(47821, None), peer, 47821, 2).await;
        for index in 0..2 {
            let reply = tokio::time::timeout(Duration::from_secs(5), echoed.recv())
                .await
                .expect("echo timed out")
                .unwrap();
            assert_eq!(reply, format!("hello {index}"));
            let (remote, port) = seen.recv().await.unwrap();
            assert_eq!(
                remote,
                SocketAddr::new("100.64.0.2".parse().unwrap(), 40000 + index)
            );
            assert_eq!(port, 47821);
        }
        // The first connection stayed open while the second was accepted.
        assert_eq!(stats.accepted.load(Ordering::Relaxed), 2);
        assert_eq!(stats.active.load(Ordering::Relaxed), 2);
        stop.cancel();
    }

    #[tokio::test]
    async fn drops_syns_from_peers_not_allowed_without_a_reset() {
        let peer = IpAddress::v4(100, 64, 0, 2);
        let allowed = vec!["100.64.0.9".parse().unwrap()];
        let (stop, stats, mut echoed, mut seen, mut states) =
            serving(served(47821, Some(allowed)), peer, 47821, 1).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while stats.denied.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("SYN was not counted as denied");
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(echoed.try_recv().is_err());
        assert!(seen.try_recv().is_err());
        // No RST: the peer is still waiting for an answer.
        assert_eq!(*states.borrow_and_update(), vec![tcp::State::SynSent]);
        stop.cancel();
    }

    #[test]
    fn gate_checks_only_tcp_to_serve_ports() {
        fn tcp_v4(source: [u8; 4], port: u16, flags: u8) -> Vec<u8> {
            let mut packet = vec![0; 40];
            packet[0] = 0x45;
            packet[9] = 6;
            packet[12..16].copy_from_slice(&source);
            packet[16..20].copy_from_slice(&[100, 64, 0, 1]);
            packet[22..24].copy_from_slice(&port.to_be_bytes());
            packet[33] = flags;
            packet
        }
        let gate = served(47821, Some(vec!["100.64.0.2".parse().unwrap()]));
        assert_eq!(
            gate.admits(&tcp_v4([100, 64, 0, 2], 47821, 0x02)),
            Admission::Pass
        );
        assert_eq!(
            gate.admits(&tcp_v4([100, 64, 0, 3], 47821, 0x02)),
            Admission::Denied { syn: true }
        );
        assert_eq!(
            gate.admits(&tcp_v4([100, 64, 0, 3], 47821, 0x10)),
            Admission::Denied { syn: false }
        );
        // Replies to our own outbound connections are never filtered.
        assert_eq!(
            gate.admits(&tcp_v4([100, 64, 0, 3], 49200, 0x12)),
            Admission::Pass
        );
        let mut udp = tcp_v4([100, 64, 0, 3], 47821, 0x02);
        udp[9] = 17;
        assert_eq!(gate.admits(&udp), Admission::Pass);
        // IPv6 extension headers could hide TCP from the check.
        let mut v6 = vec![0; 60];
        v6[0] = 0x60;
        v6[6] = 0;
        assert_eq!(gate.admits(&v6), Admission::Denied { syn: false });
        assert_eq!(
            served(47821, None).admits(&tcp_v4([100, 64, 0, 3], 47821, 0x02)),
            Admission::Pass
        );
    }

    #[test]
    fn outbound_ports_stay_out_of_the_serve_range() {
        let mut port = FIRST_PORT;
        for _ in 0..40000 {
            port = if port >= LAST_PORT {
                FIRST_PORT
            } else {
                port + 1
            };
            assert!((FIRST_PORT..=LAST_PORT).contains(&port));
        }
    }

    #[tokio::test]
    async fn connects_and_carries_data_without_a_periodic_tick() {
        let (commands, command_rx) = mpsc::channel(4);
        let (to_stack, incoming) = mpsc::channel(256);
        let (outgoing, from_stack) = mpsc::channel(256);
        let (open, mut open_rx) = watch::channel(Vec::new());
        let stop = CancellationToken::new();
        let (_gate, inbound, _accepted) = inbound(Gate::default());
        tokio::spawn(run(
            command_rx,
            incoming,
            outgoing,
            open,
            inbound,
            stop.clone(),
        ));
        tokio::spawn(echo_peer(from_stack, to_stack));
        commands
            .send(Command::Addresses(vec!["100.64.0.1/32".parse().unwrap()]))
            .await
            .unwrap();
        let handle = Handle { commands };
        let mut stream = tokio::time::timeout(
            Duration::from_secs(5),
            handle.connect("100.64.0.2:80".parse().unwrap()),
        )
        .await
        .expect("connect timed out")
        .unwrap();
        for round in 0..2 {
            let message = format!("hello {round}");
            stream.write_all(message.as_bytes()).await.unwrap();
            let mut reply = vec![0; message.len()];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut reply))
                .await
                .expect("echo timed out")
                .unwrap();
            assert_eq!(reply, message.as_bytes());
            // Idle past smoltcp's delayed timers: the next round must still
            // be carried although nothing ticks the stack in between.
            tokio::time::sleep(Duration::from_millis(1200)).await;
        }
        let peer: IpAddr = "100.64.0.2".parse().unwrap();
        assert_eq!(*open_rx.borrow_and_update(), vec![peer]);
        // Once closed, the peer no longer counts as in use.
        drop(stream);
        tokio::time::timeout(
            Duration::from_secs(5),
            open_rx.wait_for(|open| open.is_empty()),
        )
        .await
        .expect("closed connection still listed")
        .unwrap();
        stop.cancel();
    }
}
