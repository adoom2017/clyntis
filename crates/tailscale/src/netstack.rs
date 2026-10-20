//! Userspace TCP/IP for outbound connections from this node's tailnet
//! addresses. IP packets go to and come from the WireGuard router.
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
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Notify, mpsc, oneshot},
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

pub enum Command {
    Connect(SocketAddr, oneshot::Sender<Result<BoxStream>>),
    Addresses(Vec<ipnet::IpNet>),
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

struct Flow {
    handle: SocketHandle,
    input: Option<mpsc::Sender<Vec<u8>>>,
    output: mpsc::Receiver<Vec<u8>>,
    pending: Option<(Vec<u8>, usize)>,
    eof: bool,
    /// Until established: where to hand the stream, and when to give up.
    connecting: Option<(oneshot::Sender<Result<BoxStream>>, Instant, Option<Stream>)>,
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

/// Runs the stack until `stop`: `commands` opens connections, `incoming`
/// carries decrypted packets from peers, `outgoing` takes packets to encrypt.
pub async fn run(
    mut commands: mpsc::Receiver<Command>,
    mut incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
    stop: CancellationToken,
) {
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
    let mut next_port: u16 = 49152;
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
                }
                Some(Command::Connect(remote, reply)) => {
                    let local = iface.ip_addrs().iter().map(|c| c.address()).find(|a| {
                        matches!((a, remote.ip()), (IpAddress::Ipv4(_), IpAddr::V4(_)) | (IpAddress::Ipv6(_), IpAddr::V6(_)))
                    });
                    let Some(local) = local else {
                        let _ = reply.send(Err(anyhow::anyhow!("this node has no tailnet address for {remote}")));
                        continue;
                    };
                    let mut socket = tcp::Socket::new(
                        tcp::SocketBuffer::new(vec![0; BUFFER]),
                        tcp::SocketBuffer::new(vec![0; BUFFER]),
                    );
                    socket.set_nagle_enabled(false);
                    socket.set_ack_delay(None);
                    socket.set_keep_alive(Some(NetDuration::from_secs(30)));
                    socket.set_timeout(Some(NetDuration::from_secs(300)));
                    next_port = if next_port >= 65000 { 49152 } else { next_port + 1 };
                    let endpoint = IpEndpoint::new(remote.ip().into(), remote.port());
                    if let Err(error) = socket.connect(iface.context(), endpoint, (local, next_port)) {
                        let _ = reply.send(Err(anyhow::anyhow!("tailnet connect: {error}")));
                        continue;
                    }
                    let handle = sockets.add(socket);
                    let (input, receiver) = mpsc::channel(QUEUE);
                    let (sender, output) = mpsc::channel(QUEUE);
                    let stream = Stream { input: receiver, pending: None, output: Some(PollSender::new(sender)), wake: wake.clone() };
                    flows.push(Flow { handle, input: Some(input), output, pending: None, eof: false,
                        connecting: Some((reply, Instant::now() + CONNECT_TIMEOUT, Some(stream))) });
                }
            },
            packet = incoming.recv() => match packet {
                None => break,
                Some(packet) => {
                    device.incoming.push_back(packet);
                    while device.incoming.len() < 256 {
                        let Ok(packet) = incoming.try_recv() else { break };
                        device.incoming.push_back(packet);
                    }
                }
            },
            _ = wake.notified() => {},
            _ = timer => {},
        }
        poll(&mut iface, now(), &mut device, &mut sockets);
        flows.retain_mut(|flow| {
            let socket = sockets.get_mut::<tcp::Socket>(flow.handle);
            if let Some((_, deadline, _)) = &flow.connecting {
                match socket.state() {
                    tcp::State::Established => {
                        let (reply, _, stream) = flow.connecting.take().unwrap();
                        let _ = reply.send(Ok(Box::new(stream.unwrap())));
                    }
                    tcp::State::Closed | tcp::State::TimeWait => {
                        let (reply, _, _) = flow.connecting.take().unwrap();
                        let _ =
                            reply.send(Err(anyhow::anyhow!("tailnet peer refused the connection")));
                        sockets.remove(flow.handle);
                        return false;
                    }
                    _ if Instant::now() >= *deadline => {
                        let (reply, _, _) = flow.connecting.take().unwrap();
                        let _ = reply.send(Err(anyhow::anyhow!("tailnet connection timed out")));
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
            poll(&mut iface, now(), &mut device, &mut sockets);
            while let Ok(packet) = sent.try_recv() {
                if to.send(packet).await.is_err() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    #[tokio::test]
    async fn connects_and_carries_data_without_a_periodic_tick() {
        let (commands, command_rx) = mpsc::channel(4);
        let (to_stack, incoming) = mpsc::channel(256);
        let (outgoing, from_stack) = mpsc::channel(256);
        let stop = CancellationToken::new();
        tokio::spawn(run(command_rx, incoming, outgoing, stop.clone()));
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
        stop.cancel();
    }
}
