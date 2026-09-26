//! Raw IP to proxy-session adapter. smoltcp owns TCP/IP protocol state.
#[path = "packet_ipv6.rs"]
mod ipv6;
use crate::Core;
use anyhow::{Result, ensure};
use meta_platform::PacketIo;
use meta_protocol::Target;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{tcp, udp},
    time::{Duration as NetDuration, Instant as NetInstant},
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, IpVersion, Ipv4Packet,
        Ipv6Packet, TcpPacket, UdpPacket,
    },
};
use std::{
    collections::{HashMap, VecDeque},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::mpsc,
    task::JoinSet,
};
use tokio_util::{sync::PollSender, task::AbortOnDropHandle};

const MAX_TCP: usize = 512;
const MAX_UDP: usize = 512;
const MAX_PORTS: usize = 256;
const BUFFER: usize = 32768;
const CHUNK: usize = 8192;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct Flow {
    source: IpEndpoint,
    target: IpEndpoint,
    tcp: bool,
}
struct TcpFlow {
    handle: SocketHandle,
    input: Option<mpsc::Sender<Vec<u8>>>,
    output: mpsc::Receiver<Vec<u8>>,
    pending: Option<(Vec<u8>, usize)>,
    eof: bool,
    last: Instant,
    task: tokio::task::AbortHandle,
}
struct UdpFlow {
    input: mpsc::Sender<Vec<u8>>,
    task: tokio::task::AbortHandle,
}
struct UdpPort {
    handle: SocketHandle,
    last: Instant,
}
struct Reply {
    flow: Flow,
    payload: Vec<u8>,
}

pub(crate) struct PacketDevice {
    pub(crate) incoming: VecDeque<Vec<u8>>,
    pub(crate) outgoing: mpsc::Sender<Vec<u8>>,
    pub(crate) mtu: usize,
}
pub(crate) struct Receive(Vec<u8>);
pub(crate) struct Transmit(mpsc::OwnedPermit<Vec<u8>>);
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
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities.max_burst_size = Some(64);
        capabilities
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

struct ChannelStream {
    input: mpsc::Receiver<Vec<u8>>,
    pending: Option<(Vec<u8>, usize)>,
    output: Option<PollSender<Vec<u8>>>,
}
impl AsyncRead for ChannelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.pending.is_none() {
            match this.input.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(bytes)) => this.pending = Some((bytes, 0)),
            }
        }
        let (bytes, offset) = this.pending.as_mut().unwrap();
        let n = buffer.remaining().min(bytes.len() - *offset);
        buffer.put_slice(&bytes[*offset..*offset + n]);
        *offset += n;
        if *offset == bytes.len() {
            this.pending = None;
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for ChannelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let Some(output) = self.get_mut().output.as_mut() else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match output.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Ready(Ok(())) => {
                let n = bytes.len().min(CHUNK);
                Poll::Ready(
                    output
                        .send_item(bytes[..n].to_vec())
                        .map(|()| n)
                        .map_err(|_| io::ErrorKind::BrokenPipe.into()),
                )
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().output.take();
        Poll::Ready(Ok(()))
    }
}

fn sniff(bytes: &[u8]) -> Option<(Flow, bool)> {
    let (source, target, mut protocol, mut payload) = match IpVersion::of_packet(bytes).ok()? {
        IpVersion::Ipv4 => {
            let packet = Ipv4Packet::new_checked(bytes).ok()?;
            if packet.frag_offset() != 0 || !packet.verify_checksum() {
                return None;
            }
            (
                packet.src_addr().into(),
                packet.dst_addr().into(),
                packet.next_header(),
                packet.payload(),
            )
        }
        IpVersion::Ipv6 => {
            let packet = Ipv6Packet::new_checked(bytes).ok()?;
            (
                packet.src_addr().into(),
                packet.dst_addr().into(),
                packet.next_header(),
                packet.payload(),
            )
        }
    };
    for _ in 0..8 {
        if !matches!(
            protocol,
            IpProtocol::HopByHop | IpProtocol::Ipv6Opts | IpProtocol::Ipv6Route
        ) {
            break;
        }
        let extension = smoltcp::wire::Ipv6ExtHeader::new_checked(payload).ok()?;
        protocol = extension.next_header();
        payload = payload.get((extension.header_len() as usize + 1) * 8..)?;
    }
    let (source_port, target_port, tcp, syn) = match protocol {
        IpProtocol::Tcp => {
            let packet = TcpPacket::new_checked(payload).ok()?;
            if !packet.verify_checksum(&source, &target) {
                return None;
            }
            (
                packet.src_port(),
                packet.dst_port(),
                true,
                packet.syn() && !packet.ack(),
            )
        }
        IpProtocol::Udp => {
            // The initial fragment may contain only part of a UDP datagram.
            if payload.len() < 8 {
                return None;
            }
            let packet = UdpPacket::new_unchecked(payload);
            (packet.src_port(), packet.dst_port(), false, false)
        }
        _ => return None,
    };
    if source_port == 0 || target_port == 0 {
        return None;
    }
    Some((
        Flow {
            source: IpEndpoint::new(source, source_port),
            target: IpEndpoint::new(target, target_port),
            tcp,
        },
        syn,
    ))
}

fn hijack_dns(core: &Core, endpoint: IpEndpoint, tcp: bool) -> bool {
    core.config.tun.dns_hijack.iter().any(|entry| {
        let entry = if let Some(e) = entry.strip_prefix("tcp://") {
            if !tcp {
                return false;
            }
            e
        } else if let Some(e) = entry.strip_prefix("udp://") {
            if tcp {
                return false;
            }
            e
        } else {
            entry
        };
        entry == format!("any:{}", endpoint.port) || entry == endpoint.to_string()
    })
}
async fn tcp_session(core: Arc<Core>, flow: Flow, mut stream: ChannelStream) -> Result<()> {
    if hijack_dns(&core, flow.target, true) {
        let serve = async {
            for _ in 0..100 {
                let n = stream.read_u16().await?;
                let mut bytes = vec![0; n as usize];
                stream.read_exact(&mut bytes).await?;
                let response = core.resolver.answer(&bytes).await?;
                tracing::debug!(
                    request_bytes = bytes.len(),
                    response_bytes = response.len(),
                    "TUN DNS TCP query answered"
                );
                stream.write_u16(response.len() as u16).await?;
                stream.write_all(&response).await?;
            }
            Ok(())
        };
        return tokio::time::timeout(Duration::from_secs(120), serve).await?;
    }
    let target = Target::new(flow.target.addr.to_string(), flow.target.port)?;
    let source = flow.source.to_string();
    if core.should_sniff(&core.restore_target(&target)) {
        let (route, destination, prefix) = core.sniff_target(&mut stream, &target).await?;
        let (mut outbound, name) = core.dial_sniffed(&route, &destination, &source).await?;
        outbound.write_all(&prefix).await?;
        return core.relay(Box::new(stream), route, outbound, name).await;
    }
    let (outbound, name) = core.dial_logged(&target, None, &source).await?;
    core.relay(Box::new(stream), target, outbound, name).await
}
async fn udp_session(
    core: Arc<Core>,
    flow: Flow,
    mut input: mpsc::Receiver<Vec<u8>>,
    output: mpsc::Sender<Reply>,
) -> Result<()> {
    if hijack_dns(&core, flow.target, false) {
        while let Some(packet) =
            tokio::time::timeout(Duration::from_secs(120), input.recv()).await?
        {
            match tokio::time::timeout(Duration::from_secs(10), core.resolver.answer(&packet)).await
            {
                Ok(Ok(payload)) => {
                    tracing::debug!(
                        request_bytes = packet.len(),
                        response_bytes = payload.len(),
                        "TUN DNS UDP query answered"
                    );
                    let _ = output.try_send(Reply { flow, payload });
                }
                Ok(Err(error)) => tracing::debug!(%error, "TUN DNS UDP query failed"),
                Err(_) => tracing::debug!("TUN DNS UDP query timed out"),
            }
        }
        return Ok(());
    }
    let target = Target::new(flow.target.addr.to_string(), flow.target.port)?;
    let session = core
        .datagram_for_source(&target, &format!("tun:{}", flow.source))
        .await?;
    let target = core.restore_target(&target);
    // Keep each receive alive while sending: stream-based UDP decoders cannot
    // resume safely if a partially read frame is cancelled for every upload.
    let send = async {
        while let Some(packet) =
            tokio::time::timeout(Duration::from_secs(120), input.recv()).await?
        {
            session.send(&target, &packet).await?;
        }
        Ok::<(), anyhow::Error>(())
    };
    let recv = async {
        loop {
            let (_, payload) = session.recv().await?;
            let _ = output.try_send(Reply { flow, payload });
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {
        biased;
        _ = core.stop.cancelled() => Ok(()),
        result = send => result,
        result = recv => result,
    }
}

pub(crate) async fn run(core: Arc<Core>, io: Arc<dyn PacketIo>) -> Result<()> {
    ensure!(
        (1280..=9000).contains(&core.config.tun.mtu),
        "invalid TUN MTU"
    );
    let started = Instant::now();
    let now = || NetInstant::from_millis(started.elapsed().as_millis() as i64);
    let (transmit, mut outgoing) = mpsc::channel::<Vec<u8>>(256);
    let writer_io = io.clone();
    let mtu = core.config.tun.mtu as usize;
    let mut writer = AbortOnDropHandle::new(tokio::spawn(async move {
        let mut ident = uuid::Uuid::new_v4().as_u128() as u32;
        while let Some(packet) = outgoing.recv().await {
            ident = ident.wrapping_add(1);
            let frames = match ipv6::fragment(packet, mtu, ident) {
                Ok(frames) => frames,
                Err(error) => {
                    tracing::debug!(%error, "dropping oversized or invalid TUN reply");
                    continue;
                }
            };
            let send = async {
                for frame in frames {
                    writer_io.send(&frame).await?;
                }
                Ok::<(), anyhow::Error>(())
            };
            tokio::time::timeout(Duration::from_secs(5), send).await??;
        }
        Ok::<(), anyhow::Error>(())
    }));
    let mut device = PacketDevice {
        incoming: VecDeque::new(),
        outgoing: transmit,
        mtu: core.config.tun.mtu as usize,
    };
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = uuid::Uuid::new_v4().as_u128() as u64;
    let mut iface = Interface::new(config, &mut device, now());
    let v4 = "198.18.0.1".parse().unwrap();
    let v6 = "fdfe:dcba:9876::1".parse().unwrap();
    iface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(v4), 32))
            .unwrap();
        addresses
            .push(IpCidr::new(IpAddress::Ipv6(v6), 128))
            .unwrap();
    });
    iface.routes_mut().add_default_ipv4_route(v4).unwrap();
    iface.routes_mut().add_default_ipv6_route(v6).unwrap();
    iface.set_any_ip(true);
    let mut sockets = SocketSet::new(vec![]);
    let mut tcp_flows: HashMap<Flow, TcpFlow> = HashMap::new();
    let mut udp_flows: HashMap<Flow, UdpFlow> = HashMap::new();
    let mut ports: HashMap<IpEndpoint, UdpPort> = HashMap::new();
    let mut tasks = JoinSet::new();
    let (replies, mut incoming_replies) = mpsc::channel::<Reply>(256);
    let mut tick = tokio::time::interval(Duration::from_millis(2));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut packet = vec![0; 65535];
    let mut fragments = ipv6::Reassembly::default();
    let mut last_expiry = Instant::now();
    loop {
        tokio::select! {
            biased;
            _ = core.stop.cancelled() => break,
            result = &mut writer => { result??; break; },
            result = io.recv(&mut packet), if device.incoming.len() < 256 => {
                let n = result?;
                ensure!(n <= packet.len(), "PacketIo returned invalid length");
                if n == 0 { continue; }
                if !core.config.ipv6 && packet[0] >> 4 == 6 { continue; }
                let Some(packet) = fragments.accept(&packet[..n], Instant::now()) else { continue; };
                if let Some((flow, syn)) = sniff(&packet) {
                    if !core.config.ipv6 && matches!(flow.target.addr, IpAddress::Ipv6(_)) { continue; }
                    if flow.tcp && syn && !tcp_flows.contains_key(&flow) && tcp_flows.len() < MAX_TCP {
                        let mut socket = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; BUFFER]), tcp::SocketBuffer::new(vec![0; BUFFER]));
                        socket.set_timeout(Some(NetDuration::from_secs(300)));
                        socket.set_keep_alive(Some(NetDuration::from_secs(30)));
                        socket.listen(flow.target)?;
                        let handle = sockets.add(socket);
                        let (input, receiver) = mpsc::channel(4);
                        let (sender, output) = mpsc::channel(4);
                        let stream = ChannelStream { input: receiver, pending: None, output: Some(PollSender::new(sender)) };
                        let core = core.clone();
                        let task = tasks.spawn(async move { (flow, tcp_session(core, flow, stream).await) });
                        tcp_flows.insert(flow, TcpFlow { handle, input: Some(input), output, pending: None, eof: false, last: Instant::now(), task });
                    } else if !flow.tcp && !ports.contains_key(&flow.target) && ports.len() < MAX_PORTS {
                        let buffer = || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 65535]);
                        let mut socket = udp::Socket::new(buffer(), buffer());
                        socket.bind(flow.target)?;
                        ports.insert(flow.target, UdpPort { handle: sockets.add(socket), last: Instant::now() });
                    }
                }
                device.incoming.push_back(packet.into_owned());
            },
            _ = tick.tick() => {},
        }
        if last_expiry.elapsed() >= Duration::from_secs(1) {
            last_expiry = Instant::now();
            fragments.expire(last_expiry);
        }
        iface.poll(now(), &mut device, &mut sockets);
        while let Some(result) = tasks.try_join_next() {
            if let Ok((flow, result)) = result {
                if flow.tcp {
                    if let Some(state) = tcp_flows.get_mut(&flow)
                        && result.is_err()
                    {
                        sockets.get_mut::<tcp::Socket>(state.handle).abort();
                    }
                } else {
                    udp_flows.remove(&flow);
                }
            }
        }
        let mut retired = vec![];
        tcp_flows.retain(|_, state| {
            let socket = sockets.get_mut::<tcp::Socket>(state.handle);
            if state.last.elapsed() > Duration::from_secs(300) {
                socket.abort();
            }
            if matches!(socket.state(), tcp::State::Listen | tcp::State::SynReceived)
                && state.last.elapsed() > Duration::from_secs(30)
            {
                socket.abort();
            }
            while socket.can_recv() {
                let Some(input) = &state.input else {
                    socket.abort();
                    break;
                };
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
                state.last = Instant::now();
            }
            if !socket.may_recv()
                && !matches!(socket.state(), tcp::State::Listen | tcp::State::SynReceived)
            {
                state.input.take();
            }
            while socket.can_send() {
                if state.pending.is_none() && !state.eof {
                    match state.output.try_recv() {
                        Ok(bytes) => state.pending = Some((bytes, 0)),
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            state.eof = true;
                        }
                        Err(mpsc::error::TryRecvError::Empty) => break,
                    }
                }
                let Some((bytes, offset)) = state.pending.as_mut() else {
                    if state.eof {
                        socket.close();
                    }
                    break;
                };
                let n = socket.send_slice(&bytes[*offset..]).unwrap_or(0);
                if n == 0 {
                    break;
                }
                *offset += n;
                state.last = Instant::now();
                if *offset == bytes.len() {
                    state.pending = None;
                }
            }
            if !socket.is_open() {
                state.task.abort();
                retired.push(state.handle);
                false
            } else {
                true
            }
        });
        for (endpoint, port) in &mut ports {
            let socket = sockets.get_mut::<udp::Socket>(port.handle);
            while let Ok((bytes, metadata)) = socket.recv() {
                port.last = Instant::now();
                let flow = Flow {
                    source: metadata.endpoint,
                    target: *endpoint,
                    tcp: false,
                };
                if !udp_flows.contains_key(&flow) && udp_flows.len() < MAX_UDP {
                    let (input, receiver) = mpsc::channel(16);
                    let core = core.clone();
                    let replies = replies.clone();
                    let task = tasks.spawn(async move {
                        (flow, udp_session(core, flow, receiver, replies).await)
                    });
                    udp_flows.insert(flow, UdpFlow { input, task });
                }
                if let Some(session) = udp_flows.get(&flow) {
                    let _ = session.input.try_send(bytes.to_vec());
                }
            }
        }
        for _ in 0..256 {
            let Ok(reply) = incoming_replies.try_recv() else {
                break;
            };
            if let Some(port) = ports.get_mut(&reply.flow.target) {
                let socket = sockets.get_mut::<udp::Socket>(port.handle);
                let _ = socket.send_slice(&reply.payload, reply.flow.source);
                port.last = Instant::now();
            }
        }
        ports.retain(|endpoint, port| {
            if port.last.elapsed() <= Duration::from_secs(120) {
                return true;
            }
            udp_flows.retain(|flow, state| {
                if flow.target != *endpoint {
                    return true;
                }
                state.task.abort();
                false
            });
            sockets.remove(port.handle);
            false
        });
        iface.poll(now(), &mut device, &mut sockets);
        for handle in retired {
            sockets.remove(handle);
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
#[path = "packet_tests.rs"]
mod tests;
