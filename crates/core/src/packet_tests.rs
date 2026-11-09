use super::*;
use async_trait::async_trait;
use clyntis_config::Config as CoreConfig;
use std::net::SocketAddr;
use tokio::sync::Mutex;

thread_local! {
    /// A budget for this thread's packet loop (`#[tokio::test]` runs it on
    /// the test's thread): small limits without hundreds of sockets.
    pub(super) static BUDGET: std::cell::Cell<Option<Budget>> = const { std::cell::Cell::new(None) };
}

struct Packets {
    receiver: Mutex<mpsc::Receiver<Vec<u8>>>,
    sender: mpsc::Sender<Vec<u8>>,
}
#[async_trait]
impl PacketIo for Packets {
    async fn recv(&self, packet: &mut [u8]) -> Result<usize> {
        let bytes = self
            .receiver
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("packet channel closed"))?;
        ensure!(bytes.len() <= packet.len(), "packet buffer too small");
        packet[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }
    async fn send(&self, packet: &[u8]) -> Result<()> {
        self.sender.send(packet.to_vec()).await?;
        Ok(())
    }
}
fn pair() -> (Arc<Packets>, Arc<Packets>) {
    let (a, b) = mpsc::channel(256);
    let (c, d) = mpsc::channel(256);
    (
        Arc::new(Packets {
            receiver: Mutex::new(b),
            sender: c,
        }),
        Arc::new(Packets {
            receiver: Mutex::new(d),
            sender: a,
        }),
    )
}

async fn client(packets: Arc<Packets>, target: SocketAddr, payload: Vec<u8>, tcp: bool) -> Vec<u8> {
    let expected = payload.len();
    client_stream(packets, target, payload, tcp, expected, None).await
}

async fn client_stream(
    packets: Arc<Packets>,
    target: SocketAddr,
    payload: Vec<u8>,
    tcp: bool,
    expected: usize,
    progress: Option<mpsc::UnboundedSender<usize>>,
) -> Vec<u8> {
    let started = Instant::now();
    let now = || NetInstant::from_millis(started.elapsed().as_millis() as i64);
    let (outgoing, mut output) = mpsc::channel(256);
    let mut device = PacketDevice {
        incoming: VecDeque::new(),
        outgoing,
        mtu: 1500,
    };
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = 123;
    let mut iface = Interface::new(config, &mut device, now());
    let source: IpAddress = if target.is_ipv4() {
        "10.0.0.2"
    } else {
        "fd00::2"
    }
    .parse()
    .unwrap();
    iface.update_ip_addrs(|addresses| {
        addresses.push(IpCidr::new(source, 0)).unwrap();
    });
    let remote = IpEndpoint::new(target.ip().into(), target.port());
    let local = IpEndpoint::new(source, 54321);
    let mut sockets = SocketSet::new(vec![]);
    let handle = if tcp {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; Budget::DESKTOP.tcp_buffer]),
            tcp::SocketBuffer::new(vec![0; Budget::DESKTOP.tcp_buffer]),
        );
        socket.connect(iface.context(), remote, local).unwrap();
        sockets.add(socket)
    } else {
        let buffer = || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 65535]);
        let mut socket = udp::Socket::new(buffer(), buffer());
        socket.bind(local).unwrap();
        socket.send_slice(&payload, remote).unwrap();
        sockets.add(socket)
    };
    let mut packet = vec![0; 65535];
    let mut result = vec![];
    let mut sent = 0;
    let mut tick = tokio::time::interval(Duration::from_millis(2));
    let mut fragments = ipv6::Reassembly::default();
    let mut ident = 0;
    loop {
        iface.poll(now(), &mut device, &mut sockets);
        if tcp {
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            assert!(
                started.elapsed() < Duration::from_secs(if progress.is_some() { 900 } else { 8 }),
                "TCP {target} state {:?}, sent {sent}, received {}",
                socket.state(),
                result.len()
            );
            if sent < payload.len() && socket.can_send() {
                sent += socket.send_slice(&payload[sent..]).unwrap();
            }
            while socket.can_recv() {
                socket
                    .recv(|bytes| {
                        result.extend_from_slice(bytes);
                        if let Some(progress) = &progress {
                            let _ = progress.send(result.len());
                        }
                        (bytes.len(), ())
                    })
                    .unwrap();
            }
            if result.len() == expected {
                socket.close();
            }
            if result.len() == expected && !socket.is_open() {
                return result;
            }
        } else {
            let socket = sockets.get_mut::<udp::Socket>(handle);
            assert!(
                started.elapsed() < Duration::from_secs(8),
                "UDP {target} no response"
            );
            if let Ok((bytes, metadata)) = socket.recv() {
                assert_eq!(metadata.endpoint, remote);
                return bytes.to_vec();
            }
        }
        iface.poll(now(), &mut device, &mut sockets);
        while let Ok(packet) = output.try_recv() {
            ident += 1;
            for frame in ipv6::fragment(packet, 1500, ident).unwrap() {
                packets.send(&frame).await.unwrap();
            }
        }
        tokio::select! {
            n = packets.recv(&mut packet) => {
                let n = n.unwrap();
                if let Some(packet) = fragments.accept(&packet[..n], Instant::now().into()) {
                    device.incoming.push_back(packet.into_owned());
                }
            },
            _ = tick.tick() => {},
        }
    }
}

#[tokio::test]
async fn raw_ip_tcp_udp_ipv4_ipv6_and_half_close() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for host in ["127.0.0.1", "::1"] {
            for tcp in [true, false] {
                let (device, host_io) = pair();
                let mut config = CoreConfig::default();
                config.tun.enable = true;
                let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
                let running = core.start_with_packets(Some(device)).await.unwrap();
                let payload: Vec<u8> = (0..if tcp { 131072 } else { 4000 })
                    .map(|n| (n % 251) as u8)
                    .collect();
                let (target, oracle) = if tcp {
                    let listener =
                        tokio::net::TcpListener::bind(SocketAddr::new(host.parse().unwrap(), 0))
                            .await
                            .unwrap();
                    let target = listener.local_addr().unwrap();
                    let n = payload.len();
                    (
                        target,
                        tokio::spawn(async move {
                            let (mut stream, _) = listener.accept().await.unwrap();
                            let mut bytes = vec![0; n];
                            stream.read_exact(&mut bytes).await.unwrap();
                            stream.write_all(&bytes).await.unwrap();
                            stream.shutdown().await.unwrap();
                            assert_eq!(
                                stream.read_u8().await.unwrap_err().kind(),
                                io::ErrorKind::UnexpectedEof
                            );
                        }),
                    )
                } else {
                    let socket =
                        tokio::net::UdpSocket::bind(SocketAddr::new(host.parse().unwrap(), 0))
                            .await
                            .unwrap();
                    (
                        socket.local_addr().unwrap(),
                        tokio::spawn(async move {
                            let mut bytes = vec![0; 65535];
                            let (n, peer) = socket.recv_from(&mut bytes).await.unwrap();
                            socket.send_to(&bytes[..n], peer).await.unwrap();
                        }),
                    )
                };
                assert_eq!(client(host_io, target, payload.clone(), tcp).await, payload);
                oracle.await.unwrap();
                assert_eq!(
                    core.upload.load(std::sync::atomic::Ordering::Relaxed),
                    payload.len() as u64
                );
                assert_eq!(
                    core.download.load(std::sync::atomic::Ordering::Relaxed),
                    payload.len() as u64
                );
                running.shutdown().await;
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn packet_dns_hijack_returns_fake_ip_without_upstream() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (device, host_io) = pair();
        let mut config = CoreConfig::default();
        config.tun.enable = true;
        let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        let running = core.start_with_packets(Some(device)).await.unwrap();
        let mut query = hickory_proto::op::Message::new();
        query.set_id(42).add_query(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_ascii("tun.test").unwrap(),
            hickory_proto::rr::RecordType::A,
        ));
        let response = client(
            host_io,
            "8.8.8.8:53".parse().unwrap(),
            query.to_vec().unwrap(),
            false,
        )
        .await;
        let response = hickory_proto::op::Message::from_vec(&response).unwrap();
        assert_eq!(response.id(), 42);
        let hickory_proto::rr::RData::A(address) = response.answers()[0].data() else {
            panic!("expected A");
        };
        assert_eq!(
            core.resolver.original(address.0.into()).as_deref(),
            Some("tun.test")
        );
        running.shutdown().await;
    })
    .await
    .unwrap();
}

// Darwin rejects the intentionally over-limit datagram in sendto(2), before it
// can reach the packet writer behavior covered here on Windows and Linux.
#[cfg(not(target_os = "macos"))]
#[tokio::test]
async fn oversized_ipv6_reply_does_not_stop_packet_delivery() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (device, host_io) = pair();
        let mut config = CoreConfig::default();
        config.tun.enable = true;
        let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        let running = core.start_with_packets(Some(device)).await.unwrap();
        let socket = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let target = socket.local_addr().unwrap();
        let oracle = tokio::spawn(async move {
            let mut query = [0; 4];
            let (_, peer) = socket.recv_from(&mut query).await.unwrap();
            socket.send_to(&vec![1; 65500], peer).await.unwrap();
            socket.send_to(b"pong", peer).await.unwrap();
        });
        assert_eq!(
            client(host_io, target, b"ping".to_vec(), false).await,
            b"pong"
        );
        oracle.await.unwrap();
        running.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn udp_upload_does_not_cancel_a_partial_vless_response() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = CoreConfig::parse(format!("proxies:\n- name: vless\n  type: vless\n  server: 127.0.0.1\n  port: {}\n  uuid: 11223344-5566-7788-99aa-bbccddeeff00\nrules: ['MATCH,vless']\n", listener.local_addr().unwrap().port()).as_bytes()).unwrap();
        let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        let flow = Flow { source: "10.0.0.2:12345".parse().unwrap(), target: "192.0.2.1:9999".parse().unwrap(), tcp: false };
        let (input, receiver) = mpsc::channel(16); let (output, mut replies) = mpsc::channel(16);
        let session = tokio::spawn(udp_session(core.clone(), flow, 1, receiver, output, Arc::default()));
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut request = [0; 26]; peer.read_exact(&mut request).await.unwrap();
        peer.write_all(&[0]).await.unwrap();
        input.send(b"one".to_vec()).await.unwrap();
        let mut frame = [0; 5]; peer.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame, b"\x00\x03one");
        peer.write_all(&[0, 0]).await.unwrap();
        input.send(b"two".to_vec()).await.unwrap();
        peer.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame, b"\x00\x03two");
        peer.write_all(b"\x04pong").await.unwrap();
        assert_eq!(replies.recv().await.unwrap().payload, b"pong");
        core.stop.cancel(); session.await.unwrap().unwrap();
    }).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn tun_sse_resumes_after_six_minutes_with_tcp_keepalive() {
    let (device, host_io) = pair();
    let mut config = CoreConfig::default();
    config.tun.enable = true;
    let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
    let running = core.start_with_packets(Some(device)).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let request = b"GET /events HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let first = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: first\n\n";
    let last = b"data: resumed\n\n";
    let (progress, mut received) = mpsc::unbounded_channel();
    let client = tokio::spawn(client_stream(
        host_io,
        target,
        request.to_vec(),
        true,
        first.len() + last.len(),
        Some(progress),
    ));
    let (mut server, _) = listener.accept().await.unwrap();
    server
        .read_exact(&mut vec![0; request.len()])
        .await
        .unwrap();
    server.write_all(first).await.unwrap();
    while received.recv().await.unwrap() < first.len() {}
    // Keep polling both TCP stacks so their keepalive probes are acknowledged,
    // but send no application bytes for longer than the former idle cutoff.
    for _ in 0..12 {
        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !client.is_finished(),
            "TUN closed a live idle SSE connection"
        );
    }
    assert_eq!(core.connections().len(), 1, "idle SSE relay was removed");
    server.write_all(last).await.unwrap();
    server.shutdown().await.unwrap();
    let bytes = tokio::time::timeout(Duration::from_secs(5), client)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bytes, [first.as_slice(), last.as_slice()].concat());
    assert_eq!(server.read(&mut [0]).await.unwrap(), 0);
    running.shutdown().await;
}

/// macOS ACKs every few segments, not each one. smoltcp sends one segment per
/// socket per egress pass, so the loop must keep transmitting after each
/// wakeup; sending one or two segments per ACK capped downloads near 10 MB/s
/// (this test took ~10 s). Run in release with `--nocapture` for MB/s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tun_download_keeps_up_with_sparse_host_acks() {
    const TOTAL: usize = 16 * 1024 * 1024;
    const ACK_EVERY: u64 = 8;
    let (device, host_io) = pair();
    let mut config = CoreConfig::default();
    config.tun.enable = true;
    let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
    let running = core.start_with_packets(Some(device)).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        // One segment per write, as an upstream socket is read from a NIC.
        let segment = [7u8; 1448];
        let mut sent = 0;
        while sent < TOTAL {
            let n = segment.len().min(TOTAL - sent);
            stream.write_all(&segment[..n]).await.unwrap();
            sent += n;
            tokio::task::yield_now().await;
        }
        stream.shutdown().await.unwrap();
    });
    let started = Instant::now();
    let now = || NetInstant::from_millis(started.elapsed().as_millis() as i64);
    let (outgoing, mut output) = mpsc::channel(1024);
    let mut device = PacketDevice {
        incoming: VecDeque::new(),
        outgoing,
        mtu: 1500,
    };
    let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, now());
    let source: IpAddress = "10.0.0.2".parse().unwrap();
    iface.update_ip_addrs(|a| a.push(IpCidr::new(source, 0)).unwrap());
    let mut sockets = SocketSet::new(vec![]);
    // A host kernel's autotuned receive window.
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 4 << 20]),
        tcp::SocketBuffer::new(vec![0; 64 * 1024]),
    );
    socket
        .connect(
            iface.context(),
            IpEndpoint::new(target.ip().into(), target.port()),
            IpEndpoint::new(source, 54321),
        )
        .unwrap();
    let handle = sockets.add(socket);
    let mut packet = vec![0; 65535];
    let mut received = 0;
    let mut acks = 0u64;
    // A withheld ACK goes out on a delayed-ACK timer, like the host's.
    let mut held: Option<(Vec<u8>, Instant)> = None;
    while received < TOTAL {
        iface.poll(now(), &mut device, &mut sockets);
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        while socket.can_recv() {
            received += socket.recv(|b| (b.len(), b.len())).unwrap();
        }
        iface.poll(now(), &mut device, &mut sockets);
        while let Ok(packet) = output.try_recv() {
            let pure_ack = Ipv4Packet::new_checked(&packet[..])
                .ok()
                .and_then(|ip| {
                    TcpPacket::new_checked(ip.payload())
                        .ok()
                        .map(|tcp| tcp.payload().is_empty() && !tcp.syn() && !tcp.fin())
                })
                .unwrap_or(false);
            if pure_ack {
                acks += 1;
                if !acks.is_multiple_of(ACK_EVERY) {
                    held = Some((packet, Instant::now()));
                    continue;
                }
            }
            held = None;
            host_io.send(&packet).await.unwrap();
        }
        if let Some((packet, at)) = &held
            && at.elapsed() >= Duration::from_millis(40)
        {
            host_io.send(packet).await.unwrap();
            held = None;
        }
        let wait = iface
            .poll_delay(now(), &sockets)
            .map_or(Duration::from_millis(5), |d| {
                Duration::from_micros(d.total_micros())
            })
            .min(Duration::from_millis(5));
        if let Ok(n) = tokio::time::timeout(wait, host_io.recv(&mut packet)).await {
            device.incoming.push_back(packet[..n.unwrap()].to_vec());
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "TUN download stalled at {received} of {TOTAL} bytes"
        );
    }
    println!(
        "TUN download with sparse ACKs: {:.1} MB/s",
        TOTAL as f64 / started.elapsed().as_secs_f64() / 1e6
    );
    running.shutdown().await;
}

#[test]
fn port_unreachable_quotes_the_flow_with_valid_checksums() {
    use smoltcp::wire::{Icmpv4Packet, Icmpv6Packet};
    let v4 = Flow {
        source: IpEndpoint::new("198.18.0.2".parse().unwrap(), 52805),
        target: IpEndpoint::new("117.88.123.99".parse().unwrap(), 443),
        tcp: false,
    };
    let bytes = port_unreachable(&v4).unwrap();
    let ip = Ipv4Packet::new_checked(&bytes[..]).unwrap();
    assert!(ip.verify_checksum());
    assert_eq!(
        (ip.src_addr().to_string(), ip.dst_addr().to_string()),
        ("117.88.123.99".into(), "198.18.0.2".into())
    );
    assert_eq!(ip.next_header(), IpProtocol::Icmp);
    let icmp = Icmpv4Packet::new_checked(ip.payload()).unwrap();
    assert!(icmp.verify_checksum());
    assert_eq!((u8::from(icmp.msg_type()), icmp.msg_code()), (3, 3));
    let quoted = Ipv4Packet::new_checked(icmp.data()).unwrap();
    assert!(quoted.verify_checksum());
    let udp = UdpPacket::new_unchecked(quoted.payload());
    assert_eq!((udp.src_port(), udp.dst_port()), (52805, 443));

    let v6 = Flow {
        source: IpEndpoint::new("fdfe:dcba:9876::2".parse().unwrap(), 40000),
        target: IpEndpoint::new("2001:db8::1".parse().unwrap(), 443),
        tcp: false,
    };
    let bytes = port_unreachable(&v6).unwrap();
    let ip = Ipv6Packet::new_checked(&bytes[..]).unwrap();
    assert_eq!(ip.next_header(), IpProtocol::Icmpv6);
    let icmp = Icmpv6Packet::new_checked(ip.payload()).unwrap();
    assert!(icmp.verify_checksum(&ip.src_addr(), &ip.dst_addr()));
    assert_eq!((u8::from(icmp.msg_type()), icmp.msg_code()), (1, 4));
}

#[tokio::test]
async fn rejected_udp_gets_port_unreachable_at_once() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (device, host_io) = pair();
        let mut config = CoreConfig::default();
        config.tun.enable = true;
        config.rules = vec!["DST-PORT,443,REJECT".into(), "MATCH,DIRECT".into()];
        let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        let running = core.start_with_packets(Some(device)).await.unwrap();
        let app = [10, 0, 0, 2];
        let remote = [203, 0, 113, 9];
        let datagram = |port: u16| {
            let mut udp = Vec::new();
            udp.extend(port.to_be_bytes());
            udp.extend(443u16.to_be_bytes());
            udp.extend(12u16.to_be_bytes());
            udp.extend([0, 0]);
            udp.extend(b"quic");
            let mut packet = ipv4_header(app, remote, 17, udp.len());
            packet.extend(udp);
            packet
        };
        // The first datagram is routed and rejected; a retry is refused at
        // once, without routing it again.
        for _ in 0..2 {
            host_io.send(&datagram(50000)).await.unwrap();
            let mut reply = vec![0; 1500];
            let n = host_io.recv(&mut reply).await.unwrap();
            let ip = Ipv4Packet::new_checked(&reply[..n]).unwrap();
            assert_eq!(ip.next_header(), IpProtocol::Icmp);
            assert_eq!(ip.src_addr().octets(), remote);
            let icmp = smoltcp::wire::Icmpv4Packet::new_checked(ip.payload()).unwrap();
            assert_eq!((u8::from(icmp.msg_type()), icmp.msg_code()), (3, 3));
        }
        running.shutdown().await;
    })
    .await
    .unwrap();
}

/// Reads packets from the TUN until `wanted` accepts one, or panics.
async fn wait_for(host_io: &Packets, mut wanted: impl FnMut(&[u8]) -> bool) -> Vec<u8> {
    let mut buffer = vec![0; 65535];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), host_io.recv(&mut buffer))
            .await
            .expect("no matching packet")
            .unwrap();
        if wanted(&buffer[..n]) {
            return buffer[..n].to_vec();
        }
    }
}

fn udp_datagram(source: ([u8; 4], u16), target: ([u8; 4], u16), payload: &[u8]) -> Vec<u8> {
    let mut udp = Vec::new();
    udp.extend(source.1.to_be_bytes());
    udp.extend(target.1.to_be_bytes());
    udp.extend(((8 + payload.len()) as u16).to_be_bytes());
    udp.extend([0, 0]);
    udp.extend(payload);
    let mut packet = ipv4_header(source.0, target.0, 17, udp.len());
    packet.extend(udp);
    packet
}

/// The UDP payload sent to `port`, if `packet` is one.
fn udp_reply_to(packet: &[u8], port: u16) -> Option<Vec<u8>> {
    let ip = Ipv4Packet::new_checked(packet).ok()?;
    (ip.next_header() == IpProtocol::Udp).then_some(())?;
    let udp = UdpPacket::new_checked(ip.payload()).ok()?;
    (udp.dst_port() == port).then(|| udp.payload().to_vec())
}

/// Whether `packet` is ICMP port unreachable for a datagram from `port`.
fn unreachable_for(packet: &[u8], port: u16) -> bool {
    let Ok(ip) = Ipv4Packet::new_checked(packet) else {
        return false;
    };
    if ip.next_header() != IpProtocol::Icmp {
        return false;
    }
    let Ok(icmp) = smoltcp::wire::Icmpv4Packet::new_checked(ip.payload()) else {
        return false;
    };
    let Ok(quoted) = Ipv4Packet::new_checked(icmp.data()) else {
        return false;
    };
    (u8::from(icmp.msg_type()), icmp.msg_code()) == (3, 3)
        && UdpPacket::new_unchecked(quoted.payload()).src_port() == port
}

/// With every data session taken, a new flow gets an ICMP error at once
/// instead of silence, existing flows keep working, and DNS still answers
/// from the sessions kept for it.
#[tokio::test]
async fn full_udp_sessions_refuse_new_flows_but_keep_old_ones_and_dns() {
    BUDGET.set(Some(Budget {
        max_udp: udp_table::DNS_RESERVE + 4,
        max_ports: 8,
        trace_above: 0,
        shed_above: 0,
        close_above: 0,
        ..Budget::DESKTOP
    }));
    tokio::time::timeout(Duration::from_secs(20), async {
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buffer = [0; 1500];
            while let Ok((n, from)) = echo.recv_from(&mut buffer).await {
                let _ = echo.send_to(&buffer[..n], from).await;
            }
        });
        let (device, host_io) = pair();
        let mut config = CoreConfig::default();
        config.tun.enable = true;
        let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        let running = core.start_with_packets(Some(device)).await.unwrap();
        let app = [10, 0, 0, 2];
        let echo_at = ([127, 0, 0, 1], echo_port);
        for port in 40000..40004 {
            host_io
                .send(&udp_datagram((app, port), echo_at, b"ping"))
                .await
                .unwrap();
            wait_for(&host_io, |packet| udp_reply_to(packet, port).is_some()).await;
        }
        // Every data session is taken: the next flow is told so at once.
        host_io
            .send(&udp_datagram((app, 40004), echo_at, b"ping"))
            .await
            .unwrap();
        wait_for(&host_io, |packet| unreachable_for(packet, 40004)).await;
        // The flows already admitted are untouched.
        host_io
            .send(&udp_datagram((app, 40000), echo_at, b"again"))
            .await
            .unwrap();
        let reply = wait_for(&host_io, |packet| udp_reply_to(packet, 40000).is_some()).await;
        assert_eq!(udp_reply_to(&reply, 40000).unwrap(), b"again");
        // Names still resolve through the hijacked DNS.
        let mut query = hickory_proto::op::Message::new();
        query.set_id(7).add_query(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_ascii("busy.test").unwrap(),
            hickory_proto::rr::RecordType::A,
        ));
        let query = query.to_vec().unwrap();
        host_io
            .send(&udp_datagram((app, 39999), ([8, 8, 8, 8], 53), &query))
            .await
            .unwrap();
        let answer = wait_for(&host_io, |packet| udp_reply_to(packet, 39999).is_some()).await;
        let answer =
            hickory_proto::op::Message::from_vec(&udp_reply_to(&answer, 39999).unwrap()).unwrap();
        assert_eq!(answer.id(), 7);
        running.shutdown().await;
    })
    .await
    .unwrap();
    BUDGET.set(None);
}

/// A new flow's opening burst (QUIC sends a window of datagrams) reaches its
/// session before the session first runs, and its replies come back as a
/// burst too: none of either may be dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_udp_burst_opening_a_flow_gets_every_reply() {
    const BURST: u32 = 64;
    tokio::time::timeout(Duration::from_secs(10), async {
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buffer = [0; 1500];
            while let Ok((n, from)) = echo.recv_from(&mut buffer).await {
                let _ = echo.send_to(&buffer[..n], from).await;
            }
        });
        let (device, host_io) = pair();
        let mut config = CoreConfig::default();
        config.tun.enable = true;
        let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        let running = core.start_with_packets(Some(device)).await.unwrap();
        for sequence in 0..BURST {
            let mut payload = vec![0; 1200];
            payload[..4].copy_from_slice(&sequence.to_be_bytes());
            host_io
                .send(&udp_datagram(
                    ([10, 0, 0, 2], 40100),
                    ([127, 0, 0, 1], echo_port),
                    &payload,
                ))
                .await
                .unwrap();
        }
        let mut answered = std::collections::BTreeSet::new();
        while answered.len() < BURST as usize {
            let reply = wait_for(&host_io, |p| udp_reply_to(p, 40100).is_some()).await;
            let payload = udp_reply_to(&reply, 40100).unwrap();
            answered.insert(u32::from_be_bytes(payload[..4].try_into().unwrap()));
        }
        running.shutdown().await;
    })
    .await
    .expect("datagrams of the burst or their replies were dropped");
}

/// TUN benchmarks, ignored by default. Run with
/// `cargo test --release -p clyntis-core tun_bench -- --ignored --nocapture --test-threads 1`.
mod tun_bench {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn tun() -> (Arc<Packets>, crate::Running) {
        let (device, host_io) = pair();
        let mut config = CoreConfig::default();
        config.tun.enable = true;
        let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        let running = core.start_with_packets(Some(device)).await.unwrap();
        (host_io, running)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn tun_bench_tcp_upload() {
        const TOTAL: usize = 64 << 20;
        let (host_io, running) = tun().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0; 64 << 10];
            let mut read = 0;
            while read < TOTAL {
                read += stream.read(&mut buffer).await.unwrap();
            }
            stream.write_all(b"k").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let started = Instant::now();
        let reply = client_stream(host_io, target, vec![1; TOTAL], true, 1, None).await;
        assert_eq!(reply, b"k");
        println!(
            "TUN TCP upload: {:.1} MB/s",
            TOTAL as f64 / started.elapsed().as_secs_f64() / 1e6
        );
        running.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn tun_bench_tcp_download() {
        const TOTAL: usize = 64 << 20;
        let (host_io, running) = tun().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 1];
            stream.read_exact(&mut request).await.unwrap();
            let chunk = vec![7u8; 16 << 10];
            for _ in 0..TOTAL / chunk.len() {
                stream.write_all(&chunk).await.unwrap();
            }
            stream.shutdown().await.unwrap();
        });
        let started = Instant::now();
        let reply = client_stream(host_io, target, vec![1], true, TOTAL, None).await;
        assert_eq!(reply.len(), TOTAL);
        println!(
            "TUN TCP download: {:.1} MB/s",
            TOTAL as f64 / started.elapsed().as_secs_f64() / 1e6
        );
        running.shutdown().await;
    }

    async fn udp_echo() -> SocketAddr {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = vec![0; 65535];
            loop {
                let (n, peer) = server.recv_from(&mut buffer).await.unwrap();
                let _ = server.send_to(&buffer[..n], peer).await;
            }
        });
        address
    }

    /// One datagram at a time, like DNS: each reply's delay is the latency.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn tun_bench_udp_round_trip() {
        const ROUNDS: usize = 500;
        let (host_io, running) = tun().await;
        let echo = udp_echo().await;
        let mut times = vec![];
        for round in 0..ROUNDS {
            let payload = (round as u32).to_be_bytes();
            let started = Instant::now();
            host_io
                .send(&udp_datagram(
                    ([10, 0, 0, 2], 40000),
                    ([127, 0, 0, 1], echo.port()),
                    &payload,
                ))
                .await
                .unwrap();
            wait_for(&host_io, |p| {
                udp_reply_to(p, 40000).as_deref() == Some(&payload[..])
            })
            .await;
            times.push(started.elapsed());
        }
        times.sort();
        println!(
            "TUN UDP round trip: median {:?}, p99 {:?}, max {:?}",
            times[ROUNDS / 2],
            times[ROUNDS * 99 / 100],
            times[ROUNDS - 1]
        );
        running.shutdown().await;
    }

    /// Up to 64 datagrams in flight, like a QUIC download window.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn tun_bench_udp_burst() {
        const COUNT: u32 = 50_000;
        const WINDOW: u32 = 64;
        let (host_io, running) = tun().await;
        let echo = udp_echo().await;
        let receiver = host_io.clone();
        let (done, mut acked) = mpsc::unbounded_channel::<u32>();
        tokio::spawn(async move {
            let mut buffer = vec![0; 65535];
            while let Ok(n) = receiver.recv(&mut buffer).await {
                if let Some(payload) = udp_reply_to(&buffer[..n], 40001) {
                    let _ = done.send(u32::from_be_bytes(payload[..4].try_into().unwrap()));
                }
            }
        });
        let mut payload = vec![0u8; 1200];
        let started = Instant::now();
        let (mut sent, mut received) = (0u32, 0u32);
        while sent < COUNT {
            while sent < COUNT && sent - received < WINDOW {
                payload[..4].copy_from_slice(&sent.to_be_bytes());
                host_io
                    .send(&udp_datagram(
                        ([10, 0, 0, 2], 40001),
                        ([127, 0, 0, 1], echo.port()),
                        &payload,
                    ))
                    .await
                    .unwrap();
                sent += 1;
            }
            // A lost datagram frees its slot after 20 ms.
            match tokio::time::timeout(Duration::from_millis(20), acked.recv()).await {
                Ok(Some(_)) => received += 1,
                _ => received = received.max(sent.saturating_sub(WINDOW - 1)),
            }
        }
        let mut replies = received;
        while let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(200), acked.recv()).await
        {
            replies += 1;
        }
        let elapsed = started.elapsed().as_secs_f64();
        println!(
            "TUN UDP burst: {:.1} MB/s each way, {:.0} datagrams/s, {} of {COUNT} answered",
            f64::from(COUNT) * 1200.0 / elapsed / 1e6,
            f64::from(COUNT) / elapsed,
            replies.min(COUNT)
        );
        running.shutdown().await;
    }

    #[cfg(unix)]
    fn cpu_time() -> Duration {
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
        let time = |t: libc::timeval| Duration::new(t.tv_sec as u64, t.tv_usec as u32 * 1000);
        time(usage.ru_utime) + time(usage.ru_stime)
    }

    /// CPU the packet loop spends while no packet arrives.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn tun_bench_idle_cpu() {
        let (host_io, running) = tun().await;
        // One answered DNS-like flow leaves a UDP port behind, as on a host.
        let echo = udp_echo().await;
        host_io
            .send(&udp_datagram(
                ([10, 0, 0, 2], 40002),
                ([127, 0, 0, 1], echo.port()),
                b"ping",
            ))
            .await
            .unwrap();
        wait_for(&host_io, |p| udp_reply_to(p, 40002).is_some()).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        let (cpu, wall) = (cpu_time(), Instant::now());
        tokio::time::sleep(Duration::from_secs(5)).await;
        let used = cpu_time() - cpu;
        println!(
            "TUN idle: {:?} CPU in {:?} ({:.2}%)",
            used,
            wall.elapsed(),
            used.as_secs_f64() / wall.elapsed().as_secs_f64() * 100.0
        );
        running.shutdown().await;
    }
}
