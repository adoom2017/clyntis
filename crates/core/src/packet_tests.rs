use super::*;
use async_trait::async_trait;
use meta_config::Config as CoreConfig;
use std::net::SocketAddr;
use tokio::sync::Mutex;

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
            tcp::SocketBuffer::new(vec![0; BUFFER]),
            tcp::SocketBuffer::new(vec![0; BUFFER]),
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
                started.elapsed() < Duration::from_secs(8),
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
                        (bytes.len(), ())
                    })
                    .unwrap();
            }
            if result.len() == payload.len() {
                socket.close();
            }
            if result.len() == payload.len() && !socket.is_open() {
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
                if let Some(packet) = fragments.accept(&packet[..n], Instant::now()) {
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
                let core = Core::new(config, Arc::new(meta_platform::DefaultHooks)).unwrap();
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
        let core = Core::new(config, Arc::new(meta_platform::DefaultHooks)).unwrap();
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
        let core = Core::new(config, Arc::new(meta_platform::DefaultHooks)).unwrap();
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
        let core = Core::new(config, Arc::new(meta_platform::DefaultHooks)).unwrap();
        let flow = Flow { source: "10.0.0.2:12345".parse().unwrap(), target: "192.0.2.1:9999".parse().unwrap(), tcp: false };
        let (input, receiver) = mpsc::channel(16); let (output, mut replies) = mpsc::channel(16);
        let session = tokio::spawn(udp_session(core.clone(), flow, receiver, output));
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
