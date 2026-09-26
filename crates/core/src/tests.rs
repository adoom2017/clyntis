use super::*;
use tokio::io::AsyncReadExt;
use tower::ServiceExt;

#[tokio::test]
async fn additional_system_dns_listener_answers_local_queries() {
    let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let mut config = Config::default();
    config.dns.enable = true;
    config.dns.listen = "127.0.0.1:0".into();
    config.dns.enhanced_mode = "fake-ip".into();
    let core = Core::new(config, Arc::new(meta_platform::DefaultHooks)).unwrap();
    let mut running = core.start_with_packets_and_system_dns(None, Some(address)).await.unwrap();
    let mut query = hickory_proto::op::Message::new();
    query.set_id(79).add_query(hickory_proto::op::Query::query(
        hickory_proto::rr::Name::from_ascii("system-dns.test").unwrap(),
        hickory_proto::rr::RecordType::A,
    ));
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&query.to_vec().unwrap(), address).await.unwrap();
    let mut buffer = [0u8; 4096];
    let (size, _) = tokio::time::timeout(std::time::Duration::from_secs(2), socket.recv_from(&mut buffer))
        .await.unwrap().unwrap();
    let answer = hickory_proto::op::Message::from_vec(&buffer[..size]).unwrap();
    assert_eq!(answer.id(), 79);
    assert_eq!(answer.answers().len(), 1);
    let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let replacement = reservation.local_addr().unwrap();
    drop(reservation);
    running.rebind_system_dns(replacement).await.unwrap();
    socket.send_to(&query.to_vec().unwrap(), replacement).await.unwrap();
    let (size, _) = tokio::time::timeout(std::time::Duration::from_secs(2), socket.recv_from(&mut buffer))
        .await.unwrap().unwrap();
    assert_eq!(hickory_proto::op::Message::from_vec(&buffer[..size]).unwrap().id(), 79);
    assert!(tokio::net::TcpListener::bind(address).await.is_ok());
    assert!(tokio::net::UdpSocket::bind(address).await.is_ok());
    running.shutdown().await;
}

#[tokio::test]
async fn listener_conflicts_identify_service_transport_and_address() {
    for label in [
        "HTTP proxy",
        "SOCKS proxy",
        "mixed HTTP/SOCKS proxy",
        "DNS",
        "controller",
    ] {
        let blocker = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = blocker.local_addr().unwrap();
        let mut config = Config::default();
        match label {
            "HTTP proxy" => config.port = address.port(),
            "SOCKS proxy" => config.socks_port = address.port(),
            "mixed HTTP/SOCKS proxy" => config.mixed_port = address.port(),
            "DNS" => {
                config.dns.enable = true;
                config.dns.listen = address.to_string();
            }
            "controller" => config.external_controller = Some(address.to_string()),
            _ => unreachable!(),
        }
        let core = Core::new(config, Arc::new(meta_platform::DefaultHooks)).unwrap();
        let error = match core.start().await {
            Err(error) => error,
            Ok(_) => panic!("occupied TCP listener unexpectedly started"),
        };
        assert!(
            error
                .to_string()
                .contains(&format!("cannot bind {label} TCP listener at {address}"))
        );
        assert!(error.downcast_ref::<std::io::Error>().is_some());
        assert!(core.stop.is_cancelled());
        if label == "DNS" {
            // A failure of DNS TCP must release the UDP listener already opened.
            assert!(tokio::net::UdpSocket::bind(address).await.is_ok());
        }
    }
    let blocker = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = blocker.local_addr().unwrap();
    let mut config = Config::default();
    config.dns.enable = true;
    config.dns.listen = address.to_string();
    let core = Core::new(config, Arc::new(meta_platform::DefaultHooks)).unwrap();
    let error = match core.start().await {
        Err(error) => error,
        Ok(_) => panic!("occupied UDP listener unexpectedly started"),
    };
    assert!(
        error
            .to_string()
            .contains(&format!("cannot bind DNS UDP listener at {address}"))
    );
    assert!(error.downcast_ref::<std::io::Error>().is_some());
}

async fn api_call(
    core: Arc<Core>,
    method: &str,
    path: &str,
    body: &str,
    secret: bool,
) -> (u16, serde_json::Value) {
    let mut request = http::Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if secret {
        request = request.header("authorization", format!("Bearer {}", core.config.secret));
    }
    let response = api::router(core)
        .oneshot(
            request
                .body(axum::body::Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn controller_policy_updates_are_atomic_and_redacted() {
    let config = Config::parse(b"secret: api-secret\nauthentication: ['user:password']\nproxy-groups:\n- name: choose\n  type: select\n  proxies: [DIRECT, REJECT]\nrules: ['MATCH,DIRECT']\n").unwrap();
    let core = Core::new(config, Arc::new(meta_platform::DefaultHooks)).unwrap();
    assert_eq!(
        api_call(core.clone(), "GET", "/configs", "", false).await.0,
        401
    );
    assert_eq!(
        api_call(
            core.clone(),
            "PATCH",
            "/configs",
            r#"{"mode":"direct","rules":["MATCH,missing"]}"#,
            true
        )
        .await
        .0,
        400
    );
    assert_eq!(core.configuration()["mode"], "rule");
    assert_eq!(
        api_call(
            core.clone(),
            "PATCH",
            "/configs",
            r#"{"rules":["MATCH,REJECT"]}"#,
            true
        )
        .await
        .0,
        200
    );
    assert_eq!(
        api_call(
            core.clone(),
            "PATCH",
            "/configs",
            r#"{"mode":"direct"}"#,
            true
        )
        .await
        .0,
        200
    );
    let (_, config) = api_call(core.clone(), "GET", "/configs", "", true).await;
    assert_eq!(config["mode"], "direct");
    assert_eq!(config["rules"], serde_json::json!(["MATCH,REJECT"]));
    assert!(config.get("authentication").is_none());
    assert!(config.get("secret").is_none());
    assert_eq!(
        api_call(
            core.clone(),
            "PUT",
            "/proxies/choose",
            r#"{"name":"REJECT"}"#,
            true
        )
        .await
        .0,
        200
    );
    assert_eq!(
        api_call(core, "GET", "/proxies/choose", "", true).await.1["now"],
        "REJECT"
    );
}

#[tokio::test]
async fn live_tcp_counters_close_and_abort_release_registry() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let core = Core::new(Config::default(), Arc::new(meta_platform::DefaultHooks)).unwrap();
        for abort in [false, true] {
            let (mut client, inbound) = tokio::io::duplex(1024);
            let (outbound, mut peer) = tokio::io::duplex(1024);
            let owner = core.clone();
            let relay = tokio::spawn(async move {
                owner
                    .relay(
                        Box::new(inbound),
                        Target::new("example.test", 443).unwrap(),
                        Box::new(outbound),
                        "DIRECT".into(),
                    )
                    .await
            });
            client.write_all(b"request").await.unwrap();
            let mut bytes = [0; 7];
            peer.read_exact(&mut bytes).await.unwrap();
            peer.write_all(b"reply").await.unwrap();
            client.read_exact(&mut bytes[..5]).await.unwrap();
            let info = core.connections();
            assert_eq!(info.len(), 1);
            assert_eq!((info[0].upload, info[0].download), (7, 5));
            if abort {
                relay.abort();
                assert!(relay.await.unwrap_err().is_cancelled());
            } else {
                assert_eq!(
                    api_call(
                        core.clone(),
                        "DELETE",
                        &format!("/connections/{}", info[0].id),
                        "",
                        false
                    )
                    .await
                    .0,
                    200
                );
                relay.await.unwrap().unwrap();
                assert_eq!(client.read(&mut bytes).await.unwrap(), 0);
            }
            assert!(core.connections().is_empty());
        }
        assert_eq!(core.upload.load(std::sync::atomic::Ordering::Relaxed), 14);
        assert_eq!(core.download.load(std::sync::atomic::Ordering::Relaxed), 10);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn udp_counters_close_and_core_cancellation_cover_dns_routing() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::default();
        config.dns.nameserver = vec![dns.local_addr().unwrap().to_string()];
        config.dns.ipv6 = false;
        config.rules = vec!["IP-CIDR,192.0.2.0/24,REJECT".into(), "MATCH,DIRECT".into()];
        let core = Core::new(config, Arc::new(meta_platform::DefaultHooks)).unwrap();
        let target = Target::parse(&udp.local_addr().unwrap().to_string()).unwrap();
        let session = core.datagram(&target).await.unwrap();
        session.send(&target, b"ping").await.unwrap();
        let mut packet = [0; 1024];
        let (_, addr) = udp.recv_from(&mut packet).await.unwrap();
        udp.send_to(b"pong", addr).await.unwrap();
        assert_eq!(session.recv().await.unwrap().1, b"pong");
        let info = core.connections();
        assert_eq!((info[0].upload, info[0].download), (4, 4));
        api_call(core.clone(), "DELETE", "/connections", "", false).await;
        assert!(session.send(&target, b"closed").await.is_err());
        assert!(session.recv().await.is_err());
        drop(session);
        assert!(core.connections().is_empty());
        let owner = core.clone();
        let dial = tokio::spawn(async move {
            owner
                .dial(&Target::new("pending.test", 80).unwrap(), None)
                .await
        });
        dns.recv_from(&mut packet).await.unwrap();
        core.stop.cancel();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), dial)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(core.datagram(&target).await.is_err());
    })
    .await
    .unwrap();
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn configuration(server: SocketAddr, xudp: bool) -> Config {
    Config::parse(format!("proxies:\n- name: vless\n  type: vless\n  server: {}\n  port: {}\n  uuid: 11223344-5566-7788-99aa-bbccddeeff00\n  xudp: {xudp}\nrules: ['MATCH,vless']\n", server.ip(), server.port()).as_bytes()).unwrap()
}

async fn read_http_header(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut bytes = vec![];
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 32768);
        bytes.push(stream.read_u8().await.unwrap());
    }
    bytes
}

#[tokio::test]
async fn ipv6_http_forwarding_and_probe_preserve_authority() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let origin = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let address = origin.local_addr().unwrap();
        let oracle = tokio::spawn(async move {
            for path in ["/inspect?q=1", "/probe"] {
                let (mut stream, _) = origin.accept().await.unwrap();
                let request = String::from_utf8(read_http_header(&mut stream).await).unwrap();
                assert!(request.starts_with(&format!("GET {path} HTTP/1.1\r\n")));
                assert!(request.contains(&format!("\r\nHost: {address}\r\n")));
                assert!(!request.to_lowercase().contains("proxy-authorization"));
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await.unwrap();
            }
        });
        let port = free_port();
        let config = Config {
            ipv6: true,
            mixed_port: port,
            ..Config::default()
        };
        let core = Core::new(config, Arc::new(meta_platform::DefaultHooks)).unwrap();
        let running = core.start().await.unwrap();
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(format!("GET http://{address}/inspect?q=1 HTTP/1.1\r\nHost: wrong.test\r\nProxy-Authorization: Basic ignored\r\n\r\n").as_bytes()).await.unwrap();
        let mut response = vec![];
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert!(response.ends_with(b"\r\n\r\nok"));
        core.probe("DIRECT", &format!("http://{address}/probe"), Duration::from_secs(3)).await.unwrap();
        oracle.await.unwrap();
        running.shutdown().await;
    }).await.unwrap();
}

#[tokio::test]
async fn mixed_socks_and_http_connect_use_vless_and_restore_fake_ip() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for socks in [false, true] {
            let oracle = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut config = configuration(oracle.local_addr().unwrap(), false);
            config.mixed_port = free_port();
            let port = config.mixed_port;
            let core = Core::new(config, Arc::new(meta_platform::DefaultHooks)).unwrap();
            let name = hickory_proto::rr::Name::from_ascii("example.test").unwrap();
            let mut query = hickory_proto::op::Message::new();
            query.add_query(hickory_proto::op::Query::query(
                name,
                hickory_proto::rr::RecordType::A,
            ));
            let answer = core
                .resolver
                .answer(&query.to_vec().unwrap())
                .await
                .unwrap();
            let answer = hickory_proto::op::Message::from_vec(&answer).unwrap();
            let hickory_proto::rr::RData::A(fake) = answer.answers()[0].data() else {
                panic!("expected A")
            };
            let fake = fake.0;
            let task = tokio::spawn(async move {
                let (mut server, _) = oracle.accept().await.unwrap();
                let mut request = [0; 19];
                server.read_exact(&mut request).await.unwrap();
                assert_eq!(request[0], 0);
                assert_eq!(&request[17..], &[0, 1]);
                assert_eq!(server.read_u16().await.unwrap(), 443);
                assert_eq!(server.read_u8().await.unwrap(), 2);
                let n = server.read_u8().await.unwrap();
                let mut host = vec![0; n as usize];
                server.read_exact(&mut host).await.unwrap();
                assert_eq!(host, b"example.test");
                let mut payload = [0; 4];
                server.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"ping");
                server.write_all(b"\x00\x00pong").await.unwrap();
            });
            let running = core.start().await.unwrap();
            let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            if socks {
                client.write_all(&[5, 1, 0]).await.unwrap();
                let mut reply = [0; 2];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(reply, [5, 0]);
                let mut request = vec![5, 1, 0, 1];
                request.extend(fake.octets());
                request.extend(443u16.to_be_bytes());
                client.write_all(&request).await.unwrap();
                let mut reply = [0; 10];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(reply[1], 0);
            } else {
                client
                    .write_all(
                        format!("CONNECT {fake}:443 HTTP/1.1\r\nHost: {fake}:443\r\n\r\n")
                            .as_bytes(),
                    )
                    .await
                    .unwrap();
                assert!(
                    read_http_header(&mut client)
                        .await
                        .starts_with(b"HTTP/1.1 200")
                );
            }
            client.write_all(b"ping").await.unwrap();
            let mut reply = [0; 4];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"pong");
            drop(client);
            task.await.unwrap();
            running.shutdown().await;
            assert!(
                tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .is_err()
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn core_selects_udp_or_xudp_from_configuration() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for xudp in [false, true] {
            let oracle = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let core = Core::new(
                configuration(oracle.local_addr().unwrap(), xudp),
                Arc::new(meta_platform::DefaultHooks),
            )
            .unwrap();
            let task = tokio::spawn(async move {
                let (mut stream, _) = oracle.accept().await.unwrap();
                let mut request = [0; 19];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request[17..], &[0, if xudp { 3 } else { 2 }]);
                if xudp {
                    assert_eq!(stream.read_u16().await.unwrap(), 12);
                    let mut metadata = [0; 12];
                    stream.read_exact(&mut metadata).await.unwrap();
                    assert_eq!(metadata, [0, 0, 1, 1, 2, 0, 53, 1, 1, 2, 3, 4]);
                } else {
                    let mut target = [0; 7];
                    stream.read_exact(&mut target).await.unwrap();
                    assert_eq!(target, [0, 53, 1, 1, 2, 3, 4]);
                }
                assert_eq!(stream.read_u16().await.unwrap(), 4);
                let mut data = [0; 4];
                stream.read_exact(&mut data).await.unwrap();
                assert_eq!(&data, b"ping");
                stream.write_all(&[0, 0]).await.unwrap();
                if xudp {
                    stream.write_all(&[0, 4, 0, 0, 2, 1]).await.unwrap();
                }
                stream.write_all(b"\x00\x04pong").await.unwrap();
            });
            let target = Target::new("1.2.3.4", 53).unwrap();
            let session = core.datagram(&target).await.unwrap();
            session.send(&target, b"ping").await.unwrap();
            assert_eq!(session.recv().await.unwrap(), (target, b"pong".to_vec()));
            task.await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn xudp_pools_flows_and_reuses_source_global_id() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let oracle = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let core = Core::new(
            configuration(oracle.local_addr().unwrap(), true),
            Arc::new(meta_platform::DefaultHooks),
        )
        .unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = oracle.accept().await.unwrap();
            let mut request = [0; 19];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[17..], &[0, 3]);
            let mut frames = Vec::new();
            for _ in 0..2 {
                let length = stream.read_u16().await.unwrap() as usize;
                let mut metadata = vec![0; length];
                stream.read_exact(&mut metadata).await.unwrap();
                let payload_length = stream.read_u16().await.unwrap() as usize;
                let mut payload = vec![0; payload_length];
                stream.read_exact(&mut payload).await.unwrap();
                assert_eq!(metadata[2], 1);
                assert_eq!(metadata.len(), 20);
                frames.push((
                    u16::from_be_bytes([metadata[0], metadata[1]]),
                    metadata[12..20].to_vec(),
                    metadata[5..12].to_vec(),
                    payload,
                ));
            }
            assert_ne!(frames[0].0, frames[1].0);
            assert_eq!(frames[0].1, frames[1].1);
            assert_ne!(frames[0].1, [0; 8]);
            stream.write_all(&[0, 0]).await.unwrap();
            for (id, _, address, payload) in frames.into_iter().rev() {
                stream.write_u16(12).await.unwrap();
                stream.write_u16(id).await.unwrap();
                stream.write_all(&[2, 1, 2]).await.unwrap();
                stream.write_all(&address).await.unwrap();
                stream.write_u16(payload.len() as u16).await.unwrap();
                stream.write_all(&payload).await.unwrap();
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(50), oracle.accept())
                    .await
                    .is_err(),
                "XUDP flows opened more than one physical connection"
            );
        });
        let first_target = Target::new("1.1.1.1", 53).unwrap();
        let second_target = Target::new("2.2.2.2", 443).unwrap();
        let first = core
            .datagram_for_source(&first_target, "socks:127.0.0.1:12345")
            .await
            .unwrap();
        let second = core
            .datagram_for_source(&second_target, "socks:127.0.0.1:12345")
            .await
            .unwrap();
        first.send(&first_target, b"first").await.unwrap();
        second.send(&second_target, b"second").await.unwrap();
        assert_eq!(
            first.recv().await.unwrap(),
            (first_target, b"first".to_vec())
        );
        assert_eq!(
            second.recv().await.unwrap(),
            (second_target, b"second".to_vec())
        );
        task.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_udp_reconnects_after_outbound_closes() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for xudp in [false, true] {
            let oracle = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut config = configuration(oracle.local_addr().unwrap(), xudp);
            config.socks_port = free_port();
            let port = config.socks_port;
            let core = Core::new(config, Arc::new(meta_platform::DefaultHooks)).unwrap();
            let running = core.start().await.unwrap();
            let task = tokio::spawn(async move {
                for round in 0..3u8 {
                    let (mut stream, _) = oracle.accept().await.unwrap();
                    let mut header = vec![0; if xudp { 19 } else { 26 }];
                    stream.read_exact(&mut header).await.unwrap();
                    assert_eq!(header[18], if xudp { 3 } else { 2 });
                    if xudp {
                        let length = stream.read_u16().await.unwrap();
                        let mut metadata = vec![0; length as usize];
                        stream.read_exact(&mut metadata).await.unwrap();
                        assert_eq!(metadata[2], 1);
                    }
                    assert_eq!(stream.read_u16().await.unwrap(), 1);
                    assert_eq!(stream.read_u8().await.unwrap(), round);
                    stream.write_all(&[0, 0]).await.unwrap();
                    if xudp {
                        stream.write_all(&[0, 4, 0, 0, 2, 1]).await.unwrap();
                    }
                    stream.write_all(&[0, 1, round]).await.unwrap();
                    stream.shutdown().await.unwrap();
                }
            });
            let mut control = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            control.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0; 2];
            control.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);
            control
                .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut reply = [0; 10];
            control.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply[..4], &[5, 0, 0, 1]);
            let relay = SocketAddr::from((
                [reply[4], reply[5], reply[6], reply[7]],
                u16::from_be_bytes([reply[8], reply[9]]),
            ));
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            for round in 0..3u8 {
                let packet = [0, 0, 0, 1, 1, 2, 3, 4, 0, 53, round];
                loop {
                    socket.send_to(&packet, relay).await.unwrap();
                    let mut reply = [0; 128];
                    if let Ok(Ok((n, source))) = tokio::time::timeout(
                        Duration::from_millis(100),
                        socket.recv_from(&mut reply),
                    )
                    .await
                    {
                        assert_eq!(source, relay);
                        assert_eq!(&reply[..n], &packet);
                        break;
                    }
                }
            }
            task.await.unwrap();
            drop(control);
            running.shutdown().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn tcp_relay_survives_six_minutes_without_application_data() {
    let core = Core::new(Config::default(), Arc::new(meta_platform::DefaultHooks)).unwrap();
    let (mut client, inbound) = tokio::io::duplex(1024);
    let (outbound, mut peer) = tokio::io::duplex(1024);
    let owner = core.clone();
    let relay = tokio::spawn(async move {
        owner
            .relay(
                Box::new(inbound),
                Target::new("sse.test", 443).unwrap(),
                Box::new(outbound),
                "DIRECT".into(),
            )
            .await
    });
    client.write_all(b"request").await.unwrap();
    peer.read_exact(&mut [0; 7]).await.unwrap();
    tokio::time::advance(Duration::from_secs(360)).await;
    tokio::task::yield_now().await;
    assert!(
        !relay.is_finished(),
        "idle SSE connection was forcibly closed"
    );
    peer.write_all(b"data: resumed\n\n").await.unwrap();
    let mut event = [0; 15];
    client.read_exact(&mut event).await.unwrap();
    assert_eq!(&event, b"data: resumed\n\n");
    // Half-close the upload while allowing the download to continue.
    client.shutdown().await.unwrap();
    assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
    peer.write_all(b"data: final\n\n").await.unwrap();
    peer.shutdown().await.unwrap();
    let mut remaining = vec![];
    client.read_to_end(&mut remaining).await.unwrap();
    assert_eq!(remaining, b"data: final\n\n");
    relay.await.unwrap().unwrap();
    assert!(core.connections().is_empty());
}
