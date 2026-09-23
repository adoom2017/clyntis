use anyhow::{Context, Result, ensure};
use boring::{
    pkey::PKey,
    ssl::{SslAcceptor, SslMethod, SslVersion},
    x509::X509,
};
use meta_config::Config;
use meta_protocol::{Datagram, Target, vless, xudp};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn proxy(tls: bool, insecure: bool) -> meta_config::Proxy {
    Config::parse(format!("proxies:\n- name: test\n  type: vless\n  server: localhost\n  port: 443\n  uuid: 11223344-5566-7788-99aa-bbccddeeff00\n  tls: {tls}\n  skip-cert-verify: {insecure}\n  client-fingerprint: chrome\n").as_bytes()).unwrap().proxies.remove(0)
}

fn tls_server_version(version: SslVersion) -> SslAcceptor {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = X509::from_der(cert.cert.der().as_ref()).unwrap();
    let key = PKey::private_key_from_pkcs8(&cert.signing_key.serialize_der()).unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_certificate(&certificate).unwrap();
    acceptor.set_private_key(&key).unwrap();
    acceptor.set_min_proto_version(Some(version)).unwrap();
    acceptor.set_max_proto_version(Some(version)).unwrap();
    acceptor.check_private_key().unwrap();
    acceptor.build()
}

fn tls_server() -> SslAcceptor {
    tls_server_version(SslVersion::TLS1_3)
}

#[tokio::test]
async fn boring_tls13_handshake_completes() -> Result<()> {
    use boring::ssl::{SslConnector, SslVerifyMode};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let mut connector = SslConnector::builder(SslMethod::tls())?;
    connector.set_verify(SslVerifyMode::NONE);
    connector.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    connector.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    let mut configured = connector.build().configure()?;
    configured.set_verify_hostname(false);
    let ssl = configured.into_ssl("localhost")?;
    let acceptor = tls_server();
    let server_task = tokio::spawn(async move {
        let (server, _) = listener.accept().await?;
        tokio_boring::accept(&acceptor, server)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    });
    let client = tokio::net::TcpStream::connect(address).await?;
    let (client, server) = tokio::time::timeout(Duration::from_secs(5), async {
        let client = tokio_boring::SslStreamBuilder::new(ssl, client)
            .connect()
            .await;
        let server = server_task.await.unwrap();
        (client, server)
    })
    .await?;
    match (&client, &server) {
        (Err(client), Err(server)) => anyhow::bail!("client={client}; server={server}"),
        (Err(client), _) => anyhow::bail!("client={client}"),
        (_, Err(server)) => anyhow::bail!("server={server}"),
        _ => {}
    }
    Ok(())
}

#[tokio::test]
async fn tls12_supports_vless_but_rejects_vision_before_request() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        for vision in [false, true] {
            let (client, server) = tokio::io::duplex(8192);
            let acceptor = tls_server_version(SslVersion::TLS1_2);
            let task = tokio::spawn(async move {
                let mut stream = tokio_boring::accept(&acceptor, server).await?;
                let byte = stream.read_u8().await;
                if vision {
                    ensure!(byte.is_err(), "Vision sent a request over TLS 1.2");
                } else {
                    ensure!(byte? == 0, "VLESS version mismatch");
                }
                Ok::<_, anyhow::Error>(())
            });
            let mut proxy = proxy(true, true);
            if vision {
                proxy.flow = "xtls-rprx-vision".into();
            }
            let stream = vless::connect(client, &proxy, &Target::new("example.com", 80)?, 1).await;
            ensure!(stream.is_err() == vision, "incorrect TLS 1.2 handling");
            drop(stream);
            task.await??;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn tcp_plain_and_tls_fragmented_reply_and_large_transfer() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        for tls in [false, true] {
            let config = proxy(tls, true);
            for host in ["127.0.0.1", "2001:db8::1", "example.com"] {
                let target = Target::new(host, 8443)?;
                let header = vless::request(config.uuid.unwrap(), &target, 1, "")?;
                let payload: Vec<_> = (0..128 * 1024).map(|i| (i % 251) as u8).collect();
                let expected_payload = payload.clone();
                // Keep enough room for both application data and TLS 1.3
                // post-handshake messages while this deterministic test uses
                // sequential client writes and reads.
                let (client, server) = tokio::io::duplex(512 * 1024);
                let server_config = tls_server();
                let task = tokio::spawn(async move {
                    let mut server: meta_protocol::BoxStream = if tls {
                        Box::new(tokio_boring::accept(&server_config, server).await?)
                    } else {
                        Box::new(server)
                    };
                    let mut request = vec![0; header.len()];
                    server.read_exact(&mut request).await?;
                    ensure!(request == header, "VLESS request mismatch");
                    let mut received = vec![0; expected_payload.len()];
                    server.read_exact(&mut received).await?;
                    ensure!(received == expected_payload, "VLESS upload mismatch");
                    server.write_all(&[0, 2, 9, 9]).await?;
                    server.write_all(&received).await?;
                    server.flush().await?;
                    Ok::<_, anyhow::Error>(())
                });
                let mut stream = vless::connect(client, &config, &target, 1).await?;
                stream.write_all(&payload).await?;
                stream.flush().await?;
                let mut received = vec![0; payload.len()];
                stream
                    .read_exact(&mut received)
                    .await
                    .with_context(|| format!("client tls={tls} host={host}"))?;
                ensure!(received == payload, "TCP echo mismatch");
                task.await?
                    .with_context(|| format!("server tls={tls} host={host}"))?;
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn tls_rejects_untrusted_certificate_before_sending_uuid() -> Result<()> {
    let config = proxy(true, false);
    let (client, server) = tokio::io::duplex(8192);
    let acceptor = tls_server();
    let task = tokio::spawn(async move {
        let _ = tokio_boring::accept(&acceptor, server).await;
    });
    let result = vless::connect(client, &config, &Target::new("example.com", 80)?, 1).await;
    assert!(result.is_err());
    task.abort();
    let _ = task.await;
    Ok(())
}

#[tokio::test]
async fn udp_framing_preserves_packet_boundaries() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        for multiplex in [false, true] {
            let config = proxy(false, false);
            let target = Target::new("1.2.3.4", 53)?;
            let (client, mut server) = tokio::io::duplex(64);
            let expected = vless::request(
                config.uuid.unwrap(),
                &target,
                if multiplex { 3 } else { 2 },
                "",
            )?;
            let task = tokio::spawn(async move {
                let mut header = vec![0; expected.len()];
                server.read_exact(&mut header).await?;
                ensure!(header == expected, "UDP request mismatch");
                server.write_all(&[0, 0]).await?;
                for index in 0..4 {
                    if multiplex {
                        let length = server.read_u16().await?;
                        ensure!(length == 12, "unexpected XUDP metadata length");
                        let mut metadata = [0; 12];
                        server.read_exact(&mut metadata).await?;
                        ensure!(
                            metadata
                                == [
                                    0,
                                    0,
                                    if index == 0 { 1 } else { 2 },
                                    1,
                                    2,
                                    0,
                                    53,
                                    1,
                                    1,
                                    2,
                                    3,
                                    4
                                ],
                            "XUDP metadata mismatch"
                        );
                    }
                    let length = server.read_u16().await?;
                    let mut payload = vec![0; length as usize];
                    server.read_exact(&mut payload).await?;
                    if multiplex {
                        server.write_all(&[0, 4, 0, 0, 2, 1]).await?;
                    }
                    server.write_u16(length).await?;
                    server.write_all(&payload).await?;
                    server.flush().await?;
                }
                Ok::<_, anyhow::Error>(())
            });
            let stream =
                vless::connect(client, &config, &target, if multiplex { 3 } else { 2 }).await?;
            let session: Arc<dyn Datagram> = if multiplex {
                Arc::new(xudp::Session::new(stream, target.clone()))
            } else {
                Arc::new(vless::UdpSession::new(stream, target.clone()))
            };
            for size in [0, 1, 1232, 65507] {
                let payload: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
                session.send(&target, &payload).await?;
                ensure!(
                    session.recv().await? == (target.clone(), payload),
                    "UDP echo mismatch"
                );
            }
            task.await??;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await?
}
