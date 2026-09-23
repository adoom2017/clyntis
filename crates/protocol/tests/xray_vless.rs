//! Fixed-version external oracle. It is never linked or launched by the product.
use anyhow::{Context, Result, ensure};
use meta_protocol::{Datagram, Target, vless, xudp};
use std::{
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinSet,
};

struct Oracle(Child);
impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn command(binary: &str) -> Command {
    let command = Command::new(binary);
    #[cfg(windows)]
    let command = {
        use std::os::windows::process::CommandExt;
        let mut command = command;
        command.creation_flags(0x08000000);
        command
    };
    command
}

#[tokio::test]
#[ignore = "requires XRAY_BIN official Xray v25.9.11"]
async fn tcp_tls_udp_xudp_ipv4_ipv6_and_authentication() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(90), scenario()).await?
}

async fn scenario() -> Result<()> {
    let binary = std::env::var("XRAY_BIN").context("set XRAY_BIN to official Xray v25.9.11")?;
    let version = command(&binary).arg("version").output()?;
    ensure!(
        version.status.success()
            && String::from_utf8_lossy(&version.stdout).starts_with("Xray 25.9.11 "),
        "incorrect oracle version"
    );
    let tmp = tempfile::tempdir()?;
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_path = tmp.path().join("cert.pem");
    let key_path = tmp.path().join("key.pem");
    std::fs::write(
        &cert_path,
        pem_rfc7468::encode_string(
            "CERTIFICATE",
            pem_rfc7468::LineEnding::LF,
            certificate.cert.der(),
        )?,
    )?;
    std::fs::write(
        &key_path,
        pem_rfc7468::encode_string(
            "PRIVATE KEY",
            pem_rfc7468::LineEnding::LF,
            &certificate.signing_key.serialize_der(),
        )?,
    )?;
    let reservations = [
        std::net::TcpListener::bind("127.0.0.1:0")?,
        std::net::TcpListener::bind("127.0.0.1:0")?,
        std::net::TcpListener::bind("127.0.0.1:0")?,
        std::net::TcpListener::bind("127.0.0.1:0")?,
    ];
    let ports = [
        reservations[0].local_addr()?.port(),
        reservations[1].local_addr()?.port(),
    ];
    let transport_ports = [
        reservations[2].local_addr()?.port(),
        reservations[3].local_addr()?.port(),
    ];
    let id = uuid::Uuid::from_u128(0x112233445566778899aabbccddeeff00);
    let vision_id = uuid::Uuid::from_u128(0x112233445566778899aabbccddeeff01);
    let mut inbounds = vec![];
    for (index, port) in ports.iter().enumerate() {
        let mut inbound = serde_json::json!({"listen":"127.0.0.1","port":port,"protocol":"vless","settings":{"clients":[{"id":id}],"decryption":"none"},"streamSettings":{"network":"tcp","security":"none"}});
        if index == 1 {
            inbound["settings"]["clients"] =
                serde_json::json!([{"id":id},{"id":vision_id,"flow":"xtls-rprx-vision"}]);
            inbound["streamSettings"] = serde_json::json!({"network":"tcp","security":"tls","tlsSettings":{"certificates":[{"certificateFile":cert_path,"keyFile":key_path}]}});
        }
        inbounds.push(inbound);
    }
    inbounds.push(serde_json::json!({
        "listen":"127.0.0.1","port":transport_ports[0],"protocol":"vless",
        "settings":{"clients":[{"id":id}],"decryption":"none"},
        "streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/transport"}}
    }));
    inbounds.push(serde_json::json!({
        "listen":"127.0.0.1","port":transport_ports[1],"protocol":"vless",
        "settings":{"clients":[{"id":id}],"decryption":"none"},
        "streamSettings":{"network":"grpc","security":"none","grpcSettings":{"serviceName":"custom"}}
    }));
    let path = tmp.path().join("xray.json");
    std::fs::write(
        &path,
        serde_json::to_vec(
            &serde_json::json!({"log":{"loglevel":"warning"},"inbounds":inbounds,"outbounds":[{"protocol":"freedom"}]}),
        )?,
    )?;
    let log_path = tmp.path().join("xray.log");
    let log = std::fs::File::create(&log_path)?;
    drop(reservations);
    let mut oracle = Oracle(
        command(&binary)
            .args(["run", "-config"])
            .arg(path)
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?,
    );
    for port in ports.into_iter().chain(transport_ports) {
        let mut ready = false;
        for _ in 0..100 {
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                ready = true;
                break;
            }
            ensure!(
                oracle.0.try_wait()?.is_none(),
                "oracle exited: {}",
                std::fs::read_to_string(&log_path)?
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        ensure!(ready, "oracle failed to listen");
    }
    let mut tasks = JoinSet::new();
    for host in ["127.0.0.1", "::1"] {
        let tcp = TcpListener::bind((host, 0)).await?;
        let tcp_port = tcp.local_addr()?.port();
        let udp = UdpSocket::bind((host, 0)).await?;
        let udp_port = udp.local_addr()?.port();
        tasks.spawn(async move {
            let mut children=JoinSet::new();
            loop {tokio::select! {
                accepted=tcp.accept()=>{let Ok((mut stream,_))=accepted else{break;};children.spawn(async move{let(mut r,mut w)=stream.split();let _=tokio::io::copy(&mut r,&mut w).await;});},
                _=children.join_next(),if !children.is_empty()=>{}
            }}
        });
        tasks.spawn(async move {
            let mut bytes = vec![0; 65535];
            while let Ok((n, peer)) = udp.recv_from(&mut bytes).await {
                let _ = udp.send_to(&bytes[..n], peer).await;
            }
        });
        for (index, port) in ports.iter().copied().enumerate() {
            eprintln!("TCP host={host} tls={}", index == 1);
            let proxy: meta_config::Proxy = serde_json::from_value(
                serde_json::json!({"name":"test","type":"vless","server":"127.0.0.1","port":port,"uuid":id,"tls":index==1,"servername":"localhost","skip-cert-verify":true}),
            )?;
            let target = Target::new(host, tcp_port)?;
            let socket = TcpStream::connect(("127.0.0.1", port)).await?;
            let mut stream = vless::connect(socket, &proxy, &target, 1).await?;
            for size in [1, 8192, 131072] {
                let payload: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
                stream.write_all(&payload).await?;
                stream.flush().await?;
                let mut reply = vec![0; size];
                stream.read_exact(&mut reply).await?;
                ensure!(
                    reply == payload,
                    "TCP echo failed tls={} target={target}",
                    index == 1
                );
            }
            for multiplex in [false, true] {
                eprintln!("UDP host={host} tls={} xudp={multiplex}", index == 1);
                let target = Target::new(host, udp_port)?;
                let socket = TcpStream::connect(("127.0.0.1", port)).await?;
                let stream =
                    vless::connect(socket, &proxy, &target, if multiplex { 3 } else { 2 }).await?;
                let session: Arc<dyn Datagram> = if multiplex {
                    Arc::new(xudp::Session::new(stream, target.clone()))
                } else {
                    Arc::new(vless::UdpSession::new(stream, target.clone()))
                };
                // Xray v25.9.11 command-2 responses reserve two bytes in its
                // 8192-byte buffer; larger responses are discarded by Xray.
                for size in [1, 1232, if multiplex { 8192 } else { 8190 }] {
                    eprintln!("UDP payload={size}");
                    let payload = vec![73; size];
                    session.send(&target, &payload).await?;
                    let (source, reply) = tokio::time::timeout(
                        Duration::from_secs(8),
                        session.recv(),
                    )
                    .await
                    .with_context(|| {
                        format!(
                            "UDP reply timeout host={host} tls={} xudp={multiplex} size={size}",
                            index == 1
                        )
                    })??;
                    ensure!(
                        source == target && reply == payload,
                        "UDP echo failed tls={} xudp={multiplex} target={target}",
                        index == 1
                    );
                }
            }
            let mut wrong = proxy.clone();
            eprintln!("invalid UUID host={host} tls={}", index == 1);
            wrong.uuid = Some(uuid::Uuid::nil());
            let mut stream = vless::connect(
                TcpStream::connect(("127.0.0.1", port)).await?,
                &wrong,
                &target,
                1,
            )
            .await?;
            stream.write_all(b"invalid-id").await?;
            stream.flush().await?;
            let rejected = tokio::time::timeout(Duration::from_secs(8), stream.read_u8()).await?;
            ensure!(rejected.is_err(), "wrong UUID accepted");
            if index == 1 {
                let mut vision = proxy.clone();
                vision.uuid = Some(vision_id);
                vision.flow = "xtls-rprx-vision".into();
                let mut stream = vless::connect(
                    TcpStream::connect(("127.0.0.1", port)).await?,
                    &vision,
                    &target,
                    1,
                )
                .await?;
                stream.write_all(b"tls-vision").await?;
                stream.flush().await?;
                let mut reply = [0; 10];
                stream.read_exact(&mut reply).await?;
                ensure!(&reply == b"tls-vision", "TLS Vision TCP failed");
                let udp_target = Target::new(host, udp_port)?;
                let stream = vless::connect(
                    TcpStream::connect(("127.0.0.1", port)).await?,
                    &vision,
                    &udp_target,
                    3,
                )
                .await?;
                let session = xudp::Session::new(stream, udp_target.clone());
                session.send(&udp_target, b"tls-vision-udp").await?;
                let (source, reply) = session.recv().await?;
                ensure!(
                    source == udp_target && reply == b"tls-vision-udp",
                    "TLS Vision XUDP failed"
                );
                let mut secure = proxy;
                secure.skip_cert_verify = false;
                ensure!(
                    vless::connect(
                        TcpStream::connect(("127.0.0.1", port)).await?,
                        &secure,
                        &target,
                        1
                    )
                    .await
                    .is_err(),
                    "untrusted TLS certificate accepted"
                );
            }
        }
        eprintln!("XUDP pooled flows host={host}");
        let proxy: meta_config::Proxy = serde_json::from_value(serde_json::json!({
            "name":"xudp-pool-oracle","type":"vless","server":"127.0.0.1",
            "port":ports[0],"uuid":id
        }))?;
        let target = Target::new(host, udp_port)?;
        let stream = vless::connect(
            TcpStream::connect(("127.0.0.1", ports[0])).await?,
            &proxy,
            &target,
            3,
        )
        .await?;
        let mux = xudp::Multiplexer::new(stream);
        let first = mux.session(target.clone(), Some([1; 8]))?;
        let second = mux.session(target.clone(), Some([2; 8]))?;
        first.send(&target, b"pooled-first").await?;
        second.send(&target, b"pooled-second").await?;
        ensure!(
            tokio::time::timeout(Duration::from_secs(8), first.recv()).await??
                == (target.clone(), b"pooled-first".to_vec()),
            "first pooled XUDP flow failed"
        );
        ensure!(
            tokio::time::timeout(Duration::from_secs(8), second.recv()).await??
                == (target.clone(), b"pooled-second".to_vec()),
            "second pooled XUDP flow failed"
        );
        for (network, port) in [("ws", transport_ports[0]), ("grpc", transport_ports[1])] {
            eprintln!("{network} TCP/XUDP host={host}");
            let mut value = serde_json::json!({
                "name":format!("{network}-oracle"),"type":"vless","server":"127.0.0.1",
                "port":port,"uuid":id,"network":network
            });
            if network == "ws" {
                value["ws-opts"] = serde_json::json!({"path":"/transport"});
            } else {
                value["grpc-opts"] = serde_json::json!({"grpc-service-name":"custom"});
            }
            let proxy: meta_config::Proxy = serde_json::from_value(value)?;
            let target = Target::new(host, tcp_port)?;
            let socket = TcpStream::connect(("127.0.0.1", port)).await?;
            let mut stream = match tokio::time::timeout(
                Duration::from_secs(8),
                vless::connect(socket, &proxy, &target, 1),
            )
            .await
            {
                Ok(result) => result?,
                Err(_) => anyhow::bail!(
                    "{network} TCP connect timeout; oracle log: {}",
                    std::fs::read_to_string(&log_path)?
                ),
            };
            eprintln!("{network} TCP connected host={host}");
            let payload = vec![31; 64 * 1024];
            tokio::time::timeout(Duration::from_secs(8), async {
                stream.write_all(&payload).await?;
                stream.flush().await
            })
            .await
            .with_context(|| format!("{network} TCP upload timeout"))??;
            let mut reply = vec![0; payload.len()];
            tokio::time::timeout(Duration::from_secs(8), stream.read_exact(&mut reply))
                .await
                .with_context(|| format!("{network} TCP reply timeout"))??;
            ensure!(
                reply == payload,
                "{network} TCP echo failed target={target}"
            );
            eprintln!("{network} TCP echoed host={host}");
            drop(stream);

            let target = Target::new(host, udp_port)?;
            let socket = TcpStream::connect(("127.0.0.1", port)).await?;
            let stream = tokio::time::timeout(
                Duration::from_secs(8),
                vless::connect(socket, &proxy, &target, 3),
            )
            .await
            .with_context(|| format!("{network} XUDP connect timeout"))??;
            eprintln!("{network} XUDP connected host={host}");
            let session = xudp::Session::new(stream, target.clone());
            let payload = vec![47; 8192];
            session.send(&target, &payload).await?;
            let (source, reply) = tokio::time::timeout(Duration::from_secs(8), session.recv())
                .await
                .with_context(|| format!("{network} XUDP reply timeout target={target}"))??;
            ensure!(
                source == target && reply == payload,
                "{network} XUDP echo failed target={target}"
            );
        }
    }
    Ok(())
}
