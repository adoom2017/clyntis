//! Fixed-version external oracle. It is never linked or launched by the product.
use anyhow::{Context, Result, ensure};
use clyntis_protocol::{
    Datagram, Target,
    hysteria2::{Binder, Client, Options},
    tls::{Clock, TlsFingerprint},
};
use std::{
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

struct Oracle(Child);
impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn binder() -> Binder {
    Arc::new(|server: SocketAddr| {
        let socket = StdUdpSocket::bind(if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })?;
        socket.set_nonblocking(true)?;
        Ok(socket)
    })
}

fn options(port: u16) -> Options {
    Options {
        addresses: vec!["127.0.0.1".parse().unwrap()],
        ports: vec![port],
        hop_interval: Duration::from_secs(30),
        server_name: "localhost".into(),
        password: "correct horse".into(),
        insecure: true,
        alpn: vec![],
        up: None,
        down: None,
        obfs: None,
        mtu_discovery: true,
        fingerprint: TlsFingerprint::Chrome,
        compact: false,
    }
}

/// Starts the official server with `extra` YAML and waits until it listens.
async fn server(binary: &str, dir: &std::path::Path, port: u16, extra: &str) -> Result<Oracle> {
    let config = dir.join(format!("server-{port}.yaml"));
    std::fs::write(
        &config,
        format!(
            "listen: 127.0.0.1:{port}\ntls:\n  cert: {}\n  key: {}\nauth:\n  type: password\n  password: correct horse\n{extra}",
            dir.join("cert.pem").display(),
            dir.join("key.pem").display(),
        ),
    )?;
    let child = Command::new(binary)
        .args(["server", "--disable-update-check", "-l", "error", "-c"])
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    let oracle = Oracle(child);
    tokio::time::sleep(Duration::from_millis(800)).await;
    Ok(oracle)
}

fn free_udp_port() -> Result<u16> {
    Ok(StdUdpSocket::bind("127.0.0.1:0")?.local_addr()?.port())
}

async fn echo_servers() -> Result<(u16, u16)> {
    let tcp = TcpListener::bind("127.0.0.1:0").await?;
    let tcp_port = tcp.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = tcp.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    let udp_port = udp.local_addr()?.port();
    tokio::spawn(async move {
        let mut buffer = vec![0; 65536];
        while let Ok((n, peer)) = udp.recv_from(&mut buffer).await {
            let _ = udp.send_to(&buffer[..n], peer).await;
        }
    });
    Ok((tcp_port, udp_port))
}

async fn exchange(client: &Client, tcp_port: u16, udp_port: u16) -> Result<()> {
    let mut stream = client.tcp(&Target::new("127.0.0.1", tcp_port)?).await?;
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i * 7) as u8).collect();
    let (mut read, mut write) = tokio::io::split(&mut stream);
    let send = async {
        write.write_all(&payload).await?;
        write.flush().await?;
        anyhow::Ok(())
    };
    let mut echoed = vec![0; payload.len()];
    let receive = read.read_exact(&mut echoed);
    let (sent, received) = tokio::join!(send, receive);
    sent?;
    received?;
    ensure!(echoed == payload, "TCP echo differs");

    let udp = client.udp()?;
    let target = Target::new("127.0.0.1", udp_port)?;
    // 3000 bytes do not fit in one QUIC datagram: both ways are fragmented.
    for size in [1, 512, 3000] {
        let packet: Vec<u8> = (0..size).map(|i| i as u8).collect();
        let mut answer = None;
        for _ in 0..5 {
            udp.send(&target, &packet).await?;
            if let Ok(result) = tokio::time::timeout(Duration::from_secs(1), udp.recv()).await {
                answer = Some(result?);
                break;
            }
        }
        let (source, bytes) = answer.with_context(|| format!("no UDP echo for {size} bytes"))?;
        ensure!(source == target, "UDP source {source}");
        ensure!(bytes == packet, "UDP echo differs for {size} bytes");
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires HYSTERIA_BIN official Hysteria v2.13.0"]
async fn tcp_udp_obfs_hopping_brutal_and_authentication() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(120), scenario()).await?
}

async fn scenario() -> Result<()> {
    let binary = std::env::var("HYSTERIA_BIN").context("set HYSTERIA_BIN to Hysteria v2.13.0")?;
    let version = Command::new(&binary).arg("version").output()?;
    ensure!(
        String::from_utf8_lossy(&version.stdout).contains("Version:\tv2.13.0"),
        "incorrect oracle version"
    );
    let tmp = tempfile::tempdir()?;
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    std::fs::write(
        tmp.path().join("cert.pem"),
        pem_rfc7468::encode_string(
            "CERTIFICATE",
            pem_rfc7468::LineEnding::LF,
            certificate.cert.der(),
        )?,
    )?;
    std::fs::write(
        tmp.path().join("key.pem"),
        pem_rfc7468::encode_string(
            "PRIVATE KEY",
            pem_rfc7468::LineEnding::LF,
            &certificate.signing_key.serialize_der(),
        )?,
    )?;
    let (tcp_port, udp_port) = echo_servers().await?;
    let clock = Arc::new(Clock::default());

    // Plain: BBR, TCP and fragmented UDP; a wrong password is refused.
    let port = free_udp_port()?;
    let _plain = server(&binary, tmp.path(), port, "").await?;
    let client = Client::connect(&options(port), binder(), clock.clone()).await?;
    ensure!(client.supports_udp(), "server should allow UDP");
    exchange(&client, tcp_port, udp_port).await?;
    let wrong = Options {
        password: "wrong".into(),
        ..options(port)
    };
    let refused = Client::connect(&wrong, binder(), clock.clone()).await;
    ensure!(
        refused
            .as_ref()
            .is_err_and(|e| format!("{e:#}").contains("authentication failed")),
        "wrong password: {:?}",
        refused.err()
    );
    // Verification is on unless asked off: the self-signed certificate fails.
    let verified = Options {
        insecure: false,
        ..options(port)
    };
    let untrusted = Client::connect(&verified, binder(), clock.clone()).await;
    ensure!(
        untrusted
            .as_ref()
            .is_err_and(|e| format!("{e:#}").contains("certificate")),
        "self-signed certificate: {:?}",
        untrusted.err()
    );
    // Every browser profile's QUIC ClientHello completes the handshake.
    for fingerprint in [
        TlsFingerprint::Firefox,
        TlsFingerprint::Safari,
        TlsFingerprint::Ios,
        TlsFingerprint::Android,
        TlsFingerprint::Edge,
        TlsFingerprint::Randomized,
    ] {
        let profiled = Options {
            fingerprint,
            ..options(port)
        };
        let client = Client::connect(&profiled, binder(), clock.clone())
            .await
            .with_context(|| format!("{fingerprint:?}"))?;
        let mut stream = client.tcp(&Target::new("127.0.0.1", tcp_port)?).await?;
        stream.write_all(b"ping").await?;
        let mut pong = [0; 4];
        stream.read_exact(&mut pong).await?;
        ensure!(&pong == b"ping", "{fingerprint:?} echo");
    }

    // Salamander: the right password works, a client without it does not.
    let port = free_udp_port()?;
    let _obfs = server(
        &binary,
        tmp.path(),
        port,
        "obfs:\n  type: salamander\n  salamander:\n    password: obfs secret\n",
    )
    .await?;
    let obfuscated = Options {
        obfs: Some("obfs secret".into()),
        ..options(port)
    };
    let client = Client::connect(&obfuscated, binder(), clock.clone()).await?;
    exchange(&client, tcp_port, udp_port).await?;
    let plain = tokio::time::timeout(
        Duration::from_secs(3),
        Client::connect(&options(port), binder(), clock.clone()),
    )
    .await;
    ensure!(
        !matches!(plain, Ok(Ok(_))),
        "plain client passed obfuscation"
    );

    // Brutal: both sides state bandwidth; hopping moves to a new local socket
    // every 5 seconds (one listening port, so the server sees migration).
    let port = free_udp_port()?;
    let _brutal = server(
        &binary,
        tmp.path(),
        port,
        "bandwidth:\n  up: 200 mbps\n  down: 200 mbps\n",
    )
    .await?;
    let hopping = Options {
        ports: vec![port, port],
        hop_interval: Duration::from_secs(5),
        up: Some(50_000_000 / 8),
        down: Some(100_000_000 / 8),
        ..options(port)
    };
    let client = Client::connect(&hopping, binder(), clock.clone()).await?;
    for _ in 0..3 {
        exchange(&client, tcp_port, udp_port).await?;
        tokio::time::sleep(Duration::from_secs(4)).await;
    }
    ensure!(client.is_alive(), "connection died across hops");
    Ok(())
}
