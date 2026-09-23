//! Optional interoperability oracle. Set `XRAY_BIN` to an official Xray binary.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use boring::{
    pkey::PKey,
    ssl::{SslAcceptor, SslMethod, SslVersion},
    x509::X509,
};
use meta_protocol::{Datagram, Target, vless, xudp};
use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

struct Oracle(Child);
impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn tls_acceptor() -> SslAcceptor {
    // Xray's REALITY bridge treats a combined encrypted handshake record as
    // such once it is larger than 512 bytes. Keep this local decoy fixture
    // representative of public certificates, which normally exceed that.
    let mut names = vec!["localhost".into()];
    names.extend((0..12).map(|index| format!("reality-fixture-{index}.localhost")));
    let generated = rcgen::generate_simple_self_signed(names).unwrap();
    let cert = X509::from_der(generated.cert.der().as_ref()).unwrap();
    let key = PKey::private_key_from_pkcs8(&generated.signing_key.serialize_der()).unwrap();
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    builder.set_certificate(&cert).unwrap();
    builder.set_private_key(&key).unwrap();
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    builder.build()
}

#[tokio::test]
#[ignore = "requires XRAY_BIN official oracle and local network access"]
async fn reality_tcp_vision_and_xudp() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(90), scenario()).await?
}

async fn scenario() -> Result<()> {
    let binary = std::env::var("XRAY_BIN").context("set XRAY_BIN to official Xray executable")?;
    ensure!(
        Command::new(&binary)
            .arg("version")
            .output()?
            .status
            .success(),
        "invalid Xray executable"
    );

    let decoy = TcpListener::bind("127.0.0.1:0").await?;
    let decoy_port = decoy.local_addr()?.port();
    let acceptor = tls_acceptor();
    let decoy_task = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = decoy.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut stream) = tokio_boring::accept(&acceptor, socket).await {
                    let mut bytes = [0u8; 4096];
                    while let Ok(size) = stream.read(&mut bytes).await {
                        if size == 0 || stream.write_all(&bytes[..size]).await.is_err() {
                            break;
                        }
                    }
                }
            });
        }
    });

    let echo = TcpListener::bind("127.0.0.1:0").await?;
    let echo_port = echo.local_addr()?.port();
    let echo_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = echo.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let udp_port = udp.local_addr()?.port();
    let udp_task = tokio::spawn(async move {
        let mut bytes = [0u8; 65535];
        while let Ok((size, peer)) = udp.recv_from(&mut bytes).await {
            let _ = udp.send_to(&bytes[..size], peer).await;
        }
    });

    // Xray's `x25519` command prints the clamped private key. Use the same
    // canonical representation in the server fixture.
    let mut secret_bytes = [17u8; 32];
    secret_bytes[0] &= 248;
    secret_bytes[31] &= 127;
    secret_bytes[31] |= 64;
    let secret = x25519_dalek::StaticSecret::from(secret_bytes);
    let public = x25519_dalek::PublicKey::from(&secret);
    let port = free_port();
    let id = uuid::Uuid::from_u128(0x112233445566778899aabbccddeeff00);
    let vision_id = uuid::Uuid::from_u128(0x112233445566778899aabbccddeeff01);
    let temp = tempfile::tempdir()?;
    let server_config = serde_json::json!({
        "log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"vless",
          "settings":{"clients":[{"id":vision_id,"flow":"xtls-rprx-vision"},{"id":id}],"decryption":"none"},
          "streamSettings":{"network":"tcp","security":"reality","realitySettings":{
            "show":false,"dest":format!("127.0.0.1:{decoy_port}"),"serverNames":["localhost"],
            "privateKey":URL_SAFE_NO_PAD.encode(secret.to_bytes()),"shortIds":["01020304"]}}}],
        "outbounds":[{"protocol":"freedom"}]
    });
    let config_path = temp.path().join("xray.json");
    std::fs::write(&config_path, serde_json::to_vec(&server_config)?)?;
    let log = std::fs::File::create(temp.path().join("xray.log"))?;
    let mut command = Command::new(&binary);
    command
        .args(["run", "-config"])
        .arg(&config_path)
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut oracle = Oracle(command.spawn()?);
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        ensure!(
            oracle.0.try_wait()?.is_none(),
            "Xray exited before listening"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let base = serde_json::json!({
        "name":"reality", "type":"vless", "server":"127.0.0.1", "port":port,
        "uuid":id, "tls":true, "servername":"localhost", "client-fingerprint":"chrome",
        "reality-opts":{"public-key":URL_SAFE_NO_PAD.encode(public.as_bytes()),"short-id":"01020304"}
    });
    for vision in [false, true] {
        eprintln!("REALITY TCP vision={vision}: connect");
        let mut value = base.clone();
        if vision {
            value["uuid"] = vision_id.to_string().into();
            value["flow"] = "xtls-rprx-vision".into();
        }
        let proxy: meta_config::Proxy = serde_json::from_value(value)?;
        let mut stream = vless::connect(
            TcpStream::connect(("127.0.0.1", port)).await?,
            &proxy,
            &Target::new("127.0.0.1", echo_port)?,
            1,
        )
        .await?;
        eprintln!("REALITY TCP vision={vision}: connected");
        let payload = vec![42u8; 32768];
        stream.write_all(&payload).await?;
        stream.flush().await?;
        let mut reply = vec![0u8; payload.len()];
        stream.read_exact(&mut reply).await?;
        eprintln!("REALITY TCP vision={vision}: echoed");
        ensure!(reply == payload, "REALITY TCP echo failed, vision={vision}");
    }

    let proxy: meta_config::Proxy = serde_json::from_value(base)?;
    eprintln!("REALITY XUDP: connect");
    let target = Target::new("127.0.0.1", udp_port)?;
    let stream = vless::connect(
        TcpStream::connect(("127.0.0.1", port)).await?,
        &proxy,
        &target,
        3,
    )
    .await?;
    eprintln!("REALITY XUDP: connected");
    let mux = xudp::Multiplexer::new(stream);
    let first = mux.session(target.clone(), Some([3; 8]))?;
    let second = mux.session(target.clone(), Some([4; 8]))?;
    first.send(&target, b"reality-xudp-first").await?;
    second.send(&target, b"reality-xudp-second").await?;
    eprintln!("REALITY XUDP: sent");
    ensure!(
        first.recv().await? == (target.clone(), b"reality-xudp-first".to_vec()),
        "first REALITY XUDP flow failed"
    );
    ensure!(
        second.recv().await? == (target, b"reality-xudp-second".to_vec()),
        "second REALITY XUDP flow failed"
    );

    decoy_task.abort();
    echo_task.abort();
    udp_task.abort();
    Ok(())
}
