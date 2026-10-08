//! Against the real Tailscale control plane; needs network access.
//! `cargo test -p meta-tailscale --test live -- --ignored --nocapture`
use meta_protocol::{
    BoxStream,
    tls::{Clock, SecureConnector, TlsConnectConfig, TlsFingerprint},
};
use meta_tailscale::{
    Dialer,
    control::{Control, ServerUrl},
    key::{NodeKey, Private},
    tailcfg::{CAPABILITY_VERSION, Hostinfo, RegisterAuth, RegisterRequest},
};
use std::sync::Arc;

pub struct Plain;
#[async_trait::async_trait]
impl Dialer for Plain {
    async fn connect_tcp(&self, host: &str, port: u16) -> anyhow::Result<BoxStream> {
        Ok(Box::new(
            tokio::net::TcpStream::connect((host, port)).await?,
        ))
    }
    async fn connect_tls(&self, host: &str, port: u16) -> anyhow::Result<BoxStream> {
        let tcp = self.connect_tcp(host, port).await?;
        SecureConnector::new(Arc::new(Clock::default()))
            .connect(
                tcp,
                &TlsConnectConfig {
                    server_name: host.into(),
                    alpn: vec!["http/1.1".into()],
                    verify_cert: true,
                    fingerprint: TlsFingerprint::Native,
                    reality: None,
                },
            )
            .await
    }
    async fn bind_udp(&self) -> anyhow::Result<tokio::net::UdpSocket> {
        Ok(tokio::net::UdpSocket::bind("0.0.0.0:0").await?)
    }
    async fn local_ipv4(&self) -> Option<std::net::IpAddr> {
        None
    }
    async fn resolve(&self, host: &str) -> anyhow::Result<Vec<std::net::IpAddr>> {
        Ok(tokio::net::lookup_host((host, 0))
            .await?
            .map(|a| a.ip())
            .collect())
    }
}

#[tokio::test]
#[ignore]
async fn noise_and_http2_reach_the_control_server() {
    let server = ServerUrl::parse("https://controlplane.tailscale.com").unwrap();
    let machine = Private::generate();
    let mut control = Control::connect(Arc::new(Plain), &server, &machine)
        .await
        .unwrap();
    let node = Private::generate();
    let result = control
        .register(&RegisterRequest {
            version: CAPABILITY_VERSION,
            node_key: NodeKey(node.public()),
            old_node_key: NodeKey(Default::default()),
            auth: Some(RegisterAuth {
                auth_key: "tskey-auth-invalid".into(),
            }),
            hostinfo: Hostinfo {
                hostname: "clyntis-test".into(),
                os: "macOS".into(),
                ipn_version: "clyntis".into(),
                ..Default::default()
            },
            ephemeral: true,
        })
        .await;
    println!("register with an invalid key: {result:?}");
    // The server must answer at the application level: the transport worked.
    match result {
        Ok(response) => assert!(!response.error.is_empty() || !response.auth_url.is_empty()),
        Err(error) => assert!(format!("{error:#}").contains("HTTP"), "{error:#}"),
    }
}

#[tokio::test]
#[ignore]
async fn derp_relays_between_two_keys() {
    use meta_tailscale::{derp, tailcfg::DerpNode};
    let node = DerpNode {
        name: "1a".into(),
        host_name: "derp1.tailscale.com".into(),
        ..Default::default()
    };
    let (a, b) = (Private::generate(), Private::generate());
    let (a_in, _a_rx) = tokio::sync::mpsc::channel(8);
    let (b_in, mut b_rx) = tokio::sync::mpsc::channel(8);
    let a_link = derp::connect(&Plain, &node, &a, true, a_in).await.unwrap();
    let _b_link = derp::connect(&Plain, &node, &b, true, b_in).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(a_link.send(b.public(), b"over derp".to_vec()));
    let (from, packet) = tokio::time::timeout(std::time::Duration::from_secs(10), b_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from, a.public());
    assert_eq!(packet, b"over derp");
}
