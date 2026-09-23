#![cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
use meta_core::Core;
use meta_platform::{DefaultHooks, native::NativeTun};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct OwnedRoute(route_manager::Route);
impl Drop for OwnedRoute {
    fn drop(&mut self) {
        let mut manager = route_manager::RouteManager::new().unwrap();
        for route in manager.list().unwrap().into_iter().filter(|route| {
            route.network() == self.0.network()
                && route.prefix() == self.0.prefix()
                && route.if_index() == self.0.if_index()
        }) {
            manager.delete(&route).unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires root/administrator and a native TUN driver; adds isolated test /32 and /128 routes"]
async fn operating_system_tcp_and_udp_use_native_tun_and_restore_route() {
    tokio::time::timeout(Duration::from_secs(40), scenario())
        .await
        .unwrap();
}

async fn scenario() {
    let oracle = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = oracle.local_addr().unwrap();
    let config = meta_config::Config::parse(format!("ipv6: true\ntun: {{enable: true, auto-route: false}}\nproxies:\n- name: test\n  type: vless\n  server: 127.0.0.1\n  port: {}\n  uuid: 11223344-5566-7788-99aa-bbccddeeff00\nrules: ['MATCH,test']\n", address.port()).as_bytes()).unwrap();
    let core = Core::new(config, Arc::new(DefaultHooks)).unwrap();
    let name = if cfg!(target_os = "macos") {
        "utun19"
    } else {
        "meta-test"
    };
    let device = Arc::new(NativeTun::open(name, 1500, true).unwrap());
    let index = device.index().unwrap();
    let running = core.start_with_packets(Some(device)).await.unwrap();
    let destinations: [IpAddr; 2] = [
        "198.19.254.253".parse().unwrap(),
        "fdfe:dcba:9877::fd".parse().unwrap(),
    ];
    let server = tokio::spawn(async move {
        for ip in destinations {
            for udp in [false, true] {
                let (mut stream, _) = oracle.accept().await.unwrap();
                let mut request = [0; 19];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(request[18], if udp { 2 } else { 1 });
                assert_eq!(
                    stream.read_u16().await.unwrap(),
                    if udp { 23457 } else { 23456 }
                );
                assert_eq!(
                    stream.read_u8().await.unwrap(),
                    if ip.is_ipv4() { 1 } else { 3 }
                );
                let expected = match ip {
                    IpAddr::V4(ip) => ip.octets().to_vec(),
                    IpAddr::V6(ip) => ip.octets().to_vec(),
                };
                let mut actual = vec![0; expected.len()];
                stream.read_exact(&mut actual).await.unwrap();
                assert_eq!(actual, expected);
                let size = if udp { 4000 } else { 8192 };
                if udp {
                    assert_eq!(stream.read_u16().await.unwrap(), size as u16);
                }
                let mut data = vec![0; size];
                stream.read_exact(&mut data).await.unwrap();
                stream.write_all(&[0, 0]).await.unwrap();
                if udp {
                    stream.write_u16(size as u16).await.unwrap();
                }
                stream.write_all(&data).await.unwrap();
            }
        }
    });
    let mut manager = route_manager::RouteManager::new().unwrap();
    for ip in destinations {
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        let route = route_manager::Route::new(ip, prefix).with_if_index(index);
        #[cfg(target_os = "linux")]
        let route = route.with_table(254);
        let absent = |routes: Vec<route_manager::Route>| {
            !routes
                .iter()
                .any(|r| r.network() == ip && r.prefix() == prefix)
        };
        assert!(absent(manager.list().unwrap()));
        manager.add(&route).unwrap();
        let route = OwnedRoute(route);
        let payload: Vec<u8> = (0..8192).map(|n| (n % 251) as u8).collect();
        let mut tcp = tokio::net::TcpStream::connect(SocketAddr::new(ip, 23456))
            .await
            .unwrap();
        tcp.write_all(&payload).await.unwrap();
        let mut reply = vec![0; payload.len()];
        tcp.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, payload);
        drop(tcp);
        let udp = tokio::net::UdpSocket::bind(if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
            .await
            .unwrap();
        let target = SocketAddr::new(ip, 23457);
        udp.send_to(&payload[..4000], target).await.unwrap();
        let (n, source) = udp.recv_from(&mut reply).await.unwrap();
        assert_eq!(n, 4000);
        assert_eq!(&reply[..n], &payload[..4000]);
        assert_eq!(source, target);
        drop(route);
        assert!(absent(manager.list().unwrap()));
    }
    server.await.unwrap();
    running.shutdown().await;
}
