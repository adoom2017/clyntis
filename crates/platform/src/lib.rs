//! Host-owned networking. Embedded cores never change routes or process state.
use anyhow::Result;
use async_trait::async_trait;
use std::{net::SocketAddr, sync::Arc};
#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
pub mod desktop;
#[cfg(target_os = "macos")]
pub mod macos_dns;
#[cfg(target_os = "macos")]
pub const MACOS_TUN_DNS_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(198, 19, 255, 254);
#[cfg(any(
    target_os = "windows",
    target_os = "macos",
    target_os = "linux",
    target_os = "android"
))]
pub mod native;

pub trait PlatformHooks: Send + Sync + std::fmt::Debug {
    /// Called before connect/send. Android hosts protect this socket from VPN
    /// capture; desktop hosts may bind the physical interface. Failure is fatal.
    fn protect_socket(&self, socket: &socket2::Socket) -> Result<()>;
    fn egress_description(&self, _destination: SocketAddr) -> Option<String> { None }
    fn prepare_socket(
        &self,
        socket: &socket2::Socket,
        _destination: Option<SocketAddr>,
    ) -> Result<()> {
        self.protect_socket(socket)
    }
}
#[derive(Debug, Default)]
pub struct DefaultHooks;
impl PlatformHooks for DefaultHooks {
    fn protect_socket(&self, _: &socket2::Socket) -> Result<()> {
        Ok(())
    }
}
pub type Hooks = Arc<dyn PlatformHooks>;

pub async fn tcp_connect(
    addr: SocketAddr,
    hooks: &dyn PlatformHooks,
) -> Result<tokio::net::TcpStream> {
    tcp_connect_options(addr, hooks, 30, false).await
}
pub async fn tcp_connect_options(
    addr: SocketAddr,
    hooks: &dyn PlatformHooks,
    keep_alive: u64,
    fast_open: bool,
) -> Result<tokio::net::TcpStream> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_nonblocking(true)?;
    if keep_alive > 0 {
        socket.set_tcp_keepalive(
            &socket2::TcpKeepalive::new()
                .with_time(std::time::Duration::from_secs(keep_alive))
                .with_interval(std::time::Duration::from_secs(keep_alive)),
        )?;
    }
    #[cfg(windows)]
    if fast_open {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{IPPROTO_TCP, TCP_FASTOPEN, setsockopt};
        let enabled: i32 = 1;
        let result = unsafe {
            setsockopt(
                socket.as_raw_socket() as _,
                IPPROTO_TCP,
                TCP_FASTOPEN,
                (&enabled as *const i32).cast(),
                std::mem::size_of::<i32>() as i32,
            )
        };
        if result != 0 {
            tracing::debug!("TCP Fast Open unavailable; using normal TCP handshake");
        }
    }
    #[cfg(not(windows))]
    let _ = fast_open;
    hooks.prepare_socket(&socket, Some(addr))?;
    let stream: std::net::TcpStream = socket.into();
    let socket = tokio::net::TcpSocket::from_std_stream(stream);
    let stream = socket.connect(addr).await.map_err(|error| {
        tracing::debug!(%addr, egress = ?hooks.egress_description(addr), %error, "physical TCP connection failed");
        error
    })?;
    stream.set_nodelay(true)?;
    Ok(stream)
}
pub fn udp_bind(addr: SocketAddr, hooks: &dyn PlatformHooks) -> Result<tokio::net::UdpSocket> {
    udp_bind_for(addr, None, hooks)
}
pub fn udp_bind_for(
    addr: SocketAddr,
    destination: Option<SocketAddr>,
    hooks: &dyn PlatformHooks,
) -> Result<tokio::net::UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_nonblocking(true)?;
    hooks.prepare_socket(&socket, Some(destination.unwrap_or(addr)))?;
    socket.bind(&addr.into())?;
    Ok(tokio::net::UdpSocket::from_std(socket.into())?)
}

#[async_trait]
pub trait PacketIo: Send + Sync {
    /// Exactly one raw IP packet, without a Darwin address-family prefix.
    async fn recv(&self, packet: &mut [u8]) -> Result<usize>;
    async fn send(&self, packet: &[u8]) -> Result<()>;
}
