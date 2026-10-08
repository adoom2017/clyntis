//! A Tailscale node in Rust: joins a tailnet through the control server and
//! carries TCP connections to peers over WireGuard, relayed through DERP.
//! No NAT traversal yet: every peer is reached through its home DERP region.
pub mod control;
pub mod derp;
mod http1;
pub mod key;
mod magic;
mod netstack;
mod node;
pub mod noise;
pub mod tailcfg;

pub use node::{Node, Options};

use anyhow::Result;
use meta_protocol::BoxStream;
use std::net::IpAddr;

/// How the node reaches the control server and DERP relays. The proxy core
/// implements it so these connections use the physical egress (or a
/// `dialer-proxy`) and its TLS stack.
#[async_trait::async_trait]
pub trait Dialer: Send + Sync + 'static {
    /// TCP connection to `host:port`.
    async fn connect_tcp(&self, host: &str, port: u16) -> Result<BoxStream>;
    /// TLS connection (ALPN http/1.1) with certificate verification.
    async fn connect_tls(&self, host: &str, port: u16) -> Result<BoxStream>;
    /// Addresses for a destination sent through an exit node.
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>>;
}
