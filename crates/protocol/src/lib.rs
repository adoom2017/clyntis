#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing;
pub mod grpc;
pub mod reality;
pub mod record;
pub mod tls;
pub mod vision;
pub mod vless;
pub mod websocket;
pub mod wire;
pub mod xudp;

use anyhow::{Result, ensure};
use async_trait::async_trait;
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Target {
    pub host: String,
    pub port: u16,
}
impl Target {
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self> {
        let host = host.into();
        ensure!(
            !host.is_empty()
                && host.len() <= 253
                && port != 0
                && !host.chars().any(|c| c.is_control() || c.is_whitespace()),
            "invalid target"
        );
        let host = if let Ok(ip) = host.parse::<IpAddr>() {
            ip.to_string()
        } else {
            ensure!(
                !host
                    .chars()
                    .any(|c| matches!(c, ':' | '[' | ']' | '/' | '?' | '#' | '@')),
                "invalid target host"
            );
            host
        };
        Ok(Self { host, port })
    }
    pub fn parse(authority: &str) -> Result<Self> {
        if let Ok(addr) = authority.parse::<SocketAddr>() {
            return Self::new(addr.ip().to_string(), addr.port());
        }
        ensure!(
            !authority.contains('@'),
            "target cannot contain user information"
        );
        let authority: http::uri::Authority = authority.parse()?;
        let port = authority
            .port_u16()
            .ok_or_else(|| anyhow::anyhow!("target must be host:port"))?;
        let host = authority.host();
        ensure!(
            !host.starts_with('['),
            "bracketed target must be an IPv6 address"
        );
        Self::new(host, port)
    }
    pub fn ip(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }
    pub fn from_uri(uri: &http::Uri, default_port: u16) -> Result<Self> {
        let authority = uri
            .authority()
            .ok_or_else(|| anyhow::anyhow!("URL authority missing"))?;
        if authority.port().is_some() {
            Self::parse(authority.as_str())
        } else {
            Self::parse(&format!("{authority}:{default_port}"))
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}
pub trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}
pub type BoxStream = Box<dyn IoStream>;

#[async_trait]
pub trait Datagram: Send + Sync {
    async fn send(&self, target: &Target, bytes: &[u8]) -> Result<()>;
    async fn recv(&self) -> Result<(Target, Vec<u8>)>;
}

#[cfg(test)]
mod target_tests {
    use super::*;
    #[test]
    fn authorities_are_unambiguous_and_ips_canonical() {
        assert_eq!(
            Target::new("a::0", 54).unwrap(),
            Target::parse("[a::]:54").unwrap()
        );
        for malformed in [
            "a::0:54",
            "host:0",
            "user@host:80",
            "host/path:80",
            "[not-an-ip]:80",
            "[::1]:65536",
        ] {
            assert!(Target::parse(malformed).is_err(), "{malformed}");
        }
    }
    #[test]
    fn url_authorities_preserve_ipv6_and_reject_invalid_ports_and_userinfo() {
        for (url, expected) in [
            ("http://[::1]/", "[::1]:80"),
            ("http://[a::0]:8080/", "[a::]:8080"),
            ("http://example.test/", "example.test:80"),
        ] {
            assert_eq!(
                Target::from_uri(&url.parse().unwrap(), 80).unwrap(),
                Target::parse(expected).unwrap()
            );
        }
        for url in ["http://host:65536/", "http://host:0/", "http://user@host/"] {
            assert!(Target::from_uri(&url.parse().unwrap(), 80).is_err());
        }
    }
}
