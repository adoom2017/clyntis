//! Control-plane client: the ts2021 Noise transport upgraded from HTTP, then
//! HTTP/2 requests for registration and the streaming network map.
use crate::{
    Dialer, http1,
    key::{Private, Public},
    noise,
    tailcfg::{self, MapRequest, MapResponse, RegisterRequest, RegisterResponse},
};
use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use bytes::Bytes;
use meta_protocol::BoxStream;
use std::sync::Arc;
use tokio::io::AsyncReadExt;

/// Where the control server lives (`control-url`).
#[derive(Clone, Debug)]
pub struct ServerUrl {
    pub tls: bool,
    pub host: String,
    pub port: u16,
}
impl ServerUrl {
    pub fn parse(url: &str) -> Result<Self> {
        let uri: http::Uri = url.parse().context("invalid control-url")?;
        let tls = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            _ => bail!("control-url must be http(s)"),
        };
        let host = uri.host().context("control-url needs a host")?.to_owned();
        let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
        Ok(Self { tls, host, port })
    }
}

async fn open(dialer: &dyn Dialer, server: &ServerUrl) -> Result<BoxStream> {
    if server.tls {
        dialer.connect_tls(&server.host, server.port).await
    } else {
        dialer.connect_tcp(&server.host, server.port).await
    }
}

/// The control server's Noise public key (`GET /key`).
async fn server_key(dialer: &dyn Dialer, server: &ServerUrl) -> Result<Public> {
    let mut stream = open(dialer, server).await?;
    let path = format!("/key?v={}", tailcfg::CAPABILITY_VERSION);
    let response = http1::request(
        &mut stream,
        "GET",
        &server.host,
        &path,
        &[("Connection", "close")],
    )
    .await?;
    let status = response.status;
    let body = http1::body(&mut stream, response, 64 * 1024).await?;
    ensure!(status == 200, "control key request failed: HTTP {status}");
    let key: tailcfg::OverTlsPublicKey =
        serde_json::from_slice(&body).context("invalid control key response")?;
    ensure!(!key.public_key.is_zero(), "control server has no Noise key");
    Ok(key.public_key)
}

pub struct Control {
    host: String,
    send: h2::client::SendRequest<Bytes>,
}

impl Control {
    pub async fn connect(
        dialer: Arc<dyn Dialer>,
        server: &ServerUrl,
        machine: &Private,
    ) -> Result<Self> {
        let control_key = server_key(&*dialer, server).await?;
        let (init, pending) = noise::initiate(machine, &control_key, tailcfg::CAPABILITY_VERSION)?;
        let mut stream = open(&*dialer, server).await?;
        let handshake = base64::engine::general_purpose::STANDARD.encode(&init);
        let response = http1::request(
            &mut stream,
            "POST",
            &server.host,
            "/ts2021",
            &[
                ("Upgrade", "tailscale-control-protocol"),
                ("Connection", "upgrade"),
                ("X-Tailscale-Handshake", &handshake),
                ("Content-Length", "0"),
            ],
        )
        .await?;
        if response.status != 101 {
            let status = response.status;
            let body = http1::body(&mut stream, response, 16 * 1024)
                .await
                .unwrap_or_default();
            bail!(
                "control upgrade failed: HTTP {status} {}",
                String::from_utf8_lossy(&body).trim()
            );
        }
        let mut data = response.rest;
        let mut buf = [0u8; 1024];
        // An error message is a 3-byte header plus text; a response is 51 bytes.
        loop {
            let want = if data.len() >= 3 && data[0] == 3 {
                3 + u16::from_be_bytes([data[1], data[2]]) as usize
            } else {
                noise::RESPONSE_LEN
            };
            if data.len() >= want {
                break;
            }
            let n = stream.read(&mut buf).await?;
            ensure!(n > 0, "control server closed during the handshake");
            data.extend_from_slice(&buf[..n]);
        }
        let leftover = data.split_off(noise::RESPONSE_LEN.min(data.len()));
        let ciphers = pending.finish(&data)?;
        let (pipe, _early) = noise::transport(stream, leftover, ciphers).await?;
        let (send, connection) = h2::client::Builder::new()
            .initial_window_size(4 << 20)
            .initial_connection_window_size(8 << 20)
            .handshake(pipe)
            .await
            .context("control HTTP/2 handshake")?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(%error, "Tailscale control HTTP/2 connection ended");
            }
        });
        Ok(Self {
            host: server.host.clone(),
            send,
        })
    }

    async fn post(
        &mut self,
        path: &str,
        node_key: &Public,
        body: Vec<u8>,
    ) -> Result<http::Response<h2::RecvStream>> {
        let send = self.send.clone().ready().await?;
        self.send = send;
        let request = http::Request::builder()
            .method("POST")
            .uri(format!("https://{}{path}", self.host))
            .header("Ts-Lb", node_key.node())
            .header("Content-Type", "application/json")
            .body(())?;
        let (response, mut stream) = self.send.send_request(request, false)?;
        stream.send_data(Bytes::from(body), true)?;
        Ok(response.await?)
    }

    pub async fn register(&mut self, request: &RegisterRequest) -> Result<RegisterResponse> {
        let response = self
            .post(
                "/machine/register",
                &request.node_key.0,
                serde_json::to_vec(request)?,
            )
            .await?;
        let status = response.status();
        let body = read_all(response.into_body(), 1 << 20).await?;
        ensure!(
            status.is_success(),
            "Tailscale register failed: HTTP {status} {}",
            String::from_utf8_lossy(&body).trim()
        );
        serde_json::from_slice(&body).context("invalid register response")
    }

    /// Starts the long-poll; with `stream: false` the server applies the
    /// request (for example a new home DERP) and answers once.
    pub async fn map(&mut self, request: &MapRequest) -> Result<MapStream> {
        let response = self
            .post(
                "/machine/map",
                &request.node_key.0,
                serde_json::to_vec(request)?,
            )
            .await?;
        let status = response.status();
        let mut body = response.into_body();
        if !status.is_success() {
            let text = read_all(body, 64 * 1024).await.unwrap_or_default();
            bail!(
                "Tailscale map request failed: HTTP {status} {}",
                String::from_utf8_lossy(&text).trim()
            );
        }
        let _ = &mut body;
        Ok(MapStream {
            body,
            buf: Vec::new(),
        })
    }
}

async fn read_all(mut body: h2::RecvStream, limit: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        let _ = body.flow_control().release_capacity(chunk.len());
        out.extend_from_slice(&chunk);
        ensure!(out.len() <= limit, "control response too large");
    }
    Ok(out)
}

/// Network-map messages: 4-byte little-endian size, then zstd-compressed JSON.
pub struct MapStream {
    body: h2::RecvStream,
    buf: Vec<u8>,
}
impl MapStream {
    pub async fn next(&mut self) -> Result<Option<MapResponse>> {
        loop {
            if self.buf.len() >= 4 {
                let size = u32::from_le_bytes(self.buf[..4].try_into().unwrap()) as usize;
                ensure!(size <= 64 << 20, "network map message too large");
                if self.buf.len() >= 4 + size {
                    let compressed: Vec<u8> = self.buf.drain(..4 + size).skip(4).collect();
                    let json = zstd::stream::decode_all(&compressed[..])
                        .context("invalid compressed network map")?;
                    return Ok(Some(
                        serde_json::from_slice(&json).context("invalid network map")?,
                    ));
                }
            }
            match self.body.data().await {
                Some(chunk) => {
                    let chunk = chunk?;
                    let _ = self.body.flow_control().release_capacity(chunk.len());
                    self.buf.extend_from_slice(&chunk);
                }
                None => return Ok(None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_control_urls() {
        let url = ServerUrl::parse("https://controlplane.tailscale.com").unwrap();
        assert!(url.tls && url.port == 443 && url.host == "controlplane.tailscale.com");
        let url = ServerUrl::parse("http://headscale.lan:8080").unwrap();
        assert!(!url.tls && url.port == 8080);
        assert!(ServerUrl::parse("ftp://x").is_err());
    }
}
