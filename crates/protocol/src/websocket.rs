//! Mihomo-compatible VLESS WebSocket and V2Ray HTTP Upgrade transport.
use crate::BoxStream;
use anyhow::{Context as _, Result, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rand::RngCore;
use sha1::{Digest, Sha1};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const MAX_HEADERS: usize = 32 * 1024;

fn split_ed(path: &str, configured: usize, header: &str) -> (String, usize, String) {
    let mut max = configured;
    let mut name = header.to_owned();
    if let Some((base, query)) = path.split_once('?') {
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix("ed=")
                && let Ok(parsed) = value.parse()
            {
                max = parsed;
                name = "Sec-WebSocket-Protocol".into();
            }
        }
        if max != configured {
            return (base.to_owned(), max, name);
        }
    }
    (path.to_owned(), max, name)
}

pub async fn connect(
    mut stream: BoxStream,
    authority: &str,
    options: &meta_config::WsOptions,
    early: &[u8],
) -> Result<(BoxStream, usize)> {
    let (mut path, max_early, early_header) = split_ed(
        &options.path,
        options.max_early_data,
        &options.early_data_header_name,
    );
    if path.is_empty() {
        path.push('/');
    }
    let consumed = early.len().min(max_early);
    let encoded = URL_SAFE_NO_PAD.encode(&early[..consumed]);
    if consumed > 0 && early_header.is_empty() {
        path.push_str(&encoded);
    }

    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let key = STANDARD.encode(nonce);
    let raw = options.v2ray_http_upgrade;
    let host = options
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.as_str())
        .unwrap_or(authority);
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
    );
    if !raw {
        request.push_str(&format!(
            "Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
        ));
    }
    if consumed > 0 && !early_header.is_empty() {
        request.push_str(&format!("{early_header}: {encoded}\r\n"));
    }
    for (name, value) in &options.headers {
        ensure!(
            !name.contains(['\r', '\n', ':']) && !value.contains(['\r', '\n']),
            "invalid WebSocket header"
        );
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("upgrade")
            || (!raw
                && (name.eq_ignore_ascii_case("sec-websocket-key")
                    || name.eq_ignore_ascii_case("sec-websocket-version")))
            || (consumed > 0 && name.eq_ignore_ascii_case(&early_header))
        {
            continue;
        }
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let expected = if raw {
        None
    } else {
        let digest = Sha1::digest(format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes());
        Some(STANDARD.encode(digest))
    };
    let fast = options.v2ray_http_upgrade_fast_open;
    let mut ws = WsStream::new(stream, raw, expected);
    if !fast {
        ws.read_upgrade().await?;
    }
    Ok((Box::new(ws), consumed))
}

pub struct WsStream {
    inner: BoxStream,
    raw: bool,
    expected_accept: Option<String>,
    upgraded: bool,
    incoming: Vec<u8>,
    payload: Vec<u8>,
    payload_at: usize,
    outgoing: Vec<u8>,
    outgoing_at: usize,
    closed: bool,
}

impl WsStream {
    fn new(inner: BoxStream, raw: bool, expected_accept: Option<String>) -> Self {
        Self {
            inner,
            raw,
            expected_accept,
            upgraded: false,
            incoming: vec![],
            payload: vec![],
            payload_at: 0,
            outgoing: vec![],
            outgoing_at: 0,
            closed: false,
        }
    }
    async fn read_upgrade(&mut self) -> Result<()> {
        while !self.upgraded {
            ensure!(
                self.incoming.len() < MAX_HEADERS,
                "WebSocket response headers too large"
            );
            let mut chunk = [0u8; 2048];
            let n = self.inner.read(&mut chunk).await?;
            ensure!(n != 0, "WebSocket server closed during upgrade");
            self.incoming.extend_from_slice(&chunk[..n]);
            self.parse_upgrade()?;
        }
        Ok(())
    }
    fn parse_upgrade(&mut self) -> Result<bool> {
        let Some(end) = self.incoming.windows(4).position(|w| w == b"\r\n\r\n") else {
            return Ok(false);
        };
        let head = std::str::from_utf8(&self.incoming[..end + 4])?;
        let mut lines = head.split("\r\n");
        let status = lines.next().context("missing WebSocket status")?;
        ensure!(
            status.split_whitespace().nth(1) == Some("101"),
            "WebSocket upgrade rejected: {status}"
        );
        if let Some(expected) = &self.expected_accept {
            let accept = lines
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("Sec-WebSocket-Accept"))
                .map(|(_, value)| value.trim());
            ensure!(
                accept == Some(expected.as_str()),
                "invalid WebSocket accept key"
            );
        }
        self.incoming.drain(..end + 4);
        self.upgraded = true;
        Ok(true)
    }
    fn flush_outgoing(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.outgoing_at < self.outgoing.len() {
            let n = ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.outgoing[self.outgoing_at..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.outgoing_at += n;
        }
        self.outgoing.clear();
        self.outgoing_at = 0;
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn frame(bytes: &[u8], opcode: u8) -> Vec<u8> {
        let mut out = vec![0x80 | opcode];
        let len = bytes.len();
        if len < 126 {
            out.push(0x80 | len as u8);
        } else if len <= u16::MAX as usize {
            out.push(0x80 | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(0x80 | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        let mut mask = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut mask);
        out.extend_from_slice(&mask);
        out.extend(bytes.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        out
    }
    fn parse_frame(&mut self) -> io::Result<bool> {
        if self.incoming.len() < 2 {
            return Ok(false);
        }
        let opcode = self.incoming[0] & 0x0f;
        let masked = self.incoming[1] & 0x80 != 0;
        let mut at = 2;
        let mut len = usize::from(self.incoming[1] & 0x7f);
        if len == 126 {
            if self.incoming.len() < 4 {
                return Ok(false);
            }
            len = usize::from(u16::from_be_bytes([self.incoming[2], self.incoming[3]]));
            at = 4;
        } else if len == 127 {
            if self.incoming.len() < 10 {
                return Ok(false);
            }
            let n = u64::from_be_bytes(self.incoming[2..10].try_into().unwrap());
            len = usize::try_from(n).map_err(|_| io::Error::other("oversized WebSocket frame"))?;
            at = 10;
        }
        let mask = if masked {
            if self.incoming.len() < at + 4 {
                return Ok(false);
            }
            let m: [u8; 4] = self.incoming[at..at + 4].try_into().unwrap();
            at += 4;
            Some(m)
        } else {
            None
        };
        if self.incoming.len() < at + len {
            return Ok(false);
        }
        let mut data = self.incoming[at..at + len].to_vec();
        self.incoming.drain(..at + len);
        if let Some(mask) = mask {
            for (i, b) in data.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        match opcode {
            0 | 2 => {
                self.payload = data;
                self.payload_at = 0;
            }
            8 => self.closed = true,
            9 => self.outgoing.extend(Self::frame(&data, 10)),
            10 => {}
            _ => return Err(io::Error::other("unsupported WebSocket frame")),
        }
        Ok(true)
    }
}

impl AsyncRead for WsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.upgraded {
            match self.parse_upgrade() {
                Ok(true) => {}
                Ok(false) => {
                    let mut scratch = [0u8; 2048];
                    let mut read = ReadBuf::new(&mut scratch);
                    ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read))?;
                    if read.filled().is_empty() {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    self.incoming.extend_from_slice(read.filled());
                    return self.poll_read(cx, out);
                }
                Err(e) => return Poll::Ready(Err(io::Error::other(e))),
            }
        }
        if self.raw {
            if !self.incoming.is_empty() {
                let count = out.remaining().min(self.incoming.len());
                out.put_slice(&self.incoming[..count]);
                self.incoming.drain(..count);
                return Poll::Ready(Ok(()));
            }
            return Pin::new(&mut self.inner).poll_read(cx, out);
        }
        if self.payload_at < self.payload.len() {
            let n = out.remaining().min(self.payload.len() - self.payload_at);
            out.put_slice(&self.payload[self.payload_at..self.payload_at + n]);
            self.payload_at += n;
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.closed {
                return Poll::Ready(Ok(()));
            }
            if self.parse_frame()? && self.payload_at < self.payload.len() {
                return self.poll_read(cx, out);
            }
            let mut scratch = [0u8; 8192];
            let mut read = ReadBuf::new(&mut scratch);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read))?;
            if read.filled().is_empty() {
                return Poll::Ready(Ok(()));
            }
            self.incoming.extend_from_slice(read.filled());
        }
    }
}

impl AsyncWrite for WsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.flush_outgoing(cx))?;
        if self.raw {
            return Pin::new(&mut self.inner).poll_write(cx, bytes);
        }
        let n = bytes.len().min(16 * 1024);
        self.outgoing = Self::frame(&bytes[..n], 2);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flush_outgoing(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.flush_outgoing(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read_headers(stream: &mut tokio::io::DuplexStream) -> String {
        let mut bytes = Vec::new();
        while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            bytes.push(stream.read_u8().await.unwrap());
        }
        String::from_utf8(bytes).unwrap()
    }

    async fn read_masked_binary(stream: &mut tokio::io::DuplexStream) -> Vec<u8> {
        assert_eq!(stream.read_u8().await.unwrap(), 0x82);
        let second = stream.read_u8().await.unwrap();
        assert_ne!(second & 0x80, 0);
        let length = match second & 0x7f {
            n @ 0..=125 => usize::from(n),
            126 => usize::from(stream.read_u16().await.unwrap()),
            _ => stream.read_u64().await.unwrap() as usize,
        };
        let mut mask = [0u8; 4];
        stream.read_exact(&mut mask).await.unwrap();
        let mut payload = vec![0; length];
        stream.read_exact(&mut payload).await.unwrap();
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
        payload
    }

    #[tokio::test]
    async fn upgrade_early_data_and_binary_frames() {
        let (client, mut server) = tokio::io::duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            let headers = read_headers(&mut server).await;
            assert!(headers.starts_with("GET /ws HTTP/1.1\r\n"));
            assert!(headers.contains("\r\nHost: front.example\r\n"));
            assert!(headers.contains("\r\nX-Early: aGVhZA\r\n"));
            let key = headers
                .lines()
                .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
                .unwrap();
            let accept = STANDARD.encode(Sha1::digest(
                format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes(),
            ));
            server
                .write_all(
                    format!(
                        "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let payload = read_masked_binary(&mut server).await;
            assert_eq!(payload, b"er-payload");
            server
                .write_all(&[0x82, payload.len() as u8])
                .await
                .unwrap();
            server.write_all(&payload).await.unwrap();
        });
        let mut headers = std::collections::BTreeMap::new();
        headers.insert("Host".into(), "front.example".into());
        let options = meta_config::WsOptions {
            path: "/ws".into(),
            headers,
            max_early_data: 4,
            early_data_header_name: "X-Early".into(),
            ..Default::default()
        };
        let (mut stream, consumed) =
            connect(Box::new(client), "origin.example", &options, b"header")
                .await
                .unwrap();
        assert_eq!(consumed, 4);
        stream.write_all(b"er-payload").await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = [0u8; 10];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"er-payload");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn http_upgrade_fast_open_sends_before_response() {
        let (client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let headers = read_headers(&mut server).await;
            assert!(!headers.contains("Sec-WebSocket-Key"));
            let mut payload = [0u8; 5];
            server.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"hello");
            server
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\nworld")
                .await
                .unwrap();
        });
        let options = meta_config::WsOptions {
            v2ray_http_upgrade: true,
            v2ray_http_upgrade_fast_open: true,
            ..Default::default()
        };
        let (mut stream, _) = connect(Box::new(client), "example.com", &options, &[])
            .await
            .unwrap();
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0u8; 5];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"world");
        server_task.await.unwrap();
    }
}
