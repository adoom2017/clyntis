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
/// Largest WebSocket frame accepted from the peer. Mihomo and Xray write at
/// most a few tens of KiB per frame; anything larger only buffers memory.
const MAX_FRAME: usize = 4 * 1024 * 1024;
/// RFC 6455 §5.5 maximum payload length for control frames (Close/Ping/Pong).
const MAX_CONTROL_FRAME: usize = 125;
/// Pause reading/parsing when buffered outgoing control replies reach this cap.
const MAX_OUTGOING: usize = 64 * 1024;
/// Largest data frame we write; one `poll_write` frames at most this much.
const WRITE_CHUNK: usize = 16 * 1024;
/// Buffers grown past this by an unusually large frame are released once
/// drained instead of being kept for the life of the stream.
const KEEP_CAPACITY: usize = 16 * 1024;

fn release_if_large(buffer: &mut Vec<u8>) {
    if buffer.is_empty() && buffer.capacity() > KEEP_CAPACITY {
        *buffer = Vec::new();
    }
}

/// Applies the 4-byte WebSocket XOR mask in place using 64-bit word operations.
fn apply_mask(data: &mut [u8], mask: [u8; 4]) {
    let mask64 = u64::from_ne_bytes([
        mask[0], mask[1], mask[2], mask[3], mask[0], mask[1], mask[2], mask[3],
    ]);
    let mut chunks = data.chunks_exact_mut(8);
    for chunk in &mut chunks {
        let word = u64::from_ne_bytes(chunk.try_into().unwrap());
        chunk.copy_from_slice(&(word ^ mask64).to_ne_bytes());
    }
    for (i, byte) in chunks.into_remainder().iter_mut().enumerate() {
        *byte ^= mask[i & 3];
    }
}

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
    options: &clyntis_config::WsOptions,
    early: &[u8],
) -> Result<(BoxStream, usize)> {
    ensure!(
        !options
            .path
            .chars()
            .any(|c| c == '\r' || c == '\n' || c.is_whitespace()),
        "invalid WebSocket path"
    );
    ensure!(
        !authority.contains(['\r', '\n']),
        "invalid WebSocket authority"
    );
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
    for (name, value) in &options.headers {
        ensure!(
            !name.contains(['\r', '\n', ':']) && !value.contains(['\r', '\n']),
            "invalid WebSocket header"
        );
    }
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
        ensure!(
            !early_header.contains(['\r', '\n', ':']),
            "invalid WebSocket early-data header"
        );
        request.push_str(&format!("{early_header}: {encoded}\r\n"));
    }
    for (name, value) in &options.headers {
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
        release_if_large(&mut self.incoming);
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
        release_if_large(&mut self.outgoing);
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    /// Appends one masked client frame to `out`, reserving its full size
    /// up front (at most 14 header bytes plus the payload).
    fn frame(out: &mut Vec<u8>, bytes: &[u8], opcode: u8) {
        let len = bytes.len();
        out.reserve(14 + len);
        out.push(0x80 | opcode);
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
        let start = out.len();
        out.extend_from_slice(bytes);
        apply_mask(&mut out[start..], mask);
    }
    fn parse_frame(&mut self) -> io::Result<bool> {
        if self.incoming.len() < 2 {
            return Ok(false);
        }
        let fin = self.incoming[0] & 0x80 != 0;
        let opcode = self.incoming[0] & 0x0f;
        let masked = self.incoming[1] & 0x80 != 0;
        let mut at = 2;
        let mut len = usize::from(self.incoming[1] & 0x7f);
        if matches!(opcode, 8..=10) {
            if !fin {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "fragmented WebSocket control frame",
                ));
            }
            if len > MAX_CONTROL_FRAME {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "oversized WebSocket control frame",
                ));
            }
        }
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
            len = usize::try_from(n).unwrap_or(usize::MAX);
            at = 10;
        }
        if len > MAX_FRAME {
            return Err(io::Error::other("oversized WebSocket frame"));
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
        let end = at
            .checked_add(len)
            .ok_or_else(|| io::Error::other("oversized WebSocket frame"))?;
        if self.incoming.len() < end {
            return Ok(false);
        }
        if let Some(mask) = mask {
            apply_mask(&mut self.incoming[at..end], mask);
        }
        match opcode {
            0 | 2 if len == 0 => {}
            0 | 2 if end == self.incoming.len() => {
                // The common case: the buffer holds exactly this frame. Hand
                // the buffer itself over instead of copying the payload out.
                self.payload.clear();
                std::mem::swap(&mut self.payload, &mut self.incoming);
                self.payload_at = at;
                release_if_large(&mut self.incoming);
                return Ok(true);
            }
            0 | 2 if self.incoming.len() - end < len => {
                // Remaining bytes for the next frame are smaller than this
                // payload: move the smaller tail instead of copying the
                // larger payload so peak memory never hits 2x frame size.
                self.payload.clear();
                self.payload.extend_from_slice(&self.incoming[end..]);
                self.incoming.truncate(end);
                std::mem::swap(&mut self.payload, &mut self.incoming);
                self.payload_at = at;
                release_if_large(&mut self.incoming);
                return Ok(true);
            }
            0 | 2 => {
                self.payload.clear();
                self.payload.extend_from_slice(&self.incoming[at..end]);
                self.payload_at = 0;
            }
            8 => {
                self.closed = true;
                Self::frame(&mut self.outgoing, &self.incoming[at..end], 8);
            }
            9 => Self::frame(&mut self.outgoing, &self.incoming[at..end], 10),
            10 => {}
            _ => return Err(io::Error::other("unsupported WebSocket frame")),
        }
        self.incoming.drain(..end);
        release_if_large(&mut self.incoming);
        Ok(true)
    }
}

impl AsyncRead for WsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut frames = 0;
        loop {
            // Drive buffered writes and control replies even on download-only
            // streams. A blocked writer must not prevent reading the peer.
            let flushed = self.flush_outgoing(cx);
            if let Poll::Ready(Err(error)) = flushed {
                return Poll::Ready(Err(error));
            }
            if !self.upgraded {
                match self.parse_upgrade() {
                    Ok(true) => {}
                    Ok(false) => {
                        if self.incoming.len() >= MAX_HEADERS {
                            return Poll::Ready(Err(io::Error::other(
                                "WebSocket response headers too large",
                            )));
                        }
                        let mut scratch = [0u8; 2048];
                        let mut read = ReadBuf::new(&mut scratch);
                        ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read))?;
                        if read.filled().is_empty() {
                            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                        }
                        self.incoming.extend_from_slice(read.filled());
                        continue;
                    }
                    Err(e) => return Poll::Ready(Err(io::Error::other(e))),
                }
            }
            if self.raw {
                if !self.incoming.is_empty() {
                    let count = out.remaining().min(self.incoming.len());
                    out.put_slice(&self.incoming[..count]);
                    self.incoming.drain(..count);
                    release_if_large(&mut self.incoming);
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(&mut self.inner).poll_read(cx, out);
            }
            if self.payload_at < self.payload.len() {
                let n = out.remaining().min(self.payload.len() - self.payload_at);
                out.put_slice(&self.payload[self.payload_at..self.payload_at + n]);
                self.payload_at += n;
                if self.payload_at == self.payload.len() {
                    self.payload.clear();
                    self.payload_at = 0;
                    release_if_large(&mut self.payload);
                }
                return Poll::Ready(Ok(()));
            }
            if self.closed {
                ready!(flushed)?;
                return Poll::Ready(Ok(()));
            }
            if self.outgoing.len() >= MAX_OUTGOING {
                ready!(flushed)?;
            }
            if self.parse_frame()? {
                // A Ping/Pong or empty data frame may be followed by an event
                // already in incoming. Do not wait for another socket read.
                frames += 1;
                if frames >= 64 {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                continue;
            }
            let mut scratch = [0u8; 8192];
            let mut read = ReadBuf::new(&mut scratch);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read))?;
            if read.filled().is_empty() {
                return Poll::Ready(if self.incoming.is_empty() {
                    Ok(())
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                });
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
        if self.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.raw {
            return Pin::new(&mut self.inner).poll_write(cx, bytes);
        }
        let n = bytes.len().min(WRITE_CHUNK);
        // flush_outgoing left `outgoing` empty; reuse its capacity.
        Self::frame(&mut self.outgoing, &bytes[..n], 2);
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

    fn upgraded_stream(inner: tokio::io::DuplexStream) -> WsStream {
        let mut stream = WsStream::new(Box::new(inner), false, None);
        stream.upgraded = true;
        stream
    }

    #[tokio::test]
    async fn download_only_stream_replies_to_ping_without_application_writes() {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            let (client, mut server) = tokio::io::duplex(1024);
            let mut stream = upgraded_stream(client);
            let peer = async {
                server.write_all(b"\x89\x04ping").await.unwrap();
                assert_eq!(server.read_u8().await.unwrap(), 0x8a);
                assert_eq!(server.read_u8().await.unwrap(), 0x84);
                let mut mask = [0; 4];
                server.read_exact(&mut mask).await.unwrap();
                let mut pong = [0; 4];
                server.read_exact(&mut pong).await.unwrap();
                for (i, byte) in pong.iter_mut().enumerate() {
                    *byte ^= mask[i % 4];
                }
                assert_eq!(&pong, b"ping");
                server.write_all(b"\x82\x09data: x\n\n").await.unwrap();
            };
            let reader = async {
                let mut event = [0; 9];
                stream.read_exact(&mut event).await.unwrap();
                assert_eq!(&event, b"data: x\n\n");
            };
            tokio::join!(peer, reader);
        })
        .await
        .expect("SSE download stalled waiting for a Pong");
    }

    #[tokio::test]
    async fn buffered_control_and_empty_frames_do_not_stall_events() {
        for prefix in [b"\x8a\x00", b"\x82\x00", b"\x89\x00"] {
            let (client, mut server) = tokio::io::duplex(1024);
            let mut stream = upgraded_stream(client);
            let bytes = [prefix.as_slice(), b"\x82\x09data: x\n\n"].concat();
            server.write_all(&bytes).await.unwrap();
            let mut event = [0; 9];
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                stream.read_exact(&mut event),
            )
            .await
            .expect("buffered SSE event waited for another network read")
            .unwrap();
            assert_eq!(&event, b"data: x\n\n");
        }
    }

    #[tokio::test]
    async fn close_frame_finishes_read_before_peer_tcp_close() {
        let (client, mut server) = tokio::io::duplex(1024);
        let mut stream = upgraded_stream(client);
        server.write_all(b"\x88\x00").await.unwrap();
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut byte),)
                .await
                .expect("Close frame did not finish the stream")
                .unwrap(),
            0
        );
        assert_eq!(server.read_u8().await.unwrap(), 0x88);
    }

    #[tokio::test]
    async fn truncated_frame_is_not_clean_eof() {
        for bytes in [b"\x82".as_slice(), b"\x82\x09data:"] {
            let (client, mut server) = tokio::io::duplex(1024);
            let mut stream = upgraded_stream(client);
            server.write_all(bytes).await.unwrap();
            server.shutdown().await.unwrap();
            assert_eq!(
                stream.read(&mut [0; 32]).await.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
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
        let options = clyntis_config::WsOptions {
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
        let options = clyntis_config::WsOptions {
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

    #[tokio::test]
    async fn oversized_frame_is_rejected_without_overflow() {
        for length in [(MAX_FRAME + 1) as u64, u64::MAX] {
            let (client, mut server) = tokio::io::duplex(1024);
            let mut stream = upgraded_stream(client);
            let mut header = vec![0x82, 127];
            header.extend_from_slice(&length.to_be_bytes());
            server.write_all(&header).await.unwrap();
            let err = stream.read(&mut [0; 16]).await.unwrap_err();
            assert!(err.to_string().contains("oversized"), "{err}");
        }
    }

    #[tokio::test]
    async fn large_frame_buffers_shrink_after_drain() {
        let payload = vec![0x5a; 128 * 1024];
        let (client, mut server) = tokio::io::duplex(256 * 1024);
        let mut stream = upgraded_stream(client);
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            let mut frame = vec![0x82, 127];
            frame.extend_from_slice(&(expected.len() as u64).to_be_bytes());
            frame.extend_from_slice(&expected);
            // Append a second small frame so the tail-swap path is also exercised.
            frame.extend_from_slice(&[0x82, 4, b't', b'a', b'i', b'l']);
            server.write_all(&frame).await.unwrap();
        });
        let mut received = vec![0u8; payload.len() + 4];
        stream.read_exact(&mut received).await.unwrap();
        writer.await.unwrap();
        assert_eq!(&received[..payload.len()], &payload[..]);
        assert_eq!(&received[payload.len()..], b"tail");
        assert!(stream.incoming.capacity() <= KEEP_CAPACITY);
        assert!(stream.payload.capacity() <= KEEP_CAPACITY);
    }

    #[test]
    fn word_sized_mask_matches_bytewise_across_all_alignments() {
        let mask = [0x37, 0xfa, 0x21, 0x3d];
        for len in (0..=33).chain([127, 128, 129, 1023, 1024, 1031]) {
            let original: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            let expected: Vec<u8> = original
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ mask[i % 4])
                .collect();

            let mut masked = original.clone();
            apply_mask(&mut masked, mask);
            assert_eq!(masked, expected, "mismatch for len {len}");

            apply_mask(&mut masked, mask);
            assert_eq!(masked, original, "roundtrip mismatch for len {len}");
        }
    }

    #[tokio::test]
    async fn control_frames_enforce_fin_and_125_byte_limit() {
        for frame in [
            vec![0x09, 0x00],                          // fragmented Ping (FIN=0)
            vec![0x89, 126, 0, 126],                   // Ping > 125 bytes
            vec![0x88, 126, 0, 126],                   // Close > 125 bytes
            vec![0x8a, 127, 0, 0, 0, 0, 0, 0, 0, 126], // Pong > 125 bytes
        ] {
            let (client, mut server) = tokio::io::duplex(1024);
            let mut stream = upgraded_stream(client);
            server.write_all(&frame).await.unwrap();
            let err = stream.read(&mut [0; 16]).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[tokio::test]
    async fn backpressure_pauses_parsing_when_outgoing_reaches_limit() {
        use std::task::Waker;
        struct PendingWriteStream(Vec<u8>);
        impl AsyncRead for PendingWriteStream {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let n = buf.remaining().min(self.0.len());
                buf.put_slice(&self.0[..n]);
                self.0.drain(..n);
                Poll::Ready(Ok(()))
            }
        }
        impl AsyncWrite for PendingWriteStream {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Pending
            }
            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Pending
            }
            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let mut ws = WsStream::new(
            Box::new(PendingWriteStream(b"\x89\x04ping\x82\x02ok".to_vec())),
            false,
            None,
        );
        ws.upgraded = true;
        ws.outgoing = vec![0u8; MAX_OUTGOING];
        let mut out = [0u8; 16];
        let mut buf = ReadBuf::new(&mut out);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            Pin::new(&mut ws).poll_read(&mut cx, &mut buf),
            Poll::Pending
        ));
        // Neither Ping nor Binary frame was parsed while outgoing is backed up.
        assert_eq!(ws.outgoing.len(), MAX_OUTGOING);
        assert!(ws.incoming.is_empty());
        assert!(ws.payload.is_empty());
    }

    #[tokio::test]
    async fn connect_rejects_crlf_in_path_and_authority() {
        let (client, _server) = tokio::io::duplex(1024);
        let bad_path = clyntis_config::WsOptions {
            path: "/ws\r\nEvil: 1".into(),
            ..Default::default()
        };
        assert!(
            connect(Box::new(client), "example.com", &bad_path, &[])
                .await
                .is_err()
        );

        let (client, _server) = tokio::io::duplex(1024);
        let opts = clyntis_config::WsOptions::default();
        assert!(
            connect(Box::new(client), "example.com\r\nEvil: 1", &opts, &[])
                .await
                .is_err()
        );
    }
}
