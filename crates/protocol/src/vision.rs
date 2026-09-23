//! Incremental XTLS Vision padding and independent read/write direct switches.
use crate::{record::RecordStream, vless::ResponseStream};
use rand::Rng;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
struct InnerTls {
    client: Vec<u8>,
    server: TlsHello,
    tls: bool,
    tls13: bool,
    remaining: usize,
}
impl InnerTls {
    fn observe(&mut self, bytes: &[u8], server: bool) {
        if self.remaining == 0 || self.tls13 {
            return;
        }
        self.remaining = self.remaining.saturating_sub(bytes.len());
        if server {
            if let Some(tls13) = self.server.observe(bytes) {
                self.tls = true;
                self.tls13 = tls13;
            }
        } else {
            let count = bytes.len().min(8usize.saturating_sub(self.client.len()));
            self.client.extend_from_slice(&bytes[..count]);
            if self.client.len() >= 6
                && self.client[0] == 22
                && self.client[1] == 3
                && self.client[5] == 1
            {
                self.tls = true;
            }
        }
    }
}

#[derive(Default)]
struct TlsHello {
    record: Vec<u8>,
    handshake: Vec<u8>,
    done: bool,
}
impl TlsHello {
    fn observe(&mut self, mut bytes: &[u8]) -> Option<bool> {
        while !bytes.is_empty() && !self.done {
            let need = if self.record.len() < 5 {
                5
            } else {
                5 + u16::from_be_bytes([self.record[3], self.record[4]]) as usize
            };
            if need > 18437 {
                self.done = true;
                return None;
            }
            let count = bytes.len().min(need - self.record.len());
            self.record.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
            if self.record.len() < 5 {
                continue;
            }
            if self.record[0] != 22 || self.record[1] != 3 {
                self.done = true;
                return None;
            }
            let need = 5 + u16::from_be_bytes([self.record[3], self.record[4]]) as usize;
            if self.record.len() < need {
                continue;
            }
            self.handshake.extend_from_slice(&self.record[5..]);
            self.record.clear();
            if self.handshake.len() > 18432 {
                self.done = true;
                return None;
            }
            if self.handshake.len() < 4 {
                continue;
            }
            if self.handshake[0] != 2 {
                self.done = true;
                return None;
            }
            let length =
                u32::from_be_bytes([0, self.handshake[1], self.handshake[2], self.handshake[3]])
                    as usize;
            if length > 18428 {
                self.done = true;
                return None;
            }
            if self.handshake.len() >= length + 4 {
                self.done = true;
                return server_hello(&self.handshake[4..length + 4]);
            }
        }
        None
    }
}

fn server_hello(bytes: &[u8]) -> Option<bool> {
    if bytes.len() < 38 || bytes[..2] != [3, 3] {
        return None;
    }
    let session_len = bytes[34] as usize;
    if session_len > 32 {
        return None;
    }
    let offset = 35 + session_len;
    if offset + 3 > bytes.len() || bytes[offset + 2] != 0 {
        return None;
    }
    let suite = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
    if offset + 3 == bytes.len() {
        return Some(false);
    }
    if offset + 5 > bytes.len() {
        return None;
    }
    let length = u16::from_be_bytes([bytes[offset + 3], bytes[offset + 4]]) as usize;
    let end = offset + 5 + length;
    if end != bytes.len() {
        return None;
    }
    let mut cursor = offset + 5;
    let mut version = None;
    while cursor < end {
        if cursor + 4 > end {
            return None;
        }
        let kind = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);
        let n = u16::from_be_bytes([bytes[cursor + 2], bytes[cursor + 3]]) as usize;
        cursor += 4;
        if cursor + n > end {
            return None;
        }
        if kind == 43 {
            if version.is_some() || n != 2 {
                return None;
            }
            version = Some(&bytes[cursor..cursor + n] == b"\x03\x04");
        }
        cursor += n;
    }
    Some(version == Some(true) && (0x1301..=0x1304).contains(&suite))
}

pub struct VisionStream<S> {
    inner: ResponseStream<RecordStream<S>>,
    id: [u8; 16],
    read_header: Vec<u8>,
    read_first: bool,
    content: usize,
    padding: usize,
    command: u8,
    read_plain: bool,
    write_first: bool,
    write_plain: bool,
    pending: Vec<u8>,
    written: usize,
    switch_write: bool,
    sniff: InnerTls,
    failed: bool,
}
impl<S: AsyncRead + AsyncWrite + Unpin> VisionStream<S> {
    pub fn new(inner: RecordStream<S>, id: uuid::Uuid) -> io::Result<Self> {
        if !inner.tls13() {
            return Err(io::Error::other("Vision requires outer TLS 1.3"));
        }
        Ok(Self::framed(inner, id))
    }

    fn framed(inner: RecordStream<S>, id: uuid::Uuid) -> Self {
        Self {
            inner: ResponseStream::new(inner),
            id: *id.as_bytes(),
            read_header: vec![],
            read_first: true,
            content: 0,
            padding: 0,
            command: 0,
            read_plain: false,
            write_first: true,
            write_plain: false,
            pending: vec![],
            written: 0,
            switch_write: false,
            sniff: InnerTls {
                remaining: 65536,
                ..Default::default()
            },
            failed: false,
        }
    }
    fn flush_frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.pending.len() {
            let n =
                ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.written..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.written += n;
        }
        ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        self.pending.clear();
        self.written = 0;
        if self.switch_write {
            self.inner.inner_mut().write_direct();
            self.switch_write = false;
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_frames(data: &[u8]) {
    use std::{io::Cursor, task::Waker};
    let mut expected = TlsHello::default();
    let expected = expected.observe(data);
    for width in [1, 31, 512] {
        let mut parser = TlsHello::default();
        let mut found = None;
        for chunk in data.chunks(width) {
            found = found.or(parser.observe(chunk));
        }
        assert_eq!(found, expected);
    }
    let inner = RecordStream::plain(Cursor::new(data.to_vec()));
    let mut stream = VisionStream::framed(inner, uuid::Uuid::nil());
    let mut cx = Context::from_waker(Waker::noop());
    let mut consumed = 0;
    for _ in 0..=data.len() + 1 {
        let mut bytes = [0; 127];
        let mut buf = ReadBuf::new(&mut bytes);
        match Pin::new(&mut stream).poll_read(&mut cx, &mut buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().is_empty() {
                    return;
                }
                consumed += buf.filled().len();
                assert!(consumed <= data.len());
            }
            Poll::Ready(Err(_)) => return,
            Poll::Pending => {}
        }
    }
    panic!("Vision parser made no progress");
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.failed {
            return Poll::Ready(Err(io::Error::other("invalid Vision stream")));
        }
        // Writes accepted into our bounded frame buffer must not wait for a
        // second application write before reaching the peer.
        if let Poll::Ready(Err(error)) = this.flush_frame(cx) {
            return Poll::Ready(Err(error));
        }
        let mut frames = 0;
        loop {
            if this.read_plain {
                if !this.read_header.is_empty() {
                    let n = this.read_header.len().min(buf.remaining());
                    buf.put_slice(&this.read_header[..n]);
                    this.read_header.drain(..n);
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            if this.content > 0 {
                let n = buf.remaining().min(this.content);
                let mut read = ReadBuf::new(&mut buf.initialize_unfilled()[..n]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
                let bytes = read.filled();
                if bytes.is_empty() {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                this.sniff.observe(bytes, true);
                let n = bytes.len();
                this.content -= n;
                buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            while this.padding > 0 {
                let mut scratch = [0; 2048];
                let n = this.padding.min(scratch.len());
                let mut read = ReadBuf::new(&mut scratch[..n]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
                if read.filled().is_empty() {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                this.padding -= read.filled().len();
            }
            if this.command != 0 {
                if this.command == 2 {
                    this.inner.inner_mut().read_direct();
                }
                this.read_plain = true;
                continue;
            }
            let need = if this.read_first { 21 } else { 5 };
            while this.read_header.len() < need {
                let start = this.read_header.len();
                this.read_header.resize(need, 0);
                let mut read = ReadBuf::new(&mut this.read_header[start..]);
                let result = Pin::new(&mut this.inner).poll_read(cx, &mut read);
                let n = read.filled().len();
                this.read_header.truncate(start + n);
                ready!(result)?;
                if n == 0 {
                    return Poll::Ready(if start == 0 {
                        Ok(())
                    } else {
                        Err(io::ErrorKind::UnexpectedEof.into())
                    });
                }
            }
            let offset = if this.read_first {
                if this.read_header[..16] != this.id {
                    // Xray's XtlsUnpadding passes through the first block when
                    // it does not start with the user UUID. This supports
                    // peers which negotiate the Vision flow but send an
                    // unpadded downlink (and older compatible servers).
                    this.read_first = false;
                    this.read_plain = true;
                    let n = this.read_header.len().min(buf.remaining());
                    buf.put_slice(&this.read_header[..n]);
                    this.read_header.drain(..n);
                    return Poll::Ready(Ok(()));
                }
                this.read_first = false;
                16
            } else {
                0
            };
            let h = &this.read_header[offset..];
            this.command = h[0];
            if this.command > 2 {
                this.failed = true;
                return Poll::Ready(Err(io::Error::other("invalid Vision command")));
            }
            this.content = u16::from_be_bytes([h[1], h[2]]) as usize;
            this.padding = u16::from_be_bytes([h[3], h[4]]) as usize;
            this.read_header.clear();
            frames += 1;
            if frames >= 64 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.flush_frame(cx))?;
        if this.write_plain {
            return Pin::new(&mut this.inner).poll_write(cx, bytes);
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let bytes = &bytes[..bytes.len().min(8192 - 21)];
        this.sniff.observe(bytes, false);
        let command = if this.sniff.tls && bytes.starts_with(b"\x17\x03\x03") {
            if this.sniff.tls13 { 2 } else { 1 }
        } else if this.sniff.remaining == 0 || (!this.sniff.tls && this.sniff.client.len() >= 8) {
            1
        } else {
            0
        };
        let padding = if bytes.len() >= 900 {
            0
        } else if this.sniff.tls {
            900 - bytes.len() + rand::thread_rng().gen_range(0..500)
        } else {
            rand::thread_rng().gen_range(0..256)
        };
        if this.write_first {
            this.pending.extend_from_slice(&this.id);
            this.write_first = false;
        }
        this.pending.push(command);
        this.pending
            .extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        this.pending
            .extend_from_slice(&(padding as u16).to_be_bytes());
        this.pending.extend_from_slice(bytes);
        this.pending.resize(this.pending.len() + padding, 0);
        if command != 0 {
            this.write_plain = true;
        }
        this.switch_write = command == 2;
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().flush_frame(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.flush_frame(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    fn hello(suite: u16, tls13: bool) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7; 32]);
        body.push(0);
        body.extend_from_slice(&suite.to_be_bytes());
        body.push(0);
        if tls13 {
            body.extend_from_slice(&[0, 6, 0, 43, 0, 2, 3, 4]);
        } else {
            body.extend_from_slice(&[0, 0]);
        }
        let mut handshake = vec![2, 0, 0, body.len() as u8];
        handshake.extend(body);
        handshake
    }

    fn tls_record(payload: &[u8]) -> Vec<u8> {
        let mut record = vec![22, 3, 3];
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    fn frame(first: bool, command: u8, content: &[u8], padding: usize) -> Vec<u8> {
        let mut bytes = if first { vec![0; 16] } else { vec![] };
        bytes.push(command);
        bytes.extend_from_slice(&(content.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&(padding as u16).to_be_bytes());
        bytes.extend_from_slice(content);
        bytes.resize(bytes.len() + padding, 0);
        bytes
    }

    async fn pair() -> (VisionStream<DuplexStream>, DuplexStream) {
        let (client_socket, server_socket) = tokio::io::duplex(256 * 1024);
        (
            VisionStream::new(
                crate::record::RecordStream::test_tls13_plain(client_socket),
                uuid::Uuid::nil(),
            )
            .unwrap(),
            server_socket,
        )
    }

    #[test]
    fn tls_detection_is_independent_of_io_and_record_boundaries() {
        for suite in [0x1301, 0x1302, 0x1303, 0x1304, 0x1305] {
            let handshake = hello(suite, true);
            let mut bytes = tls_record(&handshake[..9]);
            bytes.extend(tls_record(&handshake[9..]));
            let mut sniff = InnerTls {
                remaining: 65536,
                ..Default::default()
            };
            for byte in &bytes {
                sniff.observe(&[*byte], true);
            }
            assert!(sniff.tls);
            assert_eq!(sniff.tls13, suite != 0x1305);
        }
        let mut sniff = InnerTls {
            remaining: 65536,
            ..Default::default()
        };
        sniff.observe(&tls_record(&hello(0xc02f, false)), true);
        assert!(sniff.tls && !sniff.tls13);
        let mut malformed = hello(0x1301, true);
        malformed[38] = 255;
        assert_eq!(TlsHello::default().observe(&tls_record(&malformed)), None);
    }

    #[tokio::test]
    async fn unpadding_handles_segments_end_and_truncation() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (mut client, mut server) = pair().await;
            let mut bytes = vec![0, 0];
            bytes.extend(frame(true, 0, b"a", 3));
            bytes.extend(frame(false, 1, b"b", 2));
            bytes.extend_from_slice(b"plain");
            server.write_all(&bytes).await.unwrap();
            server.flush().await.unwrap();
            let mut result = [0; 7];
            client.read_exact(&mut result).await.unwrap();
            assert_eq!(&result, b"abplain");
            drop(server);
            assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
            for malformed in [
                vec![0, 0, 1],
                {
                    let mut b = vec![0, 0];
                    b.extend(frame(true, 3, b"invalid", 0));
                    b
                },
                {
                    let mut b = vec![0, 0];
                    let mut f = frame(true, 0, b"abc", 2);
                    f.pop();
                    b.extend(f);
                    b
                },
            ] {
                let (mut client, mut server) = pair().await;
                server.write_all(&malformed).await.unwrap();
                server.flush().await.unwrap();
                drop(server);
                assert!(client.read_to_end(&mut vec![]).await.is_err());
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn unpadding_passes_through_unframed_downlink() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (mut client, mut server) = pair().await;
            let payload = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
            let mut bytes = vec![0, 0];
            bytes.extend_from_slice(payload);
            server.write_all(&bytes).await.unwrap();
            server.shutdown().await.unwrap();

            let mut result = Vec::new();
            client.read_to_end(&mut result).await.unwrap();
            assert_eq!(result, payload);
        })
        .await
        .unwrap();
    }
}
