//! TLS record-bounded I/O used by XTLS Vision.
//!
//! BoringSSL normally reads ahead from its BIO. Vision switches from the
//! outer TLS stream to raw inner-TLS bytes independently in each direction,
//! so the BIO is deliberately limited to one complete TLS record per poll.
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const HEADER: usize = 5;
const SCRATCH: usize = 16 * 1024;

#[derive(Debug)]
pub struct RecordBoundedStream<S> {
    inner: S,
    header: [u8; HEADER],
    header_filled: usize,
    record_remaining: usize,
    yield_after_record: bool,
}

impl<S> RecordBoundedStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            header: [0; HEADER],
            header_filled: 0,
            record_remaining: 0,
            yield_after_record: false,
        }
    }
}

impl<S: AsyncRead + Unpin> RecordBoundedStream<S> {
    pub fn poll_read_raw(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.yield_after_record = false;
        Pin::new(&mut self.inner).poll_read(cx, output)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RecordBoundedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.yield_after_record {
            self.yield_after_record = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let header = self.header_filled < HEADER;
        let remaining = if header {
            HEADER - self.header_filled
        } else {
            self.record_remaining
        };
        let limit = remaining.min(output.remaining()).min(SCRATCH);
        let this = self.as_mut().get_mut();
        let mut bytes = [0u8; SCRATCH];
        let mut read = ReadBuf::new(&mut bytes[..limit]);
        ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
        let bytes = read.filled();
        if bytes.is_empty() {
            return Poll::Ready(Ok(()));
        }
        output.put_slice(bytes);
        if header {
            let end = this.header_filled + bytes.len();
            this.header[this.header_filled..end].copy_from_slice(bytes);
            this.header_filled = end;
            if end == HEADER {
                this.record_remaining =
                    usize::from(u16::from_be_bytes([this.header[3], this.header[4]]));
                if this.record_remaining == 0 {
                    this.header_filled = 0;
                    this.yield_after_record = true;
                }
            }
        } else {
            this.record_remaining -= bytes.len();
            if this.record_remaining == 0 {
                this.header_filled = 0;
                this.yield_after_record = true;
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RecordBoundedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

enum Inner<S> {
    Plain(S),
    Tls(tokio_boring::SslStream<RecordBoundedStream<S>>),
}

/// Stream with the direct-I/O controls required by Vision.
pub struct RecordStream<S> {
    // Fields drop in declaration order: SSL must go before callback state.
    inner: Inner<S>,
    _reality: Option<crate::reality::RealityGuard>,
    read_direct: bool,
    write_direct: bool,
    tls13: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> RecordStream<S> {
    pub fn plain(socket: S) -> Self {
        Self {
            inner: Inner::Plain(socket),
            _reality: None,
            read_direct: true,
            write_direct: true,
            tls13: false,
        }
    }
    pub(crate) fn tls(
        stream: tokio_boring::SslStream<RecordBoundedStream<S>>,
        reality: Option<crate::reality::RealityGuard>,
    ) -> Self {
        let tls13 = stream.ssl().version_str() == "TLSv1.3";
        Self {
            inner: Inner::Tls(stream),
            _reality: reality,
            read_direct: false,
            write_direct: false,
            tls13,
        }
    }
    pub fn tls13(&self) -> bool {
        self.tls13
    }
    pub fn read_direct(&mut self) {
        self.read_direct = true;
    }
    pub fn write_direct(&mut self) {
        self.write_direct = true;
    }
    #[cfg(test)]
    pub(crate) fn test_tls13_plain(socket: S) -> Self {
        Self {
            inner: Inner::Plain(socket),
            _reality: None,
            read_direct: false,
            write_direct: false,
            tls13: true,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for RecordStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let direct = self.read_direct;
        match &mut self.inner {
            Inner::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Inner::Tls(stream) if direct => Pin::new(stream.get_mut()).poll_read_raw(cx, buf),
            Inner::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RecordStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let direct = self.write_direct;
        match &mut self.inner {
            Inner::Plain(stream) => Pin::new(stream).poll_write(cx, bytes),
            Inner::Tls(stream) if direct => Pin::new(stream.get_mut()).poll_write(cx, bytes),
            Inner::Tls(stream) => Pin::new(stream).poll_write(cx, bytes),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let direct = self.write_direct;
        match &mut self.inner {
            Inner::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Inner::Tls(stream) if direct => Pin::new(stream.get_mut()).poll_flush(cx),
            Inner::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let direct = self.write_direct;
        match &mut self.inner {
            Inner::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Inner::Tls(stream) if direct => Pin::new(stream.get_mut()).poll_shutdown(cx),
            Inner::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}
