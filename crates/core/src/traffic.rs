use crate::{Connection, Core};
use anyhow::{Result, ensure};
use async_trait::async_trait;
use clyntis_protocol::{Datagram, Target};
use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Notify,
    time::Instant,
};

pub(crate) struct State {
    info: Connection,
    upload: AtomicU64,
    download: AtomicU64,
    created: Instant,
    /// Milliseconds after `created` when bytes last moved either way.
    active: AtomicU64,
    /// One side of a TCP relay reached EOF; `ended` wakes [`idle_expired`].
    half_closed: AtomicBool,
    ended: Notify,
}
impl State {
    /// Time since the connection was tracked.
    pub(crate) fn lifetime(&self) -> Duration {
        self.created.elapsed()
    }
    /// How long no bytes moved either way.
    fn quiet(&self) -> Duration {
        self.created
            .elapsed()
            .saturating_sub(Duration::from_millis(self.active.load(Ordering::Relaxed)))
    }
    fn mark_eof(&self) {
        if !self.half_closed.swap(true, Ordering::Relaxed) {
            self.ended.notify_one();
        }
    }
    pub(crate) fn snapshot(&self) -> Connection {
        let mut info = self.info.clone();
        info.upload = self.upload.load(Ordering::Relaxed);
        info.download = self.download.load(Ordering::Relaxed);
        info
    }
}
pub(crate) struct Tracker {
    core: Arc<Core>,
    pub(crate) state: Arc<State>,
}
impl Tracker {
    pub(crate) fn new(
        core: Arc<Core>,
        target: Target,
        node: String,
        network: &str,
    ) -> Result<Self> {
        ensure!(!core.stop.is_cancelled(), "core stopped");
        let info = Connection {
            id: uuid::Uuid::new_v4().to_string(),
            metadata: target,
            network: network.into(),
            chains: vec![node],
            upload: 0,
            download: 0,
            start: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs()
                .to_string(),
            cancel: core.stop.child_token(),
        };
        let state = Arc::new(State {
            info,
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            created: Instant::now(),
            active: AtomicU64::new(0),
            half_closed: AtomicBool::new(false),
            ended: Notify::new(),
        });
        {
            let mut connections = core.connections.lock().unwrap();
            ensure!(connections.len() < 4096, "connection limit reached");
            connections.insert(state.info.id.clone(), state.clone());
        }
        Ok(Self { core, state })
    }
    pub(crate) fn cancel(&self) -> tokio_util::sync::CancellationToken {
        self.state.info.cancel.clone()
    }
    fn record(&self, upload: bool, n: usize) {
        if n == 0 {
            return;
        }
        let (local, total) = if upload {
            (&self.state.upload, &self.core.upload)
        } else {
            (&self.state.download, &self.core.download)
        };
        local.fetch_add(n as u64, Ordering::Relaxed);
        total.fetch_add(n as u64, Ordering::Relaxed);
        self.state.active.store(
            self.state.created.elapsed().as_millis() as u64,
            Ordering::Relaxed,
        );
    }
}
impl Drop for Tracker {
    fn drop(&mut self) {
        self.core
            .connections
            .lock()
            .unwrap()
            .remove(&self.state.info.id);
    }
}
pub(crate) struct Stream<S> {
    pub(crate) inner: S,
    pub(crate) tracker: Tracker,
}
impl<S: AsyncRead + Unpin> AsyncRead for Stream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let room = buf.remaining() > 0;
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        this.tracker.record(false, n);
        if room && n == 0 && matches!(result, Poll::Ready(Ok(()))) {
            this.tracker.state.mark_eof();
        }
        result
    }
}

/// The local side of a TCP relay: reports its EOF to the connection's
/// [`State`] so a half-closed relay can be timed out.
pub(crate) struct EofWatch<S> {
    pub(crate) inner: S,
    pub(crate) state: Arc<State>,
}
impl<S: AsyncRead + Unpin> AsyncRead for EofWatch<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let room = buf.remaining() > 0;
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if room && buf.filled().len() == before && matches!(result, Poll::Ready(Ok(()))) {
            this.state.mark_eof();
        }
        result
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for EofWatch<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Idle limits for a TCP relay: no bytes either way for `idle`, or for
/// `half_closed` once one side reached EOF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RelayLimits {
    pub(crate) idle: Duration,
    pub(crate) half_closed: Duration,
}

/// Resolves with the limit that ran out. Sleeps until the earliest moment it
/// could, so a quiet relay costs one timer, not a periodic wakeup.
pub(crate) async fn idle_expired(state: &State, limits: RelayLimits) -> &'static str {
    loop {
        let (limit, reason) = if state.half_closed.load(Ordering::Relaxed) {
            (limits.half_closed, "half-closed")
        } else {
            (limits.idle, "idle")
        };
        let quiet = state.quiet();
        if quiet >= limit {
            return reason;
        }
        tokio::select! {
            _ = tokio::time::sleep(limit - quiet) => {}
            _ = state.ended.notified() => {}
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Stream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, bytes);
        if let Poll::Ready(Ok(n)) = result {
            this.tracker.record(true, n);
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub(crate) struct PacketSession {
    pub(crate) inner: Arc<dyn Datagram>,
    pub(crate) tracker: Tracker,
}
#[async_trait]
impl Datagram for PacketSession {
    async fn send(&self, target: &Target, bytes: &[u8]) -> Result<()> {
        tokio::select! {
            biased;
            _=self.tracker.state.info.cancel.cancelled()=>anyhow::bail!("UDP connection closed"),
            result=tokio::time::timeout(Duration::from_secs(20),self.inner.send(target,bytes))=>result??,
        }
        self.tracker.record(true, bytes.len());
        Ok(())
    }
    async fn recv(&self) -> Result<(Target, Vec<u8>)> {
        let packet = tokio::select! {
            biased;
            _=self.tracker.state.info.cancel.cancelled()=>anyhow::bail!("UDP connection closed"),
            result=tokio::time::timeout(Duration::from_secs(120),self.inner.recv())=>result??,
        };
        self.tracker.record(false, packet.1.len());
        Ok(packet)
    }
}
