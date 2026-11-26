//! Mihomo gRPC Gun transport over HTTP/2.
use crate::BoxStream;
use anyhow::Result;
use bytes::Bytes;
use std::{
    collections::HashMap,
    future::Future,
    hash::{Hash, Hasher},
    io,
    pin::Pin,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_FRAME: usize = 4 * 1024 * 1024;
const WRITE_CHUNK: usize = 16 * 1024;
const KEEP_CAPACITY: usize = 16 * 1024;
const INITIAL_STREAM_WINDOW_SIZE: u32 = 1024 * 1024;
const INITIAL_CONNECTION_WINDOW_SIZE: u32 = 2 * 1024 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

fn release_if_large(buffer: &mut Vec<u8>) {
    if buffer.is_empty() && buffer.capacity() > KEEP_CAPACITY {
        *buffer = Vec::new();
    }
}

fn varint_len(mut value: usize) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

fn varint(mut value: usize, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn decode_varint(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut value = 0usize;
    for (i, byte) in bytes.iter().copied().take(10).enumerate() {
        let shifted = usize::from(byte & 0x7f).checked_shl((i * 7) as u32)?;
        value |= shifted;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

fn gun_frame_len(payload_len: usize) -> usize {
    5 + 1 + varint_len(payload_len) + payload_len
}

fn gun_frame(payload: &[u8]) -> Bytes {
    let proto_len = 1 + varint_len(payload.len()) + payload.len();
    let mut frame = Vec::with_capacity(5 + proto_len);
    frame.push(0);
    frame.extend_from_slice(&(proto_len as u32).to_be_bytes());
    frame.push(0x0a);
    varint(payload.len(), &mut frame);
    frame.extend_from_slice(payload);
    Bytes::from(frame)
}

#[derive(Clone)]
struct Physical {
    id: u64,
    sender: h2::client::SendRequest<Bytes>,
    active: Arc<AtomicUsize>,
}
static POOL: OnceLock<Mutex<HashMap<String, Vec<Physical>>>> = OnceLock::new();
static NEXT_PHYSICAL_ID: AtomicU64 = AtomicU64::new(1);
static CONNECT_LOCKS: OnceLock<Vec<tokio::sync::Mutex<()>>> = OnceLock::new();

async fn connect_lock(key: &str) -> tokio::sync::MutexGuard<'static, ()> {
    let locks =
        CONNECT_LOCKS.get_or_init(|| (0..64).map(|_| tokio::sync::Mutex::new(())).collect());
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    locks[hasher.finish() as usize % locks.len()].lock().await
}

fn key(
    transport_identity: &str,
    endpoint: &str,
    authority: &str,
    options: &clyntis_config::GrpcOptions,
    secure: bool,
) -> String {
    format!(
        "{transport_identity}|{secure}|{endpoint}|{authority}|{}|{}|{}",
        options.grpc_service_name, options.grpc_user_agent, options.ping_interval
    )
}

fn reuse_least_loaded(
    load: usize,
    connections: usize,
    options: &clyntis_config::GrpcOptions,
) -> bool {
    if load == 0 {
        return true;
    }
    if options.max_connections > 0 {
        connections >= options.max_connections || load < options.min_streams
    } else {
        options.max_streams == 0 || load < options.max_streams
    }
}

fn pooled(key: &str, options: &clyntis_config::GrpcOptions) -> Option<Physical> {
    let pool = POOL.get_or_init(Default::default);
    let map = pool.lock().unwrap_or_else(|e| e.into_inner());
    let list = map.get(key)?;
    let least = list
        .iter()
        .min_by_key(|entry| entry.active.load(Ordering::Relaxed))?;
    let load = least.active.load(Ordering::Relaxed);
    reuse_least_loaded(load, list.len(), options).then(|| least.clone())
}

/// How long a PING may go unanswered: the interval, within 5–20 s.
fn ping_timeout(interval: Duration) -> Duration {
    interval.clamp(Duration::from_secs(5), Duration::from_secs(20))
}

/// Forgets every pooled HTTP/2 connection so new streams dial afresh: after
/// a network change the pooled ones may be bound to a gone interface, and
/// HTTP/2 still reports them ready. A forgotten connection closes once its
/// last stream ends.
pub fn reset_pool() {
    if let Some(pool) = POOL.get() {
        pool.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

fn remove_physical(key: &str, id: u64) {
    let mut map = POOL
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let remove_key = if let Some(list) = map.get_mut(key) {
        list.retain(|physical| physical.id != id);
        list.is_empty()
    } else {
        false
    };
    if remove_key {
        map.remove(key);
    }
}

struct ActiveLease {
    active: Arc<AtomicUsize>,
    transferred: bool,
}
impl ActiveLease {
    fn new(active: Arc<AtomicUsize>) -> Self {
        active.fetch_add(1, Ordering::Relaxed);
        Self {
            active,
            transferred: false,
        }
    }
    fn transfer(mut self) -> Arc<AtomicUsize> {
        self.transferred = true;
        self.active.clone()
    }
}
impl Drop for ActiveLease {
    fn drop(&mut self) {
        if !self.transferred {
            self.active.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

pub async fn connect(
    stream: BoxStream,
    endpoint: &str,
    authority: &str,
    options: &clyntis_config::GrpcOptions,
    tls: Option<(crate::tls::TlsConnectConfig, Arc<crate::tls::Clock>)>,
    transport_identity: &str,
) -> Result<BoxStream> {
    let secure = tls.is_some();
    let pool_key = key(transport_identity, endpoint, authority, options, secure);
    let creation_guard = connect_lock(&pool_key).await;
    let mut incoming = Some(stream);
    let (mut sender, lease) = loop {
        if let Some(physical) = pooled(&pool_key, options) {
            let lease = ActiveLease::new(physical.active.clone());
            match physical.sender.ready().await {
                Ok(sender) => {
                    drop(incoming.take());
                    break (sender, lease);
                }
                Err(_) => {
                    remove_physical(&pool_key, physical.id);
                    drop(lease);
                    continue;
                }
            }
        }
        let mut stream = incoming
            .take()
            .expect("gRPC transport stream consumed once");
        let (sender, mut connection) = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            if let Some((config, clock)) = tls.as_ref() {
                stream = crate::tls::SecureConnector::new(clock.clone())
                    .connect(stream, config)
                    .await?;
            }
            let mut builder = h2::client::Builder::new();
            builder
                .initial_window_size(INITIAL_STREAM_WINDOW_SIZE)
                .initial_connection_window_size(INITIAL_CONNECTION_WINDOW_SIZE);
            Ok::<_, anyhow::Error>(builder.handshake(stream).await?)
        })
        .await
        .map_err(|_| anyhow::anyhow!("gRPC handshake timed out"))??;
        let active = Arc::new(AtomicUsize::new(0));
        let id = NEXT_PHYSICAL_ID.fetch_add(1, Ordering::Relaxed);
        POOL.get_or_init(Default::default)
            .lock()
            .unwrap()
            .entry(pool_key.clone())
            .or_default()
            .push(Physical {
                id,
                sender: sender.clone(),
                active: active.clone(),
            });
        let ping = (options.ping_interval > 0)
            .then(|| connection.ping_pong())
            .flatten();
        let cleanup_key = pool_key.clone();
        let driver = tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(%error, "gRPC HTTP/2 connection closed");
            }
            remove_physical(&cleanup_key, id);
        });
        if let Some(mut ping) = ping {
            let interval = Duration::from_secs(options.ping_interval);
            let ping_key = pool_key.clone();
            let driver = driver.abort_handle();
            tokio::spawn(async move {
                let mut timer = tokio::time::interval(interval);
                timer.tick().await;
                loop {
                    timer.tick().await;
                    if driver.is_finished() {
                        break;
                    }
                    // A dead link never answers: without a deadline the
                    // pinger waited forever and new streams kept joining it.
                    match tokio::time::timeout(
                        ping_timeout(interval),
                        ping.ping(h2::Ping::opaque()),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {}
                        Ok(Err(_)) => break,
                        Err(_) => {
                            tracing::debug!("gRPC HTTP/2 ping unanswered; closing the connection");
                            remove_physical(&ping_key, id);
                            // Dropping the connection fails its streams now
                            // instead of when TCP gives up.
                            driver.abort();
                            break;
                        }
                    }
                }
            });
        }
        let lease = ActiveLease::new(active);
        break (sender.ready().await?, lease);
    };
    drop(creation_guard);
    let path = if options.grpc_service_name.starts_with('/') {
        options.grpc_service_name.clone()
    } else {
        format!(
            "/{}/Tun",
            if options.grpc_service_name.is_empty() {
                "GunService"
            } else {
                &options.grpc_service_name
            }
        )
    };
    let scheme = if secure { "https" } else { "http" };
    let request = http::Request::post(format!("{scheme}://{authority}{path}"))
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header(
            http::header::USER_AGENT,
            if options.grpc_user_agent.is_empty() {
                "grpc-go/1.36.0"
            } else {
                &options.grpc_user_agent
            },
        )
        .header("te", "trailers")
        .body(())?;
    let (response, send) = sender.send_request(request, false)?;
    Ok(Box::new(GrpcStream {
        send,
        response: Some(response),
        recv: None,
        incoming: vec![],
        payload: vec![],
        payload_at: 0,
        unreleased_incoming: 0,
        unreleased_payload: 0,
        data_ended: false,
        closed: false,
        active: lease.transfer(),
    }))
}

pub struct GrpcStream {
    send: h2::SendStream<Bytes>,
    response: Option<h2::client::ResponseFuture>,
    recv: Option<h2::RecvStream>,
    incoming: Vec<u8>,
    payload: Vec<u8>,
    payload_at: usize,
    unreleased_incoming: usize,
    unreleased_payload: usize,
    data_ended: bool,
    closed: bool,
    active: Arc<AtomicUsize>,
}

impl Drop for GrpcStream {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl GrpcStream {
    fn release_capacity(&mut self, bytes: usize) {
        if bytes > 0
            && let Some(recv) = self.recv.as_mut()
        {
            let _ = recv.flow_control().release_capacity(bytes);
        }
    }

    fn parse(&mut self) -> io::Result<bool> {
        if self.incoming.len() < 5 {
            return Ok(false);
        }
        if self.incoming[0] != 0 {
            return Err(io::Error::other("compressed gRPC messages are unsupported"));
        }
        let length = u32::from_be_bytes(self.incoming[1..5].try_into().unwrap()) as usize;
        if length > MAX_FRAME {
            return Err(io::Error::other("oversized gRPC message"));
        }
        let total = 5 + length;
        if self.incoming.len() < total {
            return Ok(false);
        }
        let proto = &self.incoming[5..total];
        if proto.first() != Some(&0x0a) {
            return Err(io::Error::other("invalid Gun protobuf message"));
        }
        let (payload_len, prefix) = decode_varint(&proto[1..])
            .ok_or_else(|| io::Error::other("invalid Gun protobuf length"))?;
        let start = 1 + prefix;
        if start.checked_add(payload_len) != Some(proto.len()) {
            return Err(io::Error::other("invalid Gun protobuf payload"));
        }
        let payload_start = 5 + start;
        let remaining = self.incoming.len() - total;
        let drained_unreleased = self.unreleased_incoming.saturating_sub(remaining);
        self.unreleased_incoming = self.unreleased_incoming.min(remaining);
        let release_now = drained_unreleased.saturating_sub(payload_len);
        self.unreleased_payload += drained_unreleased - release_now;
        self.release_capacity(release_now);

        if payload_len == 0 {
            self.incoming.drain(..total);
            release_if_large(&mut self.incoming);
        } else if total == self.incoming.len() {
            self.payload.clear();
            std::mem::swap(&mut self.payload, &mut self.incoming);
            self.payload_at = payload_start;
            release_if_large(&mut self.incoming);
        } else if remaining < payload_len {
            self.payload.clear();
            self.payload.extend_from_slice(&self.incoming[total..]);
            self.incoming.truncate(total);
            std::mem::swap(&mut self.payload, &mut self.incoming);
            self.payload_at = payload_start;
            release_if_large(&mut self.incoming);
        } else {
            self.payload.clear();
            self.payload
                .extend_from_slice(&self.incoming[payload_start..total]);
            self.payload_at = 0;
            self.incoming.drain(..total);
            release_if_large(&mut self.incoming);
        }
        Ok(true)
    }
}

impl AsyncRead for GrpcStream {
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
            if self.payload_at < self.payload.len() {
                let n = out.remaining().min(self.payload.len() - self.payload_at);
                out.put_slice(&self.payload[self.payload_at..self.payload_at + n]);
                self.payload_at += n;
                let release = self.unreleased_payload.min(n);
                self.unreleased_payload -= release;
                self.release_capacity(release);
                if self.payload_at == self.payload.len() {
                    self.payload.clear();
                    self.payload_at = 0;
                    release_if_large(&mut self.payload);
                }
                return Poll::Ready(Ok(()));
            }
            if self.parse()? {
                frames += 1;
                if frames >= 64 {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                continue;
            }
            if self.closed {
                return Poll::Ready(Ok(()));
            }
            if self.recv.is_none() {
                let response = ready!(
                    Pin::new(
                        self.response
                            .as_mut()
                            .expect("gRPC response future consumed once")
                    )
                    .poll(cx)
                )
                .map_err(io::Error::other)?;
                if !response.status().is_success() {
                    return Poll::Ready(Err(io::Error::other(format!(
                        "gRPC transport rejected: {}",
                        response.status()
                    ))));
                }
                self.recv = Some(response.into_body());
                self.response = None;
            }
            if !self.data_ended {
                let next = {
                    let this = self.as_mut().get_mut();
                    let recv = this.recv.as_mut().expect("gRPC response body initialized");
                    match Pin::new(&mut *recv).poll_data(cx) {
                        Poll::Ready(item) => item,
                        Poll::Pending => {
                            // We need more bytes to finish an incomplete frame
                            // (already validated <= MAX_FRAME); release held
                            // capacity for those buffered bytes so frames larger
                            // than the HTTP/2 receive window cannot stall.
                            if this.unreleased_incoming > 0 {
                                let release = std::mem::take(&mut this.unreleased_incoming);
                                let _ = recv.flow_control().release_capacity(release);
                            }
                            return Poll::Pending;
                        }
                    }
                };
                match next {
                    Some(Ok(data)) => {
                        self.incoming.extend_from_slice(&data);
                        self.unreleased_incoming += data.len();
                        continue;
                    }
                    Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
                    None => self.data_ended = true,
                }
            }
            if self.data_ended {
                let recv = self.recv.as_mut().expect("gRPC response body initialized");
                match ready!(Pin::new(recv).poll_trailers(cx)) {
                    Ok(Some(trailers)) => {
                        if let Some(status) =
                            trailers.get("grpc-status").and_then(|v| v.to_str().ok())
                            && status != "0"
                        {
                            let msg = trailers
                                .get("grpc-message")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("");
                            return Poll::Ready(Err(io::Error::other(format!(
                                "gRPC stream failed with status {status}: {msg}"
                            ))));
                        }
                    }
                    Ok(None) => {}
                    Err(error) => return Poll::Ready(Err(io::Error::other(error))),
                }
                self.closed = true;
            }
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = bytes.len().min(WRITE_CHUNK);
        let framed = gun_frame_len(n);
        if self.send.capacity() < framed {
            self.send.reserve_capacity(framed);
            while self.send.capacity() < framed {
                match ready!(self.send.poll_capacity(cx)) {
                    Some(Ok(_)) => {}
                    Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
                    None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                }
            }
        }
        let frame = gun_frame(&bytes[..n]);
        self.send
            .send_data(frame, false)
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.send
            .send_data(Bytes::new(), true)
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[test]
    fn gun_framing_roundtrip_shape() {
        let frame = gun_frame(b"hello");
        assert_eq!(&frame[..7], &[0, 0, 0, 0, 7, 0x0a, 5]);
        assert_eq!(&frame[7..], b"hello");
        for size in [0, 1, 127, 128, 16383, 16384, 65536] {
            let payload = vec![0u8; size];
            assert_eq!(gun_frame_len(size), gun_frame(&payload).len(), "{size}");
        }
    }

    #[tokio::test]
    async fn gun_stream_uses_expected_path_headers_and_frames() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.uri().path(), "/custom/Tun");
            assert_eq!(request.uri().authority().unwrap(), "front.example");
            assert_eq!(
                request.headers()[http::header::CONTENT_TYPE],
                "application/grpc"
            );
            assert_eq!(request.headers()[http::header::USER_AGENT], "test-agent");
            let handler = tokio::spawn(async move {
                let mut body = request.into_body();
                let first = body.data().await.unwrap().unwrap();
                let first_size = first.len();
                let response = http::Response::builder().status(200).body(()).unwrap();
                let mut send = respond.send_response(response, false).unwrap();
                send.send_data(first, false).unwrap();
                body.flow_control().release_capacity(first_size).unwrap();
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.unwrap();
                    let size = chunk.len();
                    send.send_data(chunk, false).unwrap();
                    body.flow_control().release_capacity(size).unwrap();
                }
                send.send_data(Bytes::new(), true).unwrap();
            });
            tokio::pin!(handler);
            loop {
                tokio::select! {
                    result = &mut handler => { result.unwrap(); break; }
                    incoming = connection.accept() => {
                        assert!(incoming.is_none(), "unexpected second gRPC stream");
                    }
                }
            }
        });
        let options = clyntis_config::GrpcOptions {
            grpc_service_name: "custom".into(),
            grpc_user_agent: "test-agent".into(),
            ..Default::default()
        };
        let mut stream = tokio::time::timeout(
            Duration::from_secs(1),
            connect(
                Box::new(client),
                "unit.example:443",
                "front.example",
                &options,
                None,
                "unit-transport",
            ),
        )
        .await
        .expect("gRPC connect must not wait for response headers")
        .unwrap();
        stream.write_all(b"hello grpc").await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = [0u8; 10];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello grpc");
        stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[test]
    fn pool_reuses_idle_and_matches_mihomo_thresholds() {
        let mut options = clyntis_config::GrpcOptions {
            max_connections: 2,
            min_streams: 2,
            ..Default::default()
        };
        assert!(reuse_least_loaded(0, 1, &options));
        assert!(reuse_least_loaded(1, 1, &options));
        assert!(!reuse_least_loaded(2, 1, &options));
        assert!(reuse_least_loaded(2, 2, &options));
        options.max_connections = 0;
        options.min_streams = 0;
        options.max_streams = 3;
        assert!(reuse_least_loaded(2, 1, &options));
        assert!(!reuse_least_loaded(3, 1, &options));
    }

    #[tokio::test]
    async fn physical_connection_creation_is_serialized_per_pool() {
        let key = format!("connect-lock-{}", rand::random::<u64>());
        let first = connect_lock(&key).await;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (acquired_tx, mut acquired_rx) = tokio::sync::oneshot::channel();
        let task_key = key.clone();
        let task = tokio::spawn(async move {
            started_tx.send(()).unwrap();
            let _guard = connect_lock(&task_key).await;
            acquired_tx.send(()).unwrap();
        });
        started_rx.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut acquired_rx)
                .await
                .is_err(),
            "a second physical connection entered the same pool concurrently"
        );
        drop(first);
        tokio::time::timeout(Duration::from_secs(1), acquired_rx)
            .await
            .unwrap()
            .unwrap();
        task.await.unwrap();
    }

    /// Tests that inspect the process-wide pool, which `reset_pool` clears.
    static POOL_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// A gRPC stream over an in-memory link whose server accepts one
    /// stream and then either keeps serving the connection or stops reading
    /// it, as a link that died without a reset looks.
    async fn pooled_stream(
        identity: &str,
        options: &clyntis_config::GrpcOptions,
        answer: bool,
    ) -> (BoxStream, tokio::task::JoinHandle<()>) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            let _stream = connection.accept().await.unwrap().unwrap();
            if answer {
                while connection.accept().await.is_some() {}
            } else {
                std::future::pending::<()>().await;
            }
        });
        let stream = connect(
            Box::new(client),
            "unit.example:443",
            "front.example",
            options,
            None,
            identity,
        )
        .await
        .unwrap();
        (stream, server)
    }

    #[tokio::test(start_paused = true)]
    async fn unanswered_ping_drops_the_pooled_connection_and_its_streams() {
        let _pool = POOL_TESTS.lock().await;
        let identity = format!("ping-{}", rand::random::<u64>());
        let options = clyntis_config::GrpcOptions {
            ping_interval: 1,
            ..Default::default()
        };
        let pool_key = key(
            &identity,
            "unit.example:443",
            "front.example",
            &options,
            false,
        );
        let (mut stream, server) = pooled_stream(&identity, &options, false).await;
        assert!(pooled(&pool_key, &options).is_some());
        // First ping after 1 s, given up 5 s later.
        tokio::time::sleep(Duration::from_secs(7)).await;
        assert!(
            pooled(&pool_key, &options).is_none(),
            "new streams would still join the dead connection"
        );
        let read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut [0; 8])).await;
        assert!(
            matches!(read, Ok(Err(_)) | Ok(Ok(0))),
            "a stream on the dropped connection kept waiting: {read:?}"
        );
        server.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn answered_pings_keep_the_connection_pooled() {
        let _pool = POOL_TESTS.lock().await;
        let identity = format!("ping-ok-{}", rand::random::<u64>());
        let options = clyntis_config::GrpcOptions {
            ping_interval: 1,
            ..Default::default()
        };
        let pool_key = key(
            &identity,
            "unit.example:443",
            "front.example",
            &options,
            false,
        );
        let (_stream, server) = pooled_stream(&identity, &options, true).await;
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert!(pooled(&pool_key, &options).is_some());
        server.abort();
    }

    #[tokio::test]
    async fn reset_pool_makes_new_streams_dial_afresh() {
        let _pool = POOL_TESTS.lock().await;
        let identity = format!("reset-{}", rand::random::<u64>());
        let options = clyntis_config::GrpcOptions::default();
        let pool_key = key(
            &identity,
            "unit.example:443",
            "front.example",
            &options,
            false,
        );
        let (_stream, server) = pooled_stream(&identity, &options, true).await;
        assert!(pooled(&pool_key, &options).is_some());
        reset_pool();
        assert!(pooled(&pool_key, &options).is_none());
        server.abort();
    }

    #[tokio::test]
    async fn large_upload_obeys_h2_flow_control() {
        let (client, server) = tokio::io::duplex(512 * 1024);
        let server_task = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            let handler = tokio::spawn(async move {
                let mut body = request.into_body();
                let response = http::Response::builder().status(200).body(()).unwrap();
                let mut send = respond.send_response(response, false).unwrap();
                let mut received = 0;
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.unwrap();
                    let size = chunk.len();
                    received += size;
                    body.flow_control().release_capacity(size).unwrap();
                }
                send.send_data(Bytes::new(), true).unwrap();
                received
            });
            tokio::pin!(handler);
            loop {
                tokio::select! {
                    result = &mut handler => { break result.unwrap(); }
                    incoming = connection.accept() => {
                        assert!(incoming.is_none(), "unexpected second gRPC stream");
                    }
                }
            }
        });
        let options = clyntis_config::GrpcOptions::default();
        let mut stream = connect(
            Box::new(client),
            "flow.example:443",
            "flow.example",
            &options,
            None,
            "flow-control-test",
        )
        .await
        .unwrap();
        let payload: Vec<_> = (0..256 * 1024).map(|index| (index % 251) as u8).collect();
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();
        let framed_size = server_task.await.unwrap();
        assert!(framed_size > payload.len());
    }

    #[tokio::test]
    async fn large_download_frame_completes_under_h2_flow_control_and_rejects_oversized() {
        let large_payload: Vec<u8> = (0..128 * 1024).map(|i| (i % 251) as u8).collect();
        let expected = large_payload.clone();
        let (client, server) = tokio::io::duplex(256 * 1024);
        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            let (_request, mut respond) = connection.accept().await.unwrap().unwrap();
            let handler = tokio::spawn(async move {
                let response = http::Response::builder().status(200).body(()).unwrap();
                let mut send = respond.send_response(response, false).unwrap();
                let mut combined = gun_frame(&expected).to_vec();
                combined.extend_from_slice(&gun_frame(b"after"));
                let mut offset = 0;
                while offset < combined.len() {
                    let want = (combined.len() - offset).min(16 * 1024);
                    send.reserve_capacity(want);
                    let cap = loop {
                        if send.capacity() > 0 {
                            break send.capacity().min(combined.len() - offset);
                        }
                        std::future::poll_fn(|cx| send.poll_capacity(cx))
                            .await
                            .unwrap()
                            .unwrap();
                    };
                    send.send_data(
                        Bytes::copy_from_slice(&combined[offset..offset + cap]),
                        false,
                    )
                    .unwrap();
                    offset += cap;
                }
                // Follow with an oversized frame header (> MAX_FRAME).
                let mut oversized = vec![0u8];
                oversized.extend_from_slice(&((MAX_FRAME + 1) as u32).to_be_bytes());
                send.reserve_capacity(oversized.len());
                while send.capacity() < oversized.len() {
                    std::future::poll_fn(|cx| send.poll_capacity(cx))
                        .await
                        .unwrap()
                        .unwrap();
                }
                send.send_data(Bytes::from(oversized), true).unwrap();
            });
            tokio::pin!(handler);
            let mut handler_done = false;
            loop {
                tokio::select! {
                    result = &mut handler, if !handler_done => {
                        result.unwrap();
                        handler_done = true;
                    }
                    _ = &mut done_rx, if handler_done => break,
                    incoming = connection.accept() => {
                        assert!(incoming.is_none());
                    }
                }
            }
        });
        let options = clyntis_config::GrpcOptions::default();
        let mut stream = connect(
            Box::new(client),
            "large-dl.example:443",
            "large-dl.example",
            &options,
            None,
            "large-dl-test",
        )
        .await
        .unwrap();
        let mut received = vec![0u8; large_payload.len() + 5];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut received))
            .await
            .expect("large gRPC frame deadlocked against H2 flow control")
            .unwrap();
        assert_eq!(&received[..large_payload.len()], &large_payload[..]);
        assert_eq!(&received[large_payload.len()..], b"after");
        let err = stream.read(&mut [0u8; 8]).await.unwrap_err();
        assert!(err.to_string().contains("oversized"), "{err}");
        let _ = done_tx.send(());
        server_task.await.unwrap();
    }
}
