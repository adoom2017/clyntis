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
        value |= usize::from(byte & 0x7f) << (i * 7);
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

fn gun_frame(payload: &[u8]) -> Bytes {
    let mut proto = Vec::with_capacity(payload.len() + 10);
    proto.push(0x0a);
    varint(payload.len(), &mut proto);
    proto.extend_from_slice(payload);
    let mut frame = Vec::with_capacity(proto.len() + 5);
    frame.push(0);
    frame.extend_from_slice(&(proto.len() as u32).to_be_bytes());
    frame.extend(proto);
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
    options: &meta_config::GrpcOptions,
    secure: bool,
) -> String {
    format!(
        "{transport_identity}|{secure}|{endpoint}|{authority}|{}|{}|{}",
        options.grpc_service_name, options.grpc_user_agent, options.ping_interval
    )
}

fn reuse_least_loaded(load: usize, connections: usize, options: &meta_config::GrpcOptions) -> bool {
    if load == 0 {
        return true;
    }
    if options.max_connections > 0 {
        connections >= options.max_connections || load < options.min_streams
    } else {
        options.max_streams == 0 || load < options.max_streams
    }
}

fn pooled(key: &str, options: &meta_config::GrpcOptions) -> Option<Physical> {
    let pool = POOL.get_or_init(Default::default);
    let map = pool.lock().unwrap();
    let list = map.get(key)?;
    let least = list
        .iter()
        .min_by_key(|entry| entry.active.load(Ordering::Relaxed))?;
    let load = least.active.load(Ordering::Relaxed);
    reuse_least_loaded(load, list.len(), options).then(|| least.clone())
}

fn remove_physical(key: &str, id: u64) {
    let mut map = POOL.get_or_init(Default::default).lock().unwrap();
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
    options: &meta_config::GrpcOptions,
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
        if let Some((config, clock)) = tls.as_ref() {
            stream = crate::tls::SecureConnector::new(clock.clone())
                .connect(stream, config)
                .await?;
        }
        let (sender, mut connection) = h2::client::handshake(stream).await?;
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
        if options.ping_interval > 0
            && let Some(mut ping) = connection.ping_pong()
        {
            let interval = options.ping_interval;
            tokio::spawn(async move {
                let mut timer = tokio::time::interval(Duration::from_secs(interval));
                loop {
                    timer.tick().await;
                    if ping.ping(h2::Ping::opaque()).await.is_err() {
                        break;
                    }
                }
            });
        }
        let cleanup_key = pool_key.clone();
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(%error, "gRPC HTTP/2 connection closed");
            }
            remove_physical(&cleanup_key, id);
        });
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
    closed: bool,
    active: Arc<AtomicUsize>,
}

impl Drop for GrpcStream {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl GrpcStream {
    fn parse(&mut self) -> io::Result<bool> {
        if self.incoming.len() < 5 {
            return Ok(false);
        }
        if self.incoming[0] != 0 {
            return Err(io::Error::other("compressed gRPC messages are unsupported"));
        }
        let length = u32::from_be_bytes(self.incoming[1..5].try_into().unwrap()) as usize;
        if length > 16 * 1024 * 1024 {
            return Err(io::Error::other("oversized gRPC message"));
        }
        if self.incoming.len() < 5 + length {
            return Ok(false);
        }
        let proto = &self.incoming[5..5 + length];
        if proto.first() != Some(&0x0a) {
            return Err(io::Error::other("invalid Gun protobuf message"));
        }
        let (payload_len, prefix) = decode_varint(&proto[1..])
            .ok_or_else(|| io::Error::other("invalid Gun protobuf length"))?;
        let start = 1 + prefix;
        if start + payload_len != proto.len() {
            return Err(io::Error::other("invalid Gun protobuf payload"));
        }
        self.payload = proto[start..].to_vec();
        self.payload_at = 0;
        self.incoming.drain(..5 + length);
        Ok(true)
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.payload_at < self.payload.len() {
            let n = out.remaining().min(self.payload.len() - self.payload_at);
            out.put_slice(&self.payload[self.payload_at..self.payload_at + n]);
            self.payload_at += n;
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.parse()? {
                return self.poll_read(cx, out);
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
            let next = {
                let recv = self.recv.as_mut().expect("gRPC response body initialized");
                match ready!(Pin::new(&mut *recv).poll_data(cx)) {
                    Some(Ok(data)) => {
                        let _ = recv.flow_control().release_capacity(data.len());
                        Some(Ok(data))
                    }
                    Some(Err(error)) => Some(Err(error)),
                    None => None,
                }
            };
            match next {
                Some(Ok(data)) => self.incoming.extend_from_slice(&data),
                Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
                None => self.closed = true,
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
        let n = bytes.len().min(16 * 1024);
        let frame = gun_frame(&bytes[..n]);
        self.send.reserve_capacity(frame.len());
        while self.send.capacity() < frame.len() {
            match ready!(self.send.poll_capacity(cx)) {
                Some(Ok(_)) => {}
                Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
                None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
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
        let options = meta_config::GrpcOptions {
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
        let mut options = meta_config::GrpcOptions {
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
        let options = meta_config::GrpcOptions::default();
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
}
