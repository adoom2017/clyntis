//! Hysteria2 client: one QUIC connection per server, authenticated with an
//! HTTP/3 request, carrying TCP on bidirectional streams and UDP in QUIC
//! datagrams. See https://v2.hysteria.network/docs/developers/Protocol/.

pub mod brutal;
pub mod socket;

use crate::{
    BoxStream, Datagram, Target, quic,
    tls::{Clock, TlsFingerprint},
};
use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use bytes::Bytes;
use clyntis_config::Proxy;
use rand::{Rng, distributions::Alphanumeric};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU16, AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    sync::mpsc,
    task::JoinHandle,
};

pub use socket::Binder;

const TCP_REQUEST: u64 = 0x401;
const AUTH_OK: u16 = 233;
/// Queued UDP packets per session before new ones are dropped.
const SESSION_QUEUE: usize = 256;

/// Everything needed to reach one Hysteria2 server.
#[derive(Clone)]
pub struct Options {
    /// Resolved server addresses, tried in order.
    pub addresses: Vec<IpAddr>,
    /// The first is quinn's notion of the server port; more mean port hopping.
    pub ports: Vec<u16>,
    pub hop_interval: Duration,
    pub server_name: String,
    pub password: String,
    pub insecure: bool,
    pub alpn: Vec<String>,
    /// Our upload limit, bytes per second; with the server's limit it picks
    /// Brutal over BBR.
    pub up: Option<u64>,
    /// Our download limit, bytes per second, told to the server.
    pub down: Option<u64>,
    pub obfs: Option<String>,
    pub mtu_discovery: bool,
    /// The browser whose QUIC ClientHello the handshake resembles.
    pub fingerprint: TlsFingerprint,
    /// Smaller QUIC windows for hosts with a tight memory limit (the iOS
    /// packet tunnel is killed above ~50 MiB).
    pub compact: bool,
}
impl Options {
    /// `fingerprint` is the profile's `global-client-fingerprint`, which the
    /// proxy's `client-fingerprint` overrides.
    pub fn from_proxy(proxy: &Proxy, addresses: Vec<IpAddr>, fingerprint: &str) -> Result<Self> {
        let ports = clyntis_config::port_list(proxy)?;
        let server_name = proxy
            .sni
            .clone()
            .or_else(|| proxy.servername.clone())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| proxy.server.clone());
        let password = if proxy.password.is_empty() {
            proxy.auth_str.clone()
        } else {
            proxy.password.clone()
        };
        Ok(Self {
            addresses,
            ports,
            hop_interval: Duration::from_secs(clyntis_config::duration_seconds(
                &proxy.hop_interval,
            )?),
            server_name,
            password,
            insecure: proxy.skip_cert_verify,
            alpn: proxy.alpn.clone(),
            up: proxy
                .up
                .as_deref()
                .map(clyntis_config::bandwidth)
                .transpose()?,
            down: proxy
                .down
                .as_deref()
                .map(clyntis_config::bandwidth)
                .transpose()?,
            obfs: proxy.obfs.is_some().then(|| proxy.obfs_password.clone()),
            mtu_discovery: !proxy.disable_mtu_discovery,
            fingerprint: TlsFingerprint::parse(
                proxy.client_fingerprint.as_deref().unwrap_or(fingerprint),
            )?,
            compact: false,
        })
    }
}

/// An authenticated connection to a Hysteria2 server.
pub struct Client {
    connection: quinn::Connection,
    endpoint: quinn::Endpoint,
    /// Dropping the last request handle closes the HTTP/3 (and so QUIC)
    /// connection, so it lives as long as the client.
    _requests: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    tasks: Vec<JoinHandle<()>>,
    udp: Option<Arc<Sessions>>,
    pub remote: SocketAddr,
}
impl Drop for Client {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"");
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Client {
    pub async fn connect(options: &Options, bind: Binder, clock: Arc<Clock>) -> Result<Self> {
        ensure!(!options.addresses.is_empty(), "no server address");
        let mut last = anyhow::anyhow!("no server address");
        for ip in options.addresses.iter().take(4) {
            let remote = SocketAddr::new(*ip, options.ports[0]);
            match Self::connect_to(options, remote, bind.clone(), clock.clone()).await {
                Ok(client) => return Ok(client),
                Err(error) => {
                    tracing::debug!(%remote, "Hysteria2 connection failed: {error:#}");
                    last = error;
                }
            }
        }
        Err(last)
    }

    async fn connect_to(
        options: &Options,
        remote: SocketAddr,
        bind: Binder,
        clock: Arc<Clock>,
    ) -> Result<Self> {
        let transport = socket::Transport::new(
            remote,
            options.ports.clone(),
            options.hop_interval,
            options.obfs.as_deref().map(socket::Salamander::new),
            bind,
        )?;
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::new(Arc::new(quic::ResetKey::random())),
            None,
            Arc::new(transport),
            Arc::new(quinn::TokioRuntime),
        )?;
        let rate = brutal::Rate::default();
        endpoint.set_default_client_config(client_config(options, clock, rate.clone())?);
        let connection = endpoint
            .connect(remote, &options.server_name)?
            .await
            .context("QUIC handshake")?;
        let (mut driver, mut requests) = h3::client::builder()
            .send_grease(false)
            .build::<_, _, Bytes>(h3_quinn::Connection::new(connection.clone()))
            .await
            .context("HTTP/3 setup")?;
        let mut tasks = vec![tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        })];
        let request = http::Request::post("https://hysteria/auth")
            .header("Hysteria-Auth", &options.password)
            .header("Hysteria-CC-RX", options.down.unwrap_or(0).to_string())
            .header("Hysteria-Padding", padding(256..2048))
            .body(())?;
        let mut stream = requests.send_request(request).await?;
        stream.finish().await?;
        let response = stream.recv_response().await.context("authentication")?;
        if response.status().as_u16() != AUTH_OK {
            for task in tasks {
                task.abort();
            }
            bail!(
                "authentication failed (HTTP {})",
                response.status().as_u16()
            );
        }
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned()
        };
        let udp = header("Hysteria-UDP").eq_ignore_ascii_case("true");
        // As the official client: Brutal at our limit, capped by the server's
        // receive limit, unless the server asks for BBR ("auto").
        let server_rx = header("Hysteria-CC-RX");
        if server_rx != "auto" {
            let max_tx = options.up.unwrap_or(0);
            let mut tx = server_rx.parse::<u64>().unwrap_or(0);
            if tx == 0 || tx > max_tx {
                tx = max_tx;
            }
            rate.set(tx);
        }
        let udp = udp.then(|| {
            let sessions = Arc::new(Sessions::default());
            tasks.push(tokio::spawn(Sessions::receive(
                sessions.clone(),
                connection.clone(),
            )));
            sessions
        });
        Ok(Self {
            connection,
            endpoint,
            _requests: requests,
            tasks,
            udp,
            remote,
        })
    }

    pub fn is_alive(&self) -> bool {
        self.connection.close_reason().is_none()
    }

    pub fn supports_udp(&self) -> bool {
        self.udp.is_some()
    }

    /// A TCP connection to `target` through the server.
    pub async fn tcp(&self, target: &Target) -> Result<BoxStream> {
        let (mut send, mut recv) = self.connection.open_bi().await?;
        let address = target.to_string();
        let padding = padding(64..512);
        let mut request = Vec::with_capacity(16 + address.len() + padding.len());
        put_varint(&mut request, TCP_REQUEST);
        put_varint(&mut request, address.len() as u64);
        request.extend_from_slice(address.as_bytes());
        put_varint(&mut request, padding.len() as u64);
        request.extend_from_slice(padding.as_bytes());
        send.write_all(&request).await?;
        let status = recv.read_u8().await?;
        let message = read_bytes(&mut recv, 2048).await?;
        read_bytes(&mut recv, 4096).await?;
        if status != 0 {
            bail!(
                "server refused {target}: {}",
                String::from_utf8_lossy(&message)
            );
        }
        Ok(Box::new(tokio::io::join(recv, send)))
    }

    /// A UDP session; each sends to and receives from any target.
    pub fn udp(&self) -> Result<UdpSession> {
        let sessions = self.udp.clone().context("server disabled UDP")?;
        let (sender, receiver) = mpsc::channel(SESSION_QUEUE);
        let id = sessions.open(sender);
        Ok(UdpSession {
            connection: self.connection.clone(),
            sessions,
            id,
            packet: AtomicU16::new(0),
            receiver: tokio::sync::Mutex::new(receiver),
        })
    }

    pub fn close(&self) {
        self.connection.close(0u32.into(), b"");
        self.endpoint.close(0u32.into(), b"");
    }
}

fn padding(range: std::ops::Range<usize>) -> String {
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(range);
    rng.sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn client_config(
    options: &Options,
    clock: Arc<Clock>,
    rate: brutal::Rate,
) -> Result<quinn::ClientConfig> {
    let alpn = if options.alpn.is_empty() {
        vec!["h3".to_owned()]
    } else {
        options.alpn.clone()
    };
    let mut config = quinn::ClientConfig::new(Arc::new(quic::ClientConfig {
        alpn,
        verify: !options.insecure,
        fingerprint: options.fingerprint,
        clock,
    }));
    // Hysteria's client defaults; a fraction of them when memory is tight.
    let (stream, connection, datagrams) = if options.compact {
        (1 << 20, 4 << 20, 1 << 20)
    } else {
        (8 << 20, 20 << 20, 4 << 20)
    };
    let mut transport = quinn::TransportConfig::default();
    transport
        .stream_receive_window(quinn::VarInt::from_u32(stream))
        .receive_window(quinn::VarInt::from_u32(connection))
        .send_window(u64::from(connection))
        .max_idle_timeout(Some(Duration::from_secs(30).try_into()?))
        .keep_alive_interval(Some(Duration::from_secs(10)))
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(1024))
        .datagram_receive_buffer_size(Some(datagrams as usize))
        .datagram_send_buffer_size(datagrams as usize)
        .congestion_controller_factory(Arc::new(brutal::Factory { rate }));
    if !options.mtu_discovery {
        transport.mtu_discovery_config(None);
    }
    config.transport_config(Arc::new(transport));
    Ok(config)
}

/// QUIC variable-length integer (RFC 9000 §16).
fn put_varint(out: &mut Vec<u8>, value: u64) {
    match value {
        0..0x40 => out.push(value as u8),
        0x40..0x4000 => out.extend_from_slice(&(value as u16 | 0x4000).to_be_bytes()),
        0x4000..0x4000_0000 => out.extend_from_slice(&(value as u32 | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}
fn parse_varint(input: &[u8]) -> Option<(u64, usize)> {
    let first = *input.first()?;
    let len = 1 << (first >> 6);
    let bytes = input.get(..len)?;
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = value << 8 | u64::from(*byte);
    }
    Some((value, len))
}
async fn read_varint<R: AsyncRead + Unpin>(reader: &mut R) -> Result<u64> {
    let first = reader.read_u8().await?;
    let len = 1 << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for _ in 1..len {
        value = value << 8 | u64::from(reader.read_u8().await?);
    }
    Ok(value)
}
async fn read_bytes<R: AsyncRead + Unpin>(reader: &mut R, limit: u64) -> Result<Vec<u8>> {
    let len = read_varint(reader).await?;
    ensure!(len <= limit, "Hysteria2 field too long");
    let mut bytes = vec![0; len as usize];
    reader.read_exact(&mut bytes).await?;
    Ok(bytes)
}

/// One UDP message: a whole packet, or one fragment of it.
#[derive(Debug, PartialEq)]
struct Message {
    session: u32,
    packet: u16,
    fragment: u8,
    fragments: u8,
    address: String,
    payload: Bytes,
}
impl Message {
    fn header_len(address: &str) -> usize {
        let mut varint = Vec::new();
        put_varint(&mut varint, address.len() as u64);
        8 + varint.len() + address.len()
    }
    fn encode(&self) -> Bytes {
        let mut out = Vec::with_capacity(Self::header_len(&self.address) + self.payload.len());
        out.extend_from_slice(&self.session.to_be_bytes());
        out.extend_from_slice(&self.packet.to_be_bytes());
        out.push(self.fragment);
        out.push(self.fragments);
        put_varint(&mut out, self.address.len() as u64);
        out.extend_from_slice(self.address.as_bytes());
        out.extend_from_slice(&self.payload);
        out.into()
    }
    fn decode(datagram: Bytes) -> Option<Self> {
        let header = datagram.get(..8)?;
        let (len, size) = parse_varint(&datagram[8..])?;
        let start = 8 + size;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        let address = std::str::from_utf8(datagram.get(start..end)?)
            .ok()?
            .to_owned();
        let message = Self {
            session: u32::from_be_bytes(header[..4].try_into().ok()?),
            packet: u16::from_be_bytes(header[4..6].try_into().ok()?),
            fragment: header[6],
            fragments: header[7],
            address,
            payload: datagram.slice(end..),
        };
        (message.fragments > 0 && message.fragment < message.fragments).then_some(message)
    }
    /// Splits a packet into messages that each fit in `max` bytes.
    fn split(
        session: u32,
        packet: u16,
        address: String,
        payload: &[u8],
        max: usize,
    ) -> Result<Vec<Self>> {
        let room = max
            .checked_sub(Self::header_len(&address))
            .filter(|&room| room > 0)
            .context("UDP address too long for a datagram")?;
        let count = payload.len().div_ceil(room).max(1);
        ensure!(count <= 255, "UDP packet too large");
        Ok((0..count)
            .map(|i| Self {
                session,
                packet,
                fragment: i as u8,
                fragments: count as u8,
                address: address.clone(),
                payload: Bytes::copy_from_slice(
                    &payload[(i * room).min(payload.len())..((i + 1) * room).min(payload.len())],
                ),
            })
            .collect())
    }
}

/// Reassembles one fragmented packet at a time per session, as Hysteria does:
/// a fragment of a newer packet discards the unfinished older one.
#[derive(Default)]
struct Defragger {
    packet: u16,
    parts: Vec<Option<Bytes>>,
    received: usize,
}
impl Defragger {
    fn feed(&mut self, message: Message) -> Option<(String, Bytes)> {
        if message.fragments == 1 {
            return Some((message.address, message.payload));
        }
        if message.packet != self.packet || self.parts.len() != usize::from(message.fragments) {
            self.packet = message.packet;
            self.parts = vec![None; usize::from(message.fragments)];
            self.received = 0;
        }
        let slot = &mut self.parts[usize::from(message.fragment)];
        if slot.is_none() {
            *slot = Some(message.payload);
            self.received += 1;
        }
        if self.received < self.parts.len() {
            return None;
        }
        let mut whole = Vec::new();
        for part in self.parts.drain(..).flatten() {
            whole.extend_from_slice(&part);
        }
        self.received = 0;
        Some((message.address, whole.into()))
    }
}

type Inbox = mpsc::Sender<(Target, Vec<u8>)>;

#[derive(Default)]
struct Sessions {
    next: AtomicU32,
    open: Mutex<HashMap<u32, (Inbox, Defragger)>>,
}
impl Sessions {
    fn open(&self, inbox: Inbox) -> u32 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.open
            .lock()
            .unwrap()
            .insert(id, (inbox, Defragger::default()));
        id
    }
    /// Hands each datagram to its session until the connection ends; then
    /// every session's receiver sees the end.
    async fn receive(sessions: Arc<Self>, connection: quinn::Connection) {
        while let Ok(datagram) = connection.read_datagram().await {
            let Some(message) = Message::decode(datagram) else {
                continue;
            };
            let mut open = sessions.open.lock().unwrap();
            let Some((inbox, defragger)) = open.get_mut(&message.session) else {
                continue;
            };
            let Some((address, payload)) = defragger.feed(message) else {
                continue;
            };
            let Ok(source) = Target::parse(&address) else {
                continue;
            };
            // A full queue drops the packet, as a congested link would.
            let _ = inbox.try_send((source, payload.to_vec()));
        }
        sessions.open.lock().unwrap().clear();
    }
}

pub struct UdpSession {
    connection: quinn::Connection,
    sessions: Arc<Sessions>,
    id: u32,
    packet: AtomicU16,
    receiver: tokio::sync::Mutex<mpsc::Receiver<(Target, Vec<u8>)>>,
}
impl Drop for UdpSession {
    fn drop(&mut self) {
        self.sessions.open.lock().unwrap().remove(&self.id);
    }
}
#[async_trait]
impl Datagram for UdpSession {
    async fn send(&self, target: &Target, bytes: &[u8]) -> Result<()> {
        let max = self
            .connection
            .max_datagram_size()
            .context("server does not accept datagrams")?;
        let packet = self.packet.fetch_add(1, Ordering::Relaxed);
        for message in Message::split(self.id, packet, target.to_string(), bytes, max)? {
            self.connection.send_datagram(message.encode())?;
        }
        Ok(())
    }
    async fn recv(&self) -> Result<(Target, Vec<u8>)> {
        self.receiver
            .lock()
            .await
            .recv()
            .await
            .context("Hysteria2 connection closed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_use_the_shortest_quic_encoding() {
        for (value, len) in [
            (0, 1),
            (63, 1),
            (64, 2),
            (0x401, 2),
            (16383, 2),
            (16384, 4),
            ((1 << 30) - 1, 4),
            (1 << 30, 8),
        ] {
            let mut out = Vec::new();
            put_varint(&mut out, value);
            assert_eq!(out.len(), len, "{value}");
            assert_eq!(parse_varint(&out), Some((value, len)));
        }
        // The TCP request type, as on the wire.
        let mut out = Vec::new();
        put_varint(&mut out, TCP_REQUEST);
        assert_eq!(out, [0x44, 0x01]);
        assert_eq!(parse_varint(&[0x44]), None);
    }

    #[test]
    fn udp_messages_round_trip_and_reassemble_out_of_order() {
        let payload: Vec<u8> = (0..=255).cycle().take(3000).collect();
        let parts = Message::split(7, 9, "[::1]:53".into(), &payload, 1200).unwrap();
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|m| m.encode().len() <= 1200));
        let mut decoded: Vec<_> = parts
            .iter()
            .map(|m| Message::decode(m.encode()).unwrap())
            .collect();
        assert_eq!(decoded[0], parts[0]);
        let mut defragger = Defragger::default();
        let last = decoded.remove(2);
        assert_eq!(defragger.feed(last), None);
        // A repeated fragment changes nothing.
        assert_eq!(
            defragger.feed(Message::decode(parts[2].encode()).unwrap()),
            None
        );
        assert_eq!(defragger.feed(decoded.remove(1)), None);
        let (address, whole) = defragger.feed(decoded.remove(0)).unwrap();
        assert_eq!(address, "[::1]:53");
        assert_eq!(&whole[..], &payload[..]);

        // A small packet is one message; an empty one still is.
        assert_eq!(
            Message::split(1, 1, "a:1".into(), b"x", 1200)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            Message::split(1, 1, "a:1".into(), b"", 1200).unwrap().len(),
            1
        );
        // Malformed datagrams are rejected rather than misread.
        assert_eq!(Message::decode(Bytes::from_static(&[0; 7])), None);
        assert_eq!(
            Message::decode(Bytes::from_static(&[0, 0, 0, 1, 0, 0, 2, 1, 0])),
            None
        );
        assert_eq!(
            Message::decode(Bytes::from_static(&[0, 0, 0, 1, 0, 0, 0, 1, 5, b'a'])),
            None
        );
    }

    #[test]
    fn a_newer_packet_replaces_an_unfinished_one() {
        let mut defragger = Defragger::default();
        let old = Message::split(1, 1, "a:1".into(), &[1; 300], 120).unwrap();
        let new = Message::split(1, 2, "a:1".into(), &[2; 300], 120).unwrap();
        assert_eq!(new.len(), old.len());
        assert_eq!(
            defragger.feed(Message::decode(old[0].encode()).unwrap()),
            None
        );
        for (i, part) in new.iter().enumerate() {
            let result = defragger.feed(Message::decode(part.encode()).unwrap());
            assert_eq!(result.is_some(), i == new.len() - 1);
            if let Some((_, whole)) = result {
                assert_eq!(&whole[..], &[2; 300][..]);
            }
        }
    }
}
