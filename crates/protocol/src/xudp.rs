//! XUDP over VLESS command 3, including multiplexing unrelated UDP flows on one
//! physical stream.
use crate::{BoxStream, Datagram, Target, vless};
use anyhow::{Result, ensure};
use async_trait::async_trait;
use std::{
    collections::HashMap,
    io,
    sync::{
        Arc, Mutex as StdMutex, Weak,
        atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

const SESSION_ID: u16 = 0;
const NEW: u8 = 1;
const KEEP: u8 = 2;
const END: u8 = 3;
const KEEPALIVE: u8 = 4;
const DATA: u8 = 1;
const ERROR: u8 = 2;
const UDP: u8 = 2;
const MAX_METADATA: usize = 512;
const MAX_PAYLOAD: usize = 65507;
/// Everything a closing session may spend telling the peer (END): waiting for
/// the shared writer, writing and flushing. Past it the peer's own idle
/// timeout ends the session; the stream is not held for a stalled peer.
/// Tune against weak networks before shortening it.
const END_DEADLINE: Duration = Duration::from_secs(10);
/// END frames waiting or being written at once. Closes beyond it skip the
/// frame rather than queue without bound behind a stalled writer.
const MAX_PENDING_ENDS: usize = 32;

struct Writer {
    stream: WriteHalf<BoxStream>,
    first: bool,
    usable: bool,
}

struct Reader {
    stream: ReadHalf<BoxStream>,
    usable: bool,
}

pub struct Session {
    target: Target,
    reader: Mutex<Reader>,
    writer: Mutex<Writer>,
}

impl Session {
    pub fn new(stream: BoxStream, target: Target) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            target,
            reader: Mutex::new(Reader {
                stream: reader,
                usable: true,
            }),
            writer: Mutex::new(Writer {
                stream: writer,
                first: true,
                usable: true,
            }),
        }
    }
}

type RoutedPacket = std::result::Result<(Target, Vec<u8>), String>;

#[derive(Clone)]
struct Route {
    target: Target,
    sender: mpsc::Sender<RoutedPacket>,
}

struct Shared {
    writer: Mutex<WriteHalf<BoxStream>>,
    routes: StdMutex<HashMap<u16, Route>>,
    next_id: AtomicU16,
    alive: AtomicBool,
    /// Cancelled when the stream fails or the last owner leaves: pending END
    /// frames stop and release the stream.
    closed: CancellationToken,
    pending_ends: AtomicUsize,
}

/// One physical VLESS command-3 stream shared by independent UDP flows.
pub struct Multiplexer {
    shared: Arc<Shared>,
    reader: tokio::task::AbortHandle,
}

impl Multiplexer {
    pub fn new(stream: BoxStream) -> Arc<Self> {
        let (reader, writer) = tokio::io::split(stream);
        let shared = Arc::new(Shared {
            writer: Mutex::new(writer),
            routes: StdMutex::new(HashMap::new()),
            next_id: AtomicU16::new(0),
            alive: AtomicBool::new(true),
            closed: CancellationToken::new(),
            pending_ends: AtomicUsize::new(0),
        });
        let reader = tokio::spawn(read_multiplexed(reader, Arc::downgrade(&shared))).abort_handle();
        Arc::new(Self { shared, reader })
    }

    pub fn is_alive(&self) -> bool {
        self.shared.alive.load(Ordering::Acquire)
    }

    pub fn session(
        self: &Arc<Self>,
        target: Target,
        global_id: Option<[u8; 8]>,
    ) -> Result<MuxSession> {
        ensure!(self.is_alive(), "XUDP multiplexer is closed");
        let (sender, receiver) = mpsc::channel(64);
        let mut routes = self.shared.routes.lock().unwrap();
        ensure!(self.is_alive(), "XUDP multiplexer is closed");
        let id = (0..=u16::MAX)
            .find_map(|_| {
                let id = self.shared.next_id.fetch_add(1, Ordering::Relaxed);
                (!routes.contains_key(&id)).then_some(id)
            })
            .ok_or_else(|| anyhow::anyhow!("XUDP session ID space exhausted"))?;
        routes.insert(
            id,
            Route {
                target: target.clone(),
                sender,
            },
        );
        drop(routes);
        Ok(MuxSession {
            mux: self.clone(),
            id,
            target,
            global_id,
            send: Mutex::new(MuxSendState {
                first: true,
                usable: true,
            }),
            receiver: Mutex::new(receiver),
        })
    }
}

impl Drop for Multiplexer {
    fn drop(&mut self) {
        self.reader.abort();
        fail_multiplexer(&self.shared, "XUDP multiplexer dropped");
    }
}

struct MuxSendState {
    first: bool,
    usable: bool,
}

pub struct MuxSession {
    mux: Arc<Multiplexer>,
    id: u16,
    target: Target,
    global_id: Option<[u8; 8]>,
    send: Mutex<MuxSendState>,
    receiver: Mutex<mpsc::Receiver<RoutedPacket>>,
}

struct WriteAttempt {
    shared: Arc<Shared>,
    committed: bool,
}

impl Drop for WriteAttempt {
    fn drop(&mut self) {
        if !self.committed {
            fail_multiplexer(&self.shared, "XUDP write interrupted");
        }
    }
}

fn fail_multiplexer(shared: &Shared, message: &str) {
    shared.closed.cancel();
    if !shared.alive.swap(false, Ordering::AcqRel) {
        return;
    }
    let routes = std::mem::take(&mut *shared.routes.lock().unwrap());
    for route in routes.into_values() {
        let _ = route.sender.try_send(Err(message.to_owned()));
    }
}

struct MuxMetadata {
    id: u16,
    status: u8,
    data: bool,
    target: Option<Target>,
}

fn multiplexed_metadata(bytes: &[u8]) -> Result<MuxMetadata> {
    ensure!(
        (4..=MAX_METADATA).contains(&bytes.len()),
        "invalid XUDP metadata length"
    );
    let id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let status = bytes[2];
    let flags = bytes[3];
    ensure!(flags & !(DATA | ERROR) == 0, "invalid XUDP options");
    ensure!(flags & ERROR == 0, "XUDP peer rejected session");
    ensure!(
        matches!(status, KEEP | END | KEEPALIVE),
        "unexpected XUDP frame status"
    );
    let target = if bytes.len() == 4 {
        None
    } else {
        ensure!(status == KEEP && bytes[4] == UDP, "invalid XUDP network");
        let (target, consumed) = vless::decode_address(&bytes[5..])?;
        ensure!(consumed + 5 == bytes.len(), "trailing XUDP metadata");
        Some(target)
    };
    ensure!(
        status != KEEPALIVE || flags == 0,
        "XUDP keepalive cannot carry data"
    );
    Ok(MuxMetadata {
        id,
        status,
        data: flags & DATA != 0,
        target,
    })
}

async fn read_multiplexed(mut reader: ReadHalf<BoxStream>, shared: Weak<Shared>) {
    let result = async {
        loop {
            let length = reader.read_u16().await? as usize;
            ensure!(
                (4..=MAX_METADATA).contains(&length),
                "invalid XUDP metadata length"
            );
            let mut header = vec![0; length];
            reader.read_exact(&mut header).await?;
            let metadata = multiplexed_metadata(&header)?;
            let payload = if metadata.data {
                let length = reader.read_u16().await? as usize;
                ensure!(length <= MAX_PAYLOAD, "XUDP payload exceeds limit");
                let mut payload = vec![0; length];
                reader.read_exact(&mut payload).await?;
                Some(payload)
            } else {
                None
            };
            let Some(shared) = shared.upgrade() else {
                return Ok::<(), anyhow::Error>(());
            };
            if metadata.status == KEEPALIVE {
                continue;
            }
            let route = if metadata.status == END {
                shared.routes.lock().unwrap().remove(&metadata.id)
            } else {
                shared.routes.lock().unwrap().get(&metadata.id).cloned()
            };
            let Some(route) = route else {
                continue;
            };
            if metadata.status == END {
                let _ = route.sender.try_send(Err("XUDP session ended".into()));
            } else if let Some(payload) = payload {
                let target = metadata.target.unwrap_or(route.target);
                if let Err(mpsc::error::TrySendError::Full(_)) =
                    route.sender.try_send(Ok((target, payload)))
                {
                    crate::drops::XUDP_INBOX_FULL.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
    .await;
    if let Some(shared) = shared.upgrade() {
        let message = result
            .err()
            .map(|error| error.to_string())
            .unwrap_or_else(|| "XUDP multiplexer closed".into());
        fail_multiplexer(&shared, &message);
    }
}

#[async_trait]
impl Datagram for MuxSession {
    async fn send(&self, target: &Target, payload: &[u8]) -> Result<()> {
        ensure!(target == &self.target, "XUDP session target changed");
        ensure!(self.mux.is_alive(), "XUDP multiplexer is closed");
        let mut state = self.send.lock().await;
        ensure!(state.usable, "XUDP writer interrupted or closed");
        let frame = packet(self.id, target, payload, state.first, self.global_id)?;
        state.usable = false;
        let mut writer = self.mux.shared.writer.lock().await;
        ensure!(self.mux.is_alive(), "XUDP multiplexer is closed");
        let mut attempt = WriteAttempt {
            shared: self.mux.shared.clone(),
            committed: false,
        };
        writer.write_all(&frame).await?;
        writer.flush().await?;
        attempt.committed = true;
        state.first = false;
        state.usable = true;
        Ok(())
    }

    async fn recv(&self) -> Result<(Target, Vec<u8>)> {
        let mut receiver = self.receiver.lock().await;
        match receiver.recv().await {
            Some(Ok(packet)) => Ok(packet),
            Some(Err(error)) => anyhow::bail!(error),
            None => anyhow::bail!("XUDP multiplexer closed"),
        }
    }
}

impl Drop for MuxSession {
    fn drop(&mut self) {
        if self
            .mux
            .shared
            .routes
            .lock()
            .unwrap()
            .remove(&self.id)
            .is_none()
        {
            return;
        }
        let shared = self.mux.shared.clone();
        if !shared.alive.load(Ordering::Acquire) {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if shared.pending_ends.fetch_add(1, Ordering::AcqRel) >= MAX_PENDING_ENDS {
            shared.pending_ends.fetch_sub(1, Ordering::AcqRel);
            tracing::debug!(
                id = self.id,
                "XUDP close frames backed up; leaving this one to the peer's idle timeout"
            );
            return;
        }
        let id = self.id;
        handle.spawn(async move {
            let _pending = PendingEnd(shared.clone());
            tokio::select! {
                _ = shared.closed.cancelled() => {}
                _ = tokio::time::timeout(END_DEADLINE, send_end(&shared, id)) => {}
            }
        });
    }
}

/// Counts an END frame in flight until its task ends, however it ends.
struct PendingEnd(Arc<Shared>);
impl Drop for PendingEnd {
    fn drop(&mut self) {
        self.0.pending_ends.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Writes END for `id`. Cancelled before the writer is ours, nothing was
/// written and the stream stays usable; cancelled after, the frame may be
/// partial, so `WriteAttempt` fails the whole stream and its sessions reconnect.
async fn send_end(shared: &Arc<Shared>, id: u16) {
    let mut writer = shared.writer.lock().await;
    if !shared.alive.load(Ordering::Acquire) {
        return;
    }
    let mut attempt = WriteAttempt {
        shared: shared.clone(),
        committed: false,
    };
    let frame = [0, 4, (id >> 8) as u8, id as u8, END, 0];
    if writer.write_all(&frame).await.is_ok() && writer.flush().await.is_ok() {
        attempt.committed = true;
    }
}

fn packet(
    session_id: u16,
    target: &Target,
    payload: &[u8],
    first: bool,
    global_id: Option<[u8; 8]>,
) -> Result<Vec<u8>> {
    ensure!(payload.len() <= MAX_PAYLOAD, "XUDP payload exceeds limit");
    let mut frame = vec![0, 0];
    frame.extend_from_slice(&session_id.to_be_bytes());
    frame.extend_from_slice(&[if first { NEW } else { KEEP }, DATA, UDP]);
    vless::encode_address(target, &mut frame)?;
    if first && let Some(global_id) = global_id {
        frame.extend_from_slice(&global_id);
    }
    let size = (frame.len() - 2) as u16;
    frame[..2].copy_from_slice(&size.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn metadata(bytes: &[u8], default: &Target) -> Result<(Target, bool)> {
    ensure!(
        (4..=MAX_METADATA).contains(&bytes.len()),
        "invalid XUDP metadata length"
    );
    let id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let status = bytes[2];
    let flags = bytes[3];
    ensure!(flags & !(DATA | ERROR) == 0, "invalid XUDP options");
    ensure!(flags & ERROR == 0, "XUDP peer rejected session");
    ensure!(
        status == KEEPALIVE || id == SESSION_ID,
        "unexpected XUDP session ID"
    );
    match status {
        END => {
            return Err(
                io::Error::new(io::ErrorKind::ConnectionAborted, "XUDP session ended").into(),
            );
        }
        KEEP | KEEPALIVE => {}
        _ => anyhow::bail!("unexpected XUDP frame status"),
    }
    let target = if bytes.len() == 4 {
        default.clone()
    } else {
        ensure!(status == KEEP && bytes[4] == UDP, "invalid XUDP network");
        let (target, consumed) = vless::decode_address(&bytes[5..])?;
        ensure!(consumed + 5 == bytes.len(), "trailing XUDP metadata");
        target
    };
    ensure!(
        status != KEEPALIVE || flags == 0,
        "XUDP keepalive cannot carry data"
    );
    Ok((target, flags & DATA != 0))
}

#[async_trait]
impl Datagram for Session {
    async fn send(&self, target: &Target, payload: &[u8]) -> Result<()> {
        ensure!(target == &self.target, "XUDP session target changed");
        let mut writer = self.writer.lock().await;
        ensure!(writer.usable, "XUDP writer interrupted or closed");
        let frame = packet(SESSION_ID, target, payload, writer.first, None)?;
        // An interrupted frame cannot be retried on this byte stream. Mark it
        // unusable before the first await, including when the future is dropped.
        writer.usable = false;
        writer.stream.write_all(&frame).await?;
        writer.stream.flush().await?;
        writer.first = false;
        writer.usable = true;
        Ok(())
    }

    async fn recv(&self) -> Result<(Target, Vec<u8>)> {
        let mut reader = self.reader.lock().await;
        ensure!(reader.usable, "XUDP reader interrupted or closed");
        reader.usable = false;
        for _ in 0..256 {
            let length = reader.stream.read_u16().await? as usize;
            ensure!(
                (4..=MAX_METADATA).contains(&length),
                "invalid XUDP metadata length"
            );
            let mut header = vec![0; length];
            reader.stream.read_exact(&mut header).await?;
            let (target, data) = metadata(&header, &self.target)?;
            if !data {
                continue;
            }
            let length = reader.stream.read_u16().await? as usize;
            ensure!(length <= MAX_PAYLOAD, "XUDP payload exceeds limit");
            let mut payload = vec![0; length];
            reader.stream.read_exact(&mut payload).await?;
            reader.usable = true;
            return Ok((target, payload));
        }
        anyhow::bail!("too many XUDP control frames without data")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn golden_new_and_keep_packets() {
        let target = Target::new("1.2.3.4", 53).unwrap();
        assert_eq!(
            packet(SESSION_ID, &target, &[0xab, 0xcd], true, None).unwrap(),
            [0, 12, 0, 0, 1, 1, 2, 0, 53, 1, 1, 2, 3, 4, 0, 2, 0xab, 0xcd]
        );
        let next = packet(SESSION_ID, &target, &[], false, None).unwrap();
        assert_eq!(next[4], KEEP);
        assert_eq!(&next[14..], &[0, 0]);
        assert!(packet(SESSION_ID, &target, &vec![0; MAX_PAYLOAD + 1], true, None).is_err());
    }

    #[tokio::test]
    async fn fragmented_response_addresses_keepalives_and_empty_datagrams() {
        let target = Target::new("example.com", 53).unwrap();
        let reply = Target::new("2001:db8::1", 53).unwrap();
        let (local, mut peer) = tokio::io::duplex(1);
        let session = Session::new(Box::new(local), target.clone());
        let mut frame = vec![0, 4, 0, 0, KEEPALIVE, 0];
        let mut response = packet(SESSION_ID, &reply, b"abc", false, None).unwrap();
        frame.append(&mut response);
        frame.extend_from_slice(&[0, 4, 0, 0, KEEP, DATA, 0, 0]);
        let task = tokio::spawn(async move {
            peer.write_all(&frame).await.unwrap();
        });
        assert_eq!(session.recv().await.unwrap(), (reply, b"abc".to_vec()));
        assert_eq!(session.recv().await.unwrap(), (target, vec![]));
        task.await.unwrap();
        assert!(session.recv().await.is_err());
    }

    #[test]
    fn rejects_invalid_headers() {
        let target = Target::new("example.com", 53).unwrap();
        for header in [
            vec![],
            vec![0, 0, KEEP],
            vec![0, 1, KEEP, DATA],
            vec![0, 0, NEW, DATA],
            vec![0, 0, END, 0],
            vec![0, 0, KEEP, ERROR],
            vec![0, 0, KEEP, 4],
            vec![0, 0, KEEP, DATA, 1],
            vec![0, 0, KEEPALIVE, DATA],
        ] {
            assert!(metadata(&header, &target).is_err(), "{header:?}");
        }
    }

    #[tokio::test]
    async fn multiplexer_routes_independent_sessions_and_global_ids() {
        let (local, mut peer) = tokio::io::duplex(64 * 1024);
        let mux = Multiplexer::new(Box::new(local));
        let first_target = Target::new("1.1.1.1", 53).unwrap();
        let second_target = Target::new("example.com", 443).unwrap();
        let first = mux.session(first_target.clone(), Some([11; 8])).unwrap();
        let second = mux.session(second_target.clone(), Some([22; 8])).unwrap();
        let peer_task = tokio::spawn(async move {
            let mut received = Vec::new();
            for _ in 0..2 {
                let length = peer.read_u16().await.unwrap() as usize;
                let mut metadata = vec![0; length];
                peer.read_exact(&mut metadata).await.unwrap();
                let payload_length = peer.read_u16().await.unwrap() as usize;
                let mut payload = vec![0; payload_length];
                peer.read_exact(&mut payload).await.unwrap();
                assert_eq!(metadata[2], NEW);
                let global_id: [u8; 8] = metadata[metadata.len() - 8..].try_into().unwrap();
                received.push((
                    u16::from_be_bytes([metadata[0], metadata[1]]),
                    global_id,
                    payload,
                ));
            }
            assert_eq!(received[0].1, [11; 8]);
            assert_eq!(received[1].1, [22; 8]);
            peer.write_all(
                &packet(received[1].0, &second_target, b"second-reply", false, None).unwrap(),
            )
            .await
            .unwrap();
            peer.write_all(
                &packet(received[0].0, &first_target, b"first-reply", false, None).unwrap(),
            )
            .await
            .unwrap();
        });
        first.send(&first.target, b"first").await.unwrap();
        second.send(&second.target, b"second").await.unwrap();
        assert_eq!(
            first.recv().await.unwrap(),
            (first.target.clone(), b"first-reply".to_vec())
        );
        assert_eq!(
            second.recv().await.unwrap(),
            (second.target.clone(), b"second-reply".to_vec())
        );
        peer_task.await.unwrap();
    }

    /// Closing a session behind a busy writer gives up at the deadline
    /// without writing: the stream and the other sessions stay usable.
    #[tokio::test(start_paused = true)]
    async fn close_frames_wait_for_the_writer_without_corrupting_the_stream() {
        let (local, _peer) = tokio::io::duplex(64 * 1024);
        let mux = Multiplexer::new(Box::new(local));
        let target = Target::new("1.1.1.1", 53).unwrap();
        let closing = mux.session(target.clone(), None).unwrap();
        let other = mux.session(target.clone(), None).unwrap();
        let busy = mux.shared.writer.lock().await;
        drop(closing);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(mux.shared.pending_ends.load(Ordering::Acquire), 1);
        tokio::time::sleep(END_DEADLINE).await;
        assert_eq!(mux.shared.pending_ends.load(Ordering::Acquire), 0);
        drop(busy);
        assert!(mux.is_alive());
        other.send(&target, b"still here").await.unwrap();
    }

    /// An END frame cut off mid-write would misalign every later frame: the
    /// whole stream fails and its sessions learn it, so they reconnect.
    #[tokio::test(start_paused = true)]
    async fn a_partly_written_close_frame_fails_the_stream() {
        // Room for four of END's six bytes; the peer never reads.
        let (local, _peer) = tokio::io::duplex(4);
        let mux = Multiplexer::new(Box::new(local));
        let target = Target::new("1.1.1.1", 53).unwrap();
        let closing = mux.session(target.clone(), None).unwrap();
        let other = mux.session(target.clone(), None).unwrap();
        drop(closing);
        tokio::time::sleep(END_DEADLINE + Duration::from_secs(1)).await;
        assert!(!mux.is_alive());
        assert!(other.recv().await.is_err());
        assert!(other.send(&target, b"x").await.is_err());
        assert_eq!(mux.shared.pending_ends.load(Ordering::Acquire), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn closes_behind_a_stalled_writer_stay_bounded() {
        let (local, _peer) = tokio::io::duplex(64 * 1024);
        let mux = Multiplexer::new(Box::new(local));
        let target = Target::new("1.1.1.1", 53).unwrap();
        let busy = mux.shared.writer.lock().await;
        for _ in 0..100 {
            drop(mux.session(target.clone(), None).unwrap());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(
            mux.shared.pending_ends.load(Ordering::Acquire),
            MAX_PENDING_ENDS
        );
        tokio::time::sleep(END_DEADLINE).await;
        assert_eq!(mux.shared.pending_ends.load(Ordering::Acquire), 0);
        drop(busy);
        assert!(mux.is_alive());
    }

    /// Once every session and the multiplexer are gone, a close frame stuck
    /// on a stalled peer no longer holds the stream until its deadline.
    #[tokio::test(start_paused = true)]
    async fn the_last_owner_leaving_releases_the_stream() {
        let (local, _peer) = tokio::io::duplex(4);
        let mux = Multiplexer::new(Box::new(local));
        let target = Target::new("1.1.1.1", 53).unwrap();
        let first = mux.session(target.clone(), None).unwrap();
        let second = mux.session(target, None).unwrap();
        drop(first);
        tokio::time::sleep(Duration::from_millis(10)).await;
        let shared = Arc::downgrade(&mux.shared);
        drop(second);
        drop(mux);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(shared.upgrade().is_none(), "the stream is still held");
    }

    #[tokio::test]
    async fn interrupted_read_cannot_desynchronize_next_packet() {
        let (local, mut peer) = tokio::io::duplex(16);
        let session = Session::new(Box::new(local), Target::new("example.com", 53).unwrap());
        peer.write_all(&[0]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), session.recv())
                .await
                .is_err()
        );
        let error = session.recv().await.unwrap_err();
        assert!(error.to_string().contains("interrupted"));
    }
}
