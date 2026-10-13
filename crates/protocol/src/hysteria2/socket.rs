//! The UDP socket under a Hysteria2 QUIC connection. It can scramble every
//! packet with Salamander and hop between server ports; quinn sees one
//! ordinary socket talking to one fixed server address.

use blake2::{Blake2b, Digest, digest::consts::U32};
use quinn::{
    AsyncUdpSocket, Runtime, TokioRuntime, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use rand::{Rng, RngCore};
use std::{
    fmt,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

/// Binds a UDP socket that reaches the given server address outside the
/// tunnel (the platform hooks decide how).
pub type Binder = Arc<dyn Fn(SocketAddr) -> io::Result<std::net::UdpSocket> + Send + Sync>;

const SALT: usize = 8;

/// Salamander: each packet is an 8-byte random salt followed by the payload
/// XORed with BLAKE2b-256(password || salt).
#[derive(Clone)]
pub struct Salamander {
    password: Vec<u8>,
}
impl Salamander {
    pub fn new(password: &str) -> Self {
        Self {
            password: password.as_bytes().to_vec(),
        }
    }
    fn key(&self, salt: &[u8]) -> [u8; 32] {
        let mut hash = Blake2b::<U32>::new();
        hash.update(&self.password);
        hash.update(salt);
        hash.finalize().into()
    }
    pub fn obfuscate(&self, packet: &[u8]) -> Vec<u8> {
        let mut out = vec![0; SALT + packet.len()];
        rand::thread_rng().fill_bytes(&mut out[..SALT]);
        let key = self.key(&out[..SALT]);
        for (i, byte) in packet.iter().enumerate() {
            out[SALT + i] = byte ^ key[i % key.len()];
        }
        out
    }
    /// Unscrambles in place, moving the payload to the front; returns its length.
    pub fn deobfuscate(&self, packet: &mut [u8]) -> Option<usize> {
        let len = packet.len().checked_sub(SALT).filter(|&n| n > 0)?;
        let key = self.key(&packet[..SALT]);
        for i in 0..len {
            packet[i] = packet[SALT + i] ^ key[i % key.len()];
        }
        Some(len)
    }
}

struct Sockets {
    current: Arc<dyn AsyncUdpSocket>,
    /// The socket before the last hop, kept for packets still in flight.
    previous: Option<Arc<dyn AsyncUdpSocket>>,
    port: u16,
    /// Bumped on every hop so the write poller follows the new socket.
    generation: u64,
    next_hop: Option<Instant>,
    /// quinn's receive task: the new socket has no readiness interest yet,
    /// so a hop has to wake it to poll that socket.
    receiver: Option<Waker>,
}

pub struct Transport {
    /// The address quinn believes it talks to: the first port.
    server: SocketAddr,
    ports: Vec<u16>,
    hop_interval: Option<Duration>,
    obfs: Option<Salamander>,
    bind: Binder,
    sockets: Mutex<Sockets>,
}
impl fmt::Debug for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("hysteria2::Transport")
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}
impl Transport {
    pub fn new(
        server: SocketAddr,
        ports: Vec<u16>,
        hop_interval: Duration,
        obfs: Option<Salamander>,
        bind: Binder,
    ) -> io::Result<Self> {
        let hopping = ports.len() > 1;
        let port = if hopping {
            ports[rand::thread_rng().gen_range(0..ports.len())]
        } else {
            server.port()
        };
        let current = TokioRuntime.wrap_udp_socket(bind(server)?)?;
        Ok(Self {
            server,
            ports,
            hop_interval: hopping.then_some(hop_interval),
            obfs,
            bind,
            sockets: Mutex::new(Sockets {
                current,
                previous: None,
                port,
                generation: 0,
                next_hop: hopping.then(|| Instant::now() + hop_interval),
                receiver: None,
            }),
        })
    }
    /// Moves to a new local socket and a random server port, as Hysteria
    /// does, so a middlebox throttling one UDP flow loses track of it.
    fn hop_if_due(&self, sockets: &mut Sockets) {
        let (Some(interval), Some(due)) = (self.hop_interval, sockets.next_hop) else {
            return;
        };
        let now = Instant::now();
        if now < due {
            return;
        }
        sockets.next_hop = Some(now + interval);
        let socket = match (self.bind)(self.server).and_then(|s| TokioRuntime.wrap_udp_socket(s)) {
            Ok(socket) => socket,
            Err(error) => {
                tracing::debug!(%error, "Hysteria2 port hop skipped");
                return;
            }
        };
        sockets.previous = Some(std::mem::replace(&mut sockets.current, socket));
        sockets.port = self.ports[rand::thread_rng().gen_range(0..self.ports.len())];
        sockets.generation += 1;
        if let Some(receiver) = sockets.receiver.take() {
            receiver.wake();
        }
    }
    /// Turns what one socket received into what quinn expects: the fixed
    /// server address and, under Salamander, the unscrambled packets.
    fn received(&self, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta], count: usize) {
        for (buf, meta) in bufs.iter_mut().zip(meta.iter_mut()).take(count) {
            if self.ports.contains(&meta.addr.port()) && meta.addr.ip() == self.server.ip() {
                meta.addr = self.server;
            }
            let Some(obfs) = &self.obfs else { continue };
            // Coalesced (GRO) packets were each scrambled with their own salt.
            let stride = meta.stride.max(1);
            let mut written = 0;
            let mut new_stride = 0;
            for start in (0..meta.len).step_by(stride) {
                let end = (start + stride).min(meta.len);
                let Some(len) = obfs.deobfuscate(&mut buf[start..end]) else {
                    continue;
                };
                buf.copy_within(start..start + len, written);
                written += len;
                if new_stride == 0 {
                    new_stride = len;
                }
            }
            meta.len = written;
            meta.stride = new_stride.max(1);
        }
    }
}

impl AsyncUdpSocket for Transport {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        let (inner, generation) = {
            let sockets = self.sockets.lock().unwrap();
            (
                sockets.current.clone().create_io_poller(),
                sockets.generation,
            )
        };
        Box::pin(Poller {
            transport: self,
            inner,
            generation,
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let (socket, port) = {
            let mut sockets = self.sockets.lock().unwrap();
            self.hop_if_due(&mut sockets);
            (sockets.current.clone(), sockets.port)
        };
        let mut destination = transmit.destination;
        if destination == self.server {
            destination.set_port(port);
        }
        match &self.obfs {
            None => socket.try_send(&Transmit {
                destination,
                ..*transmit
            }),
            Some(obfs) => {
                let packet = obfs.obfuscate(transmit.contents);
                socket.try_send(&Transmit {
                    destination,
                    ecn: transmit.ecn,
                    contents: &packet,
                    segment_size: None,
                    src_ip: transmit.src_ip,
                })
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let (current, previous) = {
            let mut sockets = self.sockets.lock().unwrap();
            sockets.receiver = Some(cx.waker().clone());
            (sockets.current.clone(), sockets.previous.clone())
        };
        if let Poll::Ready(result) = current.poll_recv(cx, bufs, meta) {
            let count = result?;
            self.received(bufs, meta, count);
            return Poll::Ready(Ok(count));
        }
        if let Some(previous) = previous {
            match previous.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(count)) => {
                    self.received(bufs, meta, count);
                    return Poll::Ready(Ok(count));
                }
                Poll::Ready(Err(_)) => self.sockets.lock().unwrap().previous = None,
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sockets.lock().unwrap().current.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        // Salamander salts each packet, so quinn must hand them over singly.
        match self.obfs {
            Some(_) => 1,
            None => self.sockets.lock().unwrap().current.max_transmit_segments(),
        }
    }

    fn max_receive_segments(&self) -> usize {
        self.sockets.lock().unwrap().current.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.sockets.lock().unwrap().current.may_fragment()
    }
}

/// Write readiness of whichever socket is current.
struct Poller {
    transport: Arc<Transport>,
    inner: Pin<Box<dyn UdpPoller>>,
    generation: u64,
}
impl fmt::Debug for Poller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("hysteria2::Poller").finish_non_exhaustive()
    }
}
impl UdpPoller for Poller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let (current, generation) = {
            let sockets = this.transport.sockets.lock().unwrap();
            (sockets.current.clone(), sockets.generation)
        };
        if generation != this.generation {
            this.inner = current.create_io_poller();
            this.generation = generation;
        }
        this.inner.as_mut().poll_writable(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salamander_round_trips_with_a_fresh_salt_per_packet() {
        let obfs = Salamander::new("secret");
        let packet = b"quic initial packet".repeat(10);
        let first = obfs.obfuscate(&packet);
        let second = obfs.obfuscate(&packet);
        assert_eq!(first.len(), packet.len() + SALT);
        assert_ne!(first, second);
        assert_ne!(&first[SALT..], &packet[..]);
        let mut received = first.clone();
        let len = obfs.deobfuscate(&mut received).unwrap();
        assert_eq!(&received[..len], &packet[..]);
        // The wrong password yields garbage, and a bare salt nothing.
        let mut wrong = first;
        let len = Salamander::new("other").deobfuscate(&mut wrong).unwrap();
        assert_ne!(&wrong[..len], &packet[..]);
        assert_eq!(obfs.deobfuscate(&mut [0; SALT]), None);
    }

    #[test]
    fn salamander_matches_the_reference_key_schedule() {
        // BLAKE2b-256("pw" || salt) XOR payload, as in Hysteria's obfs package.
        let obfs = Salamander::new("pw");
        let mut packet = vec![1, 2, 3, 4, 5, 6, 7, 8];
        packet.extend_from_slice(&[0; 40]);
        let key = obfs.key(&packet[..SALT]);
        let len = obfs.deobfuscate(&mut packet).unwrap();
        assert_eq!(len, 40);
        assert_eq!(&packet[..32], &key[..]);
        assert_eq!(&packet[32..40], &key[..8]);
    }
}
