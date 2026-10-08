//! DERP relay client: an HTTP-upgraded TLS connection carrying packets
//! addressed by node public key.
use crate::{
    Dialer, http1,
    key::{Private, Public},
    tailcfg::DerpNode,
};
use anyhow::{Context, Result, bail, ensure};
use crypto_box::{
    SalsaBox,
    aead::{Aead, AeadCore},
};
use std::time::Duration;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};

const MAGIC: &[u8] = "DERP🔑".as_bytes();
const SERVER_KEY: u8 = 0x01;
const CLIENT_INFO: u8 = 0x02;
const SERVER_INFO: u8 = 0x03;
const SEND_PACKET: u8 = 0x04;
const RECV_PACKET: u8 = 0x05;
const KEEP_ALIVE: u8 = 0x06;
const NOTE_PREFERRED: u8 = 0x07;
const PEER_GONE: u8 = 0x08;
const PING: u8 = 0x12;
const PONG: u8 = 0x13;
const HEALTH: u8 = 0x14;
const RESTARTING: u8 = 0x15;
const MAX_PACKET: usize = 64 << 10;
/// Servers send a keepalive every 60 s; silence well past that is a dead link.
const READ_TIMEOUT: Duration = Duration::from_secs(130);

/// A packet relayed from `source`.
pub type Inbound = mpsc::Sender<(Public, Vec<u8>)>;

/// Sends through an established DERP connection; dropping it closes the link.
#[derive(Clone)]
pub struct Link {
    tx: mpsc::Sender<Frame>,
}
enum Frame {
    Send(Public, Vec<u8>),
    Pong([u8; 8]),
}
impl Link {
    /// Queues a packet; drops it when the connection is congested or gone,
    /// as a network would. WireGuard retransmits.
    pub fn send(&self, to: Public, packet: Vec<u8>) -> bool {
        self.tx.try_send(Frame::Send(to, packet)).is_ok()
    }
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

/// NaCl box (curve25519-xsalsa20-poly1305): nonce || tag || ciphertext.
pub fn seal(ours: &Private, theirs: &Public, message: &[u8]) -> Vec<u8> {
    let secret = crypto_box::SecretKey::from(ours.0.to_bytes());
    let public = crypto_box::PublicKey::from(theirs.0);
    let sealed = SalsaBox::new(&public, &secret);
    let nonce = SalsaBox::generate_nonce(&mut rand::rngs::OsRng);
    let mut out = nonce.to_vec();
    out.extend(sealed.encrypt(&nonce, message).expect("naclbox seal"));
    out
}
pub fn open(ours: &Private, theirs: &Public, sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < 24 + 16 {
        return None;
    }
    let secret = crypto_box::SecretKey::from(ours.0.to_bytes());
    let public = crypto_box::PublicKey::from(theirs.0);
    SalsaBox::new(&public, &secret)
        .decrypt(sealed[..24].into(), &sealed[24..])
        .ok()
}

fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(kind);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

async fn read_frame(
    reader: &mut (impl AsyncRead + Unpin),
    pending: &mut Vec<u8>,
) -> Result<(u8, Vec<u8>)> {
    loop {
        if pending.len() >= 5 {
            let len = u32::from_be_bytes(pending[1..5].try_into().unwrap()) as usize;
            ensure!(len <= MAX_PACKET + 1024, "DERP frame too large");
            if pending.len() >= 5 + len {
                let kind = pending[0];
                let payload = pending[5..5 + len].to_vec();
                pending.drain(..5 + len);
                return Ok((kind, payload));
            }
        }
        let mut buf = [0u8; 16 * 1024];
        let n = tokio::time::timeout(READ_TIMEOUT, reader.read(&mut buf))
            .await
            .context("DERP connection idle")??;
        ensure!(n > 0, "DERP connection closed");
        pending.extend_from_slice(&buf[..n]);
    }
}

/// Connects to `node`, logs in with `key` and relays packets addressed to us
/// into `inbound` until the connection fails. `home` tells the server this is
/// the region peers use to reach us.
pub async fn connect(
    dialer: &dyn Dialer,
    node: &DerpNode,
    key: &Private,
    home: bool,
    inbound: Inbound,
) -> Result<Link> {
    let port = if node.derp_port == 0 {
        443
    } else {
        node.derp_port
    };
    let mut stream = dialer.connect_tls(&node.host_name, port).await?;
    let response = http1::request(
        &mut stream,
        "GET",
        &node.host_name,
        "/derp",
        &[("Upgrade", "DERP"), ("Connection", "Upgrade")],
    )
    .await?;
    if response.status != 101 {
        bail!(
            "DERP {} refused the upgrade: HTTP {}",
            node.host_name,
            response.status
        );
    }
    let mut pending = response.rest;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (kind, payload) = read_frame(&mut reader, &mut pending).await?;
    ensure!(
        kind == SERVER_KEY && payload.len() >= 40 && payload.starts_with(MAGIC),
        "invalid DERP server greeting"
    );
    let server = Public(payload[8..40].try_into().unwrap());
    let info = serde_json::json!({"version": 2, "CanAckPings": true});
    let mut hello = key.public().0.to_vec();
    hello.extend(seal(key, &server, info.to_string().as_bytes()));
    writer.write_all(&frame(CLIENT_INFO, &hello)).await?;
    let (kind, payload) = read_frame(&mut reader, &mut pending).await?;
    ensure!(kind == SERVER_INFO, "DERP login failed (frame {kind:#x})");
    ensure!(
        open(key, &server, &payload).is_some(),
        "DERP server info not authentic"
    );
    if home {
        writer.write_all(&frame(NOTE_PREFERRED, &[1])).await?;
    }
    writer.flush().await?;
    let (tx, mut rx) = mpsc::channel::<Frame>(512);
    let name = node.host_name.clone();
    let pong = tx.clone();
    let reader_task = tokio::spawn(async move {
        let result: Result<()> = async {
            loop {
                let (kind, payload) = read_frame(&mut reader, &mut pending).await?;
                match kind {
                    RECV_PACKET if payload.len() >= 32 => {
                        let source = Public(payload[..32].try_into().unwrap());
                        if inbound
                            .send((source, payload[32..].to_vec()))
                            .await
                            .is_err()
                        {
                            return Ok(());
                        }
                    }
                    PING if payload.len() == 8 => {
                        let _ = pong.try_send(Frame::Pong(payload[..8].try_into().unwrap()));
                    }
                    RESTARTING => bail!("DERP server restarting"),
                    KEEP_ALIVE | PEER_GONE | PONG | HEALTH => {}
                    _ => {}
                }
            }
        }
        .await;
        if let Err(error) = result {
            tracing::debug!(server = %name, error = %format!("{error:#}"), "DERP read ended");
        }
    });
    let name = node.host_name.clone();
    tokio::spawn(async move {
        let result: Result<()> = async {
            while let Some(item) = rx.recv().await {
                let bytes = match item {
                    Frame::Send(to, packet) => {
                        let mut payload = to.0.to_vec();
                        payload.extend_from_slice(&packet);
                        frame(SEND_PACKET, &payload)
                    }
                    Frame::Pong(data) => frame(PONG, &data),
                };
                writer.write_all(&bytes).await?;
                // Batch whatever is already queued into one TLS write.
                while let Ok(Frame::Send(to, packet)) = rx.try_recv() {
                    let mut payload = to.0.to_vec();
                    payload.extend_from_slice(&packet);
                    writer.write_all(&frame(SEND_PACKET, &payload)).await?;
                }
                writer.flush().await?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            tracing::debug!(server = %name, error = %format!("{error:#}"), "DERP write ended");
        }
        reader_task.abort();
    });
    Ok(Link { tx })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn naclbox_round_trips_and_rejects_other_keys() {
        let a = Private::generate();
        let b = Private::generate();
        let sealed = seal(&a, &b.public(), b"hello");
        assert_eq!(sealed.len(), 24 + 16 + 5);
        assert_eq!(open(&b, &a.public(), &sealed).unwrap(), b"hello");
        assert!(open(&b, &Private::generate().public(), &sealed).is_none());
    }

    #[test]
    fn frames_have_a_big_endian_length() {
        assert_eq!(frame(SEND_PACKET, b"ab"), [4, 0, 0, 0, 2, b'a', b'b']);
    }
}
