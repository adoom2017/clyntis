//! Tailscale's control transport ("controlbase"): Noise_IK_25519_ChaChaPoly_BLAKE2s
//! with the machine key as the client static key, then length-prefixed records.
//! Unlike the Noise spec, transport nonces are big-endian.
use crate::key::{Private, Public};
use anyhow::{Context, Result, bail, ensure};
use blake2::{Blake2s256, Digest};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use meta_protocol::BoxStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";
const MSG_INITIATION: u8 = 1;
const MSG_RESPONSE: u8 = 2;
const MSG_ERROR: u8 = 3;
const MSG_RECORD: u8 = 4;
const MAX_MESSAGE: usize = 4096;
const TAG: usize = 16;
const MAX_PLAINTEXT: usize = MAX_MESSAGE - 3 - TAG;
pub const RESPONSE_LEN: usize = 51;
/// Prefix of the optional JSON message the server sends before HTTP/2.
const EARLY_PAYLOAD_MAGIC: &[u8] = b"\xff\xff\xffTS";

struct Symmetric {
    h: [u8; 32],
    ck: [u8; 32],
}
impl Symmetric {
    fn new() -> Self {
        let h: [u8; 32] = Blake2s256::digest(PROTOCOL_NAME).into();
        Self { h, ck: h }
    }
    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Blake2s256::new();
        hasher.update(self.h);
        hasher.update(data);
        self.h = hasher.finalize().into();
    }
    /// HKDF(ck, DH) -> (ck, k), as in Noise's MixKey.
    fn mix_dh(&mut self, private: &Private, public: &Public) -> Result<[u8; 32]> {
        let shared = private.dh(public)?;
        let (_, hkdf) = hkdf::SimpleHkdf::<Blake2s256>::extract(Some(&self.ck), &shared);
        let mut out = [0u8; 64];
        hkdf.expand(&[], &mut out)
            .map_err(|_| anyhow::anyhow!("HKDF"))?;
        self.ck.copy_from_slice(&out[..32]);
        Ok(out[32..].try_into().unwrap())
    }
    fn encrypt_and_hash(&mut self, key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let out = cipher
            .encrypt(
                &[0u8; 12].into(),
                Payload {
                    msg: plaintext,
                    aad: &self.h,
                },
            )
            .expect("ChaCha20Poly1305 seal");
        self.mix_hash(&out);
        out
    }
    fn decrypt_and_hash(&mut self, key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let out = cipher
            .decrypt(
                &[0u8; 12].into(),
                Payload {
                    msg: ciphertext,
                    aad: &self.h,
                },
            )
            .map_err(|_| anyhow::anyhow!("control handshake authentication failed"))?;
        self.mix_hash(ciphertext);
        Ok(out)
    }
    fn split(&self) -> ([u8; 32], [u8; 32]) {
        let (_, hkdf) = hkdf::SimpleHkdf::<Blake2s256>::extract(Some(&self.ck), &[]);
        let mut out = [0u8; 64];
        hkdf.expand(&[], &mut out).expect("HKDF length");
        (out[..32].try_into().unwrap(), out[32..].try_into().unwrap())
    }
}

fn prologue(version: u16) -> Vec<u8> {
    format!("Tailscale Control Protocol v{version}").into_bytes()
}

/// The client half of a handshake whose initiation has been sent.
pub struct Pending {
    state: Symmetric,
    machine: Private,
    ephemeral: Private,
}

/// Builds the 101-byte initiation (sent in the `X-Tailscale-Handshake` header).
pub fn initiate(machine: &Private, control: &Public, version: u16) -> Result<(Vec<u8>, Pending)> {
    let mut state = Symmetric::new();
    state.mix_hash(&prologue(version));
    state.mix_hash(&control.0);
    let ephemeral = Private::generate();
    let ephemeral_public = ephemeral.public();
    let mut message = Vec::with_capacity(101);
    message.extend_from_slice(&version.to_be_bytes());
    message.push(MSG_INITIATION);
    message.extend_from_slice(&96u16.to_be_bytes());
    message.extend_from_slice(&ephemeral_public.0);
    state.mix_hash(&ephemeral_public.0);
    let key = state.mix_dh(&ephemeral, control)?;
    let sealed_static = state.encrypt_and_hash(&key, &machine.public().0);
    message.extend_from_slice(&sealed_static);
    let key = state.mix_dh(machine, control)?;
    message.extend_from_slice(&state.encrypt_and_hash(&key, &[]));
    debug_assert_eq!(message.len(), 101);
    Ok((
        message,
        Pending {
            state,
            machine: machine.clone(),
            ephemeral,
        },
    ))
}

/// Transport keys after a completed handshake.
pub struct Ciphers {
    tx: [u8; 32],
    rx: [u8; 32],
}

impl Pending {
    /// Completes the handshake with the server's response message.
    pub fn finish(mut self, response: &[u8]) -> Result<Ciphers> {
        ensure!(response.len() >= 3, "short control handshake response");
        if response[0] == MSG_ERROR {
            let len = u16::from_be_bytes([response[1], response[2]]) as usize;
            let text = String::from_utf8_lossy(&response[3..(3 + len).min(response.len())]);
            bail!("control server refused the handshake: {text}");
        }
        ensure!(
            response.len() == RESPONSE_LEN
                && response[0] == MSG_RESPONSE
                && u16::from_be_bytes([response[1], response[2]]) == 48,
            "invalid control handshake response"
        );
        let server_ephemeral = Public(response[3..35].try_into().unwrap());
        self.state.mix_hash(&server_ephemeral.0);
        self.state.mix_dh(&self.ephemeral, &server_ephemeral)?;
        let key = self.state.mix_dh(&self.machine, &server_ephemeral)?;
        self.state.decrypt_and_hash(&key, &response[35..])?;
        let (tx, rx) = self.state.split();
        Ok(Ciphers { tx, rx })
    }
}

struct Nonce(u64);
impl Nonce {
    fn next(&mut self) -> Result<[u8; 12]> {
        ensure!(self.0 != u64::MAX, "control transport nonces exhausted");
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.0.to_be_bytes());
        self.0 += 1;
        Ok(nonce)
    }
}

/// Runs the record layer over `stream` (with `leftover` bytes already read
/// after the handshake) and returns a plaintext pipe plus the early payload,
/// if the server sent one. The pipe closes when the connection ends.
pub async fn transport(
    stream: BoxStream,
    leftover: Vec<u8>,
    ciphers: Ciphers,
) -> Result<(DuplexStream, Option<serde_json::Value>)> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let rx = ChaCha20Poly1305::new((&ciphers.rx).into());
    let tx = ChaCha20Poly1305::new((&ciphers.tx).into());
    let mut rx_nonce = Nonce(0);
    let mut pending = leftover;
    async fn record(
        reader: &mut (impl AsyncReadExt + Unpin),
        pending: &mut Vec<u8>,
        rx: &ChaCha20Poly1305,
        nonce: &mut Nonce,
    ) -> Result<Option<Vec<u8>>> {
        loop {
            if pending.len() >= 3 {
                ensure!(
                    pending[0] == MSG_RECORD,
                    "unexpected control record type {}",
                    pending[0]
                );
                let len = u16::from_be_bytes([pending[1], pending[2]]) as usize;
                ensure!(3 + len <= MAX_MESSAGE, "control record too large");
                if pending.len() >= 3 + len {
                    let plain = rx
                        .decrypt(&nonce.next()?.into(), &pending[3..3 + len])
                        .map_err(|_| anyhow::anyhow!("control record authentication failed"))?;
                    pending.drain(..3 + len);
                    return Ok(Some(plain));
                }
            }
            let mut buf = [0u8; MAX_MESSAGE];
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                return Ok(None);
            }
            pending.extend_from_slice(&buf[..n]);
        }
    }
    // The first 9 plaintext bytes are an HTTP/2 frame header or the early
    // payload header (magic + 4-byte big-endian length).
    let mut plain = Vec::new();
    while plain.len() < 9 {
        let data = record(&mut reader, &mut pending, &rx, &mut rx_nonce)
            .await?
            .context("control connection closed before HTTP/2")?;
        plain.extend_from_slice(&data);
    }
    let mut early = None;
    if plain.starts_with(EARLY_PAYLOAD_MAGIC) {
        let len = u32::from_be_bytes(plain[5..9].try_into().unwrap()) as usize;
        ensure!(len <= 10 << 20, "invalid early payload length");
        while plain.len() < 9 + len {
            let data = record(&mut reader, &mut pending, &rx, &mut rx_nonce)
                .await?
                .context("control connection closed in the early payload")?;
            plain.extend_from_slice(&data);
        }
        early = Some(serde_json::from_slice(&plain[9..9 + len])?);
        plain.drain(..9 + len);
    }
    let (local, remote) = tokio::io::duplex(256 * 1024);
    let (mut pipe_read, mut pipe_write) = tokio::io::split(remote);
    tokio::spawn(async move {
        let result: Result<()> = async {
            if !plain.is_empty() {
                pipe_write.write_all(&plain).await?;
            }
            while let Some(data) = record(&mut reader, &mut pending, &rx, &mut rx_nonce).await? {
                pipe_write.write_all(&data).await?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            tracing::debug!(error = %format!("{error:#}"), "Tailscale control read ended");
        }
        let _ = pipe_write.shutdown().await;
    });
    tokio::spawn(async move {
        let mut tx_nonce = Nonce(0);
        let mut buf = vec![0u8; MAX_PLAINTEXT];
        let result: Result<()> = async {
            loop {
                let n = pipe_read.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                let sealed = tx
                    .encrypt(&tx_nonce.next()?.into(), &buf[..n])
                    .map_err(|_| anyhow::anyhow!("control record seal"))?;
                let mut out = Vec::with_capacity(3 + sealed.len());
                out.push(MSG_RECORD);
                out.extend_from_slice(&(sealed.len() as u16).to_be_bytes());
                out.extend_from_slice(&sealed);
                writer.write_all(&out).await?;
                writer.flush().await?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            tracing::debug!(error = %format!("{error:#}"), "Tailscale control write ended");
        }
        let _ = writer.shutdown().await;
    });
    Ok((local, early))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Server side of the handshake, mirroring controlbase.Server.
    fn respond(control: &Private, init: &[u8], version: u16) -> (Vec<u8>, Ciphers, Public) {
        let mut state = Symmetric::new();
        assert_eq!(u16::from_be_bytes([init[0], init[1]]), version);
        state.mix_hash(&prologue(version));
        state.mix_hash(&control.public().0);
        let ephemeral = Public(init[5..37].try_into().unwrap());
        state.mix_hash(&ephemeral.0);
        let key = state.mix_dh(control, &ephemeral).unwrap();
        let machine = Public(
            state
                .decrypt_and_hash(&key, &init[37..85])
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let key = state.mix_dh(control, &machine).unwrap();
        state.decrypt_and_hash(&key, &init[85..]).unwrap();
        let server_ephemeral = Private::generate();
        let mut out = vec![MSG_RESPONSE, 0, 48];
        out.extend_from_slice(&server_ephemeral.public().0);
        state.mix_hash(&server_ephemeral.public().0);
        state.mix_dh(&server_ephemeral, &ephemeral).unwrap();
        let key = state.mix_dh(&server_ephemeral, &machine).unwrap();
        out.extend_from_slice(&state.encrypt_and_hash(&key, &[]));
        let (c1, c2) = state.split();
        (out, Ciphers { tx: c2, rx: c1 }, machine)
    }

    #[test]
    fn handshake_agrees_on_keys_and_authenticates_the_machine() {
        let control = Private::generate();
        let machine = Private::generate();
        let (init, pending) = initiate(&machine, &control.public(), 115).unwrap();
        assert_eq!(init.len(), 101);
        assert_eq!(&init[2..5], &[1, 0, 96]);
        let (response, server, seen) = respond(&control, &init, 115);
        assert_eq!(seen, machine.public());
        let client = pending.finish(&response).unwrap();
        assert_eq!(client.tx, server.rx);
        assert_eq!(client.rx, server.tx);
        // A different control key cannot complete the handshake.
        let (init, pending) = initiate(&machine, &Private::generate().public(), 115).unwrap();
        let _ = init;
        assert!(pending.finish(&response).is_err());
    }

    #[test]
    fn big_endian_nonces() {
        let mut nonce = Nonce(1);
        assert_eq!(nonce.next().unwrap(), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(nonce.next().unwrap()[11], 2);
    }
}
