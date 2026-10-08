//! Curve25519 keys in Tailscale's text forms, and the node state kept on disk.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, path::Path};
use x25519_dalek::{PublicKey, StaticSecret};

/// A public key with its wire prefix (`mkey:`, `nodekey:` or `discokey:`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Public(pub [u8; 32]);
impl Public {
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 32]
    }
    fn parse(text: &str) -> Result<Self> {
        let hex = ["mkey:", "nodekey:", "discokey:"]
            .iter()
            .find_map(|prefix| text.strip_prefix(prefix))
            .with_context(|| format!("unknown key prefix in {text:?}"))?;
        let bytes = hex::decode(hex).context("invalid key hex")?;
        ensure!(bytes.len() == 32, "key must be 32 bytes");
        Ok(Self(bytes.try_into().unwrap()))
    }
    pub fn node(&self) -> String {
        format!("nodekey:{}", hex::encode(self.0))
    }
    pub fn disco(&self) -> String {
        format!("discokey:{}", hex::encode(self.0))
    }
    pub fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }
}
impl fmt::Debug for Public {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.short())
    }
}
impl<'de> Deserialize<'de> for Public {
    fn deserialize<D: Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(de)?;
        if text.is_empty() {
            return Ok(Self::default());
        }
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// Serializes as `nodekey:<hex>`; machine and disco keys are formatted explicitly.
pub struct NodeKey(pub Public);
impl Serialize for NodeKey {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.node())
    }
}

#[derive(Clone)]
pub struct Private(pub StaticSecret);
impl Private {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        Self(StaticSecret::from(bytes))
    }
    pub fn public(&self) -> Public {
        Public(PublicKey::from(&self.0).to_bytes())
    }
    pub fn dh(&self, public: &Public) -> Result<[u8; 32]> {
        let shared = self.0.diffie_hellman(&PublicKey::from(public.0));
        if !shared.was_contributory() {
            bail!("low-order public key");
        }
        Ok(shared.to_bytes())
    }
    fn hex(&self) -> String {
        hex::encode(self.0.to_bytes())
    }
    fn from_hex(text: &str) -> Result<Self> {
        let bytes: [u8; 32] = hex::decode(text)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("private key must be 32 bytes"))?;
        Ok(Self(StaticSecret::from(bytes)))
    }
}
impl fmt::Debug for Private {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Private({:?})", self.public())
    }
}

/// Identity persisted in `state-dir`: the machine key identifies this device to
/// the control server, the node key to peers. Losing the file means logging in
/// again as a new node.
#[derive(Clone, Debug)]
pub struct State {
    pub machine: Private,
    pub node: Private,
    /// Set once the control server authorized the node key.
    pub registered: bool,
    /// The last chosen home DERP region, announced before the first netmap.
    pub home_derp: u32,
}
#[derive(Serialize, Deserialize)]
struct StateFile {
    machine: String,
    node: String,
    #[serde(default)]
    registered: bool,
    #[serde(default)]
    home_derp: u32,
}
impl State {
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if let Ok(data) = std::fs::read(path) {
            let file: StateFile = serde_json::from_slice(&data)
                .with_context(|| format!("invalid Tailscale state {}", path.display()))?;
            return Ok(Self {
                machine: Private::from_hex(&file.machine)?,
                node: Private::from_hex(&file.node)?,
                registered: file.registered,
                home_derp: file.home_derp,
            });
        }
        let state = Self {
            machine: Private::generate(),
            node: Private::generate(),
            registered: false,
            home_derp: 0,
        };
        state.save(path)?;
        Ok(state)
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec(&StateFile {
            machine: self.machine.hex(),
            node: self.node.hex(),
            registered: self.registered,
            home_derp: self.home_derp,
        })?;
        let temporary = path.with_extension("tmp");
        write_private(&temporary, &data)?;
        std::fs::rename(&temporary, path)?;
        Ok(())
    }
}
#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}
#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    Ok(std::fs::write(path, data)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_round_trip_through_text_and_disk() {
        let key = Private::generate();
        let public = key.public();
        let parsed: Public = serde_json::from_str(&format!("\"{}\"", public.node())).unwrap();
        assert_eq!(parsed, public);
        assert!(serde_json::from_str::<Public>("\"pubkey:00\"").is_err());
        let dir = std::env::temp_dir().join(format!("ts-state-{}", rand::random::<u64>()));
        let path = dir.join("state.json");
        let mut state = State::load_or_create(&path).unwrap();
        state.registered = true;
        state.save(&path).unwrap();
        let again = State::load_or_create(&path).unwrap();
        assert_eq!(again.node.public(), state.node.public());
        assert!(again.registered);
        let _ = std::fs::remove_dir_all(dir);
    }
}
