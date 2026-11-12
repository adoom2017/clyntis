//! Password-based configuration encryption.
//!
//! [`encrypt`] writes the authenticated v2 format: Argon2id derives a key from
//! the password and a random salt, and XChaCha20-Poly1305 encrypts the
//! configuration under a random nonce. The whole header, including the KDF
//! parameters, is authenticated as associated data, so a wrong password or any
//! tampering is reported as an error instead of producing garbage.
//!
//! The output is Base64 text so it can be shared, published and detected like
//! the legacy format:
//!
//! ```text
//! base64( "CLYNTISE" | version=1 | m_cost KiB (u32 LE) | t_cost (u32 LE)
//!         | lanes (u8) | salt[16] | nonce[24] | ciphertext | tag[16] )
//! ```
//!
//! [`decrypt`] still reads the Alpha legacy format (common/utils/crypto.go):
//! AES-CFB with a fixed IV and the zero-padded password as the key. It has no
//! authentication tag, so callers must validate decrypted configuration
//! before use. [`encrypt_legacy`] is kept only for interoperability tests.
use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use anyhow::{Result, anyhow, bail, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroizing;

/// Largest accepted Base64 input, matching the 16 MiB plaintext profile limit.
const MAX_CIPHERTEXT: usize = 24 * 1024 * 1024;

const MAGIC: &[u8; 8] = b"CLYNTISE";
const VERSION: u8 = 1;
const SALT: usize = 16;
const NONCE: usize = 24;
const TAG: usize = 16;
const HEADER: usize = MAGIC.len() + 1 + 4 + 4 + 1 + SALT + NONCE;

/// Argon2id cost written by [`encrypt`]: 64 MiB, three passes, one lane.
const DEFAULT_KDF: Kdf = Kdf {
    m_cost: 64 * 1024,
    t_cost: 3,
    lanes: 1,
};

/// Limits on the cost read from a file, so a crafted header cannot make the
/// reader allocate or compute without bound.
const MIN_M_COST: u32 = 8 * 1024;
const MAX_M_COST: u32 = 256 * 1024;
const MAX_T_COST: u32 = 16;
const MAX_LANES: u8 = 8;

/// The encryption format of a ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Argon2id + XChaCha20-Poly1305, authenticated.
    V2,
    /// Alpha AES-CFB, unauthenticated.
    Legacy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Kdf {
    m_cost: u32,
    t_cost: u32,
    lanes: u8,
}

impl Kdf {
    fn validate(self) -> Result<Self> {
        ensure!(
            (MIN_M_COST..=MAX_M_COST).contains(&self.m_cost)
                && (1..=MAX_T_COST).contains(&self.t_cost)
                && (1..=MAX_LANES).contains(&self.lanes)
                && self.m_cost >= 8 * u32::from(self.lanes),
            "unsupported encrypted configuration parameters"
        );
        Ok(self)
    }

    fn derive(self, password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let params = Params::new(self.m_cost, self.t_cost, u32::from(self.lanes), Some(32))
            .map_err(|e| anyhow!("invalid key derivation parameters: {e}"))?;
        let mut key = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(password.as_bytes(), salt, &mut *key)
            .map_err(|e| anyhow!("key derivation failed: {e}"))?;
        Ok(key)
    }
}

/// Encrypts `plaintext` in the authenticated v2 format as Base64 text.
pub fn encrypt(plaintext: &[u8], password: &str) -> Result<String> {
    encrypt_with(plaintext, password, DEFAULT_KDF)
}

fn encrypt_with(plaintext: &[u8], password: &str, kdf: Kdf) -> Result<String> {
    let kdf = kdf.validate()?;
    let mut header = Vec::with_capacity(HEADER + plaintext.len() + TAG);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&kdf.m_cost.to_le_bytes());
    header.extend_from_slice(&kdf.t_cost.to_le_bytes());
    header.push(kdf.lanes);
    let mut random = [0u8; SALT + NONCE];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|e| anyhow!("system random source failed: {e}"))?;
    header.extend_from_slice(&random);
    let (salt, nonce) = random.split_at(SALT);
    let key = kdf.derive(password, salt)?;
    let ciphertext = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| anyhow!("encryption failed"))?;
    header.extend_from_slice(&ciphertext);
    Ok(STANDARD.encode(header))
}

/// The format of Base64 `ciphertext`, or an error when it is not Base64.
pub fn format(ciphertext: &[u8]) -> Result<Format> {
    ensure!(
        ciphertext.len() <= MAX_CIPHERTEXT,
        "encrypted configuration exceeds size limit"
    );
    let bytes = STANDARD.decode(ciphertext)?;
    Ok(format_of(&bytes))
}

fn format_of(bytes: &[u8]) -> Format {
    if bytes.starts_with(MAGIC) {
        Format::V2
    } else {
        Format::Legacy
    }
}

/// Decrypts Base64 `ciphertext` in either format.
///
/// v2 input fails on a wrong password or modified data. Legacy input cannot be
/// checked: validate the plaintext before using it.
pub fn decrypt(ciphertext: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        ciphertext.len() <= MAX_CIPHERTEXT,
        "encrypted configuration exceeds size limit"
    );
    let bytes = Zeroizing::new(STANDARD.decode(ciphertext)?);
    match format_of(&bytes) {
        Format::V2 => decrypt_v2(&bytes, password),
        Format::Legacy => {
            let mut bytes = bytes;
            legacy_cipher(&mut bytes, password, false)?;
            Ok(bytes)
        }
    }
}

fn decrypt_v2(bytes: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        bytes.len() >= HEADER + TAG,
        "encrypted configuration is truncated"
    );
    let (header, ciphertext) = bytes.split_at(HEADER);
    if header[8] != VERSION {
        bail!("unsupported encrypted configuration version {}", header[8]);
    }
    let field = |at: usize| u32::from_le_bytes(header[at..at + 4].try_into().unwrap());
    let kdf = Kdf {
        m_cost: field(9),
        t_cost: field(13),
        lanes: header[17],
    }
    .validate()?;
    let salt = &header[18..18 + SALT];
    let nonce = &header[18 + SALT..];
    let key = kdf.derive(password, salt)?;
    let plaintext = XChaCha20Poly1305::new((&*key).into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .map_err(|_| anyhow!("wrong password or corrupted encrypted configuration"))?;
    Ok(Zeroizing::new(plaintext))
}

/// Encrypts in the unauthenticated Alpha legacy format. Only for producing
/// files that old clients can read and for interoperability tests.
pub fn encrypt_legacy(plaintext: &[u8], password: &str) -> Result<String> {
    let mut bytes = plaintext.to_vec();
    legacy_cipher(&mut bytes, password, true)?;
    Ok(STANDARD.encode(bytes))
}

const LEGACY_IV: [u8; 16] = [
    35, 46, 57, 24, 85, 35, 25, 74, 87, 35, 88, 98, 66, 33, 14, 5,
];

fn legacy_key(password: &str) -> Zeroizing<Vec<u8>> {
    let bytes = password.as_bytes();
    let size = match bytes.len() {
        0..=16 => 16,
        17..=24 => 24,
        _ => 32,
    };
    let mut key = Zeroizing::new(vec![b'0'; size]);
    let n = size.min(bytes.len());
    key[..n].copy_from_slice(&bytes[..n]);
    key
}

fn legacy_cipher(bytes: &mut [u8], password: &str, encrypt: bool) -> Result<()> {
    let key = legacy_key(password);
    let invalid = |_| anyhow!("invalid AES key/IV length");
    macro_rules! run {
        ($aes:ty) => {
            if encrypt {
                cfb_mode::Encryptor::<$aes>::new_from_slices(&key, &LEGACY_IV)
                    .map_err(invalid)?
                    .encrypt(bytes)
            } else {
                cfb_mode::Decryptor::<$aes>::new_from_slices(&key, &LEGACY_IV)
                    .map_err(invalid)?
                    .decrypt(bytes)
            }
        };
    }
    match key.len() {
        16 => run!(aes::Aes128),
        24 => run!(aes::Aes192),
        32 => run!(aes::Aes256),
        _ => unreachable!(),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &[u8] = b"mode: rule\nrules: [MATCH,DIRECT]\n";
    const FAST: Kdf = Kdf {
        m_cost: MIN_M_COST,
        t_cost: 1,
        lanes: 1,
    };

    #[test]
    fn legacy_password_lengths_and_invalid_input() {
        for n in [0, 12, 16, 20, 24, 30, 32, 36] {
            let password = "a".repeat(n);
            let encoded = encrypt_legacy(YAML, &password).unwrap();
            assert_eq!(format(encoded.as_bytes()).unwrap(), Format::Legacy);
            assert_eq!(&**decrypt(encoded.as_bytes(), &password).unwrap(), YAML);
        }
        assert!(decrypt(b"!!!", "test").is_err());
    }

    #[test]
    fn v2_round_trips_with_default_cost() {
        let encoded = encrypt(YAML, "correct horse").unwrap();
        assert_eq!(format(encoded.as_bytes()).unwrap(), Format::V2);
        assert_eq!(
            &**decrypt(encoded.as_bytes(), "correct horse").unwrap(),
            YAML
        );
        let again = encrypt(YAML, "correct horse").unwrap();
        assert_ne!(encoded, again, "salt and nonce must be random");
    }

    #[test]
    fn v2_rejects_wrong_password_and_tampering() {
        let encoded = encrypt_with(YAML, "secret", FAST).unwrap();
        assert!(decrypt(encoded.as_bytes(), "Secret").is_err());
        let bytes = STANDARD.decode(&encoded).unwrap();
        for at in [8, 9, 17, 20, HEADER - 1, HEADER, bytes.len() - 1] {
            let mut modified = bytes.clone();
            modified[at] ^= 1;
            let modified = STANDARD.encode(modified);
            assert!(decrypt(modified.as_bytes(), "secret").is_err(), "byte {at}");
        }
        let truncated = STANDARD.encode(&bytes[..HEADER + TAG - 1]);
        assert!(decrypt(truncated.as_bytes(), "secret").is_err());
    }

    #[test]
    fn v2_rejects_unbounded_cost() {
        let bytes = STANDARD
            .decode(encrypt_with(YAML, "secret", FAST).unwrap())
            .unwrap();
        for (at, value) in [(9, MAX_M_COST + 1), (9, MIN_M_COST - 1), (13, 0), (13, 17)] {
            let mut modified = bytes.clone();
            modified[at..at + 4].copy_from_slice(&value.to_le_bytes());
            let error = decrypt(STANDARD.encode(modified).as_bytes(), "secret").unwrap_err();
            assert!(error.to_string().contains("parameters"), "{error}");
        }
    }

    #[test]
    fn v2_empty_plaintext_and_unicode_password() {
        let encoded = encrypt_with(b"", "密码🔑", FAST).unwrap();
        assert!(decrypt(encoded.as_bytes(), "密码🔑").unwrap().is_empty());
    }
}
