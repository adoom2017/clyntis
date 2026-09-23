//! Compatibility with Alpha common/utils/crypto.go. This legacy format has no
//! authentication tag: callers must validate decrypted configuration before use.
use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use zeroize::Zeroizing;

const IV: [u8; 16] = [
    35, 46, 57, 24, 85, 35, 25, 74, 87, 35, 88, 98, 66, 33, 14, 5,
];

fn key(password: &str) -> Zeroizing<Vec<u8>> {
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

pub fn encrypt(plaintext: &[u8], password: &str) -> Result<String> {
    let key = key(password);
    let mut bytes = plaintext.to_vec();
    match key.len() {
        16 => cfb_mode::Encryptor::<aes::Aes128>::new_from_slices(&key, &IV)
            .map_err(|_| anyhow::anyhow!("invalid AES key/IV length"))?
            .encrypt(&mut bytes),
        24 => cfb_mode::Encryptor::<aes::Aes192>::new_from_slices(&key, &IV)
            .map_err(|_| anyhow::anyhow!("invalid AES key/IV length"))?
            .encrypt(&mut bytes),
        32 => cfb_mode::Encryptor::<aes::Aes256>::new_from_slices(&key, &IV)
            .map_err(|_| anyhow::anyhow!("invalid AES key/IV length"))?
            .encrypt(&mut bytes),
        _ => unreachable!(),
    }
    Ok(STANDARD.encode(bytes))
}

pub fn decrypt(ciphertext: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>> {
    if ciphertext.len() > 24 * 1024 * 1024 {
        bail!("encrypted configuration exceeds size limit");
    }
    let key = key(password);
    let mut bytes = Zeroizing::new(STANDARD.decode(ciphertext)?);
    match key.len() {
        16 => cfb_mode::Decryptor::<aes::Aes128>::new_from_slices(&key, &IV)
            .map_err(|_| anyhow::anyhow!("invalid AES key/IV length"))?
            .decrypt(&mut bytes),
        24 => cfb_mode::Decryptor::<aes::Aes192>::new_from_slices(&key, &IV)
            .map_err(|_| anyhow::anyhow!("invalid AES key/IV length"))?
            .decrypt(&mut bytes),
        32 => cfb_mode::Decryptor::<aes::Aes256>::new_from_slices(&key, &IV)
            .map_err(|_| anyhow::anyhow!("invalid AES key/IV length"))?
            .decrypt(&mut bytes),
        _ => unreachable!(),
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_password_lengths_and_invalid_input() {
        for n in [0, 12, 16, 20, 24, 30, 32, 36] {
            let password = "a".repeat(n);
            let encoded = encrypt(b"mode: rule\nrules: [MATCH,DIRECT]\n", &password).unwrap();
            assert_eq!(
                &**decrypt(encoded.as_bytes(), &password).unwrap(),
                b"mode: rule\nrules: [MATCH,DIRECT]\n"
            );
        }
        assert!(decrypt(b"!!!", "test").is_err());
    }
}
