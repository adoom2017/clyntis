//! Fixed v2 ciphertext, so the format stays readable by later versions.
use clyntis_config::crypto::{Format, decrypt, format};

const PLAINTEXT: &[u8] = b"mixed-port: 7890\nmode: rule\nrules: ['MATCH,DIRECT']\n";
/// Argon2id m=8 MiB, t=1, p=1; password "test-password".
const CIPHERTEXT: &str = "Q0xZTlRJU0UBACAAAAEAAAABH2+xPpTlDWnwneIDDbYH/U88mN4SjPxzSKxskKxz0HerDX7u5PuHwVZmHqMSOXPmgMUK6wP6z3+8Ott0kVYSdtdqiE65RgZwP93yZOBcFH9pOSCP6dZJDSV2ClagKO9y72404ZuMdk75erMT";

#[test]
fn v2_golden_vector() {
    assert_eq!(format(CIPHERTEXT.as_bytes()).unwrap(), Format::V2);
    assert_eq!(
        &**decrypt(CIPHERTEXT.as_bytes(), "test-password").unwrap(),
        PLAINTEXT
    );
    assert!(decrypt(CIPHERTEXT.as_bytes(), "test-passwore").is_err());
}
