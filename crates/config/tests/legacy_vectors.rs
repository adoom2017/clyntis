//! Generated with Go crypto/aes + crypto/cipher using Alpha's key/IV rules.
use meta_config::crypto::{decrypt, encrypt};

#[test]
fn alpha_cfb128_golden_vectors() {
    let plaintext = b"mixed-port: 7890\nmode: rule\nrules: ['MATCH,DIRECT']\n";
    for (password, ciphertext) in [
        (
            "",
            "ViJ/IIe2MxHERUCB+Y3D6LG7QfR4qJKMmYLw2MnQIe8guD1ZRc7AGlsSIYh175tmbhQECg==",
        ),
        (
            "test-password",
            "fzpHye22WU1hKPevr2RwfVJhLri0X0NMDQS3D4iMfGPUsXSwpivnmPeok4ej8i4i8P8bgw==",
        ),
        (
            "aaaaaaaaaaaaaaaa",
            "2BmzUr9JYnUNWFn3mitJ2HSZNzISsrXSjEDhEL+Ss3oebDh+WOGspcblf1FTd5KPNGD4hQ==",
        ),
        (
            "bbbbbbbbbbbbbbbbb",
            "bEbBdB8Ng7VNZPzjZFnY6pMOy09RdHziNlqJqvHmGhZWpARpevFMiIAcPAfq5AxPfnBy1A==",
        ),
        (
            "cccccccccccccccccccccccc",
            "PjQDBsNhXFjLn9N/WsI4hYo2tHoQj2uG8KGCsx5ybvEerrV8Y8XgbGhx/B61PMvn8C+HnQ==",
        ),
        (
            "ddddddddddddddddddddddddd",
            "gH05n62ZBiK8cZB4iqu1YFBDWSHl/CMF1VrGMJ3uCGWSjfgIycnc1fvIEOPqCdPwAqfdtw==",
        ),
        (
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "MjeKhCDjQyuNariKQ9YMx5uG5CynBsH0C9i19+aow2s4gCTyQBMVqdy4q9I7WlKKAUjYNw==",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffff",
            "MKq/UjW3EKOHtwXYRrDrFWsZbIUr6rYhLmnVk0pkhcShuLKRtNbQm4BR3KeWcCq9P4BShA==",
        ),
        (
            "\u{5bc6}\u{7801}\u{6d4b}\u{8bd5}",
            "e4CyqWXnM5kvT1vEyi2o+QnIUY8w2q6JXZSweV5bfQ6m23IIuYeuiD1T7gz8VkTNSDvv4A==",
        ),
    ] {
        assert_eq!(encrypt(plaintext, password).unwrap(), ciphertext);
        assert_eq!(
            &**decrypt(ciphertext.as_bytes(), password).unwrap(),
            plaintext
        );
    }
}
