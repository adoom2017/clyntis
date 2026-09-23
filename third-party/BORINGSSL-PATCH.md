# Locally Maintained BoringSSL Patch

Base: crates.io `boring-sys` **5.2.0** and its bundled BoringSSL revision.

The vendored copy adds narrowly scoped client APIs required by the proxy core:

- `SSL_set1_extension_order` fixes the ClientHello extension-order prefix.
- `SSL_set1_tls13_cipher_order` fixes TLS 1.3 cipher ordering.
- `SSL_set1_delegated_credential_sigalgs` and `SSL_set_record_size_limit`
  reproduce the corresponding browser extensions.
- The post-PQ browser profile patch permits Firefox-compatible FFDHE group
  advertisement while keeping key shares on supported EC/PQ groups.
- `SSL_CTX_set_client_hello_cb` mutates ClientHello before it enters the TLS
  transcript.
- `SSL_handshake_get_x25519_private_key` exposes only the ephemeral X25519
  component used to derive REALITY authentication data and follows Xray's
  independent-X25519 preference when both shares are present.
- `SSL_set_allow_unadvertised_peer_sigalg` accepts REALITY's authenticated
  Ed25519 CertificateVerify without changing the browser profile's advertised
  signature algorithms.
- `SSL_set_reuse_x25519_key_share` makes classic and hybrid X25519 shares
  derive the same REALITY authentication key across Xray server versions.
- X25519 and X25519MLKEM key shares implement the private-component accessor.
- Android cross-builds let the NDK CMake toolchain select compilers and target
  flags to avoid a CMake cache reset that re-enables tests; `BUILD_TESTING=OFF`
  keeps benchmark executable probes off the host. Only `crypto` and `ssl` are built.

The Rust crate remains version-pinned to 5.2.0. Browser profile data lives in
`crates/protocol/src/tls.rs`; protocol implementations do not depend on BoringSSL
internals. Changes to this patch require rebuilding `boring-sys` and running the
workspace TLS, REALITY and Vision tests.
