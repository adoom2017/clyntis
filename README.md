# clyntis

Rust proxy core, CLI, desktop TUN adapter and versioned C host API. This branch
replaces the Go product; the previous implementation remains on `Alpha` and in
Git history.

Protocol code is maintained here for VLESS TCP, WebSocket and gRPC, with TLS,
REALITY, XTLS Vision and UDP/XUDP. BoringSSL is the only TLS backend. Trojan and
Hysteria2 entries remain parseable for configuration/group compatibility, but
selecting either protocol returns an explicit unavailable-protocol error.

## Build and Run

Install Rust 1.93.1 with the platform C/C++ compiler. BoringSSL additionally
requires CMake, NASM and LLVM/libclang on Windows; the vendored build discovers
`libclang.dll` beside `clang.exe`. The checked-in toolchain and Cargo.lock pin the
build.

```sh
cargo build --release --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
./target/release/clyntis -f examples/vless.yaml -t
./target/release/clyntis -f examples/vless.yaml
```

Use `target/release/clyntis.exe` on Windows. Set actual server credentials in a
configuration based on [examples/vless.yaml](examples/vless.yaml). No production
server is bundled.

HTTP/CONNECT, SOCKS5 and mixed listeners share rules, select/url-test groups,
DNS/fake-IP and traffic accounting. The reduced controller defaults to loopback;
remote binds require a Bearer secret. Unknown or unsupported fields report a
configuration error. Complete configuration replacement requires a new core;
mode, rules and group selection support online updates.

## Legacy Configuration

`-f`, `-d`, `-t`, `-v`, `-p` and `--action encrypt/decrypt` remain available.
AES-CFB128/Base64 files use the previous byte-length key padding and fixed IV.
This legacy format has no authentication tag; decrypted YAML is validated before
use. Invalid Base64, invalid decrypted configuration and output overwrites fail.

```sh
clyntis -f config.yaml --action encrypt
clyntis -f config-encrypt.yaml -p PASSWORD
clyntis -f config-encrypt.yaml --action decrypt
```

Interactive encryption/decryption prompts for the password when omitted.
Noninteractive callers supply `-p`. Logs support level overrides, bounded file
rotation and controller events without exposing configured credentials.

## Platform and Delivery

Windows maintenance scripts use PowerShell 7 (`.ps1`). On macOS and Linux, run
the corresponding Bash scripts (`.sh`) for packaging, mobile builds, offline
snapshots and interoperability tests. `scripts/prepare-offline.*` creates an
offline source archive, and `scripts/package-release.*` builds a local release
package with the CLI, host libraries, header and license notices. See
[third-party patches](third-party/README.md) for vendored changes.

TUN must be explicitly enabled; desktop use requires root/administrator rights
and Windows additionally needs official `wintun.dll`. An interrupted session can
be restored with `clyntis -d CONFIG_DIRECTORY --recover-tun`.

Windows/macOS native TUN and iOS compilation still require their stated host
prerequisites. Linux native TUN and Android arm64 compilation have separate test
records; they do not substitute for Windows/macOS or mobile runtime acceptance.
Nothing is automatically pushed or published by local build/package scripts.
