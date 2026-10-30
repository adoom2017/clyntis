# clyntis

clyntis is a Rust proxy core with a desktop CLI, a desktop app, an iOS app and a
versioned C API. It reads a focused subset of the Clash/mihomo configuration
format.

- **Inbound:** HTTP/CONNECT, SOCKS5 and mixed listeners, a DNS listener and a
  desktop TUN (Windows Wintun, macOS utun, Linux TUN).
- **Outbound:** DIRECT, REJECT, VLESS (TCP, WebSocket, gRPC; TLS, REALITY, XTLS
  Vision), Hysteria2 and Tailscale (a userspace node, no Tailscale app needed).
- **Routing and DNS:** rule/global/direct modes, select and url-test groups,
  GeoIP/GeoSite and rule providers, fake-IP and redir-host DNS, ad blocking and
  per-network hosts, DNS and rules.

Trojan entries are parsed but not implemented; unknown fields fail validation.
Every option, the Clyntis additions and their limits are described in
[CONFIGURATION.md](CONFIGURATION.md).

## Build

### Requirements

- Rust **1.93.1** (pinned in `rust-toolchain.toml`), a C/C++ compiler, CMake and
  Clang/libclang for the vendored BoringSSL build.
- Windows: an MSVC toolchain, NASM and LLVM/Clang with `libclang.dll` beside
  `clang.exe`; PowerShell 7 for the `.ps1` scripts.

### CLI and core

From the repository root:

```sh
cargo build -p clyntis --release --locked
cargo test --workspace --locked
```

The executable is `target/release/clyntis` (`clyntis.exe` on Windows). On
Windows, this helper checks the prerequisites and sets `LIBCLANG_PATH`:

```powershell
pwsh -File scripts/check-boringssl-toolchain.ps1 build -p clyntis --release --locked
```

### C library

```sh
cargo build -p clyntis-ffi --release --locked
```

The header is `crates/ffi/include/clyntis.h`. Mobile targets build with
`scripts/check-mobile.sh` (or `.ps1`) and the matching SDK/NDK.

### Apps

- Desktop (Windows/macOS, Tauri 2 + React): see [desktop/README.md](desktop/README.md).
- iOS/iPadOS (SwiftUI + Network Extension): see [ios/README.md](ios/README.md).

### Versions and packages

The product version is `desktop/package.json`; set it everywhere with
`bash scripts/set-version.sh 1.2.3` (CI runs it with `--check`). Release
archives, signing and notarization: [PACKAGING.md](PACKAGING.md).

## Usage

### Quick start

`examples/vless.yaml` uses placeholder server details. Copy it to a local
`config.yaml`, fill in your server, then validate and run:

```sh
cp examples/vless.yaml config.yaml
./target/release/clyntis -f config.yaml -t   # validate only
./target/release/clyntis -f config.yaml
```

The example opens a mixed HTTP/SOCKS port and a loopback controller:

```sh
curl -x http://127.0.0.1:7890 https://example.com/
curl http://127.0.0.1:9090/version
```

A controller on a non-loopback address requires a `secret`.

### Common options

| Option | Purpose |
| --- | --- |
| `-f <file>` | Configuration file (`-` for standard input); default `config.yaml` |
| `-d <dir>` | Configuration directory for resources and state; default `.` |
| `-t` | Validate the configuration and exit |
| `--test-resources` | Load and validate GeoIP/GeoSite and rule providers |
| `--no-tun` | Run without TUN even if the configuration enables it |
| `--recover-tun` | Restore routes and DNS after an interrupted TUN session |
| `--test-egress` | macOS: probe physical exits without starting TUN |
| `--auto-dns` | macOS: point system DNS at the core for this run |
| `--ext-ctl`, `--secret` | Override the controller address and secret |
| `--action encrypt\|decrypt` | Legacy AES-CFB configuration encryption (`-p`, `-o`) |

Run `clyntis --help` for the full list.

### TUN

TUN is off unless the configuration sets `tun.enable: true`. It changes system
routes, so it needs administrator/root privileges; Windows also needs the
official `wintun.dll` beside `clyntis.exe`. If a session is interrupted, restore
routes with the same directory and privileges:

```sh
sudo ./target/release/clyntis -d /path/to/config-directory --recover-tun
```

### Logs

`log-level: debug` adds diagnostic events. With `log.log-path` set, logs go to
that file relative to `-d`; otherwise to the terminal.

### More

- Configuration reference (Hysteria2, Tailscale and `serve`, per-network
  settings, DNS, ad blocking, TUN details): [CONFIGURATION.md](CONFIGURATION.md)
- Publishing encrypted profiles to Tencent COS:
  [CONFIGURATION.md](CONFIGURATION.md#publishing-encrypted-profiles-to-tencent-cos)
