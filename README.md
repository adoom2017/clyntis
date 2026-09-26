# clyntis

clyntis is a Rust proxy core with a desktop CLI and a versioned C host API. It
implements a focused subset of Clash-style configuration; it is not a drop-in
replacement for every protocol or configuration option.

## Features and limits

- **Inbound:** HTTP/CONNECT, SOCKS5 and mixed proxy listeners; optional DNS
  listener and desktop TUN. HTTP/SOCKS authentication is supported.
- **Outbound:** DIRECT, REJECT and VLESS over TCP, WebSocket or gRPC, including
  TLS, REALITY, XTLS Vision and UDP/XUDP. BoringSSL is the TLS backend.
- **Routing:** rule/global/direct modes, select and url-test groups, domain/IP
  rules, GeoIP/GeoSite and rule providers.
- **DNS:** UDP, TCP, DNS-over-TLS and DNS-over-HTTPS upstreams; fake-IP and
  redir-host modes.
- **Desktop and host integration:** Windows Wintun, macOS utun and Linux TUN;
  route recovery after an interrupted session; a reduced local controller with
  configuration, proxy selection, connections, traffic and logs; and a C ABI for
  embedding in mobile or other hosts.

Trojan and Hysteria2 entries can be parsed for configuration compatibility, but
their outbound protocols are **not implemented**: selecting one fails instead of
silently using another proxy. Unknown or unsupported configuration fields fail
validation. `--vless-only` removes unavailable outbounds and replaces dangling
references with REJECT, not DIRECT.

## Requirements

- Rust **1.93.1** (pinned in `rust-toolchain.toml`), a C/C++ compiler, CMake and
  Clang/libclang for the vendored BoringSSL build.
- On Windows, use an MSVC toolchain, NASM and LLVM/Clang with `libclang.dll`
  beside `clang.exe`. PowerShell 7 is required for the `.ps1` helper scripts.
- Desktop TUN requires administrator/root privileges. Windows TUN also requires
  the official `wintun.dll` beside `clyntis.exe`; the driver is not bundled.

## Build

From the repository root:

```sh
cargo build -p clyntis --release --locked
cargo test --workspace --locked
```

The executable is `target/release/clyntis` on macOS/Linux or
`target/release/clyntis.exe` on Windows. On Windows, the toolchain helper checks
the native prerequisites and sets `LIBCLANG_PATH` for the build:

```powershell
pwsh -File scripts/check-boringssl-toolchain.ps1 build -p clyntis --release --locked
```

The pinned `Cargo.lock` is used by these commands. Optional external protocol
oracles and privileged TUN tests need their own environment and are not part of
the basic run path.

## Quick start

The included VLESS example uses **placeholder** server details. Copy it to a
local, ignored `config.yaml` and replace the server address, UUID, TLS server
name and other fields with your own values before connecting:

```sh
cp examples/vless.yaml config.yaml
./target/release/clyntis -f config.yaml -t
./target/release/clyntis -f config.yaml
```

On Windows, use `Copy-Item examples/vless.yaml config.yaml` and
`.\target\release\clyntis.exe` in place of the Unix commands. `-t` validates
the configuration and exits without opening listeners; it does not test the
remote server. The example opens a local mixed HTTP/SOCKS port at `127.0.0.1:7890`.
Once a real server is configured, a separate terminal can use it with:

```sh
curl -x http://127.0.0.1:7890 https://example.com/
```

The example also enables a loopback controller at `127.0.0.1:9090`; check it
with `curl http://127.0.0.1:9090/version`. Binding the controller to a non-loopback
address requires a configured Bearer secret.

By default clyntis reads `config.yaml` from the current directory. Use `-f`
to choose a file (or `-f -` for standard input), and `-d` to set the configuration
directory. For example:

```sh
./target/release/clyntis -d /path/to/config-directory
./target/release/clyntis -f config.yaml --test-resources
```

`--test-resources` loads and validates routing resources such as GeoIP/GeoSite
and rule providers; unlike `-t`, this may need access to their configured sources.
Run `clyntis --help` for all CLI options.

`log-level: debug` enables diagnostic events. If `log.log-path` is set, logs
go to that file relative to `-d`; the startup message prints the effective
level and full destination. Remove `log.log-path` to write logs to the terminal.
The top-level `log-level` takes precedence when both locations specify a level.

### TUN and recovery

TUN is disabled unless `tun.enable: true` is set in the configuration. It
changes system routes, so run it only on a machine where you have administrator
or root access. On macOS the capture routes use the nonzero subranges used by
sing-tun's Darwin `BuildAutoRouteRanges` (IPv4 starts at `1.0.0.0/8`, IPv6 at
`100::/8`). Zero-address `/1` routes are avoided because XNU treats their
destination as a default-route key, which can break interface-bound egress.
Use `--no-tun` to run the proxy listeners without TUN even when
the configuration enables it. On macOS, `tun.auto-detect-interface` probes
physical exits against `example.com:443` and configured proxy endpoints before
and after installing routes, including when there is only one candidate,
and reopens the TUN on a different exit when
needed. Use `--test-egress` to run only the probe without TUN, or set
`tun.auto-detect-interface` to keep probing exits every 15 seconds while running;
an exit change updates routes and socket bindings, closes old sessions, and
rebinds automatic DNS when the local IPv4 address changes. Use
`tun.interface` to select an interface explicitly. `tun.auto-dns` defaults to `false`,
preserving the system's existing DNS services. Literal public DNS upstreams
receive physical host routes so the proxy's own DNS queries avoid the TUN.
Setting `tun.auto-dns: true` when TUN, auto-route and the DNS listener are
enabled, or passing `--auto-dns` on macOS for a single run, listens on port 53
of the selected physical interface's own IPv4 address and temporarily sets that
network service's DNS to the same address. Enabled physical services with IPv4
addresses are also covered because macOS's default DNS service can differ from
the proxy's selected egress. Each service's original DNS is journaled and restored
independently. Only local host requests are answered on this additional listener.
VPN services, including Tailscale's scoped DNS, are not changed. This does not edit
`/etc/resolv.conf` directly. A VPN or Network Extension with its own default
resolver can still take precedence over the physical service's DNS. If a TUN
session is interrupted, restore its routes and macOS DNS with the same
configuration directory and privileges:

```sh
./target/release/clyntis -d /path/to/config-directory --recover-tun
```

On Windows, run the corresponding `.exe` in an elevated shell. Before upgrading
from an older binary after an interrupted session, recover with that binary
first because the journal filename changed with the project name.

### Legacy configuration encryption

The CLI retains the previous AES-CFB128/Base64 configuration format:

```sh
clyntis -f config.yaml --action encrypt
clyntis -f config-encrypt.yaml --action decrypt
```

The password is prompted when omitted; `-p` supplies it non-interactively.
Outputs are written to `config-encrypt.yaml` or `config-decrypt.yaml` by default
and never overwrite existing files. This legacy format is **not authenticated**;
do not treat it as a modern secret-storage format.

## Packages and embedding

After fetching locked dependencies, the local packaging scripts build offline
and write a release archive under the ignored `dist/` directory:

```sh
cargo fetch --locked
bash scripts/package-release.sh
```

On macOS, the script signs the executable and dylib with the sole available
Developer ID Application identity (hardened runtime and secure timestamp) before
generating the manifest and archive. If several identities are installed, select
one explicitly with `CLYNTIS_CODESIGN_IDENTITY` (SHA-1 fingerprint or full
identity name), for example:

```sh
CLYNTIS_CODESIGN_IDENTITY='Developer ID Application: Your Name (TEAMID)' bash scripts/package-release.sh
```

With no Developer ID identity, the package remains unsigned (as on CI); set
`CLYNTIS_CODESIGN=off` to opt out locally. Signing requires timestamp-service
access. To notarize, first store a `notarytool` keychain profile using your
Apple ID, app-specific password, and the **same team** as the signing identity
(or use an App Store Connect API key):

```sh
xcrun notarytool store-credentials clyntis-notary --apple-id 'you@example.com' --team-id YOURTEAMID
CLYNTIS_CODESIGN_IDENTITY='Developer ID Application: Your Name (TEAMID)' \
  CLYNTIS_NOTARY_PROFILE=clyntis-notary bash scripts/package-release.sh
```

When `CLYNTIS_NOTARY_PROFILE` is set, the script submits a signed DMG with
`notarytool --wait`, requires an Accepted result, then staples and validates its
ticket. The resulting `.dmg` and `.tar.gz` each have a `.sha256` sidecar. Use the
DMG for offline-verifiable distribution; tickets cannot be stapled to a tarball
or standalone CLI. Notarization needs network access and is opt-in so CI and
local offline builds remain unchanged. Do not put passwords or API keys in the
repository.

On Windows, run `cargo fetch --locked` followed by
`pwsh -File scripts/package-release.ps1`. These scripts do not publish artifacts.
The package contains the CLI, examples, licenses, C libraries and
`crates/ffi/include/clyntis.h`. For a separate host-library build, use
`cargo build -p meta-ffi --release --locked`; mobile target builds use the
`scripts/check-mobile.sh` or `scripts/check-mobile.ps1` helpers with the relevant
SDK/NDK installed.
