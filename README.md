# clyntis

clyntis is a Rust proxy core with a desktop CLI and a versioned C host API. It
implements a focused subset of Clash-style configuration; it is not a drop-in
replacement for every protocol or configuration option.

## Features and limits

- **Inbound:** HTTP/CONNECT, SOCKS5 and mixed proxy listeners; optional DNS
  listener and desktop TUN. HTTP/SOCKS authentication is supported.
- **Outbound:** DIRECT, REJECT, VLESS and Tailscale. VLESS runs over TCP,
  WebSocket or gRPC, including TLS, REALITY, XTLS Vision and UDP/XUDP.
  BoringSSL is the TLS backend. Tailscale is described [below](#tailscale-outbound).
- **Routing:** rule/global/direct modes, select and url-test groups (a url-test
  group leaves a member as soon as it fails a round and re-tests right after a
  network change), domain/IP rules, GeoIP/GeoSite and rule providers. Custom rules can be prepended to any
  profile (see `meta_config::custom`); a rule whose target or rule provider the
  profile lacks is skipped with a reason instead of failing the profile.
  A route test shows which rule a domain, IP address or URL matches and the
  node it would leave through (each group's selection along the way), without
  connecting: `POST /rules/test` with `{"target": "example.com", "port": 443,
  "network": "tcp"}` (only `target` is required), `meta_test_route_v1` over the
  C ABI, and the apps' rules page. It also says when a rule resolved a proxied
  name locally (a DNS leak).
- **DNS leak detection:** a configuration review lists what leaks or exposes
  names: redir-host mode, IP rules without `no-resolve` ahead of a proxy (each
  rule listed), plaintext upstreams and system DNS that bypasses the TUN
  (`GET /dns/leak`). An online test (`POST /dns/leak/test`, about 30 s) asks
  bash.ws which resolvers looked up random names, along two paths: connecting
  like an app (through the rules) and through the core's own upstreams, beside
  the exit address. C ABI: `meta_dns_leak_v1`; the apps show both on the rules
  page. The online test sends random names to bash.ws and reveals the exit
  and resolver addresses to it.
- **Ad blocking** (`adblock` section, written by the apps' settings): domain
  lists in Clash rule-provider, hosts or AdGuard (`||domain^`, with `@@`
  exceptions) format are downloaded and refreshed like rule providers. Listed
  domains get NXDOMAIN from DNS and their connections are refused, ahead of
  every rule; an allowlist (plain domains cover subdomains) wins and can change
  while running (`PATCH /configs` with `adblock-allow`). Counters cover DNS and
  connection blocks, the most blocked domains and the latest blocks
  (`GET /adblock`; the FFI snapshot's `adblock`). Presets: AWAvenue-Ads,
  anti-AD and AdGuard DNS filter.
- **DNS:** UDP, TCP, DNS-over-TLS and DNS-over-HTTPS upstreams; fake-IP and
  redir-host modes. Real lookups also resolve Tailscale MagicDNS names; fake-IP
  answers keep the domain so domain rules still apply.
- **Status:** per-proxy status for the apps and the controller (`/proxies`
  carries a `status` object): VLESS server, transport and security; the last
  delay test with its error and time; open connections; and, for Tailscale, the
  login state, this node's name and addresses, the home DERP region, UDP
  candidates and each peer's online state and path (direct with RTT, or DERP).
- **Desktop and host integration:** Windows Wintun, macOS utun and Linux TUN;
  route recovery after an interrupted session; a reduced local controller with
  configuration, proxy selection, connections, traffic and logs; and a C ABI for
  embedding in mobile or other hosts.

Trojan and Hysteria2 entries can be parsed for configuration compatibility, but
their outbound protocols are **not implemented**: selecting one fails instead of
silently using another proxy. Unknown or unsupported configuration fields fail
validation. `--vless-only` keeps the implemented outbounds (VLESS and Tailscale),
removes the others and replaces dangling references with REJECT, not DIRECT.

### Tailscale outbound

A `type: tailscale` proxy runs a userspace Tailscale node written in Rust (no Go
`tsnet`): it joins a tailnet through the control server and carries TCP
connections to peers over WireGuard. Rules route to it like any proxy:

```yaml
proxies:
  - name: Tailscale
    type: tailscale
    auth-key: tskey-auth-...      # required for the first login
    hostname: my-mac              # optional; default clyntis-<os>
    ephemeral: false              # optional
    accept-routes: true           # optional: use peers' advertised subnet routes
    exit-node: us-exit            # optional: node name or 100.x address
    control-url: https://...      # optional: Headscale or another control server
    state-dir: tailscale/home     # optional: relative to the configuration directory
    dialer-proxy: Proxy           # optional: carry control and DERP through this proxy/group
rules:
  - IP-CIDR,100.64.0.0/10,Tailscale,no-resolve
  - DOMAIN-SUFFIX,ts.net,Tailscale
```

- Fields follow mihomo's; `exit-node-allow-lan-access` is accepted for
  compatibility and has no effect in a proxy. `dialer-proxy` is an addition.
- Control: the ts2021 Noise transport (HTTP upgrade, then HTTP/2) registers the
  node with the auth key and streams the network map. Machine and node keys
  persist in `state-dir` (default `tailscale/<proxy name>/state.json`, mode
  0600), so later starts do not log in again. `state-dir` must stay inside the
  configuration directory.
- Paths: disco pings and STUN (with Tailscale's required attributes) find direct
  UDP paths using LAN and public candidates and call-me-maybe hole punching; a
  path is trusted for 6.5 s after a pong and kept alive by 3 s heartbeats while
  in use. Without one, WireGuard is relayed through each peer's home DERP region.
  The home region is the fastest by TLS handshake. On the desktop the UDP socket
  is bound to the physical egress, outside the TUN.
- Destinations: peers' tailnet addresses, MagicDNS names (full or short), subnet
  routes with `accept-routes`, and anything else through `exit-node`.
- At home, reach a subnet directly; away, through the tailnet: put `DIRECT` and
  the Tailscale proxy in a `url-test` group whose `url` answers only on that LAN
  (pick a service unique to it; common subnets such as `192.168.2.0/24` exist on
  other networks too). DIRECT wins while the check answers; once it fails the
  group switches to Tailscale, and a network change re-tests within seconds.

  ```yaml
  proxy-groups:
    - {name: Home LAN, type: url-test, proxies: [DIRECT, Tailscale], url: 'http://192.168.2.50:9090/', interval: 30, tolerance: 20}
  rules:
    - IP-CIDR,192.168.2.0/24,Home LAN,no-resolve
  ```
- A network change rebinds the node's UDP socket, reconnects its DERP relays and
  rediscovers direct paths at once; WireGuard sessions continue.
- Limits: TCP only (UDP through Tailscale is not supported yet); login with an
  auth key only (an interactive login URL is logged but not awaited); node-key
  expiry is not renewed automatically; no peer relays, port mapping or
  Tailscale SSH/Funnel/Serve.

## Requirements

- Rust **1.93.1** (pinned in `rust-toolchain.toml`), a C/C++ compiler, CMake and
  Clang/libclang for the vendored BoringSSL build.
- On Windows, use an MSVC toolchain, NASM and LLVM/Clang with `libclang.dll`
  beside `clang.exe`. PowerShell 7 is required for the `.ps1` helper scripts.
- Desktop TUN requires administrator/root privileges. Windows TUN also requires
  the official `wintun.dll` beside `clyntis.exe`; the driver is not bundled.

## Build

The optional Windows/macOS desktop application lives in the independent
[`desktop/`](desktop/README.md) workspace. It uses Tauri 2 and React, with
profile/subscription management, system proxy and TUN integration. See its
README for development, privileged helper installation and desktop packaging.

The native iOS/iPadOS client lives in [`ios/`](ios/README.md). It uses SwiftUI and
a Network Extension packet tunnel with the Rust C API. See its README for
Apple Silicon builds, simulator checks, device signing and current limitations.

Both apps share the core's merge logic for two layers over the selected
profile: custom rules, matched before the profile's own, and settings that
override the profile (log level, IPv6 and domain sniffing; unset values follow
the profile). Both show the per-node status described above, with delay tests
for VLESS nodes. The commands below continue to build and test the CLI/core
workspace only.

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

TCP relays, including TUN sessions, allow long periods without application data
(for example while waiting for the next SSE event). They do not impose a fixed
five-minute application-idle cutoff. TCP keepalive and transport errors detect
dead peers; explicit connection closure, shutdown and network changes still end
sessions. Upstream servers and intermediate proxies may impose their own limits.

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
`tun.auto-detect-interface` to keep probing exits every 15 seconds while running.
Exits are ranked by internet reachability, then proxies reached, then a wired
link over Wi-Fi; the current exit is kept unless another ranks higher, so one
lost probe does not switch interfaces. An exit change updates routes and socket
bindings, closes old sessions, and rebinds automatic DNS when the local IPv4
address changes; a brief loss of the IPv4 exit (sleep, Wi-Fi roaming) keeps the
TUN running and retries DNS until the network returns. Use `tun.interface` to
select an interface explicitly. With `ipv6: true`, IPv6 is captured only while a
physical interface has an IPv6 exit, so apps do not dial IPv6 the core cannot
reach. `tun.auto-dns` defaults to `false` in the core, preserving the system's
existing DNS services; the desktop app turns it on in TUN mode unless disabled
in its settings. Literal public DNS upstreams
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
`crates/ffi/include/clyntis.h`. Besides creating, starting and driving a core
(`meta_create_v1`, `meta_create_packet_tunnel_v1`, `meta_snapshot_v1`,
`meta_select_v1`, `meta_probe_v1`, packet I/O), the C API validates and merges
custom rules (`meta_custom_rule_*`, `meta_custom_rules_apply_v1`), applies app
settings (`meta_overrides_apply_v1`), checks and prefetches routing resources
(`meta_resources_state_v1`, `meta_prefetch_resources_v1`) and drains logs
(`meta_drain_logs_v1`); every function documents its buffer contract in the
header. For a separate host-library build, use
`cargo build -p meta-ffi --release --locked`; mobile target builds use the
`scripts/check-mobile.sh` or `scripts/check-mobile.ps1` helpers with the relevant
SDK/NDK installed.
