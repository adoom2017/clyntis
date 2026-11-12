# Platform Runtime and Host ABI

## Packet Processing

`Core::start_with_packets` accepts a host `PacketIo` when `tun.enable` is true.
Packets are raw IPv4/IPv6 without a Darwin family prefix. smoltcp 0.12.0 owns TCP
state, checksums, retransmission and IPv4 reassembly. Repository code bridges TCP
and UDP to normal fake-IP restoration, rules, groups, protocols and statistics.
TCP and UDP DNS hijack goes directly to the configured resolver.

Limits: 512 TCP flows, 512 UDP flows, 256 UDP destination sockets, 256 packets per
device queue, 32 KiB per TCP stack buffer, four 8 KiB chunks per TCP direction,
16 datagrams per UDP flow, 30-second incomplete TCP handshake limit, 300-second
TCP idle limit and 120-second UDP idle limit. IPv4 fragment/reassembly buffers
are 65,536 bytes. The IPv6 adapter uses smoltcp wire parsers and its range assembler
for 64 concurrent reassemblies, a 65,535-byte packet limit and 30-second expiry
(approximately 4 MiB total). Overlapping fragments invalidate the whole datagram;
atomic fragments remain independent. Generated oversized IPv6 UDP replies are
fragmented to the configured MTU. IPv6 extension chains are bounded to eight.
Oversized generated UDP replies are dropped without terminating packet delivery;
a regression sends a 65,500-byte IPv6 UDP reply followed by a normal reply.

## Desktop

Windows uses tun-rs/Wintun, macOS tun-rs/utun and Linux the system TUN device.
TUN requires administrator/root privileges. Windows requires the separately
licensed official `wintun.dll` beside the executable. macOS chooses an available
utun device when the default device name is used; explicit names must be `utunN`.

```yaml
tun:
  enable: true
  auto-route: true
  auto-dns: false
  auto-detect-interface: true
  mtu: 1500
  dns-hijack: [any:53]
  route-exclude-address: [192.168.0.0/16]
```

Physical egress discovery ignores TUN/loopback interfaces. Set `tun.interface`
to an OS name, Windows friendly name or index when automatic discovery cannot
select the desired device. IPv4/IPv6 outbound sockets bind their physical
interface before connecting, including proxy-server and DNS sockets. Loopback
destinations stay local. Missing physical egress fails instead of entering TUN.

Automatic routing always bypasses the selected physical interface's directly
connected prefixes. It also bypasses IPv4 link-local (`169.254.0.0/16`),
multicast (`224.0.0.0/4`) and limited broadcast (`255.255.255.255/32`), plus
IPv6 link-local (`fe80::/10`) and multicast (`ff00::/8`). These routes stay in
the operating-system data path and never enter the userspace TUN forwarder.
`route-exclude-address` adds deployment-specific exclusions to this built-in
set.

Automatic routing adds split default routes. On non-macOS systems it also adds
routes for known system DNS addresses; DNS packets are handled by the packet
adapter. On macOS with
`tun.auto-dns`, auto-route and `dns.enable`, Clyntis instead routes
`198.19.255.254:53` through its TUN DNS handler and changes only the selected
physical network service's DNS to that address via `networksetup`. macOS defaults
to preserving its existing DNS services and does not add DNS host routes.
Local loopback stub resolvers
and other VPN software still need deployment-specific tests.
The three-second network check refreshes physical exits and exclusions, clears
DNS caches and closes existing proxy sessions for reconnect.

A locked journal in the `-d` directory records route intent before changes and
is flushed to storage. Startup failure and ordinary shutdown remove owned routes.
Interrupted sessions retain `clyntis-tun-state.json` and, on macOS when
auto-DNS is active, `clyntis-dns-state.json`; recover them with:

```powershell
clyntis -d PATH --recover-tun
```

Recovery checks interface identity so a reused OS index does not target a new
adapter. Use the same directory and elevated privileges. Corrupt journals report
errors rather than executing arbitrary recovery actions.
Before upgrading from an older binary after an interrupted TUN session, run
that binary's recovery command first; the renamed journal has a different filename.

## Mobile and C Hosts

`crates/ffi/include/clyntis.h` defines ABI v1. Each checked integer handle owns
an independent runtime; IDs are never reused. Creation validates YAML, start is
one-shot, and stop/destroy join workers and callbacks. No Rust allocation crosses
the ABI: inputs are copied and outputs use caller buffers. Size queries return
`META_BUFFER_TOO_SMALL`; too-small packet reads retain the queued packet.
Errors are thread-local UTF-8 text from `meta_error_v1`.

iOS hosts feed NetworkExtension packets through the bounded read/write functions
and receive packet-ready notifications. Android hosts must supply socket protect;
they may use the same packet queue or call `meta_set_tun_fd_v1` before start.
The fd is duplicated; the host retains the original. Packet queue calls return an
explicit error after fd mode is selected. Hosts manage VPN permission,
routes, DNS and application lifecycle. `meta_network_changed_v1` invalidates
connections and DNS cache after a host network change. Callbacks must return
promptly and may not reenter lifecycle functions; their context must remain valid
until stop/destroy returns.

The native SwiftUI iOS app and packet-tunnel extension now live in
[`ios/`](../ios/README.md). `meta_create_packet_tunnel_v1` is an additive ABI v1
entry point: it preserves credentials/routing policy, accepts a host resource
directory, enables raw packet I/O with MTU 1280 and port-53 interception, and
disables desktop listeners and native route/DNS/interface changes. The source
YAML is retained by the app. Snapshots include live group `selections` alongside
configuration, connections, traffic and stopped state.

## Verification Record

2026-10-04, Apple Silicon / Xcode 27 / Rust 1.93.1:

- `bash scripts/build-ios.sh`: locked offline debug FFI builds passed for
  `aarch64-apple-ios` and `aarch64-apple-ios-sim`; arm64 XCFramework generated.
- Unsigned `Clyntis` app and `ClyntisTunnel` extension builds passed for device
  and simulator. iPhone 18 Pro / iOS 27 simulator launched the connection UI
  and displayed the shared app icon.
- Simulator XCTest: four passed, covering credential-preserving storage,
  failed-import cleanup, unsupported protocol rejection and real Swift/C/Rust
  listener overrides, routing mode and live node selection.
- `cargo test -p meta-config -p meta-core -p meta-ffi --locked --offline`:
  42 passed, one ignored. Workspace `cargo check` passed.
- This does **not** verify a provisioned device VPN, server reachability,
  provider socket egress, device memory limits, battery usage or distribution.
  Follow the device acceptance checklist in `ios/README.md`.

2026-09-13: `scripts/test-desktop-linux.py` runs the CLI in a fresh root Linux
network namespace with two explicitly selected virtual uplinks and a separate
upstream namespace. It verifies automatic IPv4/IPv6 split routes, IPv4 DNS
hijack/fake-IP, TCP and fragmented UDP, replacement of the selected interface,
exclusion refresh, SIGTERM restoration and SIGKILL recovery. All 121 unrelated
routes survive; the table forces multipart netlink enumeration. Run with:

```sh
sudo unshare --net --fork python3 scripts/test-desktop-linux.py /absolute/path/to/clyntis
```

The extended scenario additionally verifies IPv6 fake-IP, TCP and fragmented
UDP through both selected uplinks, including replacement. An independently open
second TUN owns overlapping IPv4/IPv6 routes and routes with the same metric as
clyntis; all four remain unchanged during operation, replacement and recovery.
The IPv6 fake-IP test uses an IPv6-only DNS name to require actual IPv6 egress.

This does not verify automatic physical-device discovery, system resolver
integration, third-party VPN applications, or Windows/macOS runtime behavior.

2026-09-12/13, Windows x64 and Ubuntu 22.04 WSL:

- Simulated IP devices: 128 KiB TCP round trips and half-close on IPv4/IPv6;
  4,000-byte fragmented IPv4/IPv6 UDP; DNS/fake-IP hijack. IPv6 regression covers
  out-of-order data, wire headers, overlaps, expiry, truncation and queue limits.
- A real Linux TUN test routed isolated `198.19.254.253/32` and
  `fdfe:dcba:9877::fd/128` through VLESS TCP and 4,000-byte UDP, and verified route
  removal. The original IPv4 case caught a partially-read
  VLESS UDP cancellation issue; a deterministic regression now covers the fix.
- Route fault injection verifies recovery after partial initialization, journal
  persistence, exclusive ownership and preservation of unrelated routes.
- Simulated C host tests cover live ICMP packets, buffer retries, notification
  reentry rejection, no callbacks after stop and independent checked handles.
- Android arm64 builds release static and dynamic FFI libraries with Rust 1.93.1, NDK
  27.0.12077973 and API 24. On macOS/Linux, `scripts/check-mobile.sh` reproduces
  the build; Windows uses `scripts/check-mobile.ps1`.
- iOS build attempted on Windows but blocked at ring's C compilation: Xcode
  `xcrun` and iPhoneOS SDK are unavailable. Run the iOS script on a Mac with Xcode.

Windows native TUN is not runtime-verified: the current process lacks administrator
privileges and no Wintun DLL is installed. macOS device/routing/network-switch
acceptance is also unverified. The Linux test is not Windows/macOS acceptance;
Android compilation is not mobile runtime acceptance. See `rust-progress.md`.
