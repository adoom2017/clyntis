# Rust Rewrite Progress

> Mobile update, 2026-10-04: the user expanded scope to native iOS application
> integration. SwiftUI app and packet-tunnel extension are now in
> [ios/README.md](../ios/README.md). Arm64 device/simulator core and unsigned app
> builds passed; four simulator tests passed. Signed device VPN acceptance is
> still outstanding. The original rewrite scope and earlier host availability
> below describe their historical checkpoints; see `platform-runtime.md` for
> current iOS verification evidence.

This records the user-approved plan and remaining work so later sessions can
continue from repository state. Work is on `clyntis`; do not modify `Alpha` or
push/publish automatically. Prioritize VLESS before completing the remaining plan.

Historical work ledger: [continuation.md](continuation.md). It records each
completed item and the evidence available at the time.

Baseline checkpoint: [handoff.md](handoff.md), 2026-09-13. It records exact commits,
artifacts and interrupted final verification steps. The continuation ledger now
records Windows/Linux offline delivery including the route-metric, HY2 network
cancellation, complete Linux route enumeration and outbound DNS fixes. Linux
namespace desktop acceptance passed; Windows/macOS runtime and Apple builds
still require the missing host prerequisites.

## Scope and Boundaries

Deliver the Rust core, CLI, reduced Clash API, Windows Wintun and macOS utun;
retain Linux support. Mobile scope is host interfaces and iOS/Android arm64 build
verification, not application integration or runtime acceptance.

Runtime protocols: VLESS TCP/WebSocket/gRPC, TLS, REALITY, Vision and XUDP.
Trojan and Hysteria2 remain parse/group-compatible and return an unavailable
protocol error when selected. Local entrances: HTTP/CONNECT, SOCKS5, mixed and
TUN. Include rules, select/url-test groups,
DNS/fake-IP, legacy encrypted configuration and rotating logs.

No servers, HY1, XHTTP, subscription providers or GUI.
No external proxy cores in production, directly or indirectly. Generic libraries
are allowed; protocol implementations and minimal TLS patches are locally owned.
Pin the toolchain, lock dependencies, archive source snapshots and verify a clean
offline build for release. Preserve source provenance and third-party licenses.

## Current Milestone: VLESS

- [x] VLESS request encoding, lazy response parsing, TCP/TLS and UDP framing.
- [x] XUDP encoding, bounded parser, cancellation handling and core integration.
- [x] Vision padding, fragmented TLS recognition and independent direct switches.
- [x] REALITY session/certificate authentication and local BoringSSL hooks.
- [x] Local byte-boundary, malformed input, large duplex transfer and TLS tests.
- [x] Core integration tests for SOCKS5/HTTP CONNECT, fake-IP and UDP selection.
- [x] Runnable CLI, configuration example and protocol/patch documentation.
- [x] Fixed-version Xray test fixtures for the main VLESS matrix.
- [x] Execute official Xray v25.9.11 interoperability matrix and resolve failures.
- [x] Expand negative oracle cases, reconnection coverage and protocol fuzzing.
- [x] Finish this VLESS milestone and record it in a local commit.

Verified on Windows x64 on 2026-09-12 against checksum-pinned official Xray
v25.9.11. All 36 workspace tests pass, including both external oracle suites.
Coverage includes authentication failures, server restart, ordinary UDP/XUDP and
TLS/REALITY/Vision. SOCKS UDP removes closed outbound sessions so the next packet
can reconnect. Three ASan/libFuzzer targets ran 20,669,305 inputs in WSL without a
protocol crash. See `vless-protocol.md` for commands, limits and exact coverage.

## Offline Source Milestone

- [x] Locked registry source archive, dependency/license inventory and file hashes.
- [x] Extracted archive builds with empty Cargo cache and target directories on
  Windows x64 and Linux x64 (Ubuntu 22.04 WSL), Rust 1.93.1.
- [x] Offline executable version/configuration checks on both hosts; Linux local
  workspace tests: 34 passed, 2 official-oracle tests intentionally ignored.
- [x] Changed source file rejected by checksum verification before compilation.

`scripts/prepare-offline.ps1` (Windows) or `scripts/prepare-offline.sh`
(macOS/Linux) creates the portable source archive; verification
commands and the exact tested archive hash are in `docs/offline-build.md`.
OS compiler/linker and Rust toolchain prerequisites are not bundled. The fuzz
workspace uses a separate toolchain/lockfile and is not part of this archive.

## Core, HY2 and Platform Milestones

The earlier HY2 runtime milestone is retained as history. Its runtime, QUIC
foundation and fuzz target were removed by the VLESS-only BoringSSL migration;
see `hysteria2-protocol.md` for the current parse-only behavior.

Core runtime update: TCP and UDP now expose live byte counters, bounded tracked
connections and cancellation cleanup. HTTP forwarding uses the same relay path.
HY2 connection setup locks are per node. Routing/DNS waits are included in dial
timeouts and core cancellation. Controller mode/rule updates validate atomically,
configuration reads reflect current policy and omit local authentication. WebSocket
sends are bounded and respond to pings. DNS caches complete positive/negative
responses (including SOA, flags and remaining TTL), with 4,096 entries / 8 MiB
limits; DoH uses Hyper with bounded bodies. Fake-IP exhaustion returns SERVFAIL
without overflowing or reusing live mappings. Eight core tests and strict
workspace Clippy pass on Windows. Full desktop/FFI acceptance remains below.

TUN and ABI v1 now have implementations: smoltcp session adaptation, tun-rs native
devices, physical egress binding, split routes, recovery journal and network
refresh; bounded host packet queues, Android fd duplication/protect callbacks and
checked lifecycle handles. Simulated TCP/UDP/IPv4/IPv6, DNS, C host and route
rollback tests pass. Real Linux TUN TCP/UDP and route cleanup pass. Android arm64
static/dynamic libraries build. Windows lacks administrator privileges/Wintun;
macOS/iOS require a Mac/Xcode. These runtime/build checks remain unfulfilled.
See `platform-runtime.md` for exact tests, commands and remaining limitations.

## Engineering Replacement and Delivery

- Synthetic Alpha AES-CFB golden vectors cover nine password boundaries; no Go
  compiler is required for compatibility tests. Go product sources and old build/
  release flows are removed. Rust desktop/mobile CI replaces the old workflows.
- IPv6 HTTP forwarding, probes and DoH share strict authority parsing; HTTP
  integration checks preserve IPv6 brackets and nondefault Host ports.
- ABI size validation precedes full structure access. Callback lifecycle reentry
  includes creation; Android fd mode explicitly rejects queue packet calls.
- IPv6 UDP fragmentation now uses smoltcp wire/assembler primitives with 64
  simultaneous packets, approximately 4 MiB storage, 30-second expiry and complete
  datagram rejection on overlapping fragments. Native Linux TCP and 4,000-byte UDP
  pass for both IP families, including route cleanup. Simulation covers malformed,
  reordered, overlapping, expired and capacity-limited fragments. Oversized IPv6
  UDP replies cannot terminate packet delivery; the next normal reply still passes.
- The separate fuzz workspace lockfile includes the new platform foundations;
  all four ASan fuzz targets build on pinned nightly-2026-08-01 in WSL.
- Local desktop packages contain the executable, ABI libraries/header, dependency
  licenses and hash manifest. Offline archives include all foundation sources,
  both local patches, documentation and reproducible build/package scripts.
  See `release.md` and `offline-build.md` for generated artifacts and verification.

## Remaining Acceptance

1. Windows 10/11 native Wintun: privileged full routing, DNS/fake-IP, direct
   exclusions, no egress loop, network switching, failed startup and recovery.
   Current Windows process is not administrator and Wintun is absent.
2. macOS 12+ Intel/Apple Silicon: native utun with the same routing/DNS/lifecycle
   matrix, plus release builds. No Mac is attached to this environment.
3. iOS arm64 core/FFI compilation on macOS with Xcode/iPhoneOS SDK. Android arm64
   release static/dynamic libraries already build with NDK 27.0.12077973/API 24.
   Simulated C host tests do not constitute a mobile VPN app runtime test.
4. Full desktop deployment matrix across physical interfaces, local DNS stubs,
   other VPNs and network changes. Current route fault-injection and isolated Linux
   native-route tests do not establish full default-route integration acceptance.

The core must remain free of terminal interaction, process exit, system route
commands and a global runtime. Final acceptance requires every first-release
feature; partial milestones must not be presented as the completed rewrite.
