# Continuation Ledger

> Historical evidence: branch names, artifact filenames and paths below describe
> earlier builds. For current `clyntis` commands, use the [README](../README.md).

This is a historical task ledger. The branch, build paths and artifact names below
record the state at the time. Keep source revisions, commands, results and artifact
hashes in Git; generated binaries/logs under ignored `target/` and `dist/` must be
transferred separately when moving machines. Never infer success from an
interrupted session or substitute cross-compilation for runtime acceptance.

## Tasks

Windows self-service acceptance: [windows-manual-acceptance.md](windows-manual-acceptance.md).
Start from `examples/windows-tun-test.yaml`; its DIRECT configuration passed the
retained Windows release CLI's `-t` check. This is preparation, not runtime acceptance.

| ID | Task | Status |
| --- | --- | --- |
| T1 | Complete workspace tests after oversized UDP fix | Complete at baseline `9e4ac576`: Windows/Linux each 54 passed, 6 ignored |
| T2 | Verify source snapshot `607ae268` offline on Windows/Linux | Complete: Windows/Linux empty-cache offline release builds |
| T3 | Refresh and verify packaged binaries from verified source | Complete for baseline `9e4ac576`; new deployment fixes require a subsequent snapshot |
| T4 | Windows route plus interface metric selection | Complete; Windows unit/live interface query tests passed |
| T5 | Cancel in-progress HY2 establishment on network changes | Complete; Windows/Linux cancellation regression passed |
| T6 | Desktop full routing/DNS/network-switch/recovery acceptance | Linux dual-stack/competing-TUN route coexistence passed; physical auto-discovery/system resolver/third-party VPN apps and Windows/macOS remain unverified |
| T7 | iOS arm64 build and macOS build matrix | iOS device/simulator debug core and unsigned native app builds passed 2026-10-04; four simulator tests passed. Signed device VPN acceptance remains open; see ios/README.md. macOS matrix is a separate acceptance item. |
| T8 | Refresh final source/binary archives including deployment fixes | Complete for implementation `89fd90f9`, with documented license-description correction |

## Evidence

### iOS native integration - 2026-10-04

Native SwiftUI app, App Group profile storage and Network Extension packet
tunnel added under `ios/`. `scripts/build-ios.sh` builds the Rust arm64 device
and simulator libraries and generates the Xcode project. Unsigned app/extension
builds and four simulator unit tests passed on Xcode 27; the simulator launched
the connection screen with the shared brand icon. Config/core/FFI tests:
42 passed, one ignored; workspace compilation passed. These checks do not
establish real-device VPN operation or complete T7. Current signing instructions,
feature limits and device acceptance are in [ios/README.md](../ios/README.md).

### 2026-09-13 Start

- Implementation baseline `9e4ac576`; documentation baseline `f6219610`.
- Branch `meta-rust`; initially clean; `Alpha` must remain unchanged.
- Linux command: `cargo test --workspace --locked --offline`, Rust 1.93.1,
  Ubuntu-22.04 WSL, target directory `/home/adoom/meta-rust-platform-target`.
  Process exit 0; log `target/continuation-workspace-linux.log`.
- Windows command: same, log `target/continuation-workspace-windows.log`;
  completion is pending at this checkpoint.
- Current Windows token is not administrator; `target/release/wintun.dll` absent.
  Do not mark Windows native TUN acceptance passed on this host.

### T1 Complete - 2026-09-13

- Both commands exited 0: Windows x64 MSVC and Linux x64 GNU (Ubuntu-22.04 WSL),
  Rust 1.93.1, `cargo test --workspace --locked --offline`.
- Each host: 54 passed, 0 failed, 6 ignored. The six require external oracle
  executables or a privileged TUN device; no runtime acceptance is inferred.
- Logs: `target/continuation-workspace-windows.log` and
  `target/continuation-workspace-linux.log`. Tested implementation `9e4ac576`;
  subsequent deployment fixes will have their own checks and source archive.
- T2 Linux verification also exited 0: extracted source `607ae268`, empty cache
  and target, locked offline release build, executable checks and 54 local tests.
  Log: `target/continuation-offline-linux.log`; archive-side build/test/result logs
  remain beside `dist/meta-rust-offline-607ae268.tar.gz`.
### T2/T3 Complete - 2026-09-13

- Windows verifier result confirms 18,767 snapshot hashes, empty initial Cargo
  home/target and successful locked offline release build on Rust 1.93.1.
  Log: `target/continuation-offline-windows.log`.
- Verified executable SHA256:
  `5fbbe63735546049f9953fc161134575a94d4fc8a08fd18ce5a591d0c6c37e11`.
- Packaged extracted snapshot `607ae268` using its verified build directory:
  `dist/meta-rust-0.1.0-x86_64-pc-windows-msvc-43fbc8d1.tar.gz`.
  SHA256: `b7ad2117ef36b6bdc1c7f97504f6a8f9bee681cacef99986068eb01084028ac0`.
- All 554 package payload hashes verified; CLI version and both VLESS/HY2
  example configuration checks passed. Log: `target/continuation-package-windows.log`.
  This package contains baseline `9e4ac576`, not the following T4/T5 fixes.

### T4/T5 Complete - 2026-09-13

- Windows default-route ordering now adds the address-family-specific interface
  metric to route metric using u64; unreadable candidates are excluded.
  Tests cover family differences, overflow and a live OS interface query.
- HY2 establishment and lock waiters observe a network-generation cancellation
  token and core shutdown. Network changes invalidate old cached clients without
  waiting for ongoing handshakes or removing clients from the new generation.
- Regression uses a real nonresponding local QUIC endpoint: cancels pending
  establishment and lock waiter, permits a fresh attempt, then cancels on stop.
- `cargo test -p meta-core -p meta-platform --locked --offline`: Windows 18
  passed, Linux 16 passed; native TUN test ignored on each. Logs:
  `target/continuation-network-tests.log`, `target/continuation-network-linux.log`.
- Remaining delivery work: archive and package a new snapshot incorporating these
  fixes; full privileged desktop acceptance and Apple builds remain outstanding.
- `cargo fmt --all`, `git diff --check` and Windows
  `cargo clippy -p meta-core -p meta-platform --all-targets --locked --offline -- -D warnings`
  passed; Clippy log: `target/continuation-network-clippy.log`.

### Desktop acceptance fixes - 2026-09-13

- The isolated Linux CLI scenario uncovered truncated route enumeration in
  route_manager 0.2.9: dump completion was tested backwards, and reads used a
  fixed 4096-byte buffer. A maintained generic foundation patch fixes synchronous
  and asynchronous listing; original Apache-2.0 source/license and patch note retained.
- Real DNS lookups uncovered relative-name versus absolute-wire-name equality
  rejecting valid upstream responses. Both normal lookup and bootstrap now build
  absolute questions; a local UDP regression exercises names without final dots.
- `scripts/test-desktop-linux.py` passed automatic IPv4/IPv6 route creation,
  IPv4 DNS/fake-IP, TCP/4000-byte UDP, virtual uplink replacement, exclusion
  refresh, graceful recovery and SIGKILL recovery preserving 121 unrelated routes.
  Log: `target/continuation-desktop-linux.log`. Namespace-only; no host routes changed.
- Full workspace tests: Windows 58 passed/6 ignored; Linux 56 passed/6 ignored.
  Logs: `target/continuation-final-tests-windows.log` and
  `target/continuation-final-tests-linux.log`.
- Interim source `66167e0b` passed Windows/Linux empty-cache offline builds, but
  predates these discovered fixes and is not the final deliverable.
- Windows administrator token and Wintun DLL checked again: both unavailable.
  No Mac/Xcode host is available. T6/T7 remain only partially accepted; virtual
  Linux checks do not substitute for those operating systems or VPN coexistence.

### Final source and Windows delivery - 2026-09-13

- Implementation `89fd90f99bdb8e4522da81c82b8006c962f32d60`; source was clean.
  `dist/meta-rust-offline-837c8410.tar.gz`, SHA256
  `655f04fba911d9556dfd9a7e4d3c0e304ed6c7640cc20a47127424a3a3110f89`.
  Inventory: 366 packages; 18,766 file hashes; includes all three local foundation
  patches and their original licenses, plus the desktop acceptance script.
- Empty-cache/target locked offline release builds passed on Windows and Linux.
  Logs: `target/continuation-delivery-windows.log`,
  `target/continuation-delivery-linux.log`; Linux also passed 56 local tests.
- Windows package: `dist/meta-rust-0.1.0-x86_64-pc-windows-msvc-9f6e0415.tar.gz`.
  SHA256: `8c76a1def00082d52b5cfa8f5e461042cb61e3a5da03950b2d6cfc64f2c6c616`.
  Archive re-extracted: exact inventory and 557 payload hashes passed, CLI version
  and VLESS/HY2 configuration checks passed. CLI SHA256:
  `bf71b2391daa376f9ae731d45be9d8419ef2a2214455c694a08e12f4a864bd9d`.
- Windows full workspace Clippy with `-D warnings` passed. The route foundation's
  optional async Linux implementation also compiled in a separate offline harness.
- Latest Linux native TUN test passed IPv4/IPv6 TCP/UDP with isolated routes;
  log `target/continuation-final-native-tun.log`.
- Android arm64 release build passed again (NDK 27.0.12077973/API24), log
  `target/continuation-final-android.log`. Dynamic library SHA256:
  `ba3d53161c371c948c62919e2bf63448814216df3526e8034bd80f5f2e0b99bf`;
  static library SHA256:
  `5371635091409eb27562b7ef08bf821ffd6e209ed642965f1a861ee2e4de7c25`.
- WSL discarded the first verifier's temporary build directory after exit.
  Linux verification is repeated with packaging in the same session; preserve
  archive-side records and packages in `dist/`, not transient `/tmp` paths.

### T8 Complete - final archive correction and Linux package

- The route_manager description incorrectly said MIT; the bundled upstream
  LICENSE was already Apache-2.0. Corrected the description in Git and all three
  archives, then regenerated manifests and archive checksums. The source inventory
  explicitly records this post-build documentation change. Comparing old/new
  manifests confirmed all build inputs unchanged; only the patch note, historical
  ledger, provenance metadata and checksum list changed. Hashes above are final;
  earlier build/package logs retain pre-correction archive hashes.
- Linux package: `dist/meta-rust-0.1.0-x86_64-unknown-linux-gnu-22f943bd.tar.gz`.
  Final SHA256:
  `a1a468bed251eed126e78cfae8e6495bc3f62d4a56d47d451872883a1abaef63`.
  All 522 payload hashes, both example configurations and the real namespace
  desktop scenario passed using the extracted release executable. Logs:
  `target/continuation-package-linux.log`,
  `target/continuation-package-linux-verified.log`.
- The packaged Linux CLI SHA256 is
  `45f66d07d720d32dbd75615039ce8aaa6a50c1032ee3e954f7b859d3844f0089`;
  it comes from the second clean offline build, retained by packaging before WSL
  removed its temporary directory. Release CLI binaries are unchanged by correction.
- Final archive inventory/hash verification:
  `target/continuation-corrected-archives-verified.log`.
- No push/publication; Alpha unchanged. Remaining acceptance is T6/T7 only:
  physical-network/VPN coexistence, Windows elevated Wintun runtime, macOS desktop
  runtime/builds and iOS build on Xcode. Android build is not mobile runtime testing.

### Extended Linux dual-stack and VPN route coexistence - 2026-09-13

- Extended the namespace scenario to use IPv6-only DNS names, real IPv6 TCP,
  4000-byte fragmented UDP and both IPv6 uplinks before/after replacement.
- A separately open TUN owns four overlapping IPv4/IPv6 routes, including routes
  with metric 7. All remain identical while meta-rust runs, changes egress,
  exits normally and recovers from SIGKILL. The prior 121 unrelated routes also
  remain intact. This is competing-TUN routing acceptance, not a third-party VPN
  application's full lifecycle or system resolver integration.
- Command: root `unshare --net --fork python3 scripts/test-desktop-linux.py` using
  the retained `22f943bd` Linux release executable. Exit 0; all six scenario
  checkpoints passed. Log: `target/continuation-dual-stack-vpn.log`.
- Only the acceptance script and documentation changed; product code and verified
  archives remain unchanged. The archive contains the earlier acceptance script;
  use the current Git script for these added checks. CI already invokes this script.
- Windows administrator token and local Wintun DLL checked again: unavailable.
  Asked for an existing Mac/Xcode environment while completing local tests; no
  connection details have been supplied at this checkpoint. T6/T7 remain open.
