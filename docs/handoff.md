# Rewrite Handoff - 2026-09-13

> iOS 最新进展（2026-10-04）：原生 App 与 Packet Tunnel 扩展已加入，
> arm64 真机/模拟器核心和未签名 App 构建通过，4 项模拟器测试通过。
> 真机 VPN 尚未验收；接入与验证请阅读 [ios/README.md](../ios/README.md)。

> 历史记录：本文的旧分支名、产物文件名和路径均为当时的真实标识，不适用于
> 当前 `clyntis` 构建。现行构建与运行命令请参阅 [README](../README.md)。

> macOS 接手请优先阅读 [macos-migration-handoff.md](macos-migration-handoff.md)。
> 该文件记录 2026-09-23 的 BoringSSL-only、VLESS-only 和 TUN 最新状态；
> 本文保留的是较早阶段的历史基线。

For current task statuses and results recorded as each item completes, start with
[continuation.md](continuation.md). This handoff retains the original baseline.

## Checkout and Boundaries

- Workspace: `E:/app_workspace/Clash.Meta`; branch `meta-rust`.
- Implementation HEAD: `9e4ac576349cb25394391c3030a317933ad22acb`.
- Checkout was clean before this documentation update. The tracking ref currently
  matches HEAD; this agent did not push or publish anything.
- `Alpha` remains `3fce2b4fe0eaefd2016f1b60312e1bb991b5c1e3`.
- Production uses repository-owned proxy protocols and generic foundations only.
  Xray may be used as an ignored VLESS test oracle. The historical Hysteria
  oracle is no longer used after the VLESS-only migration.
- Continue in this workspace; do not remove unrelated binaries or user changes.
  Do not use subagents unless explicitly requested. No test/build session from
  the previous run remains available; final interrupted checks need rerunning.

## Completed Commits

| Commit | Change |
| --- | --- |
| `8a18ef6e` | VLESS TCP/TLS, REALITY, Vision, UDP/XUDP and Xray interoperability |
| `b656e069` | Initial dependency source archive and offline verification |
| `5c0bb8d4` | HY2 TCP/UDP, Salamander, hopping, bandwidth and official interoperability |
| `e962723f` | Live traffic/connections, cancellation, DNS cache/DoH and controller updates |
| `5c158e47` | smoltcp TUN, desktop routing/recovery, C ABI and mobile interfaces |
| `fe1816cb` | IPv6 TUN fragmentation, IPv6 HTTP/probe parsing and ABI boundary fixes |
| `e215bac8` | Remove Go product/build flows, legacy vectors, Rust CI and packaging |
| `9e4ac576` | Drop oversized TUN replies without terminating delivery; preload CI sources |

Core and CLI now provide HTTP/CONNECT, SOCKS5/mixed/TUN, ordered domain/IP rules,
select/url-test groups, UDP/TCP/DoH DNS, bounded cache/fake-IP, AES-CFB compatibility,
rotating logs and the reduced authenticated controller. Desktop uses tun-rs,
physical socket binding, route journals, startup rollback and a recovery command.
OS DNS settings are preserved; DNS traffic is redirected by routes/hijacking.

ABI v1 provides independent core runtimes, checked handles, caller-owned buffers,
bounded packet queues, lifecycle/callback rules, Android fd duplication/socket
protection and iOS packet interfaces. See `platform-runtime.md` and the C header.

## Verified Results

- Windows/Linux: 53 local workspace tests passed before the final oversized-UDP
  regression. That additional regression passed separately on both hosts.
  The final full workspace run was interrupted; do not claim a 54-test full pass.
- Formatting and strict workspace/all-target Clippy passed on Windows and Linux
  after the final code fix. Five external oracle suites passed: Xray v25.9.11
  (two) and official Hysteria v2.6.4 (three).
- Linux actual TUN: IPv4/IPv6 TCP, 4,000-byte UDP fragmentation, and removal of
  isolated `198.19.254.253/32` and `fdfe:dcba:9877::fd/128` routes passed.
- Mock route rollback/recovery and simulated C-host lifecycle tests passed.
- Android arm64 release `.a` and `.so` rebuilt after the final fix with Rust
  1.93.1, NDK 27.0.12077973/API 24. This is compilation, not mobile VPN runtime.
- VLESS ASan campaigns: 20,669,305 inputs. Final HY2 campaign: 653,100 inputs.
  All four fuzz targets build with the updated separate lockfile on WSL using
  nightly-2026-08-01; no new campaign was run after the final platform changes.
- Windows/macOS native TUN and iOS compilation have not passed acceptance.

## Artifacts and Exact Status

All generated artifacts are ignored/local; preserve matching source and hashes.

| Artifact under `dist/` | Status |
| --- | --- |
| `meta-rust-offline-607ae268.tar.gz` | Latest clean source at `9e4ac576`; Linux offline release build passed; final Linux tests and Windows offline build interrupted |
| `meta-rust-offline-0930bbaf.tar.gz` | Source at `e215bac8`; empty-cache Windows/Linux release builds and Linux local tests passed |
| `meta-rust-0.1.0-x86_64-pc-windows-msvc-f9178c0a.tar.gz` | Package and all payload hashes verified; CLI/config checks passed; predates the final oversized-UDP fix |

Latest source SHA-256:
`21715f32b2c5f6fc9080c32236f40ef58e27a333c5082a44fbf38afd840ab797`.
Previous fully verified source SHA-256:
`2ecdaab5029f79f4813c1ae81638e684130ac20a413c6eb5c770c1cc967564d7`.
Current binary package SHA-256:
`f37f2177a4aae78f0d254616c91be4671a5d4c9d796ded5d159888f1d78be970`.
That historical inventory contained 366 packages (358 registry, six workspace,
two local patches) and 18,767 source-file hashes. The later BoringSSL-only
migration supersedes its TLS/QUIC dependency snapshot.

Android artifacts: `target/aarch64-linux-android/release/libmeta_ffi.a` and `.so`.
Final `.so` SHA-256:
`4d8845078180649b967debebe6d0992948253a3de6a41b237f61355911463066`.
Final `.a` SHA-256:
`f0373c941ce7928f7aab8519f8f714139581aedd4408ab32042103f7963c7742`.

## Next Work, In Order

1. Rerun the final workspace tests on both hosts; expect 54 local tests and six
   ignored prerequisites (five external oracles, one privileged TUN suite).
2. Finish verification of source `607ae268` with empty Cargo cache/build dirs.
   The Windows log `target/offline-607ae268-windows.log` is empty; the Linux build
   log has success, but its test log lacks final completion. Preserve new logs.
3. Package the latest verified extracted source and reuse its release build via
   `CARGO_TARGET_DIR`; put output outside the extracted source. Verify package
   hashes, both example configs, CLI version and ABI files. Current `f9178c0a`
   package is superseded once this completes. Add the exact new artifact record.
4. Privileged Windows 10/11 x64 and macOS 12+ Intel/Apple Silicon: test full routing,
   DNS/fake-IP, exclusions, physical egress without loops, network changes,
   partial startup rollback, ordinary shutdown and abnormal-exit recovery.
5. Build iOS arm64 with Mac/Xcode/iPhoneOS SDK; run macOS CI/build matrix. Windows
   currently lacks administrator/Wintun; no Mac is available. CI is configured
   but has not been observed running here. No mobile application test is claimed.
6. Review deployment edges: Windows route selection currently uses route metric
   without interface metric; pending HY2 connection locks can delay network-change
   cleanup up to dial deadlines; loopback DNS stubs/other VPN coexistence and full
   default-route/DNS switching need tests. Isolated Linux routes do not cover them.

## Useful Commands

```powershell
cargo test --workspace --locked --offline
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
pwsh -File scripts/test-vless.ps1
pwsh -File scripts/test-local-proxy.ps1 -ConfigPath C:/private/config.yaml -StartProxy -TestResources
pwsh -File target/offline-final-extracted/meta-rust-offline-607ae268/scripts/verify-offline.ps1
pwsh -File scripts/check-mobile.ps1 -Platform android -Ndk C:/Users/sdc/AppData/Local/Android/Sdk/ndk/27.0.12077973 -Release
```

WSL Ubuntu-22.04 user `adoom` has Rust at `/home/adoom/.cargo/bin`. Use persistent
`CARGO_TARGET_DIR=/home/adoom/meta-rust-platform-target` for normal Linux checks;
temporary directories have disappeared across sessions. Example from PowerShell:

```powershell
wsl -d Ubuntu-22.04 --exec env PATH=/home/adoom/.cargo/bin:/usr/local/bin:/usr/bin:/bin CARGO_TARGET_DIR=/home/adoom/meta-rust-platform-target cargo test --workspace --locked --offline --manifest-path /mnt/e/app_workspace/Clash.Meta/Cargo.toml
wsl -d Ubuntu-22.04 --exec bash /mnt/e/app_workspace/Clash.Meta/scripts/verify-offline-linux.sh /mnt/e/app_workspace/Clash.Meta/dist/meta-rust-offline-607ae268.tar.gz
```

After rebuilding, find the current native TUN test executable before invoking it
as WSL root; Cargo artifact hashes can change. Use `scripts/package-release.ps1`
as documented in `release.md`. Do not describe the rewrite as fully accepted
until the platform and delivery items above are completed.
