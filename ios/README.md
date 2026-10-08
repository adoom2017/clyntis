# Clyntis for iOS

Native SwiftUI client for iOS/iPadOS 17 or later, with the same icon and Apple
system-blue palette as the desktop client. The app imports local or remote
Clash-style YAML profiles, controls a system VPN, displays traffic and
connections, and switches routing mode and proxy-group selections while
connected. It also provides:

- **Profiles:** view and edit a profile's YAML (validated before saving), update
  a remote profile from its link, encrypted export, rename and delete.
- **Custom rules** (配置 → 自定义规则): matched before every profile's own rules;
  add one at a time, reorder or edit in bulk. Rules a profile cannot use (missing
  proxy, group or rule set) are skipped with the reason shown.
- **Profile overrides** (配置 → 覆盖配置文件): log level, IPv6 and domain
  sniffing replace the profile's values; "跟随配置文件" keeps them. The core
  performs the merge, the same as on the desktop.
- **Node status** (节点): each node shows a status line and a detail page. VLESS:
  server, transport, TLS/REALITY, the last delay test or its error, and open
  connections, with per-node and all-node delay tests. Tailscale: login state,
  this device's tailnet name and addresses, home DERP region, UDP candidates and
  every peer's online state and path (direct with RTT, or relayed). Proxies
  outside every group appear under "其他节点".
- **Connections** (概览 → 连接): open connections with target (the domain
  behind a fake IP), protocol, proxy chain, traffic and age; search, swipe to
  close one, or close all.
- **Logs** (日志): app, tunnel and core logs from the shared App Group file, with
  share and clear actions; credentials are redacted.

The VPN is a separate `NEPacketTunnelProvider` extension. It exchanges raw IPv4
and IPv6 packets with the Rust core through the versioned C API; it does not
open desktop proxy/controller listeners or modify native routes itself.

## Build

Use macOS with full Xcode, an Apple Silicon host, XcodeGen, and the Rust/C++
prerequisites described in the root README. Device and simulator libraries
currently contain **arm64 only**. From the repository root:

```sh
brew install xcodegen
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
cargo fetch --locked
bash scripts/build-ios.sh
open ios/Clyntis.xcodeproj
```

The script builds the core offline, creates the ignored
`ios/Frameworks/ClyntisCore.xcframework`, and generates the Xcode project from
`ios/project.yml`. Run it again after changing Rust code or the project spec.
The canonical C header is `crates/ffi/include/clyntis.h`; do not edit a generated
copy. Use `bash scripts/build-ios.sh --release` to build optimized core libraries
for device testing or distribution. Xcode's Release configuration alone does
not rebuild the Rust core.

### Xcode Cloud

The executable hook `ios/ci_scripts/ci_post_clone.sh` prepares the core before
Xcode builds the app. It installs CMake and rustup when absent, selects the Rust
version from `rust-toolchain.toml`, installs the device/simulator targets, fetches
locked Cargo dependencies, and builds a Release `ClyntisCore.xcframework` with
both arm64 slices. The framework stays ignored and is generated for each build.
Dependency preparation uses `cargo fetch --locked` without a target filter so
the subsequent offline builds have the full workspace dependency set on a fresh
cloud worker. Filtering the fetch to iOS targets can leave dependencies missing
and fail with `attempting to make an HTTP request, but --offline was specified`.

Commit and push the hook, `scripts/build-ios.sh`, and the configured Xcode project
to the branch used by the workflow. Select `ios/Clyntis.xcodeproj` and the
`Clyntis` scheme in Xcode Cloud. No additional workflow environment variables or
manual script step are required; Xcode Cloud automatically discovers the hook
beside the project. Check the **Post-Clone** log for the Rust build and successful
XCFramework creation. A fresh cloud build needs network access to Homebrew,
Rust's distribution servers and Cargo dependencies, and takes longer than a
cached local build.

The hook uses `--skip-project-generation`, so cloud builds do not need XcodeGen
and preserve the committed project, Info.plists and signing settings. Signing
for both the app and tunnel must still be configured in Xcode/Xcode Cloud.
To reproduce the dependency preparation locally on macOS:

```sh
bash ios/ci_scripts/ci_post_clone.sh
```

For a local core-only rebuild after dependencies have been fetched, use
`bash scripts/build-ios.sh --release --skip-project-generation`.
See Apple's [custom build script documentation](https://developer.apple.com/documentation/xcode/writing-custom-build-scripts).

### Local verification

Unsigned compile checks (these do not install a working VPN on a device):

```sh
xcodebuild -project ios/Clyntis.xcodeproj -scheme Clyntis \
  -destination 'generic/platform=iOS' \
  -derivedDataPath ios/build/DeviceDerivedData CODE_SIGNING_ALLOWED=NO build
xcodebuild -project ios/Clyntis.xcodeproj -scheme Clyntis \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath ios/build/DerivedData CODE_SIGNING_ALLOWED=NO build
```

Run the `ClyntisTests` scheme action on an installed iOS simulator. For example,
use `xcodebuild test` with `-destination 'platform=iOS Simulator,id=SIMULATOR_UUID'`.
Tests cover credential-preserving storage, failed-import cleanup, strict protocol
validation, remote download limits/errors/cancellation, encrypted import using
the existing Alpha golden vector, custom rules and profile overrides applied by
the core, the tunnel's IPv6 decision, node-status decoding from the core
snapshot, log redaction, and the actual Swift-to-Rust session/policy bridge. Simulator builds
can preview all tabs and import profiles; the connection action explains that
VPN operation needs a signed device.

## Device signing and first connection

1. Select an Apple development team with Network Extension provisioning for
   **both** `Clyntis` and `ClyntisTunnel`.
2. Set unique bundle identifiers and one registered App Group in `project.yml`.
   Update the app's `PRODUCT_BUNDLE_IDENTIFIER`, `CLYNTIS_TUNNEL_ID`, and
   `CLYNTIS_APP_GROUP`, then regenerate. The tunnel identifier and App Group
   settings feed both the Info.plists and entitlements.
3. Ensure both targets have the same App Group entitlement and
   `packet-tunnel-provider` Network Extension entitlement in their provisioning
   profiles. Build and run on an iPhone or iPad.
4. Import a supported YAML using **配置 → 导入 → 从文件导入** or **从链接导入**, choose it, then
   tap the connection button and accept the system VPN permission prompt.
5. Verify DNS, IPv4/IPv6, TCP/UDP, foreground/background transitions, lock/unlock,
   Wi-Fi/cellular changes, disconnect/reconnect, and invalid-server failures on
   your real network before distributing a build.

Profiles are stored in a UUID directory inside the shared App Group, excluded
from backups, and protected until the device's first unlock. Original YAML
bytes, comments and credentials are retained. Only the profile ID is stored in
the VPN preferences. Import validation does not test server reachability.
Profile switching/deletion is disabled while the VPN is active.

## Remote configuration import

Open **配置 → 导入 → 从链接导入**, enter an HTTP/HTTPS URL, an optional name and
an optional password. An empty password means the response is **plain YAML**;
a nonempty password means it must be decrypted before validation. The app does
not guess encryption or retry an encrypted response as plaintext.

Encrypted responses use the project's existing AES-CFB/Base64 configuration
format, compatible with CLI `--action encrypt`. Wrapped Base64 and final ASCII
whitespace are accepted. Passwords are used exactly as entered, including spaces
and Unicode. The legacy format has no authentication tag, so successful
decryption must also pass strict configuration validation before storage.

The importer accepts 2xx HTTP responses, rejects empty files, limits plaintext
to 16 MiB and encrypted downloads to 24 MiB, and enforces limits while streaming
even if Content-Length is missing. Request/resource timeouts are 30/60 seconds.
The form displays download/validation progress and allows cancellation or
retry after an error. Invalid imports are removed.

The password is used locally, never sent in the request or saved. The source
URL is kept with the profile so its detail page can update it from the link
(asking for the password again when the profile is encrypted); there is no
automatic subscription refresh. Decrypted original YAML is saved using the existing
protected App Group profile store. Requests use an ephemeral URLSession without
disk caches, cookie storage or stored credentials. The app target permits HTTP
imports through ATS configuration; HTTPS server certificate validation remains
enabled. See Apple's [URLSession documentation](https://developer.apple.com/documentation/foundation/urlsession)
and [ATS configuration](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity).

Before connecting, the app checks the profile's routing resources (GeoIP,
GeoSite, rule providers) without parsing them. Missing files are downloaded
first; expired ones are used as they are and refreshed in the background (the
tunnel refreshes rule providers itself, new geo files apply on the next
connect); current ones skip the step. The tunnel process never has to download
or parse them twice within its ~50 MiB memory limit, and logs its memory and
connection count every 30 seconds.

At runtime the host sets MTU 1280, installs the IPv4 default VPN route and DNS
`198.18.0.1`, and intercepts port 53 in the packet core. IPv6 is routed through
the tunnel only when the profile (or the IPv6 override) enables it **and** the
device network supports IPv6; otherwise apps would dial IPv6 literals that fail.
The decision is re-evaluated when the network changes. HTTP/SOCKS/mixed, DNS
listener and controller ports from the source profile are disabled in memory.
The source profile remains unchanged. Network-path changes on physical
interfaces notify the core so old sessions are closed; shutdown joins Rust
workers before releasing callback context. If the core stops, the extension
cancels the system tunnel.

Tailscale nodes (`type: tailscale`) run inside the tunnel as a Rust userspace
node, so the tailnet is usable together with the proxy without the Tailscale
app (iOS allows only one VPN at a time). Its control, DERP and direct UDP
connections leave through the device network. Fields and limits are described
in the root README.

## Current scope

This is the first iOS integration, not a validated App Store release. Unsigned
device/simulator compilation and simulator tests do not establish real-device
VPN routing, provider socket egress, memory-budget compliance or battery usage.
Those require a provisioned device and working server details.

- Automatic subscription refresh and resource-file import (such as local
  GeoIP/GeoSite or rule-provider files) are not implemented; routing resources
  are downloaded from the profile's configured sources.
- Protocol/configuration support is the same focused subset as the Rust core:
  VLESS and Tailscale outbounds. Unknown fields fail validation;
  Trojan/Hysteria2 outbounds remain unimplemented. UDP through Tailscale is not
  supported yet.
- No on-demand connection, reconnect-on-launch, desktop system proxy, tray, or
  local HTTP controller. Node groups, status and statistics are available after
  connection.
- Intel simulator slices, distribution signing and App Store packaging are not
  included in the build script.

Apple references: [packet tunnel provider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider)
and [provider deployment requirements](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment).
