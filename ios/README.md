# Clyntis for iOS

Native SwiftUI client for iOS/iPadOS 17 or later, with the same emerald icon as
the desktop client. The app imports local or remote Clash-style YAML profiles, controls
a system VPN, displays traffic and connections, and switches routing mode and
proxy-group selections while connected.

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
the existing Alpha golden vector, and the actual Swift-to-Rust session/policy bridge. Simulator builds
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

The password is used locally, never sent in the request or saved. Source URLs
are also not saved; this is a one-time import rather than an automatically
updated subscription. Decrypted original YAML is saved using the existing
protected App Group profile store. Requests use an ephemeral URLSession without
disk caches, cookie storage or stored credentials. The app target permits HTTP
imports through ATS configuration; HTTPS server certificate validation remains
enabled. See Apple's [URLSession documentation](https://developer.apple.com/documentation/foundation/urlsession)
and [ATS configuration](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity).

At runtime the host sets MTU 1280, installs IPv4/IPv6 default VPN routes and DNS
`198.18.0.1`, and intercepts port 53 in the packet core. HTTP/SOCKS/mixed, DNS
listener and controller ports from the source profile are disabled in memory.
The source profile remains unchanged. Network-path changes notify the core so
old sessions are closed; shutdown joins Rust workers before releasing callback
context. If the core stops, the extension cancels the system tunnel.

## Current scope

This is the first iOS integration, not a validated App Store release. Unsigned
device/simulator compilation and simulator tests do not establish real-device
VPN routing, provider socket egress, memory-budget compliance or battery usage.
Those require a provisioned device and working server details.

- Local and remote YAML import; automatic subscription refresh, configuration editing and resource-file
  import (such as local GeoIP/GeoSite or rule-provider files) are not implemented.
  Keep initial profiles self-contained; remote resource loading follows core
  behavior and must also be checked on a device.
- Protocol/configuration support is the same focused subset as the Rust core.
  Unknown fields fail validation. Trojan/Hysteria2 outbounds remain unimplemented;
  use supported VLESS nodes or DIRECT for initial testing.
- No on-demand connection, reconnect-on-launch, desktop system proxy, tray, or
  local HTTP controller. Node groups/statistics are available after connection.
- Intel simulator slices, distribution signing and App Store packaging are not
  included in the build script.

Apple references: [packet tunnel provider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider)
and [provider deployment requirements](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment).
