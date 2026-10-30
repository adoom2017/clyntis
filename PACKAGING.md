# Packages and embedding

Release archives, macOS signing and notarization, and the C API package. For
building from source, see the [README](README.md).

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
Pushing a tag `vX.Y.Z` does: the Windows Release workflow builds this package
and the unsigned desktop installer (NSIS) on Windows and attaches both, with
SHA-256 files, to the GitHub release for the tag. The tag must match the product
version, so run `bash scripts/set-version.sh X.Y.Z` and commit before tagging.
The package contains the CLI, examples, licenses, C libraries and
`crates/ffi/include/clyntis.h`. Besides creating, starting and driving a core
(`meta_create_v1`, `meta_create_packet_tunnel_v1`, `meta_snapshot_v1`,
`meta_select_v1`, `meta_probe_v1`, packet I/O), the C API validates and merges
custom rules (`meta_custom_rule_*`, `meta_custom_rules_apply_v1`), applies app
settings (`meta_overrides_apply_v1`), checks and prefetches routing resources
(`meta_resources_state_v1`, `meta_prefetch_resources_v1`) and drains logs
(`meta_drain_logs_v1`); every function documents its buffer contract in the
header. For a separate host-library build, use
`cargo build -p clyntis-ffi --release --locked`; mobile target builds use the
`scripts/check-mobile.sh` or `scripts/check-mobile.ps1` helpers with the relevant
SDK/NDK installed.
