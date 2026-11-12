# Offline Source Snapshots

The Rust source archive contains the workspace, its lockfile, the vendored and
locally patched BoringSSL binding source and licenses, and every registry source
selected by `Cargo.lock`.
It does not include Go product code, external proxy executables or the separate
fuzz workspace. Xray remains an optional, independently acquired test oracle.

## Prepare

Requires Git, tar, and the pinned Rust 1.93.1 toolchain. Windows uses PowerShell 7;
macOS/Linux use Bash and Python 3. Preparing
the archive may use the network to obtain missing locked registry sources:

```powershell
./scripts/prepare-offline.ps1
```

On macOS and Linux:

```bash
bash scripts/prepare-offline.sh
```

The script writes a uniquely named source directory, `.tar.gz` and `.sha256`
under the ignored `dist/` directory. It rejects non-crates.io registry and Git
dependency sources. `dependency-inventory.json` records package versions,
licenses, original registry archive checksums and both local foundation patches. The
base Git revision and dirty status identify the checkout used; the per-file
`snapshot-files.json` hashes bind the actual archived bytes, including local
changes. Original license files stay with dependency sources.

The archive embeds `.cargo/config.toml` with a relative vendor directory and
offline mode. It can be relocated without access to the preparer's Cargo cache.
The package list is an inventory, not a claim that every optional dependency
was linked into the production executable. Protocol projects are not production
dependencies; review new dependencies and their purpose when changing the lockfile.

## Verify the Archive

Verify the archive hash against its separately retained `.sha256` record, extract
it into a new directory outside any other Cargo workspace, then run:

```powershell
tar -xzf PATH_TO_ARCHIVE.tar.gz -C EMPTY_EXTRACTION_DIRECTORY
pwsh -File EXTRACTED_SOURCE/scripts/verify-offline.ps1
```

On macOS and Linux, use `bash EXTRACTED_SOURCE/scripts/verify-offline.sh`
instead of the PowerShell command. The optional first argument selects a
different extracted source directory.

The verifier checks every inventoried source file before building. It creates a
new empty `CARGO_HOME` and target directory, runs the pinned toolchain with
`cargo build --workspace --release --locked --offline`, then checks the CLI
version and example configuration. Build logs, the executable and `result.json`
remain in the reported temporary verification directory. The current process's
Cargo environment is restored afterward. No registry cache is copied into it.

The host must already have Rust 1.93.1 and its platform linker/C toolchain. These
OS/toolchain prerequisites are separate from the archived Cargo dependency
sources. `rustup run` fails if the pinned toolchain is missing. This verification
proves Cargo can build from the archived sources; it does not disable the host
network at the OS level or replace desktop/mobile runtime acceptance.

For normal use after extraction, from the source directory:

```sh
cargo build --workspace --release --locked --offline
cargo test --workspace --locked --offline
```

Official Xray tests remain ignored unless a verified executable is supplied as
described in `vless-protocol.md`. Fuzzing has its own lockfile and nightly toolchain
and is intentionally not part of this production source archive.

The repository also provides a Linux/WSL helper, included in current snapshots,
which checks archive and individual file hashes, extracts into a temporary directory and
runs the release build plus local tests with an empty cache:

```sh
bash scripts/verify-offline-linux.sh /absolute/path/to/ARCHIVE.tar.gz
```

It requires `sha256sum`, `tar`, Rust 1.93.1 and the host C/linker tools. Its logs
and host/executable hash record are retained beside the input archive. The
archive's `.sha256` file uses LF so GNU `sha256sum --check` can consume it directly.

## Initial VLESS Snapshot Verification

On 2026-09-12:

- Archive (historical filename, before the `clyntis` rename):
  `dist/meta-rust-offline-668cf4c0.tar.gz` (35,817,409 bytes).
- SHA-256: `8780970b301474d010d8f3fc41612918b0ea5b9525bcd09b0b71524c3574977f`.
- Inventory: 279 packages (272 registry packages, six workspace crates and the
  then-current locally patched TLS backend); 11,293 per-file hashes.
- Source: VLESS milestone `8a18ef6e` plus the archive tools, as recorded by the
  inventory's base revision/dirty status. These later verification notes and the
  repository Linux helper are outside that captured source snapshot.
- Windows x64 MSVC: extracted archive hashes verified; empty-cache locked offline
  release build passed, including the executable version/configuration checks.
- Linux x64 GNU, Ubuntu 22.04 WSL: archive hash verified; empty-cache locked offline
  release build and executable checks passed. Local tests: 34 passed, two optional
  Xray oracle tests ignored. Official interop was separately run on Windows.
- Integrity regression: changing `examples/vless.yaml` in a disposable extracted
  copy caused an explicit checksum mismatch before compilation. The archive itself
  was not modified.

Both hosts used Rust 1.93.1. No portable macOS/mobile build or desktop TUN runtime
claim follows from these checks. Archives and generated logs remain local under
ignored `dist/`; they are not automatically committed, pushed or published.
