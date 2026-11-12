# Local Release Packaging

Rust 1.93.1, tar and the host C/linker toolchain are required. Use PowerShell 7
on Windows; macOS and Linux use Bash and Python 3.
Desktop packages contain the CLI, C ABI static/dynamic libraries, C header,
examples, documentation, project license and dependency license notices.
`dependencies.json` inventories resolved foundation packages, including test and
optional packages; it does not claim that all of them are linked into the binary.
`release-manifest.json` records the target, lockfile hash and every payload hash.
Each archive has a separate SHA-256 record. Scripts create only local artifacts.
Three registry packages omit license texts: asn1-rs-impl 0.2.0, defmt 0.3.100 and
defmt-parser 1.0.0. Packaging includes notices from their matching archived upstream
workspace crates; `notice_source` records each source. Unaccounted missing notices
fail packaging rather than producing an empty license directory.

```powershell
cargo fetch --locked
./scripts/package-release.ps1
```

On macOS and Linux:

```bash
cargo fetch --locked
bash scripts/package-release.sh
```

This performs a locked offline release build and creates a unique directory and
`.tar.gz` under ignored `dist/`. On Windows, optional `-Target` selects an
installed desktop target. On macOS/Linux, pass an output directory and then an
optional target as positional arguments (for example,
`bash scripts/package-release.sh dist aarch64-apple-darwin`). A cross-build does
not run that platform's tests.
macOS native builds default to deployment target 12.0. Windows packages require
the official signed x64 Wintun DLL separately for TUN operation; it is not bundled.

For a release backed by archived dependency sources, use the `.ps1` scripts on
Windows or the matching `.sh` scripts on macOS/Linux: prepare a snapshot,
extract it, verify it and run the extracted package script. Set `CARGO_TARGET_DIR` to the
verifier's reported build directory to reuse verified release objects and supply
`-OutputDirectory` (Windows) or the first Bash argument (macOS/Linux) outside
the extracted source. The release manifest records
the source snapshot manifest hash. Retain the matching source archive, archive
checksums and build records with the binary package for distribution.

Mobile hosts build their libraries separately:

```powershell
./scripts/check-mobile.ps1 -Platform android -Ndk PATH_TO_NDK -Release
./scripts/check-mobile.ps1 -Platform ios -Release
```

On macOS and Linux, use Bash instead:

```bash
bash scripts/check-mobile.sh android /path/to/ndk/27.0.12077973 --release
bash scripts/check-mobile.sh ios --release # macOS/Xcode only
```

Android uses NDK 27.0.12077973 / API 24; iOS requires macOS/Xcode and an installed
iPhoneOS SDK. PowerShell restores compiler environment variables; Bash exports
them only in the script process. Libraries appear in the target-specific `release/` directory. Include
`crates/ffi/include/clyntis.h` in the host integration. These commands validate
compilation, not mobile application or VPN runtime behavior.

`.github/workflows/rust.yml` runs local tests, formatting, strict Clippy and release
packaging on Windows, Linux and macOS. Separate jobs build
iOS arm64 on macOS and Android arm64 with the pinned NDK on Linux. The workflow
has no artifact upload, remote release or publication step. Native privileged
TUN tests and external protocol oracles require their documented prerequisites.
