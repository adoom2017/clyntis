#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 ]]; then
    printf 'Usage: bash scripts/verify-offline.sh [EXTRACTED_SOURCE_DIRECTORY]\n' >&2
    exit 2
fi

source_root=$(cd "${1:-"$(dirname "${BASH_SOURCE[0]}")/.."}" && pwd)
python3 - "$source_root" <<'PY'
import hashlib
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
manifest = json.loads((source / "snapshot-files.json").read_text())
files = {path.relative_to(source).as_posix(): path for path in source.rglob("*")
         if path.is_file() and path != source / "snapshot-files.json"}
if set(files) != set(manifest):
    raise SystemExit("Snapshot file inventory does not match the extracted source.")
for name, path in files.items():
    if hashlib.sha256(path.read_bytes()).hexdigest() != manifest[name]:
        raise SystemExit(f"Snapshot checksum mismatch: {name}")
print(f"Verified {len(files)} snapshot files.")
PY

verification_root=$(mktemp -d "${TMPDIR:-/tmp}/clyntis-offline-XXXXXXXX")
mkdir -p "$verification_root/cargo-home" "$verification_root/build"
export CARGO_HOME="$verification_root/cargo-home"
export CARGO_TARGET_DIR="$verification_root/build"
export CARGO_NET_OFFLINE=true
cd "$source_root"
if ! rustup run 1.93.1 cargo build --workspace --release --locked --offline > "$verification_root/build.log" 2>&1; then
    tail -n 80 "$verification_root/build.log"
    printf 'Offline build failed; see %s/build.log\n' "$verification_root" >&2
    exit 1
fi
binary="$CARGO_TARGET_DIR/release/clyntis"
version=$("$binary" -v)
"$binary" -f "$source_root/examples/vless.yaml" -t
python3 - "$source_root" "$verification_root" "$binary" "$version" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

source, root, binary = map(pathlib.Path, sys.argv[1:4])
if list((root / "cargo-home").rglob("*.crate")):
    raise SystemExit("Unexpected Cargo registry archives in the isolated cache.")
manifest = json.loads((source / "snapshot-files.json").read_text())
result = dict(source=str(source), version=sys.argv[4],
              rustc=subprocess.check_output(["rustup", "run", "1.93.1", "rustc", "-vV"], text=True).strip(),
              offline=True, empty_initial_cargo_home=True, empty_initial_target_directory=True,
              snapshot_files_verified=len(manifest), executable=str(binary),
              executable_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
(root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
PY
printf 'Verification records: %s\n' "$verification_root"
