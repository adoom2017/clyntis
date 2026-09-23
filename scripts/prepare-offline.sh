#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 ]]; then
    printf 'Usage: bash scripts/prepare-offline.sh [OUTPUT_DIRECTORY]\n' >&2
    exit 2
fi

workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output_root=${1:-"$workspace/dist"}
mkdir -p "$output_root"
output_root=$(cd "$output_root" && pwd)
snapshot=$(mktemp -d "$output_root/clyntis-offline-XXXXXXXX")
name=$(basename "$snapshot")
cd "$workspace"

metadata_file=$(mktemp)
trap 'rm -f "$metadata_file"' EXIT
cargo metadata --format-version 1 --locked > "$metadata_file"
python3 - "$metadata_file" <<'PY'
import json
import sys

for package in json.load(open(sys.argv[1]))["packages"]:
    source = package.get("source")
    if source and source != "registry+https://github.com/rust-lang/crates.io-index":
        raise SystemExit(f"Unapproved dependency source: {package['name']} {source}")
PY

cp Cargo.toml Cargo.lock rust-toolchain.toml LICENSE README.md "$snapshot/"
cp -R crates third-party examples "$snapshot/"
mkdir -p "$snapshot/scripts" "$snapshot/.cargo"
for script in prepare-offline.ps1 prepare-offline.sh verify-offline.ps1 verify-offline.sh \
    verify-offline-linux.sh test-vless.ps1 test-vless.sh check-boringssl-toolchain.ps1 \
    check-mobile.ps1 check-mobile.sh package-release.ps1 package-release.sh test-desktop-linux.py; do
    cp "scripts/$script" "$snapshot/scripts/"
done
cargo vendor --locked --versioned-dirs "$snapshot/vendor" >/dev/null
cat > "$snapshot/.cargo/config.toml" <<'CONFIG'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"

[net]
offline = true
CONFIG

python3 - "$workspace" "$snapshot" "$metadata_file" <<'PY'
import datetime
import hashlib
import json
import pathlib
import subprocess
import sys

workspace, snapshot = map(pathlib.Path, sys.argv[1:3])
packages = json.loads(pathlib.Path(sys.argv[3]).read_text())["packages"]
vendor = snapshot / "vendor"

def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

inventory = []
for package in sorted(packages, key=lambda value: (value["name"], value["version"])):
    source = package.get("source")
    checksum = None
    if source:
        checksum_path = vendor / f"{package['name']}-{package['version']}" / ".cargo-checksum.json"
        checksum = json.loads(checksum_path.read_text())["package"]
        if not checksum:
            raise SystemExit(f"Missing registry checksum: {package['name']}")
    inventory.append(dict(name=package["name"], version=package["version"],
                          source=source, license=package.get("license"),
                          license_file=pathlib.Path(package["license_file"]).name if package.get("license_file") else None,
                          sha256=checksum,
                          local_patch=package["name"] in ("boring-sys", "route_manager") and not source))

revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=workspace, text=True, capture_output=True)
dirty = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=workspace)
record = dict(format=1, created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
              base_revision=revision.stdout.strip() if revision.returncode == 0 else None,
              working_tree_dirty=bool(dirty),
              cargo=subprocess.check_output(["cargo", "--version"], text=True).strip(),
              rustc=subprocess.check_output(["rustc", "--version"], text=True).strip(),
              packages=inventory)
(snapshot / "dependency-inventory.json").write_text(json.dumps(record, indent=2) + "\n")
files = {path.relative_to(snapshot).as_posix(): sha256(path)
         for path in sorted(snapshot.rglob("*")) if path.is_file()}
checksums = snapshot / "snapshot-files.sha256"
checksums.write_text("".join(f"{digest}  {name}\n" for name, digest in files.items()))
files[checksums.name] = sha256(checksums)
(snapshot / "snapshot-files.json").write_text(json.dumps(files, indent=2) + "\n")
PY

archive="$output_root/$name.tar.gz"
tar -czf "$archive" -C "$output_root" "$name"
python3 - "$archive" "$snapshot" <<'PY'
import hashlib
import json
import pathlib
import sys

archive = pathlib.Path(sys.argv[1])
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
pathlib.Path(f"{archive}.sha256").write_text(f"{digest}  {archive.name}\n", encoding="ascii")
inventory = json.loads((pathlib.Path(sys.argv[2]) / "dependency-inventory.json").read_text())
print(json.dumps(dict(archive=str(archive), sha256=digest, source=sys.argv[2], packages=len(inventory["packages"]))))
PY
