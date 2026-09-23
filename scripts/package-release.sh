#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 2 ]]; then
    printf 'Usage: bash scripts/package-release.sh [OUTPUT_DIRECTORY [TARGET]]\n' >&2
    exit 2
fi

workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output_root=${1:-"$workspace/dist"}
mkdir -p "$output_root"
output_root=$(cd "$output_root" && pwd)
target=${2:-}
explicit_target=false
if [[ -n $target ]]; then
    explicit_target=true
else
    target=$(rustc -vV | sed -n 's/^host: //p')
fi
case "$target" in
    x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu|x86_64-apple-darwin|aarch64-apple-darwin) ;;
    *) printf 'Unsupported Unix desktop target: %s\n' "$target" >&2; exit 2 ;;
esac

if [[ $(uname -s) == Darwin ]]; then
    export MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-12.0}
fi
cd "$workspace"
options=(build --workspace --release --locked --offline)
if $explicit_target; then options+=(--target "$target"); fi
cargo "${options[@]}"

metadata_file=$(mktemp)
trap 'rm -f "$metadata_file"' EXIT
cargo metadata --format-version 1 --locked --offline --filter-platform "$target" > "$metadata_file"
version=$(python3 - "$metadata_file" <<'PY'
import json
import sys

metadata = json.load(open(sys.argv[1]))
print(next(package["version"] for package in metadata["packages"] if package["name"] == "clyntis"))
PY
)
package_root=$(mktemp -d "$output_root/clyntis-$version-$target-XXXXXXXX")
name=$(basename "$package_root")
build_root=$(python3 - "$metadata_file" <<'PY'
import json
import sys

print(json.load(open(sys.argv[1]))["target_directory"])
PY
)
if $explicit_target; then build_root="$build_root/$target"; fi
build_root="$build_root/release"

case "$target" in
    *apple*) artifacts=(clyntis libmeta_ffi.dylib libmeta_ffi.a) ;;
    *) artifacts=(clyntis libmeta_ffi.so libmeta_ffi.a) ;;
esac
for artifact in "${artifacts[@]}"; do
    cp "$build_root/$artifact" "$package_root/"
done
cp "$workspace/README.md" "$workspace/LICENSE" "$package_root/"
cp -R "$workspace/examples" "$package_root/"
mkdir -p "$package_root/crates/ffi" "$package_root/third-party"
cp -R "$workspace/crates/ffi/include" "$package_root/crates/ffi/"
cp "$workspace"/third-party/*.md "$package_root/third-party/"

python3 - "$workspace" "$package_root" "$target" "$version" "$metadata_file" <<'PY'
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys
from urllib.parse import urlparse

workspace, root = map(pathlib.Path, sys.argv[1:3])
target, version, metadata_path = sys.argv[3:]
metadata = json.loads(pathlib.Path(metadata_path).read_text())
packages = metadata["packages"]
notice_pattern = re.compile(r"^(LICENSE|LICENCE|COPYING|NOTICE|COPYRIGHT)([._-].*|S)?$", re.I)

def notices(directory):
    return sorted(path for path in directory.iterdir() if path.is_file() and notice_pattern.match(path.name))

def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

inventory = []
licenses = root / "third-party-licenses"
licenses.mkdir()
for package in sorted(packages, key=lambda value: (value["name"], value["version"])):
    source = package.get("source")
    if source and source != "registry+https://github.com/rust-lang/crates.io-index":
        raise SystemExit(f"Unapproved dependency source: {package['name']}")
    if package["id"] in metadata["workspace_members"]:
        continue
    directory = pathlib.Path(package["manifest_path"]).parent
    files = notices(directory)
    license_file = package.get("license_file")
    if license_file:
        path = pathlib.Path(license_file)
        files.append(path if path.is_absolute() else directory / path)
    notice_source = f"{package['name']}-{package['version']}"
    if not files:
        companions = (item for item in packages if item["id"] != package["id"]
                      and package.get("repository") and item.get("repository") == package["repository"])
        for candidate in sorted(companions, key=lambda item: (item["name"], item["version"]), reverse=True):
            files = notices(pathlib.Path(candidate["manifest_path"]).parent)
            if files:
                notice_source = f"{candidate['name']}-{candidate['version']}"
                break
    if not files and package.get("repository"):
        repository_name = pathlib.Path(urlparse(package["repository"]).path.rstrip("/")).stem
        override = workspace / "third-party/license-overrides" / repository_name
        if override.is_dir():
            files = sorted(path for path in override.iterdir() if path.is_file())
            notice_source = f"repository-license:{repository_name}"
    if not files:
        raise SystemExit(f"Upstream workspace license notices missing for {package['name']}.")
    destination = licenses / f"{package['name']}-{package['version']}"
    destination.mkdir()
    for path in set(files):
        shutil.copy2(path, destination / path.name)
    inventory.append(dict(name=package["name"], version=package["version"],
                          license=package.get("license"), source=source, notice_source=notice_source))

(root / "dependencies.json").write_text(json.dumps(inventory, indent=2) + "\n")
files = {path.relative_to(root).as_posix(): sha256(path) for path in sorted(root.rglob("*")) if path.is_file()}
snapshot = workspace / "snapshot-files.json"
record = dict(format=1, version=version, target=target,
              rustc=subprocess.check_output(["rustc", "--version"], text=True).strip(),
              cargo_lock_sha256=sha256(workspace / "Cargo.lock"),
              source_snapshot_manifest_sha256=sha256(snapshot) if snapshot.is_file() else None,
              files=files)
(root / "release-manifest.json").write_text(json.dumps(record, indent=2) + "\n")
PY

archive="$output_root/$name.tar.gz"
tar -czf "$archive" -C "$output_root" "$name"
python3 - "$archive" "$package_root" "$target" <<'PY'
import hashlib
import json
import pathlib
import sys

archive = pathlib.Path(sys.argv[1])
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
pathlib.Path(f"{archive}.sha256").write_text(f"{digest}  {archive.name}\n", encoding="ascii")
print(json.dumps(dict(archive=str(archive), sha256=digest, package=sys.argv[2], target=sys.argv[3])))
PY
