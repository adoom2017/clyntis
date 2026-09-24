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

codesign_identity=
codesign_mode=${CLYNTIS_CODESIGN:-auto}
case "$codesign_mode" in
    auto|off) ;;
    *) printf 'CLYNTIS_CODESIGN must be auto or off.\n' >&2; exit 2 ;;
esac
if [[ -n ${CLYNTIS_CODESIGN_IDENTITY:-} && $codesign_mode == off ]]; then
    printf 'CLYNTIS_CODESIGN_IDENTITY cannot be used with CLYNTIS_CODESIGN=off.\n' >&2
    exit 2
fi
if [[ -n ${CLYNTIS_CODESIGN_IDENTITY:-} && ( $target != *apple-darwin || $(uname -s) != Darwin ) ]]; then
    printf 'CLYNTIS_CODESIGN_IDENTITY requires a macOS target built on macOS.\n' >&2
    exit 2
fi
notary_profile=${CLYNTIS_NOTARY_PROFILE:-}
if [[ -n $notary_profile ]]; then
    if [[ $target != *apple-darwin || $(uname -s) != Darwin || $codesign_mode == off ]]; then
        printf 'CLYNTIS_NOTARY_PROFILE requires macOS signing on a macOS target.\n' >&2
        exit 2
    fi
    if ! xcrun --find notarytool >/dev/null || ! xcrun --find stapler >/dev/null; then
        printf 'Notarization requires Xcode command-line tools with notarytool and stapler.\n' >&2
        exit 1
    fi
fi
if [[ $target == *apple-darwin && $(uname -s) == Darwin && $codesign_mode == auto ]]; then
    if ! identities_output=$(security find-identity -v -p codesigning); then
        printf 'Failed to inspect macOS code-signing identities.\n' >&2
        exit 1
    fi
    developer_ids=()
    developer_names=()
    while IFS= read -r line; do
        if [[ $line =~ ^[[:space:]]*[0-9]+\)[[:space:]]+([[:xdigit:]]{40})[[:space:]]+\"(Developer\ ID\ Application:[^\"]+)\" ]]; then
            identity_id=${BASH_REMATCH[1]}
            identity_name=${BASH_REMATCH[2]}
            found=false
            for ((index=0; index<${#developer_ids[@]}; index++)); do
                if [[ ${developer_ids[index]} == "$identity_id" ]]; then found=true; break; fi
            done
            if ! $found; then
                developer_ids+=("$identity_id")
                developer_names+=("$identity_name")
            fi
        fi
    done <<< "$identities_output"

    if [[ -n ${CLYNTIS_CODESIGN_IDENTITY:-} ]]; then
        for ((index=0; index<${#developer_ids[@]}; index++)); do
            if [[ ${CLYNTIS_CODESIGN_IDENTITY} == "${developer_ids[index]}" || ${CLYNTIS_CODESIGN_IDENTITY} == "${developer_names[index]}" ]]; then
                codesign_identity=${developer_ids[index]}
                break
            fi
        done
        if [[ -z $codesign_identity ]]; then
            printf 'CLYNTIS_CODESIGN_IDENTITY is not a valid Developer ID Application identity in the keychain.\n' >&2
            exit 2
        fi
    elif [[ ${#developer_ids[@]} -eq 1 ]]; then
        codesign_identity=${developer_ids[0]}
    elif [[ ${#developer_ids[@]} -gt 1 ]]; then
        printf 'Multiple Developer ID Application identities found; set CLYNTIS_CODESIGN_IDENTITY to the desired SHA-1 or full name:\n' >&2
        for ((index=0; index<${#developer_ids[@]}; index++)); do
            printf '  %s %s\n' "${developer_ids[index]}" "${developer_names[index]}" >&2
        done
        exit 2
    else
        printf 'No Developer ID Application identity found; creating an unsigned macOS package.\n' >&2
    fi
fi
if [[ -n $notary_profile && -z $codesign_identity ]]; then
    printf 'Notarization requires a valid Developer ID Application signing identity.\n' >&2
    exit 2
fi

if [[ $(uname -s) == Darwin ]]; then
    export MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-12.0}
fi
cd "$workspace"
options=(build --workspace --release --locked --offline)
if $explicit_target; then options+=(--target "$target"); fi
cargo "${options[@]}"

metadata_file=$(mktemp)
notary_dir=
trap 'rm -f "$metadata_file"; if [[ -n $notary_dir ]]; then rm -rf "$notary_dir"; fi' EXIT
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
if [[ -n $codesign_identity ]]; then
    for artifact in libmeta_ffi.dylib clyntis; do
        codesign --force --sign "$codesign_identity" --options runtime --timestamp "$package_root/$artifact"
        codesign --verify --strict --verbose=2 "$package_root/$artifact"
    done
fi
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

notarization_id=
notarized_dmg=
if [[ -n $notary_profile ]]; then
    notary_dir=$(mktemp -d "$output_root/.${name}.notary-XXXXXXXX")
    submission_dmg="$notary_dir/$name.dmg"
    hdiutil create -srcfolder "$package_root" -volname "$name" -format UDZO "$submission_dmg"
    notary_response="$notary_dir/response.json"
    if ! xcrun notarytool submit "$submission_dmg" --keychain-profile "$notary_profile" --wait --output-format json > "$notary_response"; then
        cat "$notary_response" >&2
        printf 'Notarization submission failed; check your credentials, network, or submission status.\n' >&2
        exit 1
    fi
    notary_result=$(python3 - "$notary_response" <<'PY'
import json
import pathlib
import sys

response = json.loads(pathlib.Path(sys.argv[1]).read_text())
print(response.get("status", ""), response.get("id", ""), sep="\t")
PY
)
    IFS=$'\t' read -r notary_status notarization_id <<< "$notary_result"
    if [[ $notary_status != Accepted || -z $notarization_id ]]; then
        printf 'Notarization was not accepted (status: %s, id: %s).\n' "$notary_status" "$notarization_id" >&2
        if [[ -n $notarization_id ]]; then
            xcrun notarytool log "$notarization_id" --keychain-profile "$notary_profile" >&2 || true
        fi
        exit 1
    fi
    xcrun stapler staple "$submission_dmg"
    xcrun stapler validate "$submission_dmg"
    notarized_dmg="$output_root/$name.dmg"
    mv "$submission_dmg" "$notarized_dmg"
fi

archive="$output_root/$name.tar.gz"
tar -czf "$archive" -C "$output_root" "$name"
python3 - "$archive" "$package_root" "$target" "$notarized_dmg" "$notarization_id" <<'PY'
import hashlib
import json
import pathlib
import sys

archive = pathlib.Path(sys.argv[1])
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
pathlib.Path(f"{archive}.sha256").write_text(f"{digest}  {archive.name}\n", encoding="ascii")
result = dict(archive=str(archive), sha256=digest, package=sys.argv[2], target=sys.argv[3])
if sys.argv[4]:
    dmg = pathlib.Path(sys.argv[4])
    dmg_digest = hashlib.sha256(dmg.read_bytes()).hexdigest()
    pathlib.Path(f"{dmg}.sha256").write_text(f"{dmg_digest}  {dmg.name}\n", encoding="ascii")
    result.update(dmg=str(dmg), dmg_sha256=dmg_digest, notarization_id=sys.argv[5])
print(json.dumps(result))
PY
