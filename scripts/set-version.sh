#!/usr/bin/env bash
# The desktop app's version (desktop/package.json) is the product version;
# the Rust crates and the iOS app follow it (the fuzz harness does not).
#   bash scripts/set-version.sh X.Y.Z   set it everywhere
#   bash scripts/set-version.sh         re-sync everything to package.json
#   bash scripts/set-version.sh --check fail if anything differs (CI)
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

mode=sync
version=
case ${1:-} in
    '') ;;
    --check) mode=check ;;
    *) version=$1 ;;
esac
if [[ -z $version ]]; then
    version=$(python3 -c 'import json; print(json.load(open("desktop/package.json"))["version"])')
fi
if [[ ! $version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    printf 'Version must be X.Y.Z, for example 1.2.3.\n' >&2; exit 2
fi

python3 - "$mode" "$version" <<'PY'
import json, re, sys
mode, version = sys.argv[1:]
stale = []

def text(path, pattern, replacement):
    with open(path) as f:
        old = f.read()
    new, count = re.subn(pattern, replacement, old, count=1, flags=re.M)
    if count != 1:
        sys.exit(f"{path}: version not found")
    if new != old:
        stale.append(path)
        if mode == "sync":
            with open(path, "w") as f:
                f.write(new)

def package(path, lock):
    with open(path) as f:
        data = json.load(f)
    current = [data["version"]] + ([data["packages"][""]["version"]] if lock else [])
    if any(v != version for v in current):
        stale.append(path)
        if mode == "sync":
            data["version"] = version
            if lock:
                data["packages"][""]["version"] = version
            with open(path, "w") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                f.write("\n")

package("desktop/package.json", False)
package("desktop/package-lock.json", True)
workspace = r'(\[workspace\.package\]\n(?:[^\[\n].*\n)*?version = ")[^"]*(")'
text("Cargo.toml", workspace, rf"\g<1>{version}\g<2>")
text("desktop/Cargo.toml", workspace, rf"\g<1>{version}\g<2>")
text("ios/Version.xcconfig", r"^(MARKETING_VERSION = ).*$", rf"\g<1>{version}")
if stale and mode == "check":
    sys.exit(f"Not at version {version}: {', '.join(stale)}. Run bash scripts/set-version.sh.")
PY

# Lockfiles record the workspace crates' versions too; --workspace touches
# only those entries, and --locked makes the check fail if any is stale.
for manifest in Cargo.toml desktop/Cargo.toml fuzz/Cargo.toml; do
    if [[ $mode == check ]]; then
        cargo update --manifest-path "$manifest" --workspace --locked --quiet
    else
        cargo update --manifest-path "$manifest" --workspace --quiet
    fi
done
if [[ $mode == check ]]; then
    printf 'Everything is at version %s.\n' "$version"
else
    printf 'Version set to %s.\n' "$version"
fi
