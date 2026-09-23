#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    printf 'Usage: bash scripts/verify-offline-linux.sh ARCHIVE.tar.gz\n' >&2
    exit 1
fi
archive=$(realpath "$1")
cd "$(dirname "$archive")"
sha256sum --check "$archive.sha256"
verification_root=$(mktemp -d /tmp/clyntis-offline.XXXXXX)
tar -xzf "$archive" -C "$verification_root"
source_name=$(basename "$archive" .tar.gz)
export CARGO_HOME="$verification_root/cargo-home"
export CARGO_TARGET_DIR="$verification_root/build"
export CARGO_NET_OFFLINE=true
export PATH="$HOME/.cargo/bin:$PATH"
mkdir -p "$CARGO_HOME" "$CARGO_TARGET_DIR"
cd "$verification_root/$source_name"
sha256sum --check --quiet snapshot-files.sha256
expected_files=$(wc -l < snapshot-files.sha256)
actual_files=$(find . -type f | wc -l)
if [ "$actual_files" -ne "$((expected_files + 2))" ]; then
    printf 'Snapshot file inventory does not match extracted source.\n' >&2
    exit 1
fi

if ! rustup run 1.93.1 cargo build --workspace --release --locked --offline > "$archive.linux-build.log" 2>&1; then
    tail -n 80 "$archive.linux-build.log"
    exit 1
fi
tail -n 5 "$archive.linux-build.log"
binary="$CARGO_TARGET_DIR/release/clyntis"
"$binary" -v
"$binary" -f examples/vless.yaml -t
if ! rustup run 1.93.1 cargo test --workspace --locked --offline > "$archive.linux-test.log" 2>&1; then
    tail -n 100 "$archive.linux-test.log"
    exit 1
fi
tail -n 35 "$archive.linux-test.log"
{
    printf 'Source: %s\nEmpty initial Cargo cache and target directory; --locked --offline.\n' "$PWD"
    rustup run 1.93.1 rustc -vV
    sha256sum "$binary"
} | tee "$archive.linux-verification.txt"
