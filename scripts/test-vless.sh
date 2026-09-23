#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! -f $1 ]]; then
    printf 'Usage: bash scripts/test-vless.sh /path/to/verified/xray\n' >&2
    exit 2
fi

export XRAY_BIN=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
cd "$(dirname "${BASH_SOURCE[0]}")/.."
cargo test -p meta-protocol --locked --offline --test xray_vless --test reality_interop -- --ignored --nocapture
