#!/usr/bin/env bash
set -euo pipefail

workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
python3 - "$workspace" <<'PY'
import json
import pathlib
import sys

workspace = pathlib.Path(sys.argv[1])
seeds = json.loads((workspace / "fuzz/seeds.json").read_text())
for target, entries in seeds.items():
    directory = workspace / "fuzz/corpus" / target
    directory.mkdir(parents=True, exist_ok=True)
    for name, hex_data in entries.items():
        (directory / name).write_bytes(bytes.fromhex(hex_data))
PY
