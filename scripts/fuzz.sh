#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p target/fuzz-logs
targets=("$@")
if [ "${#targets[@]}" -eq 0 ]; then
    targets=(vless_frames xudp_frames vision_frames)
fi
for target in "${targets[@]}"; do
    case "$target" in
        vless_frames|xudp_frames|vision_frames) ;;
        *) printf 'Unknown fuzz target: %s\n' "$target" >&2; exit 1 ;;
    esac
    log="target/fuzz-logs/$target.log"
    if cargo +nightly-2026-08-01 fuzz run "$target" -- \
        -max_total_time=60 -max_len=16384 -timeout=5 -rss_limit_mb=1024 \
        -print_final_stats=1 > "$log" 2>&1; then
        tail -n 12 "$log"
    else
        tail -n 100 "$log"
        exit 1
    fi
done
