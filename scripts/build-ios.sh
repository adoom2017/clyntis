#!/usr/bin/env bash
set -euo pipefail
workspace=$(cd "$(dirname "$0")/.." && pwd)
configuration=debug
if [[ $# -gt 0 && $1 == --release ]]; then configuration=release; shift; fi
if [[ $# -ne 0 ]]; then printf 'Usage: bash scripts/build-ios.sh [--release]\n' >&2; exit 2; fi
if [[ $(uname -s) != Darwin ]]; then printf 'iOS requires macOS and Xcode.\n' >&2; exit 1; fi
command -v xcodegen >/dev/null
xcrun --sdk iphoneos --show-sdk-path >/dev/null
xcrun --sdk iphonesimulator --show-sdk-path >/dev/null
export IPHONEOS_DEPLOYMENT_TARGET=17.0
cd "$workspace"
for target in aarch64-apple-ios aarch64-apple-ios-sim; do
    if [[ $configuration == release ]]; then
        cargo build -p meta-ffi --target "$target" --locked --offline --release
    else
        cargo build -p meta-ffi --target "$target" --locked --offline
    fi
done
headers="$workspace/ios/build/core-headers"
mkdir -p "$headers"
cp crates/ffi/include/clyntis.h "$headers/clyntis.h"
printf 'module ClyntisCore {\n  header "clyntis.h"\n  export *\n}\n' > "$headers/module.modulemap"
output="$workspace/ios/Frameworks/ClyntisCore.xcframework"
if [[ -d $output ]]; then rm -rf "$output"; fi
xcodebuild -create-xcframework \
    -library "target/aarch64-apple-ios/$configuration/libmeta_ffi.a" -headers "$headers" \
    -library "target/aarch64-apple-ios-sim/$configuration/libmeta_ffi.a" -headers "$headers" \
    -output "$output"
xcodegen generate --spec ios/project.yml
printf 'Open ios/Clyntis.xcodeproj; set one development team for both app and tunnel targets.\n'
