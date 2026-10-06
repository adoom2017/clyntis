#!/usr/bin/env bash
set -euo pipefail
workspace=$(cd "$(dirname "$0")/.." && pwd)
configuration=debug
generate_project=true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --release) configuration=release ;;
        --skip-project-generation) generate_project=false ;;
        *) printf 'Usage: bash scripts/build-ios.sh [--release] [--skip-project-generation]\n' >&2; exit 2 ;;
    esac
    shift
done
if [[ $(uname -s) != Darwin ]]; then printf 'iOS requires macOS and Xcode.\n' >&2; exit 1; fi
if [[ $generate_project == true ]]; then command -v xcodegen >/dev/null; fi
xcrun --sdk iphoneos --show-sdk-path >/dev/null
xcrun --sdk iphonesimulator --show-sdk-path >/dev/null
export IPHONEOS_DEPLOYMENT_TARGET=17.0
cd "$workspace"
target_dir=${CARGO_TARGET_DIR:-"$workspace/target"}
mkdir -p "$target_dir"
target_dir=$(cd "$target_dir" && pwd)
for target in aarch64-apple-ios aarch64-apple-ios-sim; do
    if [[ $configuration == release ]]; then
        cargo build -p meta-ffi --target "$target" --target-dir "$target_dir" --locked --offline --release
    else
        cargo build -p meta-ffi --target "$target" --target-dir "$target_dir" --locked --offline
    fi
done
headers="$workspace/ios/build/core-headers"
mkdir -p "$headers"
cp crates/ffi/include/clyntis.h "$headers/clyntis.h"
printf 'module ClyntisCore {\n  header "clyntis.h"\n  export *\n}\n' > "$headers/module.modulemap"
output="$workspace/ios/Frameworks/ClyntisCore.xcframework"
if [[ -d $output ]]; then rm -rf "$output"; fi
xcodebuild -create-xcframework \
    -library "$target_dir/aarch64-apple-ios/$configuration/libmeta_ffi.a" -headers "$headers" \
    -library "$target_dir/aarch64-apple-ios-sim/$configuration/libmeta_ffi.a" -headers "$headers" \
    -output "$output"
if [[ $generate_project == true ]]; then
    xcodegen generate --spec ios/project.yml
    printf 'Open ios/Clyntis.xcodeproj; set one development team for both app and tunnel targets.\n'
else
    printf 'Core XCFramework ready; existing Xcode project preserved.\n'
fi
