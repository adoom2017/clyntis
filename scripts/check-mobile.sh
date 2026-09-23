#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
    printf 'Usage: bash scripts/check-mobile.sh ios [--release] | android NDK_PATH [--release]\n' >&2
    exit 2
fi

platform=$1
shift
workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
options=(--locked --offline)

case "$platform" in
    ios)
        if [[ $(uname -s) != Darwin ]]; then
            printf 'iOS compilation requires macOS with Xcode and the iPhoneOS SDK.\n' >&2
            exit 1
        fi
        xcrun --sdk iphoneos --show-sdk-path >/dev/null
        export IPHONEOS_DEPLOYMENT_TARGET=12.0
        target=aarch64-apple-ios
        ;;
    android)
        if [[ $# -eq 0 || $1 == --release ]]; then
            printf 'Supply the Android NDK path.\n' >&2
            exit 2
        fi
        export ANDROID_NDK_HOME=$1
        shift
        case "$(uname -s)-$(uname -m)" in
            Linux-x86_64) host_tag=linux-x86_64 ;;
            Darwin-arm64) host_tag=darwin-x86_64 ;;
            Darwin-x86_64) host_tag=darwin-x86_64 ;;
            *) printf 'Unsupported Android NDK host.\n' >&2; exit 1 ;;
        esac
        bin="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$host_tag/bin"
        export CC_aarch64_linux_android="$bin/aarch64-linux-android24-clang"
        export CXX_aarch64_linux_android="$bin/aarch64-linux-android24-clang++"
        export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$CC_aarch64_linux_android
        export AR_aarch64_linux_android="$bin/llvm-ar"
        for tool in "$CC_aarch64_linux_android" "$CXX_aarch64_linux_android" "$AR_aarch64_linux_android"; do
            if [[ ! -f $tool ]]; then
                printf 'Missing Android NDK tool: %s\n' "$tool" >&2
                exit 1
            fi
        done
        target=aarch64-linux-android
        ;;
    *) printf 'Unsupported platform: %s\n' "$platform" >&2; exit 2 ;;
esac

if [[ $# -gt 0 ]]; then
    if [[ $# -ne 1 || $1 != --release ]]; then
        printf 'Unexpected argument: %s\n' "$1" >&2
        exit 2
    fi
    options+=(--release)
fi

cd "$workspace"
cargo build -p meta-ffi --target "$target" "${options[@]}"
