#!/usr/bin/env bash
set -euo pipefail

# Xcode Cloud discovers this hook beside Clyntis.xcodeproj. Use its checkout
# path explicitly because the hook's working directory is ci_scripts.
workspace=${CI_PRIMARY_REPOSITORY_PATH:-$(cd "$(dirname "$0")/../.." && pwd)}
cd "$workspace"
# App Store Connect uses Xcode Cloud's build number for uploaded archives.
# build-ios.sh below applies it and an optional CLYNTIS_APP_VERSION.
if [[ -n ${CI_BUILD_NUMBER:-} ]]; then export CLYNTIS_BUILD_NUMBER=$CI_BUILD_NUMBER; fi
if [[ $(uname -s) != Darwin ]]; then
    printf 'The Xcode Cloud iOS build requires macOS and Xcode.\n' >&2
    exit 1
fi
xcrun --sdk iphoneos --show-sdk-path >/dev/null
xcrun --sdk iphonesimulator --show-sdk-path >/dev/null

export HOMEBREW_NO_AUTO_UPDATE=1
if ! command -v cmake >/dev/null 2>&1; then
    brew install cmake
fi

export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
if ! command -v rustup >/dev/null 2>&1; then
    installer=$(mktemp -t clyntis-rustup)
    trap 'rm -f "$installer"' EXIT
    curl --proto '=https' --tlsv1.2 --fail --show-error --silent --location \
        --retry 3 https://sh.rustup.rs -o "$installer"
    sh "$installer" -y --profile minimal --default-toolchain none --no-modify-path
fi

# Install the pinned toolchain and iOS targets explicitly: rustup 1.28+ no
# longer installs the active toolchain implicitly from `rustup show`.
channel=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)
if [[ -z $channel ]]; then
    printf 'Cannot read the Rust channel from rust-toolchain.toml.\n' >&2
    exit 1
fi
rustup toolchain install "$channel" --profile minimal --no-self-update \
    --target aarch64-apple-ios --target aarch64-apple-ios-sim
# Running inside the checkout selects the version in rust-toolchain.toml.
rustup show active-toolchain

# Bindgen needs the libclang bundled with the workflow's selected Xcode.
export LIBCLANG_PATH="$(dirname "$(xcrun --find clang)")/../lib"
if [[ ! -f "$LIBCLANG_PATH/libclang.dylib" ]]; then
    printf 'Missing libclang in the selected Xcode toolchain: %s\n' "$LIBCLANG_PATH" >&2
    exit 1
fi

printf 'Fetching all locked Rust workspace dependencies.\n'
# The offline build resolves workspace dependencies beyond the iOS target
# graph. A target-filtered fetch leaves crates such as async-channel absent
# on a fresh cloud worker, even though a warm local cache hides the problem.
cargo fetch --locked
printf 'Building Release ClyntisCore.xcframework for device and simulator.\n'
# Build only the framework: regenerating the project would overwrite signing
# and other settings saved in the committed Xcode project and Info.plists.
bash scripts/build-ios.sh --release --skip-project-generation
