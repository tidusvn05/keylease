#!/usr/bin/env bash
# Cross-compiles the vault core for Android and stages it into the app.
#
# Invoked by the mobile app's Gradle `preBuild`, so a stale .so can never be
# packaged. Safe to run directly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ENV_FILE="${KEYLEASE_ANDROID_ENV:-$HOME/workspace/android-toolchain/env.sh}"
if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

for command in cargo rustup cargo-ndk; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "error: $command is required; source $ENV_FILE first" >&2
    exit 1
  fi
done

# arm64 for devices, x86_64 for emulators. See the abiFilters comment in
# android/app/build.gradle.kts for why armeabi-v7a is excluded.
ABIS="${KEYLEASE_ANDROID_ABIS:-arm64-v8a x86_64}"
OUTPUT="${KEYLEASE_ANDROID_OUTPUT_DIR:-$REPO_DIR/apps/mobile-flutter/android/app/src/main/jniLibs}"
PROFILE="${KEYLEASE_ANDROID_PROFILE:-release}"

# Installed per invocation rather than pinned in rust-toolchain.toml: adding
# them there would make every cargo command in the workspace materialise Android
# std libs, including for contributors who never build for Android.
TOOLCHAIN="$(sed -n 's/^channel = "\(.*\)"/\1/p' "$REPO_DIR/rust-toolchain.toml")"
rustup target add --toolchain "$TOOLCHAIN" aarch64-linux-android x86_64-linux-android >/dev/null

targets=()
for abi in $ABIS; do targets+=(--target "$abi"); done

# Android 15 requires 16 KB-aligned ELF segments on arm64. The NDK linker
# defaults to it, but rustc drives the linker itself, so it must be explicit.
# Verified below rather than trusted.
RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,-z,max-page-size=16384" \
  cargo ndk "${targets[@]}" --platform 24 --output-dir "$OUTPUT" \
    build --locked --"$PROFILE" -p keylease-mobile

READELF="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf"
for abi in $ABIS; do
  so="$OUTPUT/$abi/libkeylease_mobile.so"
  [ -f "$so" ] || { echo "error: $so was not produced" >&2; exit 1; }
  if [ "$abi" = "arm64-v8a" ] && [ -x "$READELF" ]; then
    if ! "$READELF" -l "$so" | grep -q "0x4000"; then
      echo "error: $so is not 16 KB aligned; Android 15 will refuse to load it" >&2
      exit 1
    fi
  fi
  echo "ok $abi $(du -h "$so" | cut -f1)"
done
