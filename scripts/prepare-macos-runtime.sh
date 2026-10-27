#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${1:?output directory is required}"
CONFIGURATION="${2:-Release}"
HOST_ARCH="$(uname -m)"
source "$SCRIPT_DIR/macos-signing-identity.sh"

mkdir -p "$OUTPUT_DIR/Resources" "$OUTPUT_DIR/Library/LaunchAgents"

if [[ "$CONFIGURATION" == "Release" || "$CONFIGURATION" == "Profile" ]]; then
  rustup target add x86_64-apple-darwin aarch64-apple-darwin
  cargo build --locked --release -p keylease --target x86_64-apple-darwin
  cargo build --locked --release -p keylease --target aarch64-apple-darwin
  lipo -create \
    "$REPO_DIR/target/x86_64-apple-darwin/release/keylease" \
    "$REPO_DIR/target/aarch64-apple-darwin/release/keylease" \
    -output "$OUTPUT_DIR/Resources/keylease"
else
  TARGET="${HOST_ARCH/arm64/aarch64}-apple-darwin"
  rustup target add "$TARGET"
  cargo build --locked -p keylease --target "$TARGET"
  cp "$REPO_DIR/target/$TARGET/debug/keylease" "$OUTPUT_DIR/Resources/keylease"
fi

cp "$REPO_DIR/apps/desktop-macos-app/LaunchAgents/app.keylease.service.plist" \
  "$OUTPUT_DIR/Library/LaunchAgents/app.keylease.service.plist"
chmod 0700 "$OUTPUT_DIR/Resources/keylease"
codesign --force --options runtime --sign "$EXPANDED_CODE_SIGN_IDENTITY" "$OUTPUT_DIR/Resources/keylease"
