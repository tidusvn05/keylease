#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FLUTTER_DIR="$REPO_DIR/apps/desktop-flutter"
APP_PATH="$FLUTTER_DIR/build/macos/Build/Products/Release/KeyLease.app"
APP_BINARY="$APP_PATH/Contents/MacOS/KeyLease"
HELPER_BINARY="$APP_PATH/Contents/Resources/keylease"
SERVICE_PLIST="$APP_PATH/Contents/Library/LaunchAgents/app.keylease.service.plist"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: this check must run on macOS" >&2
  exit 1
fi
if [[ "$(uname -m)" != "x86_64" ]]; then
  echo "error: expected an Intel Mac (x86_64), got $(uname -m)" >&2
  exit 1
fi

for command in xcodebuild rustup rustc cargo flutter dart lipo codesign; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "error: missing required command: $command" >&2
    exit 1
  fi
done

echo "== Toolchain =="
sw_vers
xcodebuild -version
rustc -vV
flutter --version
flutter doctor -v

if [[ "$(rustc -vV | sed -n 's/^host: //p')" != "x86_64-apple-darwin" ]]; then
  echo "error: Rust host is not x86_64-apple-darwin" >&2
  exit 1
fi

echo "== Rust checks =="
cd "$REPO_DIR"
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release -p keylease-cli

if ! lipo -archs "$REPO_DIR/target/release/keylease" | grep -qw x86_64; then
  echo "error: release CLI does not contain x86_64" >&2
  exit 1
fi

echo "== Flutter checks =="
cd "$FLUTTER_DIR"
flutter pub get
dart format --output=none --set-exit-if-changed lib test
flutter analyze
flutter test
flutter build macos --release

if [[ ! -x "$APP_BINARY" ]]; then
  echo "error: expected app binary not found: $APP_BINARY" >&2
  exit 1
fi
if ! lipo -archs "$APP_BINARY" | grep -qw x86_64; then
  echo "error: KeyLease.app does not contain x86_64" >&2
  exit 1
fi
for architecture in x86_64 arm64; do
  if ! lipo -archs "$HELPER_BINARY" | grep -qw "$architecture"; then
    echo "error: embedded runtime does not contain $architecture" >&2
    exit 1
  fi
done
plutil -lint "$SERVICE_PLIST" >/dev/null
codesign --force --options runtime --sign - "$APP_PATH"
codesign --verify --deep --strict --verbose=2 "$APP_PATH"

echo "== Result =="
echo "Rust CLI: $REPO_DIR/target/release/keylease"
echo "macOS app: $APP_PATH"
echo "Automated Intel macOS checks passed."
