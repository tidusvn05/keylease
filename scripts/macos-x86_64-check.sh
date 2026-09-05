#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FLUTTER_DIR="$REPO_DIR/apps/desktop-flutter"
APP_PATH="$FLUTTER_DIR/build/macos/Build/Products/Release/KeyLease.app"
APP_BINARY="$APP_PATH/Contents/MacOS/KeyLease"

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

if ! rustc -vV | grep -q '^host: x86_64-apple-darwin$'; then
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
codesign --verify --deep --strict --verbose=2 "$APP_PATH"

echo "== Result =="
echo "Rust CLI: $REPO_DIR/target/release/keylease"
echo "macOS app: $APP_PATH"
echo "Automated Intel macOS checks passed. Continue with the manual checklist in docs/macos-x86_64-build-test.md."
