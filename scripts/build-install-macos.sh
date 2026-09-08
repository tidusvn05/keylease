#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FLUTTER_DIR="$REPO_DIR/apps/desktop-flutter"
APP_PATH="$FLUTTER_DIR/build/macos/Build/Products/Release/KeyLease.app"
APP_BINARY="$APP_PATH/Contents/MacOS/KeyLease"
HELPER_BINARY="$APP_PATH/Contents/Resources/keylease"
SERVICE_PLIST="$APP_PATH/Contents/Library/LaunchAgents/app.keylease.service.plist"
APPLICATIONS_DIR="${KEYLEASE_APPLICATIONS_DIR:-/Applications}"
INSTALLED_APP="$APPLICATIONS_DIR/KeyLease.app"
CLI_INSTALL_DIR="${KEYLEASE_CLI_INSTALL_DIR:-$HOME/.local/bin}"
CLI_LINK="$CLI_INSTALL_DIR/keylease"
CLI_TARGET="$INSTALLED_APP/Contents/Resources/keylease"
FLUTTER_SDK="${KEYLEASE_FLUTTER_SDK:-$HOME/develop/flutter-3.47.2}"
FLUTTER_BIN="$FLUTTER_SDK/bin/flutter"
EXPECTED_FLUTTER_VERSION="3.47.2"
RUN_FULL_CHECKS=false
BACKUP_APP=""

usage() {
  cat <<'EOF'
Usage: ./scripts/build-install-macos.sh [--full]

Build and install KeyLease.app into /Applications.

  --full  Run the complete Rust and Flutter acceptance checks before install.

Environment overrides:
  KEYLEASE_FLUTTER_SDK      Flutter SDK path (default: ~/develop/flutter-3.47.2)
  KEYLEASE_APPLICATIONS_DIR Install directory (default: /Applications)
  KEYLEASE_CLI_INSTALL_DIR  CLI directory (default: ~/.local/bin)
EOF
}

for argument in "$@"; do
  case "$argument" in
    --full)
      RUN_FULL_CHECKS=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $argument" >&2
      usage >&2
      exit 2
      ;;
  esac
done

restore_previous_app() {
  local exit_status=$?
  if [[ $exit_status -ne 0 && -n "$BACKUP_APP" && -d "$BACKUP_APP" ]]; then
    echo "Install failed; restoring the previous KeyLease.app." >&2
    rm -rf "$INSTALLED_APP"
    mv "$BACKUP_APP" "$INSTALLED_APP"
  fi
  exit "$exit_status"
}
trap restore_previous_app EXIT

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: this script must run on macOS" >&2
  exit 1
fi

for command in cargo rustup lipo codesign plutil ditto osascript pgrep pkill launchctl; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "error: missing required command: $command" >&2
    exit 1
  fi
done

if [[ ! -x "$FLUTTER_BIN" ]]; then
  echo "error: Flutter SDK not found at $FLUTTER_SDK" >&2
  echo "Set KEYLEASE_FLUTTER_SDK to the Flutter $EXPECTED_FLUTTER_VERSION SDK." >&2
  exit 1
fi

if [[ -e "$CLI_LINK" || -L "$CLI_LINK" ]]; then
  if [[ ! -L "$CLI_LINK" || "$(readlink "$CLI_LINK")" != "$CLI_TARGET" ]]; then
    echo "error: refusing to replace unrelated CLI path: $CLI_LINK" >&2
    exit 1
  fi
fi

FLUTTER_VERSION="$($FLUTTER_BIN --version | sed -n '1s/^Flutter \([^ ]*\).*/\1/p')"
if [[ "$FLUTTER_VERSION" != "$EXPECTED_FLUTTER_VERSION" ]]; then
  echo "error: expected Flutter $EXPECTED_FLUTTER_VERSION, got ${FLUTTER_VERSION:-unknown}" >&2
  exit 1
fi

echo "== Build KeyLease for macOS =="
if [[ "$RUN_FULL_CHECKS" == true ]]; then
  PATH="$FLUTTER_SDK/bin:$PATH" "$REPO_DIR/scripts/macos-x86_64-check.sh"
else
  echo "Fast incremental build (use --full for the complete acceptance suite)."
  cd "$FLUTTER_DIR"
  "$FLUTTER_BIN" build macos --release
fi

if [[ ! -x "$APP_BINARY" ]]; then
  echo "error: app binary not found: $APP_BINARY" >&2
  exit 1
fi
if ! lipo -archs "$APP_BINARY" | grep -qw x86_64; then
  echo "error: KeyLease.app does not contain x86_64" >&2
  exit 1
fi
if [[ ! -x "$HELPER_BINARY" || ! -f "$SERVICE_PLIST" ]]; then
  echo "error: embedded KeyLease background runtime is incomplete" >&2
  exit 1
fi
for architecture in x86_64 arm64; do
  if ! lipo -archs "$HELPER_BINARY" | grep -qw "$architecture"; then
    echo "error: embedded runtime does not contain $architecture" >&2
    exit 1
  fi
done
plutil -lint "$SERVICE_PLIST" >/dev/null
# The runtime phase is always re-run. On an incremental Xcode build the outer
# bundle seal may otherwise remain cached after the nested helper is re-signed.
codesign --force --options runtime --sign - "$APP_PATH"
codesign --verify --deep --strict --verbose=2 "$APP_PATH"

echo "== Install KeyLease.app =="
if [[ ! -d "$APPLICATIONS_DIR" ]]; then
  echo "error: install directory does not exist: $APPLICATIONS_DIR" >&2
  exit 1
fi

if pgrep -x KeyLease >/dev/null 2>&1; then
  echo "Quitting the running KeyLease app..."
  if ! osascript -e 'tell application id "app.keylease.desktop" to quit' >/dev/null 2>&1; then
    echo "The app declined the Quit event; sending SIGTERM."
    # The app can exit between the check and pkill; that race is success.
    pkill -TERM -x KeyLease || true
  fi
  for _ in {1..20}; do
    if ! pgrep -x KeyLease >/dev/null 2>&1; then
      break
    fi
    sleep 0.25
  done
  if pgrep -x KeyLease >/dev/null 2>&1; then
    echo "error: KeyLease did not quit; install was not attempted" >&2
    exit 1
  fi
fi

if [[ -e "$INSTALLED_APP" ]]; then
  BACKUP_APP="$APPLICATIONS_DIR/.KeyLease.app.backup.$$"
  mv "$INSTALLED_APP" "$BACKUP_APP"
fi

ditto "$APP_PATH" "$INSTALLED_APP"
codesign --verify --deep --strict --verbose=2 "$INSTALLED_APP"

# SMAppService keeps the already-running executable mapped after its containing
# app bundle is replaced. Restart the registered job so an updated UI never
# talks to an older IPC contract. A vault restart is intentionally locked.
SERVICE_LABEL="gui/$(id -u)/app.keylease.service"
if launchctl print "$SERVICE_LABEL" >/dev/null 2>&1; then
  OLD_SERVICE_PID="$(launchctl print "$SERVICE_LABEL" | sed -n 's/^[[:space:]]*pid = \([0-9][0-9]*\)$/\1/p' | head -n 1)"
  launchctl kill SIGTERM "$SERVICE_LABEL"
  for _ in {1..20}; do
    NEW_SERVICE_PID="$(launchctl print "$SERVICE_LABEL" 2>/dev/null | sed -n 's/^[[:space:]]*pid = \([0-9][0-9]*\)$/\1/p' | head -n 1)"
    if [[ -n "$NEW_SERVICE_PID" && "$NEW_SERVICE_PID" != "$OLD_SERVICE_PID" ]]; then
      break
    fi
    sleep 0.25
  done
  if [[ -z "${NEW_SERVICE_PID:-}" || "$NEW_SERVICE_PID" == "$OLD_SERVICE_PID" ]]; then
    echo "error: installed background service did not restart" >&2
    exit 1
  fi
fi

mkdir -p "$CLI_INSTALL_DIR"
ln -sfn "$CLI_TARGET" "$CLI_LINK"
if [[ ! -x "$CLI_LINK" ]]; then
  echo "error: installed CLI is not executable: $CLI_LINK" >&2
  exit 1
fi

if [[ -n "$BACKUP_APP" && -d "$BACKUP_APP" ]]; then
  rm -rf "$BACKUP_APP"
fi
BACKUP_APP=""

echo "Installed: $INSTALLED_APP"
echo "CLI: $CLI_LINK"
echo "Architecture: $(lipo -archs "$INSTALLED_APP/Contents/MacOS/KeyLease")"
echo "Runtime: $(lipo -archs "$INSTALLED_APP/Contents/Resources/keylease")"
