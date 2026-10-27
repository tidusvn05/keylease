#!/usr/bin/env bash
# Builds the Leasegate Vault Android app.
#
# It checks its toolchain, pins the Flutter version, and asserts
# post-conditions rather than trusting the build.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_DIR="$REPO_DIR/apps/mobile-flutter"

EXPECTED_FLUTTER_VERSION="3.47.2"

usage() {
  cat <<'USAGE'
Usage: scripts/build-android.sh [--debug|--release] [--aab] [--full]

  --debug     Debug APK (default).
  --release   Release artifact. Unsigned by design; see "Signing" in the
              app README.
  --aab       Build an app bundle instead of an APK.
  --full      Run analyze and tests for the package and both apps, plus
              cargo clippy and cargo test, before building.

Environment:
  KEYLEASE_ANDROID_ENV   Toolchain env script to source.
                         Default: ~/workspace/android-toolchain/env.sh
  KEYLEASE_FLUTTER_SDK   Flutter SDK root. Must report 3.47.2.
  KEYLEASE_SKIP_RUST     Set to 1 to reuse the staged .so instead of rebuilding.
USAGE
}

MODE="debug"
BUNDLE="false"
FULL="false"
while [ $# -gt 0 ]; do
  case "$1" in
    --debug) MODE="debug" ;;
    --release) MODE="release" ;;
    --aab) BUNDLE="true" ;;
    --full) FULL="true" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

ENV_FILE="${KEYLEASE_ANDROID_ENV:-$HOME/workspace/android-toolchain/env.sh}"
if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

for command in java flutter dart cargo rustup cargo-ndk unzip; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "error: $command is required; see docs and $ENV_FILE" >&2
    exit 1
  fi
done

ACTUAL_FLUTTER_VERSION="$(flutter --version | sed -n '1s/^Flutter \([^ ]*\).*/\1/p')"
if [ "$ACTUAL_FLUTTER_VERSION" != "$EXPECTED_FLUTTER_VERSION" ]; then
  echo "error: Flutter $EXPECTED_FLUTTER_VERSION is required, found $ACTUAL_FLUTTER_VERSION" >&2
  exit 1
fi

if [ "$FULL" = "true" ]; then
  echo "== workspace checks =="
  (cd "$REPO_DIR" && cargo fmt --all -- --check)
  (cd "$REPO_DIR" && cargo clippy --workspace --all-targets -- -D warnings)
  (cd "$REPO_DIR" && cargo test --workspace)
  for dir in packages/leasegate_vault_ui apps/mobile-flutter; do
    echo "== $dir =="
    (cd "$REPO_DIR/$dir" && flutter pub get && flutter analyze && flutter test)
  done
fi

# arm64 for devices, x86_64 for emulators. --target-platform is what actually
# constrains Flutter's own engine libraries; abiFilters only covers jniLibs.
TARGET_PLATFORM="android-arm64,android-x64"

cd "$APP_DIR"
flutter pub get
if [ "$BUNDLE" = "true" ]; then
  flutter build appbundle "--$MODE" --target-platform "$TARGET_PLATFORM"
  ARTIFACT="$APP_DIR/build/app/outputs/bundle/${MODE}/app-${MODE}.aab"
else
  flutter build apk "--$MODE" --target-platform "$TARGET_PLATFORM"
  ARTIFACT="$APP_DIR/build/app/outputs/flutter-apk/app-${MODE}.apk"
fi

# --- Post-conditions -------------------------------------------------------
# Building is not the same as building correctly. Each of these has a failure
# mode that is silent at build time and loud in the user's hands.

[ -f "$ARTIFACT" ] || { echo "error: $ARTIFACT was not produced" >&2; exit 1; }
echo "built $ARTIFACT ($(du -h "$ARTIFACT" | cut -f1))"

if [ "$BUNDLE" = "false" ]; then
  # Listed once into a variable rather than piped into `grep -q` per check:
  # grep -q exits on the first match and closes the pipe, unzip takes SIGPIPE,
  # and under `pipefail` the pipeline then reports failure even though the
  # pattern matched.
  CONTENTS="$(unzip -l "$ARTIFACT")"

  for abi in arm64-v8a x86_64; do
    case "$CONTENTS" in
      *"lib/$abi/libkeylease_mobile.so"*) ;;
      *) echo "error: the vault library is missing for $abi" >&2; exit 1 ;;
    esac
  done
  echo "ok: libkeylease_mobile.so present for arm64-v8a and x86_64"

  if [ "$MODE" = "release" ]; then
    # Measured: a debug build packages every Flutter engine ABI regardless of
    # --target-platform, so this is only meaningful for release. Without the
    # flag a release APK carried armeabi-v7a at 56.4 MB versus 40.2 MB.
    #
    # Checked per library rather than as "no armeabi-v7a directory": a small
    # plugin helper may still ship there, and what the exclusion is actually
    # about is not building the vault, the engine or the app for 32-bit ARM.
    for lib in libkeylease_mobile.so libflutter.so libapp.so; do
      case "$CONTENTS" in
        *"lib/armeabi-v7a/$lib"*)
          echo "error: $lib was packaged for armeabi-v7a, which is excluded" >&2
          exit 1 ;;
      esac
    done
    echo "ok: nothing substantial built for armeabi-v7a"

    # The repository never falls back to the Android debug key. A debug-signed
    # release would install and run, and only be caught at distribution.
    BUILD_TOOLS="$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)"
    CERTS="$("$BUILD_TOOLS/apksigner" verify --print-certs "$ARTIFACT" 2>/dev/null || true)"
    case "$CERTS" in
      *"CN=Android Debug"*)
        echo "error: the release artifact is signed with the Android debug key" >&2
        exit 1 ;;
    esac
    echo "ok: not debug-signed (sign it where the key lives; see the app README)"
  fi
fi
