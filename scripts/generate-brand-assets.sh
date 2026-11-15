#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BRAND_DIR="$REPO_DIR/brand"
command -v rsvg-convert >/dev/null || {
  echo "error: rsvg-convert is required" >&2
  exit 1
}
render() {
  local source="$1"
  local size="$2"
  local destination="$3"
  rsvg-convert -w "$size" -h "$size" "$source" -o "$destination"
}

render "$BRAND_DIR/leasegate-symbol.svg" 1024 "$BRAND_DIR/generated/leasegate-symbol-1024.png"
render "$BRAND_DIR/leasegate-app-icon-macos.svg" 1024 "$BRAND_DIR/generated/leasegate-app-icon-macos-1024.png"
render "$BRAND_DIR/leasegate-app-icon-ios.svg" 1024 "$BRAND_DIR/generated/leasegate-app-icon-ios-1024.png"
render "$BRAND_DIR/leasegate-brand-sheet.svg" 1600 "$BRAND_DIR/generated/leasegate-brand-sheet.png"

echo "Leasegate brand assets generated."
