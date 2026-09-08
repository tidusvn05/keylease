#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BRAND_DIR="$REPO_DIR/brand"
MAC_DIR="$REPO_DIR/apps/desktop-flutter/macos/Runner/Assets.xcassets/AppIcon.appiconset"
IOS_DIR="$REPO_DIR/apps/approval-flutter/ios/Runner/Assets.xcassets/AppIcon.appiconset"
ANDROID_DIR="$REPO_DIR/apps/approval-flutter/android/app/src/main/res"
WEB_DIR="$REPO_DIR/apps/approval-flutter/web"

command -v rsvg-convert >/dev/null || {
  echo "error: rsvg-convert is required" >&2
  exit 1
}
command -v magick >/dev/null || {
  echo "error: ImageMagick is required" >&2
  exit 1
}

render() {
  local source="$1"
  local size="$2"
  local destination="$3"
  rsvg-convert -w "$size" -h "$size" "$source" -o "$destination"
}

for size in 16 32 64 128 256 512 1024; do
  render "$BRAND_DIR/leasegate-app-icon-macos.svg" "$size" "$MAC_DIR/app_icon_${size}.png"
done

while read -r filename size; do
  render "$BRAND_DIR/leasegate-app-icon-ios.svg" "$size" "$IOS_DIR/$filename"
  magick "$IOS_DIR/$filename" -alpha off "PNG24:$IOS_DIR/$filename"
done <<'SIZES'
Icon-App-20x20@1x.png 20
Icon-App-20x20@2x.png 40
Icon-App-20x20@3x.png 60
Icon-App-29x29@1x.png 29
Icon-App-29x29@2x.png 58
Icon-App-29x29@3x.png 87
Icon-App-40x40@1x.png 40
Icon-App-40x40@2x.png 80
Icon-App-40x40@3x.png 120
Icon-App-60x60@2x.png 120
Icon-App-60x60@3x.png 180
Icon-App-76x76@1x.png 76
Icon-App-76x76@2x.png 152
Icon-App-83.5x83.5@2x.png 167
Icon-App-1024x1024@1x.png 1024
SIZES

while read -r density size; do
  render "$BRAND_DIR/leasegate-app-icon-macos.svg" "$size" "$ANDROID_DIR/mipmap-$density/ic_launcher.png"
done <<'SIZES'
mdpi 48
hdpi 72
xhdpi 96
xxhdpi 144
xxxhdpi 192
SIZES

mkdir -p "$WEB_DIR/icons"
render "$BRAND_DIR/leasegate-app-icon-ios.svg" 192 "$WEB_DIR/icons/Icon-192.png"
render "$BRAND_DIR/leasegate-app-icon-ios.svg" 512 "$WEB_DIR/icons/Icon-512.png"
render "$BRAND_DIR/leasegate-app-icon-ios.svg" 192 "$WEB_DIR/icons/Icon-maskable-192.png"
render "$BRAND_DIR/leasegate-app-icon-ios.svg" 512 "$WEB_DIR/icons/Icon-maskable-512.png"
render "$BRAND_DIR/leasegate-app-icon-macos.svg" 32 "$WEB_DIR/favicon.png"

render "$BRAND_DIR/leasegate-symbol.svg" 1024 "$BRAND_DIR/generated/leasegate-symbol-1024.png"
render "$BRAND_DIR/leasegate-app-icon-macos.svg" 1024 "$BRAND_DIR/generated/leasegate-app-icon-macos-1024.png"
render "$BRAND_DIR/leasegate-app-icon-ios.svg" 1024 "$BRAND_DIR/generated/leasegate-app-icon-ios-1024.png"
render "$BRAND_DIR/leasegate-brand-sheet.svg" 1600 "$BRAND_DIR/generated/leasegate-brand-sheet.png"

echo "Leasegate brand assets generated."
