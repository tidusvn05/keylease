#!/usr/bin/env bash
# Packs the release binaries for one platform:
#   scripts/package-binaries.sh VERSION TARGET BUILD_DIR OUT_DIR
# → OUT_DIR/keylease-VERSION-TARGET.tar.gz (+ .sha256), holding one folder
# with keylease, keylease-server, LICENSE and a short README.
set -euo pipefail

version="$1" target="$2" build="$3" out="$4"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
name="keylease-$version-$target"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

mkdir -p "$stage/$name" "$out"
cp "$build/keylease" "$build/keylease-server" "$stage/$name/"
cp "$repo/LICENSE" "$stage/$name/"
cat > "$stage/$name/README.txt" <<EOF
KeyLease $version ($target)

  keylease          the CLI and local vault
  keylease-server   the self-hosted server, with the KeyLease Console inside

Put both on your PATH (for example ~/.local/bin), then:

  keylease-server setup     # secrets, a private PostgreSQL, a service; prints what to do next

Docs: https://github.com/tidusvn05/keylease
EOF
tar -C "$stage" -czf "$out/$name.tar.gz" "$name"
(
  cd "$out"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$name.tar.gz" > "$name.tar.gz.sha256"
  else
    shasum -a 256 "$name.tar.gz" > "$name.tar.gz.sha256"
  fi
)
echo "$out/$name.tar.gz"
