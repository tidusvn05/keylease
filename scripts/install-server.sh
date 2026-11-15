#!/usr/bin/env bash
# Builds keylease-server from this checkout (with the KeyLease Console inside)
# and runs `keylease-server setup`, which prepares secrets, a private
# PostgreSQL and the service. Options after `--` go to setup, e.g.:
#
#   scripts/install-server.sh                       # listen on 127.0.0.1:8080
#   scripts/install-server.sh -- --listen 127.0.0.1:18080
#   scripts/install-server.sh --with-cli            # also install `keylease`
#
# KEYLEASE_PREFIX sets where binaries go (default ~/.local, so ~/.local/bin).
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
prefix="${KEYLEASE_PREFIX:-$HOME/.local}"
with_cli=0
setup_args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --with-cli) with_cli=1 ;;
    --) shift; setup_args=("$@"); break ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option $1 (setup options go after --)" >&2; exit 2 ;;
  esac
  shift
done

# Prebuilt binaries are quicker: install.sh at the repository root downloads
# them. This script is for building from a checkout (contributors, unreleased
# changes).
need() { command -v "$1" >/dev/null 2>&1 || { echo "error: $1 is required: $2" >&2; exit 1; }; }
need cargo "install Rust from https://rustup.rs"
need npx "install Node.js 22 or newer"

# Fail before the long build, not after it.
external_db=0
for arg in ${setup_args[@]+"${setup_args[@]}"}; do
  [ "$arg" = --database-url-file ] && external_db=1
done
if [ "$external_db" = 0 ]; then
  found=0
  if command -v initdb >/dev/null 2>&1 && command -v pg_ctl >/dev/null 2>&1; then found=1; fi
  for dir in /usr/lib/postgresql/*/bin /usr/pgsql-*/bin /opt/homebrew/opt/postgresql@*/bin /usr/local/opt/postgresql@*/bin; do
    [ -x "$dir/initdb" ] && [ -x "$dir/pg_ctl" ] && found=1
  done
  if [ "$found" = 0 ]; then
    echo "error: the server needs PostgreSQL's programs (it runs its own private database with them)." >&2
    echo "  Install them first (Debian/Ubuntu: sudo apt install postgresql; macOS: brew install postgresql@17)," >&2
    echo "  or pass a database you already have:  -- --database-url-file FILE" >&2
    exit 1
  fi
fi

echo "==> Building the KeyLease Console"
(cd "$repo/apps/console" && npx --yes pnpm@12.18.0 install --frozen-lockfile && npx --yes pnpm@12.18.0 build)

echo "==> Building keylease-server into $prefix/bin"
cargo install --locked --path "$repo/crates/keylease-server" --root "$prefix"
if [ "$with_cli" = 1 ]; then
  echo "==> Building the keylease CLI into $prefix/bin"
  cargo install --locked --path "$repo/crates/keylease-cli" --root "$prefix"
fi

echo "==> Setting up"
exec "$prefix/bin/keylease-server" setup ${setup_args[@]+"${setup_args[@]}"}
