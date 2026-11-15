#!/bin/sh
# Installs KeyLease from the prebuilt release binaries.
#
#   curl -fsSL https://raw.githubusercontent.com/tidusvn05/keylease/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/tidusvn05/keylease/main/install.sh | sh -s -- --server
#
# Options:
#   --server            also set up a server on this machine (keylease-server setup);
#                       setup options such as --listen, --public-url,
#                       --database-url-file and --no-service are passed on
#   --version X.Y.Z     a specific release (default: the latest)
#   --bin-dir DIR       where the binaries go (default: ~/.local/bin)
#
# Nothing here needs root. It checks everything it needs before downloading,
# verifies the archive's SHA-256 and changes nothing outside --bin-dir (and,
# with --server, the server's own directory and service).
set -eu

REPO="${KEYLEASE_REPO:-tidusvn05/keylease}"

say() { printf '%s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }
fail() {
  printf '\nerror: %s\n' "$1" >&2
  shift
  for line in "$@"; do printf '  %s\n' "$line" >&2; done
  exit 1
}
have() { command -v "$1" >/dev/null 2>&1; }

fetch() { # URL DEST
  if have curl; then
    curl -fsSL --retry 3 -o "$2" "$1"
  else
    wget -q -O "$2" "$1"
  fi
}

platform() {
  os=$(uname -s)
  arch=$(uname -m)
  case "$arch" in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    *) fail "no prebuilt binary for the $arch processor." \
      "Build from source instead: cargo install --locked keylease" ;;
  esac
  case "$os" in
    Linux)
      if [ -e /etc/alpine-release ] || ! ldd --version 2>&1 | grep -qi 'glibc\|gnu libc'; then
        fail "the prebuilt binaries need glibc (Alpine and other musl systems are not supported)." \
          "Use the container image ghcr.io/$REPO-server, or build from source."
      fi
      glibc=$(ldd --version 2>&1 | head -n1 | grep -o '[0-9]*\.[0-9]*$' || true)
      major=${glibc%%.*}
      minor=${glibc#*.}
      if [ -n "$glibc" ] && { [ "$major" -lt 2 ] || { [ "$major" -eq 2 ] && [ "$minor" -lt 35 ]; }; }; then
        fail "this system has glibc $glibc; the binaries need 2.35 or newer (Ubuntu 22.04, Debian 12, RHEL 9)." \
          "Build from source instead: cargo install --locked keylease"
      fi
      target="$arch-unknown-linux-gnu"
      ;;
    Darwin) target="$arch-apple-darwin" ;;
    *) fail "KeyLease runs on Linux and macOS; this is $os." ;;
  esac
}

# The same places keylease-server setup looks.
find_postgres() {
  if have initdb && have pg_ctl; then return 0; fi
  for dir in /usr/lib/postgresql/*/bin /usr/pgsql-*/bin /opt/homebrew/opt/postgresql@*/bin \
    /usr/local/opt/postgresql@*/bin; do
    [ -x "$dir/initdb" ] && [ -x "$dir/pg_ctl" ] && return 0
  done
  return 1
}

postgres_hint() {
  if [ "$(uname -s)" = Darwin ]; then
    say "brew install postgresql@17"
    return
  fi
  id=""
  [ -r /etc/os-release ] && id=$(. /etc/os-release && printf '%s %s' "${ID:-}" "${ID_LIKE:-}")
  case "$id" in
    *debian* | *ubuntu*) say "sudo apt install postgresql" ;;
    *fedora* | *rhel* | *centos*) say "sudo dnf install postgresql-server" ;;
    *arch*) say "sudo pacman -S postgresql" ;;
    *suse*) say "sudo zypper install postgresql-server" ;;
    *) say "install PostgreSQL 14 or newer with your package manager" ;;
  esac
}

main() {
  server=0
  version=""
  bin_dir="${KEYLEASE_BIN_DIR:-$HOME/.local/bin}"
  setup_args=""
  external_db=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --server) server=1 ;;
      --version) version="${2:?--version needs a value}"; version="${version#v}"; shift ;;
      --bin-dir) bin_dir="${2:?--bin-dir needs a value}"; shift ;;
      -h | --help) sed -n '2,17p' "$0" 2>/dev/null || say "see https://github.com/$REPO"; exit 0 ;;
      --database-url-file) external_db=1; setup_args="$setup_args $1 ${2:?$1 needs a value}"; shift ;;
      --listen | --public-url | --dir) setup_args="$setup_args $1 ${2:?$1 needs a value}"; shift ;;
      --no-service) setup_args="$setup_args $1" ;;
      *) fail "unknown option $1 (see --help)" ;;
    esac
    shift
  done
  if [ -n "$setup_args" ] && [ "$server" = 0 ]; then
    fail "server options need --server."
  fi

  step "Checking this machine"
  platform
  have curl || have wget || fail "curl or wget is needed."
  have tar || fail "tar is needed."
  if have sha256sum; then sha="sha256sum"; elif have shasum; then sha="shasum -a 256"; else
    fail "sha256sum or shasum is needed to verify the download."
  fi
  if [ "$server" = 1 ] && [ "$external_db" = 0 ] && ! find_postgres; then
    fail "the server needs PostgreSQL's programs (it runs its own private database with them)." \
      "Install them, then run this again:  $(postgres_hint)" \
      "Or use a database you already have:  --database-url-file FILE"
  fi
  say "Platform: $target"

  if [ -z "$version" ]; then
    step "Finding the latest release"
    meta=$(mktemp)
    fetch "https://api.github.com/repos/$REPO/releases/latest" "$meta" ||
      fail "could not reach GitHub to find the latest release." "Pass --version X.Y.Z to choose one."
    version=$(sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' "$meta" | head -n1)
    rm -f "$meta"
    [ -n "$version" ] || fail "could not read the latest release." "Pass --version X.Y.Z to choose one."
  fi
  say "Version: $version"

  name="keylease-$version-$target"
  base="${KEYLEASE_DOWNLOAD_URL:-https://github.com/$REPO/releases/download/v$version}"
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT

  step "Downloading $name"
  fetch "$base/$name.tar.gz" "$tmp/$name.tar.gz" ||
    fail "release v$version has no binary for $target." \
      "Releases before 0.4.0 shipped no binaries. Build from source instead:" \
      "  git clone https://github.com/$REPO && cd keylease && scripts/install-server.sh"
  fetch "$base/$name.tar.gz.sha256" "$tmp/$name.tar.gz.sha256" || fail "the checksum file is missing."
  expected=$(cut -d' ' -f1 <"$tmp/$name.tar.gz.sha256")
  actual=$(cd "$tmp" && $sha "$name.tar.gz" | cut -d' ' -f1)
  [ "$expected" = "$actual" ] || fail "the download does not match its checksum; nothing was installed."
  say "Checksum verified."

  step "Installing into $bin_dir"
  tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
  mkdir -p "$bin_dir"
  for bin in keylease keylease-server; do
    # Replace atomically, so a running copy keeps working until restarted.
    cp "$tmp/$name/$bin" "$bin_dir/.$bin.new"
    chmod 755 "$bin_dir/.$bin.new"
    mv -f "$bin_dir/.$bin.new" "$bin_dir/$bin"
    say "  $bin_dir/$bin"
  done

  found=$(command -v keylease 2>/dev/null || true)
  case ":$PATH:" in
    *":$bin_dir:"*)
      if [ -n "$found" ] && [ "$found" != "$bin_dir/keylease" ]; then
        say ""
        say "Note: \`keylease\` on your PATH is still $found (it comes first)."
        say "      Use $bin_dir/keylease, or remove the other copy."
      fi
      ;;
    *)
      say ""
      say "$bin_dir is not on your PATH. Add it, e.g. in ~/.profile:"
      say "  export PATH=\"$bin_dir:\$PATH\""
      ;;
  esac

  if [ "$server" = 1 ]; then
    step "Setting up the server"
    # shellcheck disable=SC2086 # setup_args is a list of words built above
    exec "$bin_dir/keylease-server" setup $setup_args
  fi

  say ""
  say "Done. Next:"
  say "  keylease vault init                 # a local vault for your agents"
  say "  keylease-server setup               # or: a server on this machine (needs PostgreSQL)"
}

main "$@"
