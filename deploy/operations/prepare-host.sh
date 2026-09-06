#!/usr/bin/env sh
set -eu

script_dir=$(dirname -- "$0")
root_dir=$(cd "$script_dir/../.." && pwd)
compose_dir="$root_dir/deploy/compose"
mode=${1:---check}

fail() {
  printf '[FAIL] %s\n' "$1" >&2
  exit 1
}

[ "$(uname -s)" = Linux ] || fail 'the single-VPS runtime requires Linux'
case "$(uname -m)" in
  x86_64|aarch64) ;;
  *) fail 'supported VPS architectures are x86_64 and aarch64' ;;
esac
for command_name in docker git gzip openssl curl age timeout; do
  command -v "$command_name" >/dev/null 2>&1 || fail "missing dependency: $command_name"
done
docker compose version >/dev/null 2>&1 || fail 'Docker Compose v2 is required'
if docker info --format '{{json .SecurityOptions}}' | grep -q 'name=rootless'; then
  fail 'rootless Docker is unsupported because mode-0600 bind-mounted secrets must retain their configured numeric owner'
fi

case "$mode" in
  --check)
    printf 'Host dependencies are ready. Run %s --prepare to initialize local configuration.\n' "$0"
    ;;
  --prepare)
    if [ ! -e "$compose_dir/.env" ]; then
      install -m 600 "$compose_dir/.env.example" "$compose_dir/.env"
    fi
    "$compose_dir/bootstrap-secrets.sh"
    printf 'Prepared %s/.env and mode-0600 secrets. Fill domain and enrollment IDs, then run single-vps-check.sh preflight.\n' "$compose_dir"
    ;;
  *) fail 'usage: prepare-host.sh [--check|--prepare]' ;;
esac
