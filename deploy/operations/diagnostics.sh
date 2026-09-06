#!/usr/bin/env sh
set -eu
umask 077

script_dir=$(dirname -- "$0")
root_dir=$(cd "$script_dir/../.." && pwd)
compose_dir="$root_dir/deploy/compose"
env_file=${LEASEGATE_ENV_FILE:-"$compose_dir/.env"}
output_dir=${1:-"$root_dir/deploy/diagnostics"}
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
output="$output_dir/leasegate-diagnostics-$timestamp.tar.gz"
[ ! -e "$output" ] || { printf 'Diagnostic output already exists.\n' >&2; exit 1; }
mkdir -p "$output_dir"
temporary_dir=$(mktemp -d)
cleanup() { rm -rf "$temporary_dir"; }
trap cleanup EXIT HUP INT TERM

redact_logs() {
  sed -E '/(authorization|bearer|token|secret|password|credential|private.key)/I c\[REDACTED SENSITIVE LOG LINE\]'
}

date -u +%Y-%m-%dT%H:%M:%SZ > "$temporary_dir/created-at.txt"
git -C "$root_dir" rev-parse HEAD > "$temporary_dir/git-revision.txt" 2>/dev/null || true
uname -a > "$temporary_dir/uname.txt"
df -h > "$temporary_dir/disk.txt"
free -h > "$temporary_dir/memory.txt" 2>/dev/null || true
docker version > "$temporary_dir/docker-version.txt" 2>&1 || true
docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" ps --all \
  > "$temporary_dir/compose-ps.txt" 2>&1 || true
docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" images \
  > "$temporary_dir/compose-images.txt" 2>&1 || true
docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" logs --no-color --tail=500 \
  control-plane worker gateway 2>&1 | redact_logs > "$temporary_dir/redacted-logs.txt" || true
LEASEGATE_ENV_FILE="$env_file" "$compose_dir/single-vps-check.sh" runtime \
  > "$temporary_dir/runtime-check.txt" 2>&1 || true

tar -C "$temporary_dir" -czf "$output" .
chmod 600 "$output"
printf 'Redacted diagnostic bundle written to %s\n' "$output"
