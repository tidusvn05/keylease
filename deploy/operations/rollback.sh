#!/usr/bin/env sh
set -eu
umask 077

script_dir=$(dirname -- "$0")
root_dir=$(cd "$script_dir/../.." && pwd)
compose_dir="$root_dir/deploy/compose"
env_file=${LEASEGATE_ENV_FILE:-"$compose_dir/.env"}
state_dir=${LEASEGATE_OPS_STATE_DIR:-"$compose_dir/.state"}
backup_dir=${LEASEGATE_BACKUP_DIR:-"$compose_dir/backups"}
: "${LEASEGATE_AGE_RECIPIENT:?Set LEASEGATE_AGE_RECIPIENT before rollback}"
[ "${LEASEGATE_ROLLBACK_CONFIRM:-}" = rollback-to-previous-images ] || {
  printf 'Set LEASEGATE_ROLLBACK_CONFIRM=rollback-to-previous-images.\n' >&2
  exit 2
}
[ -f "$state_dir/current-release.env" ] || { printf 'Current release state is missing.\n' >&2; exit 1; }
[ -f "$state_dir/previous-release.env" ] || { printf 'Previous release state is missing.\n' >&2; exit 1; }

load_release() {
  file=$1
  for key in LEASEGATE_CONTROL_IMAGE LEASEGATE_WEB_IMAGE LEASEGATE_GATEWAY_IMAGE; do
    value=$(awk -F= -v key="$key" '$1 == key {print substr($0, index($0, "=") + 1)}' "$file")
    printf '%s\n' "$value" | grep -Eq '^sha256:[0-9a-f]{64}$' || {
      printf 'Invalid image ID in release state.\n' >&2
      exit 1
    }
    docker image inspect "$value" >/dev/null
    export "$key=$value"
  done
}

LEASEGATE_ENV_FILE="$env_file" "$compose_dir/backup.sh" "$backup_dir"
load_release "$state_dir/previous-release.env"
rollback_ok=1
if ! docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" up -d --no-build --wait; then
  rollback_ok=0
elif ! LEASEGATE_ENV_FILE="$env_file" "$compose_dir/single-vps-check.sh" runtime; then
  rollback_ok=0
fi
if [ "$rollback_ok" -ne 1 ]; then
  printf 'Rollback failed; attempting to restore current images.\n' >&2
  load_release "$state_dir/current-release.env"
  docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" up -d --no-build --wait || true
  exit 1
fi
cp "$state_dir/current-release.env" "$state_dir/release-swap.tmp"
cp "$state_dir/previous-release.env" "$state_dir/current-release.env.tmp"
mv "$state_dir/current-release.env.tmp" "$state_dir/current-release.env"
mv "$state_dir/release-swap.tmp" "$state_dir/previous-release.env"
printf 'Rolled back to the previous image set. The database was not rewound.\n'
