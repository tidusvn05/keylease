#!/usr/bin/env sh
set -eu
umask 077

script_dir=$(dirname -- "$0")
script_dir=$(cd "$script_dir" && pwd)
env_file=${LEASEGATE_ENV_FILE:-"$script_dir/.env"}
database_backup=${1:?Usage: restore.sh POSTGRES_DUMP_AGE CONFIG_TAR_AGE EDGE_TAR_AGE}
config_backup=${2:?Usage: restore.sh POSTGRES_DUMP_AGE CONFIG_TAR_AGE EDGE_TAR_AGE}
edge_backup=${3:?Usage: restore.sh POSTGRES_DUMP_AGE CONFIG_TAR_AGE EDGE_TAR_AGE}
: "${LEASEGATE_AGE_IDENTITY:?Set LEASEGATE_AGE_IDENTITY to an age identity file}"
: "${LEASEGATE_RESTORE_CONFIRM:?Set LEASEGATE_RESTORE_CONFIRM=replace-self-hosted-state}"
if [ "$LEASEGATE_RESTORE_CONFIRM" != "replace-self-hosted-state" ]; then
  printf 'Restore confirmation did not match; refusing to replace state.\n' >&2
  exit 2
fi
command -v age >/dev/null
[ -f "$env_file" ] || { printf 'Missing environment file: %s\n' "$env_file" >&2; exit 1; }

temporary_dir=$(mktemp -d)
trap 'rm -rf "$temporary_dir"' EXIT HUP INT TERM
age -d -i "$LEASEGATE_AGE_IDENTITY" -o "$temporary_dir/database.dump" "$database_backup"
age -d -i "$LEASEGATE_AGE_IDENTITY" -o "$temporary_dir/config.tar" "$config_backup"
age -d -i "$LEASEGATE_AGE_IDENTITY" -o "$temporary_dir/edge.tar" "$edge_backup"

reject_unsafe_archive() {
  archive=$1
  if tar -tf "$archive" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
    printf 'Archive contains an unsafe path: %s\n' "$archive" >&2
    exit 1
  fi
}
reject_unsafe_archive "$temporary_dir/config.tar"
reject_unsafe_archive "$temporary_dir/edge.tar"
for required in secrets/admin_token secrets/control_signing_key secrets/database_url; do
  tar -tf "$temporary_dir/config.tar" | grep -Fx "$required" >/dev/null || {
    printf 'Configuration backup is missing %s\n' "$required" >&2
    exit 1
  }
done
for required in ./edge.sqlite3 ./vault.sqlite3; do
  tar -tf "$temporary_dir/edge.tar" | grep -Fx "$required" >/dev/null || {
    printf 'Edge backup is missing %s\n' "$required" >&2
    exit 1
  }
done
docker compose --env-file "$env_file" -f "$script_dir/compose.yaml" run --rm --no-deps --entrypoint pg_restore postgres \
  --list < "$temporary_dir/database.dump" >/dev/null

docker compose --env-file "$env_file" -f "$script_dir/compose.yaml" stop control-plane worker gateway
tar -C "$script_dir" -xf "$temporary_dir/config.tar"
docker compose --env-file "$env_file" -f "$script_dir/compose.yaml" run --rm --no-deps --entrypoint sh gateway \
  -c 'find /var/lib/leasegate -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +; tar -xf - -C /var/lib/leasegate' \
  < "$temporary_dir/edge.tar"
docker compose --env-file "$env_file" -f "$script_dir/compose.yaml" up -d postgres
docker compose --env-file "$env_file" -f "$script_dir/compose.yaml" exec -T postgres \
  dropdb -U leasegate --if-exists leasegate
docker compose --env-file "$env_file" -f "$script_dir/compose.yaml" exec -T postgres \
  createdb -U leasegate leasegate
docker compose --env-file "$env_file" -f "$script_dir/compose.yaml" exec -T postgres \
  pg_restore -U leasegate -d leasegate --no-owner --no-acl < "$temporary_dir/database.dump"
docker compose --env-file "$env_file" -f "$script_dir/compose.yaml" up -d
printf 'Restore completed. Verify health, policy distribution, and audit chain before resuming agents.\n'
