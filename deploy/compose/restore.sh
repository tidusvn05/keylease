#!/usr/bin/env sh
set -eu
umask 077

script_dir=$(dirname -- "$0")
script_dir=$(cd "$script_dir" && pwd)
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

temporary_dir=$(mktemp -d)
trap 'rm -rf "$temporary_dir"' EXIT HUP INT TERM
age -d -i "$LEASEGATE_AGE_IDENTITY" -o "$temporary_dir/database.dump" "$database_backup"
age -d -i "$LEASEGATE_AGE_IDENTITY" -o "$temporary_dir/config.tar" "$config_backup"
age -d -i "$LEASEGATE_AGE_IDENTITY" -o "$temporary_dir/edge.tar" "$edge_backup"

docker compose -f "$script_dir/compose.yaml" stop control-plane worker gateway
tar -C "$script_dir" -xf "$temporary_dir/config.tar"
docker compose -f "$script_dir/compose.yaml" run --rm --no-deps --entrypoint sh gateway \
  -c 'find /var/lib/leasegate -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +; tar -xf - -C /var/lib/leasegate' \
  < "$temporary_dir/edge.tar"
docker compose -f "$script_dir/compose.yaml" up -d postgres
docker compose -f "$script_dir/compose.yaml" exec -T postgres \
  dropdb -U leasegate --if-exists leasegate
docker compose -f "$script_dir/compose.yaml" exec -T postgres \
  createdb -U leasegate leasegate
docker compose -f "$script_dir/compose.yaml" exec -T postgres \
  pg_restore -U leasegate -d leasegate --no-owner --no-acl < "$temporary_dir/database.dump"
docker compose -f "$script_dir/compose.yaml" up -d
printf 'Restore completed. Verify health, policy distribution, and audit chain before resuming agents.\n'
