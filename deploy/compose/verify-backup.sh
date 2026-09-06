#!/usr/bin/env sh
set -eu
umask 077

script_dir=$(dirname -- "$0")
script_dir=$(cd "$script_dir" && pwd)
env_file=${LEASEGATE_ENV_FILE:-"$script_dir/.env"}
database_backup=${1:?Usage: verify-backup.sh POSTGRES_DUMP_AGE CONFIG_TAR_AGE EDGE_TAR_AGE}
config_backup=${2:?Usage: verify-backup.sh POSTGRES_DUMP_AGE CONFIG_TAR_AGE EDGE_TAR_AGE}
edge_backup=${3:?Usage: verify-backup.sh POSTGRES_DUMP_AGE CONFIG_TAR_AGE EDGE_TAR_AGE}
: "${LEASEGATE_AGE_IDENTITY:?Set LEASEGATE_AGE_IDENTITY to an age identity file}"

command -v age >/dev/null
command -v docker >/dev/null
[ -f "$env_file" ] || { printf 'Missing environment file: %s\n' "$env_file" >&2; exit 1; }
for backup in "$database_backup" "$config_backup" "$edge_backup"; do
  [ -s "$backup" ] || {
    printf 'Backup is missing or empty: %s\n' "$backup" >&2
    exit 1
  }
done

database_base=$(basename -- "$database_backup")
timestamp=${database_base#postgres-}
timestamp=${timestamp%.dump.age}
checksum_file=$(dirname -- "$database_backup")/backup-$timestamp.sha256
if [ -f "$checksum_file" ]; then
  (
    cd "$(dirname -- "$database_backup")"
    sha256sum -c "$(basename -- "$checksum_file")" >/dev/null
  )
fi

temporary_dir=$(mktemp -d)
trap 'rm -rf "$temporary_dir"' EXIT HUP INT TERM
age -d -i "$LEASEGATE_AGE_IDENTITY" -o "$temporary_dir/database.dump" "$database_backup"
age -d -i "$LEASEGATE_AGE_IDENTITY" -o "$temporary_dir/config.tar" "$config_backup"
age -d -i "$LEASEGATE_AGE_IDENTITY" -o "$temporary_dir/edge.tar" "$edge_backup"

docker compose --env-file "$env_file" -f "$script_dir/compose.yaml" run --rm --no-deps --entrypoint pg_restore postgres \
  --list < "$temporary_dir/database.dump" >/dev/null

reject_unsafe_archive() {
  archive=$1
  if tar -tf "$archive" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
    printf 'Archive contains an unsafe path: %s\n' "$archive" >&2
    exit 1
  fi
}

reject_unsafe_archive "$temporary_dir/config.tar"
reject_unsafe_archive "$temporary_dir/edge.tar"
config_entries=$(tar -tf "$temporary_dir/config.tar")
edge_entries=$(tar -tf "$temporary_dir/edge.tar")
for required in secrets/admin_token secrets/control_signing_key secrets/database_url; do
  printf '%s\n' "$config_entries" | grep -Fx "$required" >/dev/null || {
    printf 'Configuration backup is missing %s\n' "$required" >&2
    exit 1
  }
done
for required in ./edge.sqlite3 ./vault.sqlite3; do
  printf '%s\n' "$edge_entries" | grep -Fx "$required" >/dev/null || {
    printf 'Edge backup is missing %s\n' "$required" >&2
    exit 1
  }
done

printf 'Backup decrypts successfully and contains a readable PostgreSQL dump, configuration, and Edge state.\n'
