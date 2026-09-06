#!/usr/bin/env sh
set -eu
umask 077

script_dir=$(dirname -- "$0")
script_dir=$(cd "$script_dir" && pwd)
env_file=${LEASEGATE_ENV_FILE:-"$script_dir/.env"}
output_dir=${1:-"$script_dir/backups"}
: "${LEASEGATE_AGE_RECIPIENT:?Set LEASEGATE_AGE_RECIPIENT to an age recipient}"
retention_days=${LEASEGATE_BACKUP_RETENTION_DAYS:-30}
case "$retention_days" in
  ''|*[!0-9]*) printf 'LEASEGATE_BACKUP_RETENTION_DAYS must be an integer.\n' >&2; exit 1 ;;
esac
if [ "$retention_days" -lt 1 ] || [ "$retention_days" -gt 3650 ]; then
  printf 'Backup retention must be between 1 and 3650 days.\n' >&2
  exit 1
fi
command -v age >/dev/null
[ -f "$env_file" ] || { printf 'Missing environment file: %s\n' "$env_file" >&2; exit 1; }
mkdir -p "$output_dir"
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
database_name="postgres-$timestamp.dump.age"
config_name="config-$timestamp.tar.age"
edge_name="edge-$timestamp.tar.age"

docker compose --env-file "$env_file" -f "$script_dir/compose.yaml" exec -T postgres \
  pg_dump -U leasegate -d leasegate --format=custom --no-owner --no-acl |
  age -r "$LEASEGATE_AGE_RECIPIENT" -o "$output_dir/$database_name"

tar -C "$script_dir" -cf - secrets credential-backends.example.json siem-secrets.example.json |
  age -r "$LEASEGATE_AGE_RECIPIENT" -o "$output_dir/$config_name"

gateway_stopped=0
restart_gateway() {
  if [ "$gateway_stopped" -eq 1 ]; then
    docker compose --env-file "$env_file" -f "$script_dir/compose.yaml" up -d gateway >/dev/null
  fi
}
trap restart_gateway EXIT HUP INT TERM
docker compose --env-file "$env_file" -f "$script_dir/compose.yaml" stop gateway
gateway_stopped=1
docker compose --env-file "$env_file" -f "$script_dir/compose.yaml" run --rm --no-deps --entrypoint tar gateway \
  -C /var/lib/leasegate -cf - . |
  age -r "$LEASEGATE_AGE_RECIPIENT" -o "$output_dir/$edge_name"
docker compose --env-file "$env_file" -f "$script_dir/compose.yaml" up -d gateway >/dev/null
gateway_stopped=0
trap - EXIT HUP INT TERM

(
  cd "$output_dir"
  sha256sum "$database_name" "$config_name" "$edge_name" > "backup-$timestamp.sha256.tmp"
  mv "backup-$timestamp.sha256.tmp" "backup-$timestamp.sha256"
)
if [ -n "${LEASEGATE_BACKUP_RESULT_FILE:-}" ]; then
  printf '%s\n' "$timestamp" > "$LEASEGATE_BACKUP_RESULT_FILE"
fi
if [ -n "${LEASEGATE_AGE_IDENTITY:-}" ]; then
  "$script_dir/verify-backup.sh" \
    "$output_dir/$database_name" \
    "$output_dir/$config_name" \
    "$output_dir/$edge_name"
fi
find "$output_dir" -maxdepth 1 -type f \
  \( -name 'postgres-*.dump.age' -o -name 'config-*.tar.age' -o -name 'edge-*.tar.age' -o -name 'backup-*.sha256' \) \
  -mtime "+$retention_days" -delete

printf 'Encrypted LeaseGate backup written to %s\n' "$output_dir"
