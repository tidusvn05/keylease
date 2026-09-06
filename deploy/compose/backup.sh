#!/usr/bin/env sh
set -eu
umask 077

script_dir=$(dirname -- "$0")
script_dir=$(cd "$script_dir" && pwd)
output_dir=${1:-"$script_dir/backups"}
: "${LEASEGATE_AGE_RECIPIENT:?Set LEASEGATE_AGE_RECIPIENT to an age recipient}"
command -v age >/dev/null
mkdir -p "$output_dir"
timestamp=$(date -u +%Y%m%dT%H%M%SZ)

docker compose -f "$script_dir/compose.yaml" exec -T postgres \
  pg_dump -U leasegate -d leasegate --format=custom --no-owner --no-acl |
  age -r "$LEASEGATE_AGE_RECIPIENT" -o "$output_dir/postgres-$timestamp.dump.age"

tar -C "$script_dir" -cf - secrets credential-backends.example.json siem-secrets.example.json |
  age -r "$LEASEGATE_AGE_RECIPIENT" -o "$output_dir/config-$timestamp.tar.age"

gateway_stopped=0
restart_gateway() {
  if [ "$gateway_stopped" -eq 1 ]; then
    docker compose -f "$script_dir/compose.yaml" up -d gateway >/dev/null
  fi
}
trap restart_gateway EXIT HUP INT TERM
docker compose -f "$script_dir/compose.yaml" stop gateway
gateway_stopped=1
docker compose -f "$script_dir/compose.yaml" run --rm --no-deps --entrypoint tar gateway \
  -C /var/lib/leasegate -cf - . |
  age -r "$LEASEGATE_AGE_RECIPIENT" -o "$output_dir/edge-$timestamp.tar.age"
docker compose -f "$script_dir/compose.yaml" up -d gateway >/dev/null
gateway_stopped=0
trap - EXIT HUP INT TERM

printf 'Encrypted LeaseGate backup written to %s\n' "$output_dir"
