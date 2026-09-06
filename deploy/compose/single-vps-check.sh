#!/usr/bin/env sh
set -eu

script_dir=$(dirname -- "$0")
script_dir=$(cd "$script_dir" && pwd)
compose_file="$script_dir/compose.yaml"
env_file=${LEASEGATE_ENV_FILE:-"$script_dir/.env"}
mode=${1:-preflight}

pass() {
  printf '[PASS] %s\n' "$1"
}

fail() {
  printf '[FAIL] %s\n' "$1" >&2
  exit 1
}

read_env_value() {
  key=$1
  awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); value=$0} END {print value}' "$env_file"
}

case "$mode" in
  preflight|runtime) ;;
  *) fail 'usage: single-vps-check.sh [preflight|runtime]' ;;
esac

command -v docker >/dev/null 2>&1 || fail 'docker is not installed'
docker compose version >/dev/null 2>&1 || fail 'Docker Compose v2 is unavailable'
[ -f "$env_file" ] || fail "environment file is missing: $env_file"
[ -f "$compose_file" ] || fail 'compose.yaml is missing'

deployment_mode=$(read_env_value LEASEGATE_DEPLOYMENT_MODE)
execution_mode=$(read_env_value LEASEGATE_EXECUTION_MODE)
[ "$deployment_mode" = self_hosted ] || fail 'LEASEGATE_DEPLOYMENT_MODE must be self_hosted'
[ "$execution_mode" = local_gateway ] || fail 'LEASEGATE_EXECUTION_MODE must be local_gateway'
pass 'deployment is locked to self_hosted/local_gateway'

docker compose --env-file "$env_file" -f "$compose_file" config --quiet
pass 'Docker Compose configuration is valid'

secret_dir=${LEASEGATE_SECRET_DIR:-"$script_dir/secrets"}
[ -d "$secret_dir" ] || fail 'secrets directory is missing; run bootstrap-secrets.sh first'
required_secrets='postgres_password admin_token control_signing_key edge_storage_key database_url credential_backends.json edge_credential agent_credential vault_password'
for name in $required_secrets; do
  [ -s "$secret_dir/$name" ] || fail "required secret is missing or empty: $name"
done
unsafe_secret=$(find "$secret_dir" -type f -perm /077 -print -quit)
[ -z "$unsafe_secret" ] || fail "secret has group/world permissions: $unsafe_secret"
pass 'required secret files exist and are mode 0600 or stricter'

minimum_free_mib=${LEASEGATE_MIN_FREE_MIB:-2048}
case "$minimum_free_mib" in
  ''|*[!0-9]*) fail 'LEASEGATE_MIN_FREE_MIB must be an integer' ;;
esac
available_kib=$(df -Pk "$script_dir" | awk 'NR == 2 {print $4}')
[ "$available_kib" -ge $((minimum_free_mib * 1024)) ] || fail "less than ${minimum_free_mib} MiB is free"
pass "at least ${minimum_free_mib} MiB of disk is free"

if [ "$mode" = preflight ]; then
  printf 'Single-VPS preflight completed successfully.\n'
  exit 0
fi

running=$(docker compose --env-file "$env_file" -f "$compose_file" ps --status running --services)
for service in postgres object-store control-plane worker web gateway; do
  printf '%s\n' "$running" | grep -Fx "$service" >/dev/null || fail "service is not running: $service"
done
pass 'all single-VPS services are running'

docker compose --env-file "$env_file" -f "$compose_file" exec -T postgres \
  pg_isready -U leasegate -d leasegate >/dev/null
pass 'PostgreSQL accepts connections'

docker compose --env-file "$env_file" -f "$compose_file" exec -T control-plane \
  keylease-cloud healthcheck
pass 'Control Plane readiness endpoint and database dependency are healthy'

docker compose --env-file "$env_file" -f "$compose_file" exec -T gateway \
  leasegate-edge healthcheck
pass 'Gateway has an active policy and available audit-spool capacity'

domain=$(read_env_value LEASEGATE_DOMAIN)
case "$domain" in
  ''|*[!A-Za-z0-9.-]*) fail 'LEASEGATE_DOMAIN is invalid' ;;
esac
command -v curl >/dev/null 2>&1 || fail 'curl is required for the public TLS check'
health_url=${LEASEGATE_HEALTH_URL:-"https://$domain/api/readyz"}
curl --fail --silent --show-error --max-time 10 "$health_url" >/dev/null
pass "public TLS readiness check succeeded: $health_url"

printf 'Single-VPS runtime checks completed successfully.\n'
