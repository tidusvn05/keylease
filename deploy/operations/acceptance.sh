#!/usr/bin/env sh
set -eu
umask 077

script_dir=$(dirname -- "$0")
root_dir=$(cd "$script_dir/../.." && pwd)
compose_dir="$root_dir/deploy/compose"
env_file=${LEASEGATE_ENV_FILE:-"$compose_dir/.env"}
state_dir=${LEASEGATE_OPS_STATE_DIR:-"$compose_dir/.state"}
output=${1:-"$state_dir/phase-9-acceptance.json"}
command -v jq >/dev/null 2>&1 || { printf 'jq is required.\n' >&2; exit 1; }
mkdir -p "$(dirname -- "$output")" "$state_dir"

run_check() {
  name=$1
  shift
  log_file=$(mktemp "$state_dir/.acceptance.XXXXXX")
  if "$@" > "$log_file" 2>&1; then result=pass; else result=fail; fi
  summary=$(tail -n 1 "$log_file" | tr -cd '[:alnum:] ._:/-')
  rm -f "$log_file"
  jq -n --arg name "$name" --arg result "$result" --arg summary "$summary" \
    '{name:$name,result:$result,summary:$summary}'
}

checks=$(mktemp "$state_dir/.acceptance-checks.XXXXXX")
trap 'rm -f "$checks"' EXIT HUP INT TERM
{
  run_check preflight env LEASEGATE_ENV_FILE="$env_file" "$compose_dir/single-vps-check.sh" preflight
  run_check runtime env LEASEGATE_ENV_FILE="$env_file" "$compose_dir/single-vps-check.sh" runtime
  run_check monitor env LEASEGATE_ENV_FILE="$env_file" LEASEGATE_OPS_STATE_DIR="$state_dir" LEASEGATE_ALERT_WEBHOOK_FILE= "$script_dir/monitor.sh"
  run_check soak env LEASEGATE_OPS_STATE_DIR="$state_dir" "$script_dir/soak-status.sh"
  if command -v systemctl >/dev/null 2>&1; then
    run_check backup_timer systemctl is-enabled leasegate-backup.timer
    run_check monitor_timer systemctl is-enabled leasegate-monitor.timer
  else
    jq -n '{name:"backup_timer",result:"fail",summary:"systemctl unavailable"}'
    jq -n '{name:"monitor_timer",result:"fail",summary:"systemctl unavailable"}'
  fi
} | jq -s . > "$checks"

overall=$(jq -r 'if all(.[]; .result == "pass") then "pass" else "incomplete" end' "$checks")
temporary=$(mktemp "$(dirname -- "$output")/.phase-9-acceptance.XXXXXX")
jq -n --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg overall "$overall" \
  --slurpfile checks "$checks" \
  '{schema_version:1,phase:9,profile:"single_vps",provider_account_tests:"skipped",
    generated_at:$generated_at,overall:$overall,checks:$checks[0]}' > "$temporary"
chmod 600 "$temporary"
mv "$temporary" "$output"
printf 'Phase 9 acceptance report written to %s (%s).\n' "$output" "$overall"
[ "$overall" = pass ]
