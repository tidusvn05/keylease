#!/usr/bin/env sh
set -eu

script_dir=$(dirname -- "$0")
root_dir=$(cd "$script_dir/../.." && pwd)
state_dir=${LEASEGATE_OPS_STATE_DIR:-"$root_dir/deploy/compose/.state"}
soak_file="$state_dir/soak.state"
required_seconds=${LEASEGATE_SOAK_REQUIRED_SECONDS:-604800}
case "$required_seconds" in ''|*[!0-9]*) printf 'LEASEGATE_SOAK_REQUIRED_SECONDS must be an integer.\n' >&2; exit 1 ;; esac
[ "$required_seconds" -ge 1 ] || { printf 'LEASEGATE_SOAK_REQUIRED_SECONDS must be positive.\n' >&2; exit 1; }
[ -f "$soak_file" ] || { printf 'No soak state exists; run monitor.sh first.\n' >&2; exit 1; }
consecutive=$(awk -F= '$1 == "SOAK_CONSECUTIVE_SECONDS" {print $2}' "$soak_file")
last_check=$(awk -F= '$1 == "SOAK_LAST_CHECK_AT" {print $2}' "$soak_file")
failures=$(awk -F= '$1 == "SOAK_FAILURES" {print $2}' "$soak_file")
for value in "$consecutive" "$last_check" "$failures"; do
  case "$value" in ''|*[!0-9]*) printf 'Soak state is invalid.\n' >&2; exit 1 ;; esac
done
now=$(date +%s)
[ "$last_check" -le "$now" ] || { printf 'Soak state contains a future timestamp.\n' >&2; exit 1; }
[ $((now - last_check)) -le 600 ] || { printf 'Soak state is stale; the monitor has not run within ten minutes.\n' >&2; exit 1; }
printf 'Consecutive healthy seconds: %s / %s; observed failures: %s\n' "$consecutive" "$required_seconds" "$failures"
[ "$consecutive" -ge "$required_seconds" ] || exit 1
printf 'Single-VPS soak requirement passed.\n'
