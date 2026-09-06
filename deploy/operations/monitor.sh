#!/usr/bin/env sh
set -eu

script_dir=$(dirname -- "$0")
root_dir=$(cd "$script_dir/../.." && pwd)
compose_dir="$root_dir/deploy/compose"
env_file=${LEASEGATE_ENV_FILE:-"$compose_dir/.env"}
backup_dir=${LEASEGATE_BACKUP_DIR:-"$compose_dir/backups"}
state_dir=${LEASEGATE_OPS_STATE_DIR:-"$compose_dir/.state"}
metrics_file=${LEASEGATE_METRICS_FILE:-"$state_dir/leasegate.prom"}
status_file=${LEASEGATE_STATUS_FILE:-"$state_dir/operations-status.json"}
disk_warning_percent=${LEASEGATE_DISK_WARNING_PERCENT:-75}
disk_critical_percent=${LEASEGATE_DISK_CRITICAL_PERCENT:-90}
maximum_backup_age_seconds=${LEASEGATE_MAX_BACKUP_AGE_SECONDS:-90000}
certificate_warning_days=${LEASEGATE_CERT_WARNING_DAYS:-21}

for value in "$disk_warning_percent" "$disk_critical_percent" "$maximum_backup_age_seconds" "$certificate_warning_days"; do
  case "$value" in ''|*[!0-9]*) printf 'Monitor thresholds must be integers.\n' >&2; exit 1 ;; esac
done
[ "$disk_warning_percent" -lt "$disk_critical_percent" ] || {
  printf 'Disk warning threshold must be below critical.\n' >&2
  exit 1
}
[ -f "$env_file" ] || { printf 'Missing environment file.\n' >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { printf 'jq is required for the redacted status snapshot.\n' >&2; exit 1; }
mkdir -p "$state_dir"
chmod 700 "$state_dir"

issues=''
add_issue() {
  if [ -z "$issues" ]; then issues=$1; else issues="$issues,$1"; fi
}

disk_used_percent=$(df -Pk "$compose_dir" | awk 'NR == 2 {gsub(/%/, "", $5); print $5}')
case "$disk_used_percent" in ''|*[!0-9]*) disk_used_percent=100; add_issue disk_probe_failed ;; esac
if [ "$disk_used_percent" -ge "$disk_critical_percent" ]; then
  add_issue disk_critical
elif [ "$disk_used_percent" -ge "$disk_warning_percent" ]; then
  add_issue disk_warning
fi

running=$(docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" ps --status running --services 2>/dev/null || true)
running_count=0
for service in postgres object-store control-plane worker web gateway; do
  if printf '%s\n' "$running" | grep -Fx "$service" >/dev/null; then
    running_count=$((running_count + 1))
  else
    add_issue "service_${service}_down"
  fi
done

control_ready=0
if docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" exec -T control-plane keylease-cloud healthcheck >/dev/null 2>&1; then
  control_ready=1
else
  add_issue control_not_ready
fi
gateway_ready=0
if docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" exec -T gateway leasegate-edge healthcheck >/dev/null 2>&1; then
  gateway_ready=1
else
  add_issue gateway_not_ready
fi

now=$(date +%s)
backup_age=-1
latest_checksum=$(find "$backup_dir" -maxdepth 1 -type f -name 'backup-*.sha256' -printf '%T@ %p\n' 2>/dev/null | sort -nr | awk 'NR == 1 {sub(/^[^ ]+ /, ""); print; exit}')
if [ -n "$latest_checksum" ]; then
  backup_modified=$(stat -c %Y "$latest_checksum")
  backup_age=$((now - backup_modified))
  if [ "$backup_age" -gt "$maximum_backup_age_seconds" ]; then
    add_issue backup_stale
  fi
  if ! (cd "$(dirname -- "$latest_checksum")" && sha256sum -c "$(basename -- "$latest_checksum")" >/dev/null 2>&1); then
    add_issue backup_checksum_failed
  fi
else
  add_issue backup_missing
fi

domain=$(awk -F= '$1 == "LEASEGATE_DOMAIN" {print substr($0, index($0, "=") + 1)}' "$env_file")
case "$domain" in
  ''|*[!A-Za-z0-9.-]*) certificate_expiry_seconds=-1; add_issue certificate_domain_invalid ;;
  *)
    certificate_line=$(timeout 10 openssl s_client -connect "$domain:443" -servername "$domain" </dev/null 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null || true)
    certificate_date=${certificate_line#notAfter=}
    certificate_epoch=$(date -u -d "$certificate_date" +%s 2>/dev/null || true)
    if [ -z "$certificate_epoch" ]; then
      certificate_expiry_seconds=-1
      add_issue certificate_probe_failed
    else
      certificate_expiry_seconds=$((certificate_epoch - now))
      if [ "$certificate_expiry_seconds" -le $((certificate_warning_days * 86400)) ]; then
        add_issue certificate_expiring
      fi
    fi
    ;;
esac

healthy=1
[ -z "$issues" ] || healthy=0
soak_file="$state_dir/soak.state"
previous_soak_start=$(awk -F= '$1 == "SOAK_STARTED_AT" {print $2}' "$soak_file" 2>/dev/null || true)
previous_failures=$(awk -F= '$1 == "SOAK_FAILURES" {print $2}' "$soak_file" 2>/dev/null || true)
case "$previous_soak_start" in ''|*[!0-9]*) previous_soak_start=0 ;; esac
case "$previous_failures" in ''|*[!0-9]*) previous_failures=0 ;; esac
if [ "$previous_soak_start" -gt "$now" ]; then previous_soak_start=0; fi
if [ "$healthy" -eq 1 ]; then
  if [ "$previous_soak_start" -eq 0 ]; then soak_start=$now; else soak_start=$previous_soak_start; fi
  soak_seconds=$((now - soak_start))
  soak_failures=$previous_failures
else
  soak_start=0
  soak_seconds=0
  soak_failures=$((previous_failures + 1))
fi
temporary_soak=$(mktemp "$state_dir/.soak.XXXXXX")
printf 'SOAK_STARTED_AT=%s\nSOAK_LAST_CHECK_AT=%s\nSOAK_CONSECUTIVE_SECONDS=%s\nSOAK_FAILURES=%s\n' \
  "$soak_start" "$now" "$soak_seconds" "$soak_failures" > "$temporary_soak"
chmod 600 "$temporary_soak"
mv "$temporary_soak" "$soak_file"
metrics_dir=$(dirname -- "$metrics_file")
mkdir -p "$metrics_dir"
temporary_metrics=$(mktemp "$metrics_dir/.leasegate.prom.XXXXXX")
{
  printf '# HELP leasegate_host_healthy Whether all local single-VPS checks passed.\n'
  printf '# TYPE leasegate_host_healthy gauge\nleasegate_host_healthy %s\n' "$healthy"
  printf '# HELP leasegate_host_disk_used_percent Root filesystem usage percentage.\n'
  printf '# TYPE leasegate_host_disk_used_percent gauge\nleasegate_host_disk_used_percent %s\n' "$disk_used_percent"
  printf '# HELP leasegate_backup_age_seconds Age of the latest encrypted backup checksum manifest; -1 means missing.\n'
  printf '# TYPE leasegate_backup_age_seconds gauge\nleasegate_backup_age_seconds %s\n' "$backup_age"
  printf '# HELP leasegate_certificate_expiry_seconds Seconds until the public TLS certificate expires; -1 means probe failure.\n'
  printf '# TYPE leasegate_certificate_expiry_seconds gauge\nleasegate_certificate_expiry_seconds %s\n' "$certificate_expiry_seconds"
  printf '# HELP leasegate_compose_services_running Number of expected services running.\n'
  printf '# TYPE leasegate_compose_services_running gauge\nleasegate_compose_services_running %s\n' "$running_count"
  printf '# HELP leasegate_control_plane_ready Whether the local Control Plane readiness probe passed.\n'
  printf '# TYPE leasegate_control_plane_ready gauge\nleasegate_control_plane_ready %s\n' "$control_ready"
  printf '# HELP leasegate_gateway_ready Whether the local Gateway readiness probe passed.\n'
  printf '# TYPE leasegate_gateway_ready gauge\nleasegate_gateway_ready %s\n' "$gateway_ready"
  printf '# HELP leasegate_soak_consecutive_seconds Consecutive healthy seconds observed by the Phase 8 monitor.\n'
  printf '# TYPE leasegate_soak_consecutive_seconds gauge\nleasegate_soak_consecutive_seconds %s\n' "$soak_seconds"
  printf '# HELP leasegate_soak_failures_total Number of monitor failures observed by this local state file.\n'
  printf '# TYPE leasegate_soak_failures_total counter\nleasegate_soak_failures_total %s\n' "$soak_failures"
} > "$temporary_metrics"
chmod 644 "$temporary_metrics"
mv "$temporary_metrics" "$metrics_file"

release_id=$(awk -F= '$1 == "LEASEGATE_RELEASE_ID" {print substr($0, index($0, "=") + 1)}' "$state_dir/current-release.env" 2>/dev/null || true)
case "$release_id" in ''|*[!A-Za-z0-9._-]*) release_id=unknown ;; esac
generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
status_dir=$(dirname -- "$status_file")
mkdir -p "$status_dir"
temporary_status=$(mktemp "$status_dir/.operations-status.XXXXXX")
jq -n \
  --arg generated_at "$generated_at" \
  --arg release_id "$release_id" \
  --arg issues "$issues" \
  --argjson healthy "$healthy" \
  --argjson running "$running_count" \
  --argjson control_ready "$control_ready" \
  --argjson gateway_ready "$gateway_ready" \
  --argjson disk_used_percent "$disk_used_percent" \
  --argjson backup_age_seconds "$backup_age" \
  --argjson certificate_expiry_seconds "$certificate_expiry_seconds" \
  --argjson soak_consecutive_seconds "$soak_seconds" \
  --argjson soak_failures "$soak_failures" \
  '{schema_version:1,available:true,profile:"single_vps",generated_at:$generated_at,
    release_id:$release_id,healthy:($healthy == 1),
    issues:(if $issues == "" then [] else ($issues | split(",")) end),
    services:{expected:6,running:$running,control_plane_ready:($control_ready == 1),gateway_ready:($gateway_ready == 1)},
    disk:{used_percent:$disk_used_percent},
    backup:{age_seconds:$backup_age_seconds},
    tls:{expiry_seconds:$certificate_expiry_seconds},
    soak:{consecutive_seconds:$soak_consecutive_seconds,failures:$soak_failures}}' \
  > "$temporary_status"
chmod 644 "$temporary_status"
mv "$temporary_status" "$status_file"

if [ -n "$issues" ] && [ -n "${LEASEGATE_ALERT_WEBHOOK_FILE:-}" ]; then
  webhook_file=$LEASEGATE_ALERT_WEBHOOK_FILE
  if [ ! -f "$webhook_file" ] || [ ! -s "$webhook_file" ]; then
    printf 'Alert webhook file is missing, not regular, or empty.\n' >&2
    exit 1
  fi
  unsafe=$(find "$webhook_file" -prune -type f -perm /077 -print)
  [ -z "$unsafe" ] || { printf 'Alert webhook file permissions are too broad.\n' >&2; exit 1; }
  webhook=$(tr -d '\r\n' < "$webhook_file")
  case "$webhook" in https://*) ;; *) printf 'Alert webhook must use HTTPS.\n' >&2; exit 1 ;; esac
  curl --fail --silent --show-error --max-time 10 \
    --header 'content-type: application/json' \
    --data "{\"service\":\"leasegate\",\"profile\":\"single_vps\",\"status\":\"critical\",\"codes\":\"$issues\"}" \
    "$webhook" >/dev/null
fi

if [ -n "$issues" ]; then
  printf 'Single-VPS monitor failed: %s\n' "$issues" >&2
  exit 1
fi
printf 'Single-VPS monitor passed; metrics written to %s\n' "$metrics_file"
