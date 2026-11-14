#!/usr/bin/env sh
set -eu

requested_root=${1:?Usage: sudo install.sh ABSOLUTE_KEYLEASE_REPOSITORY_PATH --apply}
confirmation=${2:-}
[ "$confirmation" = --apply ] || { printf 'Pass --apply to install systemd units.\n' >&2; exit 2; }
case "$requested_root" in /*) ;; *) printf 'Repository path must be absolute.\n' >&2; exit 1 ;; esac
[ -d "$requested_root" ] || { printf 'Repository path does not exist.\n' >&2; exit 1; }
root_dir=$(cd "$requested_root" && pwd)
case "$root_dir" in *[!A-Za-z0-9._/-]*) printf 'Repository path contains unsupported characters.\n' >&2; exit 1 ;; esac
[ "$root_dir" != / ] || { printf 'Repository path cannot be /.\n' >&2; exit 1; }
[ -x "$root_dir/deploy/operations/monitor.sh" ] || { printf 'Invalid KeyLease repository path.\n' >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { printf 'Run this installer as root.\n' >&2; exit 1; }
service_user=$(stat -c %U "$root_dir")
service_group=$(stat -c %G "$root_dir")
[ "$service_user" != root ] || { printf 'Repository must be owned by the dedicated non-root operator.\n' >&2; exit 1; }
case "$service_user:$service_group" in *[!A-Za-z0-9_.:-]*) printf 'Repository owner or group is invalid.\n' >&2; exit 1 ;; esac

script_dir=$(dirname -- "$0")
script_dir=$(cd "$script_dir" && pwd)
install -d -m 700 /etc/keylease
if [ ! -e /etc/keylease/operations.env ]; then
  install -m 600 "$script_dir/keylease-operations.env.example" /etc/keylease/operations.env
  printf 'Created /etc/keylease/operations.env. Edit it before enabling timers.\n'
fi
for unit in keylease-backup.service keylease-monitor.service; do
  sed -e "s|@KEYLEASE_ROOT@|$root_dir|g" \
    -e "s|@KEYLEASE_USER@|$service_user|g" \
    -e "s|@KEYLEASE_GROUP@|$service_group|g" \
    "$script_dir/$unit" > "/etc/systemd/system/$unit.tmp"
  chmod 644 "/etc/systemd/system/$unit.tmp"
  mv "/etc/systemd/system/$unit.tmp" "/etc/systemd/system/$unit"
done
install -m 644 "$script_dir/keylease-backup.timer" /etc/systemd/system/keylease-backup.timer
install -m 644 "$script_dir/keylease-monitor.timer" /etc/systemd/system/keylease-monitor.timer
systemctl daemon-reload
printf 'Units installed for %s:%s but not enabled. After editing operations.env, run:\n' "$service_user" "$service_group"
printf '  systemctl enable --now keylease-backup.timer keylease-monitor.timer\n'
