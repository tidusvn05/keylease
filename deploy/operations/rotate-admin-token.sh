#!/usr/bin/env sh
set -eu
umask 077

script_dir=$(dirname -- "$0")
root_dir=$(cd "$script_dir/../.." && pwd)
compose_dir="$root_dir/deploy/compose"
env_file=${LEASEGATE_ENV_FILE:-"$compose_dir/.env"}
secret_file="$compose_dir/secrets/admin_token"
confirmation=${LEASEGATE_ROTATE_ADMIN_CONFIRM:-${1:-}}
[ "$confirmation" = rotate-bootstrap-admin-token ] || {
  printf 'Set LEASEGATE_ROTATE_ADMIN_CONFIRM=rotate-bootstrap-admin-token to continue.\n' >&2
  exit 2
}
[ -f "$secret_file" ] || { printf 'Admin token file is missing.\n' >&2; exit 1; }
temporary=$(mktemp "$compose_dir/secrets/.admin-token.XXXXXX")
previous=$(mktemp "$compose_dir/secrets/.admin-token-previous.XXXXXX")
cp "$secret_file" "$previous"
chmod 600 "$previous"
cleanup() { rm -f "$temporary" "$previous"; }
trap cleanup EXIT HUP INT TERM
printf 'kladmin_%s\n' "$(openssl rand -base64 48 | tr -d '\n=/+')" > "$temporary"
chmod 600 "$temporary"
mv "$temporary" "$secret_file"
if ! docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" \
  up -d --no-deps --force-recreate --wait control-plane; then
  mv "$previous" "$secret_file"
  docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" \
    up -d --no-deps --force-recreate --wait control-plane >/dev/null 2>&1 || true
  printf 'Control Plane restart failed; the previous administrator credential was restored.\n' >&2
  exit 1
fi
rm -f "$previous"
printf 'Bootstrap administrator credential rotated. Read it only from %s when required.\n' "$secret_file"
