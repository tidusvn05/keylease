#!/usr/bin/env sh
set -eu
umask 077

script_dir=$(dirname -- "$0")
root_dir=$(cd "$script_dir/../.." && pwd)
compose_dir="$root_dir/deploy/compose"
env_file=${LEASEGATE_ENV_FILE:-"$compose_dir/.env"}
release_dir=${1:?Usage: upgrade.sh RELEASE_DIRECTORY}
backup_dir=${LEASEGATE_BACKUP_DIR:-"$compose_dir/backups"}
state_dir=${LEASEGATE_OPS_STATE_DIR:-"$compose_dir/.state"}
: "${LEASEGATE_AGE_RECIPIENT:?Set LEASEGATE_AGE_RECIPIENT before upgrade}"

release_env="$release_dir/release.env"
[ -f "$release_env" ] || { printf 'Missing release.env.\n' >&2; exit 1; }
(cd "$release_dir" && sha256sum -c SHA256SUMS >/dev/null)
if [ -n "${LEASEGATE_COSIGN_PUBLIC_KEY:-}" ]; then
  command -v cosign >/dev/null
  cosign verify-blob --key "$LEASEGATE_COSIGN_PUBLIC_KEY" \
    --signature "$release_dir/SHA256SUMS.sig" "$release_dir/SHA256SUMS" >/dev/null
elif [ "${LEASEGATE_REQUIRE_SIGNATURE:-0}" = 1 ]; then
  printf 'A cosign public key is required by policy.\n' >&2
  exit 1
fi
[ -f "$release_dir/images.tar.gz" ] || { printf 'Release image archive is missing.\n' >&2; exit 1; }
gzip -dc "$release_dir/images.tar.gz" | docker load >/dev/null

read_image() {
  file=$1
  key=$2
  value=$(awk -F= -v key="$key" '$1 == key {print substr($0, index($0, "=") + 1)}' "$file")
  printf '%s\n' "$value" | grep -Eq '^sha256:[0-9a-f]{64}$' || {
    printf 'Invalid image ID for %s.\n' "$key" >&2
    exit 1
  }
  docker image inspect "$value" >/dev/null
  printf '%s' "$value"
}
load_release() {
  file=$1
  LEASEGATE_CONTROL_IMAGE=$(read_image "$file" LEASEGATE_CONTROL_IMAGE)
  LEASEGATE_WEB_IMAGE=$(read_image "$file" LEASEGATE_WEB_IMAGE)
  LEASEGATE_GATEWAY_IMAGE=$(read_image "$file" LEASEGATE_GATEWAY_IMAGE)
  export LEASEGATE_CONTROL_IMAGE LEASEGATE_WEB_IMAGE LEASEGATE_GATEWAY_IMAGE
}
load_release "$release_env"
candidate_control_image=$LEASEGATE_CONTROL_IMAGE
candidate_web_image=$LEASEGATE_WEB_IMAGE
candidate_gateway_image=$LEASEGATE_GATEWAY_IMAGE

mkdir -p "$backup_dir" "$state_dir"
chmod 700 "$state_dir"
current_control_container=$(docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" ps -q control-plane)
current_worker_container=$(docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" ps -q worker)
current_web_container=$(docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" ps -q web)
current_gateway_container=$(docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" ps -q gateway)
for container in "$current_control_container" "$current_worker_container" "$current_web_container" "$current_gateway_container"; do
  [ -n "$container" ] || {
    printf 'Cannot capture all running images required for safe rollback.\n' >&2
    exit 1
  }
done
current_control_image=$(docker inspect --format '{{.Image}}' "$current_control_container")
current_worker_image=$(docker inspect --format '{{.Image}}' "$current_worker_container")
current_web_image=$(docker inspect --format '{{.Image}}' "$current_web_container")
current_gateway_image=$(docker inspect --format '{{.Image}}' "$current_gateway_container")
for image in "$current_control_image" "$current_worker_image" "$current_web_image" "$current_gateway_image"; do
  printf '%s\n' "$image" | grep -Eq '^sha256:[0-9a-f]{64}$' || {
    printf 'Cannot capture the current image set for rollback.\n' >&2
    exit 1
  }
done
[ "$current_control_image" = "$current_worker_image" ] || {
  printf 'Control Plane and worker image IDs differ; refusing an ambiguous upgrade.\n' >&2
  exit 1
}
LEASEGATE_CONTROL_IMAGE=$current_control_image
LEASEGATE_WEB_IMAGE=$current_web_image
LEASEGATE_GATEWAY_IMAGE=$current_gateway_image
export LEASEGATE_CONTROL_IMAGE LEASEGATE_WEB_IMAGE LEASEGATE_GATEWAY_IMAGE

LEASEGATE_ENV_FILE="$env_file" "$compose_dir/single-vps-check.sh" preflight
LEASEGATE_ENV_FILE="$env_file" "$script_dir/migration-dry-run.sh" "$release_dir"
result_file=$(mktemp "$state_dir/.backup-result.XXXXXX")
trap 'rm -f "$result_file"' EXIT HUP INT TERM
LEASEGATE_ENV_FILE="$env_file" LEASEGATE_BACKUP_RESULT_FILE="$result_file" \
  "$compose_dir/backup.sh" "$backup_dir"

printf '%s\n' \
  'LEASEGATE_RELEASE_ID=observed-before-upgrade' \
  "LEASEGATE_CONTROL_IMAGE=$current_control_image" \
  "LEASEGATE_WEB_IMAGE=$current_web_image" \
  "LEASEGATE_GATEWAY_IMAGE=$current_gateway_image" \
  > "$state_dir/current-release.env.tmp"
mv "$state_dir/current-release.env.tmp" "$state_dir/current-release.env"
cp "$state_dir/current-release.env" "$state_dir/previous-release.env.tmp"
mv "$state_dir/previous-release.env.tmp" "$state_dir/previous-release.env"
LEASEGATE_CONTROL_IMAGE=$candidate_control_image
LEASEGATE_WEB_IMAGE=$candidate_web_image
LEASEGATE_GATEWAY_IMAGE=$candidate_gateway_image
export LEASEGATE_CONTROL_IMAGE LEASEGATE_WEB_IMAGE LEASEGATE_GATEWAY_IMAGE
upgrade_ok=1
if ! docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" \
  up -d --no-build --wait; then
  upgrade_ok=0
elif ! LEASEGATE_ENV_FILE="$env_file" "$compose_dir/single-vps-check.sh" runtime; then
  upgrade_ok=0
fi
if [ "$upgrade_ok" -ne 1 ]; then
  printf 'Upgrade failed. Attempting image rollback. Database restore is never automatic.\n' >&2
  if [ -f "$state_dir/previous-release.env" ]; then
    load_release "$state_dir/previous-release.env"
    docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" up -d --no-build --wait || true
  fi
  exit 1
fi
cp "$release_env" "$state_dir/current-release.env.tmp"
mv "$state_dir/current-release.env.tmp" "$state_dir/current-release.env"
printf 'Upgrade completed. Backup timestamp: %s\n' "$(cat "$result_file")"
