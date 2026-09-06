#!/usr/bin/env sh
set -eu
umask 077

script_dir=$(dirname -- "$0")
root_dir=$(cd "$script_dir/../.." && pwd)
compose_dir="$root_dir/deploy/compose"
env_file=${LEASEGATE_ENV_FILE:-"$compose_dir/.env"}
release_id=${1:-$(git -C "$root_dir" rev-parse --short=12 HEAD)}
output_dir=${2:-"$root_dir/deploy/releases/$release_id"}

case "$release_id" in
  ''|*[!A-Za-z0-9._-]*) printf 'Invalid release ID.\n' >&2; exit 1 ;;
esac
[ -f "$env_file" ] || { printf 'Missing environment file: %s\n' "$env_file" >&2; exit 1; }
[ -z "$(git -C "$root_dir" status --porcelain)" ] || {
  printf 'Refusing to build a release from a dirty worktree.\n' >&2
  exit 1
}
for command_name in docker git gzip sha256sum syft; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'Missing release dependency: %s\n' "$command_name" >&2
    exit 1
  }
done
[ ! -e "$output_dir" ] || { printf 'Release output already exists: %s\n' "$output_dir" >&2; exit 1; }
mkdir -p "$output_dir"

control_tag="leasegate-control-plane:$release_id"
web_tag="leasegate-web:$release_id"
gateway_tag="leasegate-gateway:$release_id"
export LEASEGATE_CONTROL_IMAGE="$control_tag"
export LEASEGATE_WEB_IMAGE="$web_tag"
export LEASEGATE_GATEWAY_IMAGE="$gateway_tag"
docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" \
  build --pull control-plane web gateway

control_image=$(docker image inspect --format '{{.Id}}' "$control_tag")
web_image=$(docker image inspect --format '{{.Id}}' "$web_tag")
gateway_image=$(docker image inspect --format '{{.Id}}' "$gateway_tag")
for image in "$control_image" "$web_image" "$gateway_image"; do
  printf '%s\n' "$image" | grep -Eq '^sha256:[0-9a-f]{64}$' || {
    printf 'Invalid image ID.\n' >&2
    exit 1
  }
done

syft "$control_image" -o spdx-json > "$output_dir/control-plane.spdx.json"
syft "$web_image" -o spdx-json > "$output_dir/web.spdx.json"
syft "$gateway_image" -o spdx-json > "$output_dir/gateway.spdx.json"
docker save "$control_tag" "$web_tag" "$gateway_tag" | gzip -n > "$output_dir/images.tar.gz"
commit=$(git -C "$root_dir" rev-parse HEAD)
created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
printf '%s\n' \
  "LEASEGATE_RELEASE_ID=$release_id" \
  "LEASEGATE_CONTROL_IMAGE=$control_image" \
  "LEASEGATE_WEB_IMAGE=$web_image" \
  "LEASEGATE_GATEWAY_IMAGE=$gateway_image" > "$output_dir/release.env"
printf '{"schema_version":1,"release_id":"%s","git_commit":"%s","created_at":"%s","images":{"control_plane":"%s","web":"%s","gateway":"%s"}}\n' \
  "$release_id" "$commit" "$created_at" "$control_image" "$web_image" "$gateway_image" \
  > "$output_dir/provenance.json"
(
  cd "$output_dir"
  sha256sum release.env provenance.json images.tar.gz control-plane.spdx.json web.spdx.json gateway.spdx.json > SHA256SUMS
)

if [ -n "${LEASEGATE_COSIGN_KEY:-}" ]; then
  command -v cosign >/dev/null 2>&1 || { printf 'cosign is required for signing.\n' >&2; exit 1; }
  cosign sign-blob --yes --key "$LEASEGATE_COSIGN_KEY" \
    --output-signature "$output_dir/SHA256SUMS.sig" "$output_dir/SHA256SUMS"
elif [ "${LEASEGATE_REQUIRE_SIGNATURE:-0}" = 1 ]; then
  printf 'LEASEGATE_REQUIRE_SIGNATURE=1 but LEASEGATE_COSIGN_KEY is unset.\n' >&2
  exit 1
fi

printf 'Content-addressed release created at %s\n' "$output_dir"
