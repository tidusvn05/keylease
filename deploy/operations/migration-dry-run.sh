#!/usr/bin/env sh
set -eu
umask 077

script_dir=$(dirname -- "$0")
root_dir=$(cd "$script_dir/../.." && pwd)
compose_dir="$root_dir/deploy/compose"
env_file=${LEASEGATE_ENV_FILE:-"$compose_dir/.env"}
release_dir=${1:?Usage: migration-dry-run.sh RELEASE_DIRECTORY}
release_env="$release_dir/release.env"
[ -f "$release_env" ] || { printf 'Missing release.env.\n' >&2; exit 1; }
(cd "$release_dir" && sha256sum -c SHA256SUMS >/dev/null)
control_image=$(awk -F= '$1 == "LEASEGATE_CONTROL_IMAGE" {print substr($0, index($0, "=") + 1)}' "$release_env")
printf '%s\n' "$control_image" | grep -Eq '^sha256:[0-9a-f]{64}$' || {
  printf 'Invalid Control Plane image ID.\n' >&2
  exit 1
}
if ! docker image inspect "$control_image" >/dev/null 2>&1; then
  [ -f "$release_dir/images.tar.gz" ] || { printf 'Candidate image is unavailable.\n' >&2; exit 1; }
  gzip -dc "$release_dir/images.tar.gz" | docker load >/dev/null
fi
docker image inspect "$control_image" >/dev/null
[ -f "$env_file" ] || { printf 'Missing environment file.\n' >&2; exit 1; }

temporary_dir=$(mktemp -d)
suffix="$$-$(date +%s)"
network="leasegate-migration-$suffix"
postgres_container="leasegate-migration-pg-$suffix"
cleanup() {
  docker rm -f "$postgres_container" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$temporary_dir"
}
trap cleanup EXIT HUP INT TERM

docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" exec -T postgres \
  pg_dump -U leasegate -d leasegate --format=custom --no-owner --no-acl \
  > "$temporary_dir/database.dump"
password=$(openssl rand -hex 24)
docker network create "$network" >/dev/null
docker run -d --name "$postgres_container" --network "$network" \
  -e POSTGRES_PASSWORD="$password" -e POSTGRES_DB=leasegate_check \
  postgres:17-alpine@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73 >/dev/null
ready=0
for _attempt in $(seq 1 30); do
  if docker exec "$postgres_container" pg_isready -U postgres -d leasegate_check >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
[ "$ready" -eq 1 ] || { printf 'Temporary PostgreSQL did not become ready.\n' >&2; exit 1; }
docker exec -i "$postgres_container" pg_restore -U postgres -d leasegate_check --no-owner --no-acl \
  < "$temporary_dir/database.dump"
printf 'postgresql://postgres:%s@%s:5432/leasegate_check\n' "$password" "$postgres_container" \
  > "$temporary_dir/database_url"
chmod 600 "$temporary_dir/database_url"
docker run --rm --network "$network" --user "$(id -u):$(id -g)" \
  -e KEYLEASE_DATABASE_URL_FILE=/run/leasegate/database_url \
  -v "$temporary_dir:/run/leasegate:ro" "$control_image" migrate
printf 'Migration dry-run passed against a disposable clone of PostgreSQL.\n'
