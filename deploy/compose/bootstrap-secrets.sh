#!/usr/bin/env sh
set -eu
umask 077

script_dir=$(dirname -- "$0")
script_dir=$(cd "$script_dir" && pwd)
secret_dir="$script_dir/secrets"
mkdir -p "$secret_dir"

write_random_text() {
  destination=$1
  prefix=$2
  if [ ! -e "$destination" ]; then
    random=$(openssl rand -base64 48 | tr -d '\n=/+')
    printf '%s%s\n' "$prefix" "$random" > "$destination"
  fi
}

write_random_text "$secret_dir/postgres_password" "pg_"
write_random_text "$secret_dir/admin_token" "kladmin_"
write_random_text "$secret_dir/minio_user" "klminio_"
write_random_text "$secret_dir/minio_password" "klminio_secret_"
write_random_text "$secret_dir/siem_hmac_secret" "klsiem_"

if [ ! -e "$secret_dir/control_signing_key" ]; then
  openssl rand -base64 32 | tr -d '\n=' > "$secret_dir/control_signing_key"
  printf '\n' >> "$secret_dir/control_signing_key"
fi
if [ ! -e "$secret_dir/edge_storage_key" ]; then
  openssl rand -base64 32 | tr -d '\n=' > "$secret_dir/edge_storage_key"
  printf '\n' >> "$secret_dir/edge_storage_key"
fi
if [ ! -e "$secret_dir/database_url" ]; then
  postgres_password=$(tr -d '\n' < "$secret_dir/postgres_password")
  printf 'postgres://leasegate:%s@postgres:5432/leasegate\n' "$postgres_password" > "$secret_dir/database_url"
fi
if [ ! -e "$secret_dir/credential_backends.json" ]; then
  cp "$script_dir/credential-backends.example.json" "$secret_dir/credential_backends.json"
fi
if [ ! -e "$secret_dir/siem-secrets.json" ]; then
  cp "$script_dir/siem-secrets.example.json" "$secret_dir/siem-secrets.json"
fi

chmod 600 "$secret_dir"/*
printf 'Secrets created in %s. Back them up encrypted and never commit them.\n' "$secret_dir"
