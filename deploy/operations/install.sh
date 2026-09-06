#!/usr/bin/env sh
set -eu
umask 077

script_dir=$(dirname -- "$0")
root_dir=$(cd "$script_dir/../.." && pwd)
compose_dir="$root_dir/deploy/compose"
env_file="$compose_dir/.env"
secret_dir="$compose_dir/secrets"
state_dir="$compose_dir/.state"

domain=''
age_recipient=''
organization_name='My organization'
project_name='default'
owner_name='Owner'
account_id='acct_selfhosted_primary'
enable_timers=1
confirmation=0

usage() {
  cat <<'EOF'
Usage: deploy/leasegate install --domain DOMAIN --age-recipient AGE_RECIPIENT --yes [OPTIONS]

Required:
  --domain DOMAIN              DNS name already pointing to this VPS
  --age-recipient RECIPIENT    Off-host age recipient used for backups
  --yes                        Confirm a new self-hosted installation

Options:
  --organization NAME          Initial organization name
  --project NAME               Initial project name
  --owner NAME                 Initial owner display name
  --account-id ID              Initial opaque account ID
  --no-systemd                 Do not install or enable backup/monitor timers
  --help                       Show this help

The installer is intentionally for a fresh deployment. It never overwrites an
existing .env, installation marker, or one-time enrollment credentials.
EOF
}

fail() { printf '[FAIL] %s\n' "$1" >&2; exit 1; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --domain) [ "$#" -ge 2 ] || fail '--domain requires a value'; domain=$2; shift 2 ;;
    --age-recipient) [ "$#" -ge 2 ] || fail '--age-recipient requires a value'; age_recipient=$2; shift 2 ;;
    --organization) [ "$#" -ge 2 ] || fail '--organization requires a value'; organization_name=$2; shift 2 ;;
    --project) [ "$#" -ge 2 ] || fail '--project requires a value'; project_name=$2; shift 2 ;;
    --owner) [ "$#" -ge 2 ] || fail '--owner requires a value'; owner_name=$2; shift 2 ;;
    --account-id) [ "$#" -ge 2 ] || fail '--account-id requires a value'; account_id=$2; shift 2 ;;
    --no-systemd) enable_timers=0; shift ;;
    --yes) confirmation=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) fail "unknown installer option: $1" ;;
  esac
done

[ "$confirmation" -eq 1 ] || fail 'pass --yes to confirm a new installation'
case "$domain" in ''|*[!A-Za-z0-9.-]*|.*|*.|*..*|-*|*-) fail 'domain must be a valid DNS hostname' ;; esac
case "$age_recipient" in age1*) ;; *) fail '--age-recipient must be an age recipient beginning with age1' ;; esac
case "$age_recipient" in *[!a-z0-9]*) fail '--age-recipient contains unsupported characters' ;; esac
[ "${#domain}" -le 253 ] || fail 'domain is longer than 253 characters'
[ "${#age_recipient}" -le 128 ] || fail '--age-recipient is unexpectedly long'
case "$account_id" in acct_*) ;; *) fail '--account-id must begin with acct_' ;; esac
case "$account_id" in *[!A-Za-z0-9._-]*) fail '--account-id contains unsupported characters' ;; esac
[ "${#account_id}" -le 200 ] || fail '--account-id is unexpectedly long'
for value in "$organization_name" "$project_name" "$owner_name"; do
  [ -n "$value" ] || fail 'setup names must not be empty'
  [ "${#value}" -le 200 ] || fail 'setup names must contain at most 200 characters'
done
[ "$(id -u)" -ne 0 ] || fail 'run as a dedicated non-root operator; the installer uses sudo only for systemd'
[ ! -e "$env_file" ] || fail "existing environment found: $env_file"
[ ! -e "$state_dir/installation.json" ] || fail 'this repository is already marked as installed'

"$script_dir/prepare-host.sh" --check
printf 'leasegate recipient validation' | age -r "$age_recipient" >/dev/null 2>&1 || fail '--age-recipient is not accepted by age'
install -m 600 "$compose_dir/.env.example" "$env_file"
mkdir -p "$state_dir"
chmod 700 "$state_dir"
"$compose_dir/bootstrap-secrets.sh"

set_env() {
  key=$1
  value=$2
  case "$value" in *'\n'*|*'\r'*) fail "invalid newline in $key" ;; esac
  temporary=$(mktemp "$compose_dir/.env.XXXXXX")
  awk -v key="$key" -v value="$value" '
    BEGIN { found=0 }
    $0 ~ "^" key "=" { print key "=" value; found=1; next }
    { print }
    END { if (!found) print key "=" value }
  ' "$env_file" > "$temporary"
  chmod 600 "$temporary"
  mv "$temporary" "$env_file"
}

set_env LEASEGATE_DOMAIN "$domain"
set_env LEASEGATE_RUNTIME_UID "$(id -u)"
set_env LEASEGATE_RUNTIME_GID "$(id -g)"

docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" build control-plane web gateway
docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" \
  up -d postgres object-store control-plane worker web

cloud_url="https://$domain/api"
ready=0
attempt=0
while [ "$attempt" -lt 60 ]; do
  if curl --fail --silent --show-error --max-time 5 "$cloud_url/readyz" >/dev/null 2>&1; then
    ready=1
    break
  fi
  attempt=$((attempt + 1))
  sleep 2
done
[ "$ready" -eq 1 ] || fail "Control Plane did not become reachable at $cloud_url/readyz"

admin_token=$(tr -d '\r\n' < "$secret_dir/admin_token")
work_dir=$(mktemp -d "$state_dir/.install.XXXXXX")
curl_config="$work_dir/curl-config"
cleanup() { rm -rf "$work_dir"; }
trap cleanup EXIT HUP INT TERM
printf 'header = "authorization: Bearer %s"\nheader = "content-type: application/json"\n' "$admin_token" > "$curl_config"
chmod 600 "$curl_config"

api_post() {
  endpoint=$1
  request_file=$2
  response_file=$3
  curl --fail-with-body --silent --show-error --config "$curl_config" \
    --data-binary "@$request_file" "$cloud_url$endpoint" > "$response_file"
}

bootstrap_request="$work_dir/bootstrap-request.json"
bootstrap_response="$work_dir/bootstrap-response.json"
jq -n --arg account "$account_id" --arg organization "$organization_name" \
  --arg project "$project_name" --arg owner "$owner_name" \
  '{account_id:$account,organization_name:$organization,project_name:$project,
    oidc_issuer:"urn:leasegate:direct-operator",oidc_subject:"owner",human_name:$owner}' \
  > "$bootstrap_request"
api_post /v1/bootstrap "$bootstrap_request" "$bootstrap_response"
organization_id=$(jq -er '.organization.id' "$bootstrap_response")
project_id=$(jq -er '.project.id' "$bootstrap_response")
approver_id=$(jq -er '.membership.human_id' "$bootstrap_response")

agent_request="$work_dir/agent-request.json"
agent_response="$work_dir/agent-response.json"
jq -n '{display_name:"Local MCP agent"}' > "$agent_request"
api_post "/v1/organizations/$organization_id/projects/$project_id/agents" "$agent_request" "$agent_response"
agent_id=$(jq -er '.agent.agent_id' "$agent_response")
jq -er '.credential' "$agent_response" > "$secret_dir/agent_credential"

if [ -e "$secret_dir/device_signing_key.pem" ]; then
  fail 'device signing key already exists; refusing to replace enrollment identity'
fi
openssl genpkey -algorithm Ed25519 -out "$secret_dir/device_signing_key.pem"
device_public_key=$(openssl pkey -in "$secret_dir/device_signing_key.pem" -pubout -outform DER | tail -c 32 | openssl base64 -A)
device_id="device_$(openssl rand -hex 16)"
enrollment_request="$work_dir/enrollment-request.json"
enrollment_response="$work_dir/enrollment-response.json"
jq -n --arg organization "$organization_id" --arg project "$project_id" \
  '{organization_id:$organization,project_id:$project,name:"Local single-VPS Gateway",ttl_seconds:600}' \
  > "$enrollment_request"
api_post /v1/edges/enrollments "$enrollment_request" "$enrollment_response"
enrollment_secret=$(jq -er '.enrollment_secret' "$enrollment_response")
edge_request="$work_dir/edge-request.json"
edge_response="$work_dir/edge-response.json"
jq -n --arg secret "$enrollment_secret" --arg device "$device_id" \
  --arg public_key "$device_public_key" \
  '{enrollment_secret:$secret,device_id:$device,public_key_base64:$public_key,software_version:"0.1.0"}' \
  > "$edge_request"
api_post /v1/edges/enroll "$edge_request" "$edge_response"
edge_id=$(jq -er '.edge.id' "$edge_response")
control_verifying_key=$(jq -er '.control_verifying_key' "$edge_response")
jq -er '.edge_credential' "$edge_response" > "$secret_dir/edge_credential"

issued_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
expires_at=$(date -u -d '+30 days' +%Y-%m-%dT%H:%M:%SZ)
policy_request="$work_dir/policy-request.json"
policy_response="$work_dir/policy-response.json"
jq -n --arg bundle "policy_bundle_$(openssl rand -hex 16)" \
  --arg organization "$organization_id" --arg project "$project_id" \
  --arg issued "$issued_at" --arg expires "$expires_at" \
  '{schema_version:1,bundle_id:$bundle,organization_id:$organization,project_id:$project,
    version:1,previous_bundle_digest:null,issued_at:$issued,not_before:$issued,
    expires_at:$expires,revocation_epoch:0,minimum_edge_version:"0.1.0",
    offline:{allow_r0_r1:false,max_seconds:0},rules:[]}' > "$policy_request"
api_post /v1/policies/activate "$policy_request" "$policy_response"
jq -e '.bundle.payload.version == 1' "$policy_response" >/dev/null

chmod 600 "$secret_dir"/*
set_env KEYLEASE_ORGANIZATION_ID "$organization_id"
set_env KEYLEASE_PROJECT_ID "$project_id"
set_env KEYLEASE_APPROVER_ID "$approver_id"
set_env LEASEGATE_EDGE_ID "$edge_id"
set_env LEASEGATE_AGENT_ID "$agent_id"
set_env LEASEGATE_CONTROL_VERIFYING_KEY "$control_verifying_key"

docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" run --rm --no-deps \
  --entrypoint keylease gateway --db /var/lib/leasegate/vault.sqlite3 \
  vault init --password-file /run/leasegate-secrets/vault_password >/dev/null
docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" build web
docker compose --env-file "$env_file" -f "$compose_dir/compose.yaml" up -d --wait

LEASEGATE_ENV_FILE="$env_file" "$compose_dir/single-vps-check.sh" runtime

if [ "$enable_timers" -eq 1 ]; then
  command -v sudo >/dev/null 2>&1 || fail 'sudo is required to install systemd timers; use --no-systemd to defer'
  sudo "$root_dir/deploy/systemd/install.sh" "$root_dir" --apply
  operations_env=$(mktemp "$state_dir/.operations-env.XXXXXX")
  sed \
    -e "s|^LEASEGATE_AGE_RECIPIENT=.*|LEASEGATE_AGE_RECIPIENT=$age_recipient|" \
    -e 's|^LEASEGATE_AGE_IDENTITY=.*|LEASEGATE_AGE_IDENTITY=|' \
    -e "s|^LEASEGATE_ENV_FILE=.*|LEASEGATE_ENV_FILE=$env_file|" \
    -e "s|^LEASEGATE_OPS_STATE_DIR=.*|LEASEGATE_OPS_STATE_DIR=$state_dir|" \
    -e "s|^LEASEGATE_METRICS_FILE=.*|LEASEGATE_METRICS_FILE=$state_dir/leasegate.prom|" \
    "$root_dir/deploy/systemd/leasegate-operations.env.example" > "$operations_env"
  sudo install -m 600 "$operations_env" /etc/leasegate/operations.env
  rm -f "$operations_env"
  sudo install -d -o "$(id -un)" -g "$(id -gn)" -m 700 /var/backups/leasegate
  initial_backup_dir=/var/backups/leasegate
else
  initial_backup_dir="$compose_dir/backups"
fi
set_env LEASEGATE_AGE_RECIPIENT "$age_recipient"
set_env LEASEGATE_BACKUP_DIR "$initial_backup_dir"

LEASEGATE_ENV_FILE="$env_file" LEASEGATE_AGE_RECIPIENT="$age_recipient" \
  "$compose_dir/backup.sh" "$initial_backup_dir"
LEASEGATE_ENV_FILE="$env_file" LEASEGATE_BACKUP_DIR="$initial_backup_dir" \
  LEASEGATE_OPS_STATE_DIR="$state_dir" "$script_dir/monitor.sh"
LEASEGATE_ENV_FILE="$env_file" "$compose_dir/single-vps-check.sh" runtime
if [ "$enable_timers" -eq 1 ]; then
  sudo systemctl enable --now leasegate-backup.timer leasegate-monitor.timer
fi

jq -n --arg installed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg domain "$domain" --arg organization "$organization_id" --arg project "$project_id" \
  --arg approver "$approver_id" --arg edge "$edge_id" --arg agent "$agent_id" \
  '{schema_version:1,profile:"single_vps",installed_at:$installed_at,domain:$domain,
    organization_id:$organization,project_id:$project,approver_id:$approver,edge_id:$edge,agent_id:$agent}' \
  > "$state_dir/installation.json"
chmod 600 "$state_dir/installation.json"

printf 'LeaseGate single-VPS installation completed at https://%s\n' "$domain"
printf 'Routing IDs are saved in %s; one-time credentials remain only in mode-0600 files.\n' "$env_file"
printf 'Move backup ciphertext off this VPS and keep the age identity on a separate trusted system.\n'
