#!/usr/bin/env sh
set -eu

policy_file=${1:?Usage: release.sh POLICY_JSON SOURCE_REVISION}
source_revision=${2:?Usage: release.sh POLICY_JSON SOURCE_REVISION}
: "${LEASEGATE_CLOUD_URL:?Set LEASEGATE_CLOUD_URL}"
: "${LEASEGATE_ORGANIZATION_ID:?Set LEASEGATE_ORGANIZATION_ID}"
: "${LEASEGATE_PROJECT_ID:?Set LEASEGATE_PROJECT_ID}"
: "${LEASEGATE_ADMIN_TOKEN_FILE:?Set LEASEGATE_ADMIN_TOKEN_FILE}"
command -v jq >/dev/null

case "$LEASEGATE_CLOUD_URL" in
  https://*) ;;
  *) printf 'LEASEGATE_CLOUD_URL must use HTTPS.\n' >&2; exit 2 ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
  source_digest=$(sha256sum "$policy_file" | awk '{print $1}')
else
  source_digest=$(shasum -a 256 "$policy_file" | awk '{print $1}')
fi
token=$(tr -d '\r\n' < "$LEASEGATE_ADMIN_TOKEN_FILE")
request=$(jq \
  --arg revision "$source_revision" \
  --arg digest "$source_digest" \
  '. + {source_revision:$revision,source_digest_sha256:$digest}' \
  "$policy_file")

curl --fail-with-body --silent --show-error \
  -H "authorization: Bearer $token" \
  -H 'content-type: application/json' \
  --data-binary "$request" \
  "$LEASEGATE_CLOUD_URL/v1/organizations/$LEASEGATE_ORGANIZATION_ID/projects/$LEASEGATE_PROJECT_ID/policy/releases"
printf '\n'
