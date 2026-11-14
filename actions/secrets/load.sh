#!/usr/bin/env bash
# Loads a KeyLease environment into $GITHUB_ENV (see action.yml).
# Requires curl and jq (present on GitHub-hosted runners) and
# `permissions: id-token: write` on the job.
set -euo pipefail

fail() { echo "::error::KeyLease: $*" >&2; exit 1; }
[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] && [ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ] \
  || fail "no OIDC token service: give the job 'permissions: id-token: write'"
server="${KEYLEASE_SERVER_URL%/}"

oidc=$(curl -fsS -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=${KEYLEASE_AUDIENCE}" | jq -r '.value') \
  || fail "could not get the job's OIDC token"
echo "::add-mask::$oidc"

granted=$(jq -n --arg identity "$KEYLEASE_MACHINE_IDENTITY" --arg token "$oidc" \
    '{identity_id: $identity, token: $token}' \
  | curl -sS -X POST -H 'content-type: application/json' --data @- "$server/v1/machine/token")
access=$(jq -r '.access_token // empty' <<<"$granted")
[ -n "$access" ] || fail "token exchange refused: $(jq -r '.reason // .error // .' <<<"$granted")"
echo "::add-mask::$access"

secrets=$(curl -fsS -H "Authorization: Bearer $access" "$server/v1/machine/secrets") \
  || fail "could not read the secrets"

count=0
while IFS= read -r name; do
  value=$(jq -r --arg name "$name" '.secrets[$name]' <<<"$secrets")
  # Mask every line of the value, then write it with a random heredoc delimiter.
  while IFS= read -r line; do
    [ -n "$line" ] && echo "::add-mask::$line"
  done <<<"$value"
  delimiter="KEYLEASE_$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  {
    printf '%s<<%s\n' "$name" "$delimiter"
    printf '%s\n' "$value"
    printf '%s\n' "$delimiter"
  } >>"$GITHUB_ENV"
  count=$((count + 1))
done < <(jq -r '.secrets | keys[] | select(test("^[A-Za-z_][A-Za-z0-9_]*$"))' <<<"$secrets")

echo "KeyLease: loaded $count secrets from $(jq -r '.project + "/" + .environment' <<<"$secrets")"
