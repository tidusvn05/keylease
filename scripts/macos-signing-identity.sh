#!/usr/bin/env bash
# Source before building to select one identity for both the app and its helper.
# Ad-hoc signatures use changing code hashes as their designated requirement,
# so macOS privacy grants cannot reliably survive a rebuild.
# Set EXPANDED_CODE_SIGN_IDENTITY explicitly to choose a certificate or "-".

if [[ -z "${EXPANDED_CODE_SIGN_IDENTITY:-}" ]]; then
  KEYLEASE_SIGNING_IDENTITIES="$(security find-identity -v -p codesigning)" || {
    echo "error: could not query code-signing identities" >&2
    return 1
  }
  KEYLEASE_DEVELOPMENT_IDENTITIES="$(printf '%s\n' "$KEYLEASE_SIGNING_IDENTITIES" |
    sed -nE 's/^[[:space:]]*[0-9]+\) ([[:xdigit:]]{40}) "Apple Development:.*$/\1/p')"
  case "$(printf '%s\n' "$KEYLEASE_DEVELOPMENT_IDENTITIES" | awk 'NF { count++ } END { print count+0 }')" in
    0)
      EXPANDED_CODE_SIGN_IDENTITY="-"
      echo "warning: no Apple Development identity; using ad-hoc signing. Screen Recording permission may need to be granted again after rebuilding." >&2
      ;;
    1)
      EXPANDED_CODE_SIGN_IDENTITY="$KEYLEASE_DEVELOPMENT_IDENTITIES"
      ;;
    *)
      echo "error: multiple Apple Development identities; set EXPANDED_CODE_SIGN_IDENTITY to a certificate hash or name" >&2
      return 1
      ;;
  esac
  unset KEYLEASE_SIGNING_IDENTITIES KEYLEASE_DEVELOPMENT_IDENTITIES
fi
export EXPANDED_CODE_SIGN_IDENTITY
