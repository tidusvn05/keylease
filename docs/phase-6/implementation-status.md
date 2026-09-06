# Phase 6 implementation status

Status: implemented self-hosted beta; external infrastructure evidence remains open

Last updated: 2026-09-06

## Delivered

| Area | Implementation |
|---|---|
| Identity | OIDC provider configuration and JWT/JWKS verification; digest-only expiring SCIM tokens; minimal SCIM 2.0 User provision/deactivate endpoints. |
| RBAC | Owner, admin, security-admin, operator, approver, auditor and member authority matrix; privileged roles cannot be granted by SCIM. |
| Access review | Membership snapshots, one-decision-per-entry, completion barrier and non-owner revocation. |
| Mobile | iOS/Android Flutter scaffold, secure Ed25519 device key, biometric gate, one-use challenge and five-minute signed operator session. |
| Policy-as-code | Git revision/source digest binding, signed staged releases, canary/active/failure/rollback lifecycle and release helper script. |
| Audit/compliance | PostgreSQL audit hash-chain, explicit retention, signed compliance evidence and durable security-alert projection. |
| SIEM | JSON/CEF exporter, local mode-0600 HMAC secret refs, HTTPS/no-redirect delivery and optimistic cursor acknowledgement. |
| HA | Stateless API compatibility and PostgreSQL renewable leader lease for workers. |
| Recovery | `age`-encrypted PostgreSQL/config backup and guarded restore scripts. |
| Credentials | RFC 9449 DPoP Ed25519 proof verification and strict provider `cnf.jkt` confirmation. |
| BYOK/workload | RLS-scoped provider and workload-binding registries without storing provider secrets. |

## Local verification

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast

KEYLEASE_TEST_DATABASE_URL=postgresql://... \
  cargo test -p keylease-cloud --test postgres_phase6 -- --test-threads=1

docker run --rm -v "$PWD/apps/approval-flutter:/app" -w /app \
  ghcr.io/cirruslabs/flutter@sha256:46691e311715845de03a3ba4753a475476936805b29431b1f00f1816981033f8 \
  sh -lc 'flutter pub get && flutter analyze && flutter test && flutter build web --release && flutter build apk --debug'

docker compose --env-file deploy/compose/.env.example \
  -f deploy/compose/compose.yaml config --quiet
sh -n deploy/compose/backup.sh deploy/compose/restore.sh deploy/policy/release.sh
```

The PostgreSQL integration test uses a disposable local PostgreSQL 17
container. OAuth DPoP uses a loopback token-server fixture. Neither requires a
real cloud or enterprise account.

## Intentionally skipped external-account tests

- AWS STS against an operator AWS account.
- OAuth token exchange and DPoP against a real authorization server.
- OIDC login and SCIM provisioning against Keycloak, Authentik, Entra ID,
  Okta or another operator IdP.
- Apple/Google push notification delivery.
- PKCS#11, AWS KMS, GCP KMS or Azure Key Vault signing.
- Multi-VPS load-balancer, PostgreSQL failover and disaster-recovery drill.
- External security review.
- iOS compilation/signing (requires macOS, Xcode and an Apple signing identity).

These require credentials, devices, HSMs or infrastructure not present in the
repository. No passing claim is made for them.

## Beta limitations

- SCIM implements the User create/update/deactivate subset, not bulk, filter,
  PATCH or Groups.
- The mobile client accepts an OIDC ID token supplied by the host login flow;
  authorization-code/PKCE browser orchestration is deployment-specific.
- Security alerts are durable and pollable; native push is not configured.
- Canary is a reviewed release state; Edge selection and automated success
  promotion require a multi-Edge production topology.
- BYOK/HSM and workload identities are registered and policy-visible metadata;
  operator-specific signer/attestor adapters remain disabled until verified.
- Android release signing must be provided by the operator; the repository never
  falls back to a debug signing key.
