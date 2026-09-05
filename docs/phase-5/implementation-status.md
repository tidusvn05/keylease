# Phase 5 implementation status

Status: implemented self-hosted beta; provider production evidence and DPoP/mTLS remain open

Last updated: 2026-09-06

## Delivered

| Area | Implementation |
|---|---|
| Deployment | Compose now uses `control-plane`, `web`, `worker` and mandatory `gateway` services. Runtime accepts only `self_hosted/local_gateway`; there is no LeaseGate-hosted execution path. |
| Credential broker | New `leasegate-credentials` crate provides request digest binding, policy TTL clamping, one-response material, idempotency, lifecycle, expiry and revoke orchestration. |
| Enforcement | Gateway maps credential requests to `credential.*.issue`, requires a healthy bound connection, current signed policy/revocation feed and exact approval for `require_approval`. R3 issuance is unavailable offline. |
| AWS | Local `AssumeRoleWithWebIdentity` backend with fixed role/endpoint, mode-0600 subject token, bounded XML and upstream expiry validation. |
| SSH | OpenSSH CA signing for allowlisted principals, public-key SHA-256 binding and serialized KRL updates on revoke. |
| PostgreSQL | Temporary login roles, random one-response passwords, `VALID UNTIL`, fixed inherited role and immediate `NOLOGIN` on revoke. |
| OAuth | RFC 8693 exchange with fixed endpoint/client/token type and audience/scope allowlists. Unsupported sender-binding claims fail closed. |
| Persistence | SQLite stores redacted records and XChaCha20-Poly1305 sealed revocation handles. PostgreSQL stores only tenant-scoped redacted metadata. |
| Operations | Signed revoke propagation, local reaper, Cloud expiry/posture sweep, redacted posture alert outbox, rotation state machine and Flutter Credentials tab. |

## Verification commands

```sh
cargo fmt --all -- --check
cargo test --workspace --no-fail-fast
cargo clippy --workspace --all-targets -- -D warnings

KEYLEASE_TEST_DATABASE_URL=postgresql://... \
  cargo test -p keylease-cloud \
    --test postgres_phase3 --test postgres_phase4 --test postgres_phase5 \
    -- --test-threads=1

KEYLEASE_TEST_DATABASE_URL=postgresql://... \
  cargo test -p leasegate-credentials --test postgres_backend

docker compose --env-file deploy/compose/.env.example \
  -f deploy/compose/compose.yaml config --quiet
docker build --target build -f deploy/compose/Dockerfile.approval .
```

The suite includes HTTP fixtures for AWS STS and OAuth token exchange, a real
OpenSSH CA/KRL test, encrypted local-handle/revocation tests, and PostgreSQL
control-plane/backend integration tests.

## Not claimed complete

- DPoP and mTLS sender-constrained OAuth credentials are deliberately disabled.
- AWS STS and provider token exchanges need release evidence against real
  operator accounts before production claims.
- SSH KRL distribution to target hosts is an operator responsibility.
- Rotation controls workflow/revision safety; provider-specific replacement and
  rollback automation is not universal.
- The one-VPS profile is a beta availability topology, not HA.
