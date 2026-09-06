# Phase 6 architecture and technical stack

Status: accepted and implemented as a self-hosted enterprise/mobile beta

Last updated: 2026-09-06

## 1. Scope decision

Phase 6 preserves the Phase 5 ownership boundary: Control Plane, Gateway,
PostgreSQL, worker and UI remain on infrastructure controlled by the operator.
There is no LeaseGate-hosted execution path.

The phase adds enterprise identity, device-bound mobile approval,
policy-as-code releases, compliance export and primitives needed to run more
than one stateless Control Plane/worker safely. It does not turn the product
into a vendor-managed service.

```text
OIDC IdP / SCIM client             Git policy repository
          |                                  |
          v                                  v
  signed ID token + SCIM             validate -> sign -> stage
          |                                  |
          +---------> Control Plane <--------+
                         |
        +----------------+------------------+
        |                |                  |
   Mobile approval   PostgreSQL/RLS    SIEM webhook
   Ed25519+biometric audit hash chain   HMAC signed
                         |
                  leader-elected worker
                         |
                  local Gateway replicas
```

## 2. Stack

| Capability | Implementation |
|---|---|
| Enterprise contracts and RBAC | Rust 2024, `leasegate-control` |
| API and worker | Axum, Tokio, SQLx |
| Enterprise state | PostgreSQL 17 with tenant RLS |
| OIDC validation | `jsonwebtoken`, exact issuer/audience, remote JWKS over HTTPS |
| Device identity | Ed25519 challenge proof, five-minute signed session |
| Mobile client | Flutter iOS/Android, `local_auth`, `flutter_secure_storage`, `cryptography` |
| Policy-as-code | Git source digest, server-signed Ed25519 bundle, staged lifecycle |
| SIEM | bounded JSON/CEF batch, HTTPS, HMAC-SHA256, no redirects |
| HA coordination | PostgreSQL renewable worker lease |
| Backup | `pg_dump` and configuration archive encrypted to an `age` recipient |

## 3. Enterprise identity and role separation

An organization stores one explicit OIDC trust configuration. The verifier
accepts only a configured HTTPS JWKS endpoint, does not follow redirects,
limits JWKS to 1 MiB, selects the token `kid`, and validates signature,
`iss`, `aud`, `exp` and `sub`. If configured, email domains and group-to-role
mapping are enforced before a mobile session is issued.

Roles are separated as follows:

| Role | Primary authority |
|---|---|
| Owner | bootstrap and all organization controls |
| Admin | organization operations and identity provisioning |
| Security admin | policy release, access review, approval and audit |
| Operator | runtime operations and audit |
| Approver | exact-request approval and audit |
| Auditor | read-only audit |
| Member | no control-plane administration |

SCIM bearer credentials are random, stored only as SHA-256 digests, returned
once and expire. The implemented SCIM User subset supports create/update by
stable external subject and deactivation. SCIM can grant member, approver,
operator or auditor, but cannot grant owner/admin/security-admin.

Access reviews snapshot all active memberships. Every entry must be retained
or revoked before completion. The owner membership cannot be removed through
this workflow.

## 4. Device-bound mobile approval

The Flutter app now includes Android and iOS projects. On enrollment it creates
an Ed25519 key pair and writes the private key to platform secure storage. A
registered device requests a two-minute, single-use challenge. On iOS/Android,
biometric authentication gates the signing operation. The Control Plane
verifies the proof and, when OIDC is enabled, also verifies the ID token and
matches it to the device owner.

The resulting operator bearer is an Ed25519-signed, tenant/device/role-bound
session with a hard five-minute lifetime. Mobile approval infers the human from
that session; changing the `approver_id` in the request fails. Mobile endpoints
only expose pending approvals and redacted security alerts.

Native push-provider delivery is not required for correctness. The app can
poll the durable security-alert queue; provider push is an optional future
wake-up optimization.

## 5. Policy-as-code

`deploy/policy/release.sh` calculates the source file SHA-256 and submits it
with a Git revision. The server builds the next rollback-safe bundle, links the
previous digest, signs it using the Control Plane key and stores the release as
`staged`.

```text
staged -> canary -> active
   |         |        |
   +---------+--------+-> failed -> rolled_back
```

Activation writes the ordinary signed policy control event, so Edge uses the
same verifier as interactive policies. Rollback never replays an old version:
the operator stages a new higher-version release containing the prior rules
and links it with `rollback_of`.

## 6. Audit, SIEM and compliance

Cloud audit ingestion serializes each new event into a per-project SHA-256
chain. Idempotent Edge replay does not advance the chain. Compliance evidence
contains bounded counts, stable control assertions and the chain head, then is
signed with the Control Plane Ed25519 key.

Retention is explicit per project and limited to 30–3650 days. The leader
worker removes only terminal approvals/credential metadata and expired audit
rows. SIEM delivery reads the existing redacted audit representation, emits
JSON or escaped CEF inside a bounded envelope and advances its cursor only
after a successful HTTPS response. HMAC secrets live in mode-0600 local files,
not PostgreSQL; redirects are disabled.

## 7. HA and recovery

The HTTP Control Plane is stateless. Multiple instances may share PostgreSQL.
Workers contend for a renewable PostgreSQL lease, ensuring maintenance,
retention and SIEM cursor updates have one active leader. SIEM cursor updates
use optimistic concurrency, so a stale worker cannot skip events.

This is the application-level HA foundation. PostgreSQL replication, load
balancing and multi-VPS network design remain operator infrastructure choices.
The included backup/restore scripts require `age` encryption and explicit
restore confirmation.

## 8. BYOK and workload identity

The Control Plane stores only BYOK/HSM provider metadata: provider kind, opaque
key reference and public-key fingerprint. It never stores an HSM PIN or cloud
KMS credential. File-backed operator-supplied Ed25519 seeds remain the only
signing backend enabled in this beta; PKCS#11/cloud-KMS signing adapters require
the operator-specific library/service and production verification.

Workload bindings record exact issuer, subject, audience, agent and optional
certificate fingerprint. The records are tenant scoped and suitable for
SPIFFE/OIDC federation. Enforcement at a TLS/workload-attestation boundary is
required before disabling the existing per-agent bootstrap credential.

## 9. Security invariants

- Managed Gateway configuration remains rejected.
- OIDC/JWKS and SIEM endpoints require HTTPS and never follow redirects.
- Raw SCIM tokens, push tokens, SIEM secrets and credential material are not
  stored in PostgreSQL.
- Mobile sessions are signed, role-bound, device-bound and short-lived.
- DPoP is accepted only after local proof verification and matching provider
  `cnf.jkt`; caller-supplied thumbprints remain rejected.
- Policy rollback uses a new monotonic version rather than replaying an old
  signed artifact.
- Worker failover cannot acknowledge an unseen SIEM batch.
