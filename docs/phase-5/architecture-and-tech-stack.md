# Phase 5 architecture and technical stack

Status: accepted and implemented as a self-hosted beta

Last updated: 2026-09-06

Scope: dynamic credentials in the one-VPS `self_hosted` / `local_gateway`
deployment. LeaseGate-hosted execution is not part of this phase.

## 1. Decision summary

“Control Plane” and “Gateway” are logical roles, not hosting ownership. The
supported Phase 5 deployment runs both roles on infrastructure controlled by
the operator:

```text
Agent / MCP client
        |
        | individual agent credential
        v
+----------------------------------------------------------+
| Operator-owned VPS                                      |
|                                                          |
| Caddy -> Flutter Web + Rust Control Plane -> PostgreSQL  |
|                         |                                |
|                  signed policy/revocation                |
|                         v                                |
|                 Rust local Gateway -> encrypted SQLite  |
|                         |                                |
|                  dynamic credential backends             |
+-------------------------+--------------------------------+
                          |
                          v
               AWS STS / SSH / PostgreSQL / OAuth AS
```

The Control Plane stores identity, policy, approvals, redacted lease metadata,
posture, rotation state and audit indexes. The local Gateway owns provider
secret files, issues credentials and stores encrypted revocation handles.
Credential material is returned once to the authenticated agent and is never
sent to the Control Plane.

`managed_gateway` is not a fallback. The binary and configuration parser reject
any deployment other than:

```yaml
deployment_mode: self_hosted
execution_mode: local_gateway
```

## 2. Stack

| Layer | Choice |
|---|---|
| Credential contracts/orchestration | Rust 2024, `leasegate-credentials` |
| Local HTTP/MCP gateway | Axum + Tokio |
| Local confidential state | SQLite, XChaCha20-Poly1305 sealing |
| Control metadata | PostgreSQL 17 + SQLx + RLS |
| Policy and approvals | Existing deterministic PDP and Ed25519 signed bundles |
| AWS | STS `AssumeRoleWithWebIdentity` HTTPS form API |
| OAuth | RFC 8693 token exchange HTTPS form API |
| SSH | OpenSSH CA certificates and KRL revocation |
| Database | PostgreSQL temporary login roles with `VALID UNTIL` |
| Operator UI | Flutter Web |
| Packaging | OCI containers + Docker Compose + Caddy |

No Kubernetes, Redis, external broker or vendor-hosted service is required.

## 3. Credential authorization

Each issue request is mapped to the existing canonical policy boundary:

| Kind | Policy action | Canonical resource |
|---|---|---|
| AWS STS | `credential.aws.issue` | `credential:aws/{backend}/{role-arn}` |
| SSH certificate | `credential.ssh.issue` | `credential:ssh/{backend}/{principal}` |
| PostgreSQL role | `credential.postgresql.issue` | `credential:postgresql/{backend}/{database}` |
| OAuth exchange | `credential.oauth.exchange` | `credential:oauth/{backend}/{audience}` |

The decision binds agent, workload, task, connection, backend, kind, target,
TTL and claims. The Gateway also requires:

1. a valid, non-expired signed policy;
2. a healthy connection;
3. current revocation state;
4. online Control Plane contact for R3 issuance;
5. an exact signed approval receipt when policy returns `require_approval`;
6. a backend whose fixed kind and connection match the request.

The effective TTL is the minimum of the request, policy, backend and compiled
one-hour ceiling. Idempotency replay cannot mint a second credential, and it
cannot recover material from the first response.

## 4. Local persistence and lifecycle

The Gateway inserts a `pending` record before contacting a provider, changes it
to `active` only after validating the provider expiry, and stores any
revocation handle using the existing Edge storage key. Provider material is
not persisted.

```text
pending -> active -> revoking -> revoked
    |          |          |
    v          +----------+-> expired
  failed
```

The two-second control loop applies signed lease/agent/connection/project
revocations and reaps expired leases. Backend cleanup is retried from
`revoking`; terminal records delete the encrypted revocation handle. Every
successful issue and direct revoke is appended to the encrypted chained audit
spool before it is considered complete.

The Control Plane migration `0003_phase5_dynamic_credentials.sql` adds only
redacted indexes:

- `credential_lease_index`;
- `connection_posture`;
- `credential_rotation_requests`.

RLS binds all three tables to an organization. An Edge may report metadata only
for its own project, registered agent and registered connection. Immutable
lease bindings and state transitions are checked before upsert.

## 5. Backend security boundaries

### AWS STS Web Identity

The role ARN and connection are fixed in local configuration. The Gateway reads
the web-identity token from a mode-0600 file immediately before exchange and
requests a 900–3600 second STS session. AWS does not support deleting one STS
session; upstream expiry is the hard revocation boundary.

### SSH certificates

Allowed principals and CA path are fixed locally. The caller supplies only a
public key. The resulting certificate is sender-constrained by possession of
the corresponding private key. Revoke serializes an OpenSSH KRL update; target
servers must configure `RevokedKeys` to use that KRL.

### PostgreSQL roles

The target database, inherited grant role and generated role prefix are fixed
locally. The Gateway creates a random password and login role with
`VALID UNTIL`. Revoke applies `NOLOGIN` first and then best-effort terminates
existing sessions. The issuer database role should be able to create only the
intended child roles.

### OAuth token exchange

The token endpoint, subject-token type, client identity, allowed audiences and
allowed scopes are fixed locally. Subject/client secrets are mode-0600 files.
Unverified `dpop_jkt` or mTLS claims are explicitly rejected: copying a
thumbprint is not sender constraint.

## 6. Rotation and posture

The Control Plane implements an optimistic-concurrency rotation workflow:

```text
pending -> rotating -> verifying -> activated
    |          |           |
    +----------+-----------+-> failed -> rolled_back
```

Only one open rotation exists per connection. Creation binds the connection's
exact `updated_at` revision. Phase 5 beta intentionally requires the operator
or a provider-specific local automation to perform the secret replacement and
verification between transitions; the Control Plane never accepts new secret
material.

The Gateway reports stable posture reason codes after local backend activity.
The UI shows posture, active/recent leases, expiry, sender binding, revoke and
rotation state without receiving credential material. The worker projects stale,
expiring, expired and rotation-due timestamps into posture changes and emits a
redacted `connection.posture.changed` outbox event for alert integrations.

## 7. API surface

Agent-local Gateway (individual agent bearer credential):

```text
GET    /v1/credential-backends
GET    /v1/credential-leases
POST   /v1/credential-leases
DELETE /v1/credential-leases/{lease}
```

Control Plane:

```text
POST /v1/edges/{edge}/credential-leases
POST /v1/edges/{edge}/connection-posture
GET  /v1/organizations/{org}/projects/{project}/credential-leases
POST /v1/organizations/{org}/projects/{project}/credential-leases/{lease}/revoke
GET  /v1/organizations/{org}/projects/{project}/connection-posture
GET  /v1/organizations/{org}/projects/{project}/credential-rotations
POST /v1/organizations/{org}/projects/{project}/credential-rotations
POST /v1/organizations/{org}/projects/{project}/credential-rotations/{rotation}/transition
```

Credential responses carry `Cache-Control: no-store` and `Pragma: no-cache`.
Public errors contain stable codes, not provider responses or secret values.

## 8. Exit criteria and beta limits

Implemented acceptance properties:

- self-hosted Compose starts one local Gateway without an optional profile;
- managed execution is rejected by runtime and config validation;
- policy/approval/connection/revocation/TTL binding occurs before issuance;
- credential and revocation-handle debug output is redacted;
- cloud metadata cannot change an existing lease's authority binding;
- AWS/OAuth responses are bounded and their expiries cannot exceed policy;
- SSH certificates are bound to the supplied public key and enter a KRL on
  revoke;
- PostgreSQL roles have upstream expiry and become `NOLOGIN` on revoke;
- restart/replay retains idempotency and encrypted local revocation state.

Explicit beta limitations:

- live AWS/provider evidence requires operator-owned accounts;
- immediate upstream revocation is unavailable for AWS STS sessions and token
  exchanges without a provider revocation endpoint, so short TTL is mandatory;
- RFC 9449 DPoP and RFC 8705 mTLS are not enabled yet; claims requesting them
  fail closed;
- rotation execution is a controlled state machine, but provider-specific
  secret replacement remains a local operator/automation step;
- a single VPS is not highly available and encrypted off-host backups remain
  required.
