# Phase 3 architecture and technical stack

Status: implemented beta; see `../phase-2-3-implementation.md` for evidence and limitations

Last updated: 2026-09-06

Scope: KeyLease Cloud + LeaseGate Edge/MCP Beta

## 1. Decision summary

Phase 3 uses a Rust-first modular monolith for the cloud control plane and a
separate Rust binary for LeaseGate Edge. The first deployment profile must run
on one self-hosted Linux VPS without requiring Kubernetes or an external event
broker.

The primary stack is:

| Layer | Choice |
|---|---|
| Domain, policy, crypto and sync contracts | Rust 2024 |
| Async runtime | Tokio |
| Cloud HTTP API | Axum + Tower |
| MCP transport | Official Rust MCP SDK (`rmcp`) + Axum |
| Cloud database | PostgreSQL + SQLx |
| Edge database | SQLite + existing `rusqlite` single-writer boundary |
| Approval UI | Flutter Web/Dart, with later reuse for iOS/Android |
| Ciphertext and attachment storage | S3-compatible object storage |
| Human authentication | OIDC Authorization Code + PKCE |
| Edge authentication | mTLS with a scoped device certificate |
| Agent authentication | Opaque random credential scoped to one agent/project |
| Policy signing | Ed25519 over RFC 8785 canonical JSON |
| Telemetry | `tracing`; optional OTLP/OpenTelemetry export |
| Packaging and infrastructure | OCI containers, Compose for one VPS, Terraform for repeatable provisioning |

This stack preserves the existing `keylease-core`, `keylease-crypto`, policy,
service and connector boundaries. Cloud and MCP are adapters around the same
canonical `ActionRequest` and `KeyLeaseService`; they must not reimplement
authorization.

## 2. Deployment profiles

### 2.1 One-VPS self-hosted beta

The complete Phase 3 control plane can run on one VPS:

```text
Internet or private network
          |
          v
  TLS reverse proxy / load balancer
          |
          +----------------------+
          |                      |
          v                      v
  keylease-cloud-api      approval-flutter
          |
          +----------------------+
          |                      |
          v                      v
  keylease-cloud-worker     PostgreSQL
          |
          v
  S3-compatible object store
  (MinIO in the single-VPS profile)

  leasegate-edge
  - may run on this VPS for a personal installation; or
  - preferably runs on the device/VPC that owns connector credentials.
```

Recommended minimum operational layout:

- Only the reverse proxy exposes ports 80/443.
- PostgreSQL and object storage listen only on the private container network.
- Cloud API and worker use different, non-superuser database roles.
- Persistent volumes hold PostgreSQL, object storage and encrypted backups.
- The Edge MCP endpoint is not published through the control-plane hostname by
  default. It is exposed only to the agent network, VPN or loopback interface.
- Automated encrypted backups are copied to a different machine or storage
  account. A backup on the same VPS is not disaster recovery.

The one-VPS profile is appropriate for development, personal self-hosting and
beta workloads. It is not a high-availability topology: failure of the VPS,
disk or network can make the control plane unavailable. Edge may continue only
within its bounded offline policy.

### 2.2 Split production profile

The same binaries can later use managed PostgreSQL and S3-compatible storage,
and run multiple API/worker instances behind a load balancer. The database
outbox remains the durable source of control events. A broker such as NATS may
be introduced only after measured scale requires it; it is not a Phase 3
dependency.

## 3. Logical architecture

```text
                         KEYLEASE CLOUD
+------------------------------------------------------------------+
| Axum Cloud API                                                   |
|                                                                  |
| Identity / Organization / Project                               |
| Device and Edge Registry                                        |
| Ciphertext Sync API                                              |
| Policy Bundle and Approval                                      |
| Revocation Feed                                                  |
| Audit Index and Edge Health                                     |
| Transactional Outbox                                             |
+------------------+----------------------+------------------------+
                   |                      |
             PostgreSQL             S3-compatible store
             control metadata       ciphertext/chunks
                   |
                   | mTLS + signed, versioned control events
                   v
+------------------------------------------------------------------+
| LEASEGATE EDGE                                                   |
|                                                                  |
| Cloud Control Client                                             |
| Signed Policy Cache and Revocation State                         |
| MCP Streamable HTTP Adapter                                      |
| Canonical Action Mapper                                          |
| Existing PDP / PEP / Lease Service                              |
| Existing Connector Runtime                                      |
| Encrypted Audit Spool                                            |
| Local KeyLease Vault                                             |
+------------------------------+-----------------------------------+
                               |
                               v
              Google / GitHub / Linear / Notion
```

Cloud is the control plane, not the mandatory execution hot path. Agents call
LeaseGate Edge. OAuth refresh tokens and API credentials remain encrypted in
the Edge-local vault. The cloud receives ciphertext, the minimum routing and
policy metadata, health state, and redacted audit events.

Managed credential execution remains disabled in Phase 3. The
`managed_gateway` value may exist in versioned schemas, but APIs must reject an
attempt to activate it until its later security boundary is implemented.

## 4. Cloud process model

Phase 3 ships two cloud binaries rather than multiple microservices:

### `keylease-cloud-api`

- OIDC session and API authentication.
- Account, organization, project and membership APIs.
- Agent, device and Edge registration.
- Ciphertext sync push/pull and attachment upload coordination.
- Policy activation, approval and revocation APIs.
- Edge control-event feed and acknowledgements.
- Redacted audit ingestion/query and health APIs.
- Flutter Web static asset hosting may be enabled for the one-VPS profile.

### `keylease-cloud-worker`

- Transactional-outbox dispatch and retries.
- Approval notifications.
- Audit indexing and retention jobs.
- Tombstone and orphaned object cleanup.
- Edge health timeout processing.
- Backup/retention coordination.

PostgreSQL is the authoritative control-state store. `LISTEN/NOTIFY` may wake
workers but is never the durable event log. Every asynchronous control event is
first committed to an outbox row in the same transaction as the state change.

## 5. Cloud data model

The initial schema contains at least:

```text
accounts
organizations
projects
memberships
human_principals
agents
agent_credentials

devices
device_public_keys
edges
edge_certificates
edge_heartbeats

vaults
vault_objects
sync_mutations
sync_cursors
attachment_chunks

policy_bundles
policy_activations
approval_requests
approval_decisions
revocations

audit_event_index
event_outbox
```

Every tenant-owned row carries an `account_id`, `organization_id` or
`project_id`. Authorization is enforced in application code and PostgreSQL
Row-Level Security as defense in depth. Runtime database roles must not have
`SUPERUSER` or `BYPASSRLS`. Migration jobs use a separate narrowly controlled
role.

Opaque IDs remain globally unique and retain the prefixes already defined in
`keylease-core`. Foreign keys use internal UUIDs or opaque IDs consistently;
public API clients never depend on sequential database identifiers.

## 6. E2EE sync protocol

The production sync contract evolves the existing `keylease-sync` simulation.
A mutation envelope contains:

```json
{
  "schema_version": 1,
  "mutation_id": "mut_...",
  "account_id": "acct_...",
  "vault_id": "vault_...",
  "object_id": "item_...",
  "device_id": "device_...",
  "base_revision": 12,
  "result_revision": 13,
  "idempotency_key": "...",
  "ciphertext_digest": "...",
  "tombstone": false,
  "created_at": "...",
  "device_signature": "..."
}
```

Required behavior:

- Vault/item encryption occurs on the client or Edge.
- Cloud never receives a master password, Account Secret Key, ARK, Vault Key,
  Item Key or plaintext connector credential.
- Device signatures authenticate mutations.
- Server updates use compare-and-swap on `base_revision`.
- Repeating an idempotency key with the same digest is a replay; repeating it
  with a different digest is rejected.
- Server does not merge concealed fields. Conflicts are returned and clients
  preserve conflict copies.
- Attachments are chunk-encrypted; object storage keys contain opaque IDs only.
- Clients persist signed revision checkpoints and reject observed rollback.
- Tombstones have a documented retention window and cannot disappear before
  all active device cursors or the retention policy permit collection.

Before Cloud Beta, enable a device-generated Account Secret Key and Emergency
Kit. A new device is enrolled by an existing device or recovers with the master
password plus Account Secret Key. Cloud authentication and vault decryption
remain separate key purposes.

## 7. Signed policy distribution

A policy bundle contains:

```text
schema_version
bundle_id
organization_id
project_id
version
previous_bundle_digest
issued_at
not_before
expires_at
revocation_epoch
minimum_edge_version
rules
signer_key_id
signature
```

The bytes to hash/sign are RFC 8785 canonical JSON. The initial signature
algorithm is Ed25519. Every signed structure has explicit schema and algorithm
versions for crypto agility.

Edge activation rules:

1. Verify the signer and signature.
2. Match the expected organization and project.
3. Require a strictly increasing policy version.
4. Require `previous_bundle_digest` to match the active bundle.
5. Reject not-yet-valid, expired or unsupported bundles.
6. Reject rollback to an older version or revocation epoch.
7. Require human/admin activation proof for authority-increasing changes.
8. Permit cloud revocation events only to reduce authority.

An Edge stores the last accepted version and digest in its local encrypted
control database. Restarting or restoring an older cache must not reset this
watermark silently.

## 8. Edge enrollment and control channel

Enrollment flow:

```text
Admin creates a one-time enrollment code
             |
Edge creates a device key pair locally
             |
Edge submits public key + enrollment code over TLS
             |
Cloud issues a scoped device certificate
             |
Edge pins account/org/project and the cloud trust anchor
             |
Subsequent control connections use mTLS
```

The private device key is never uploaded. It is protected by OS key storage,
TPM when available, or an encrypted file with restrictive permissions.

The control channel uses HTTPS/mTLS:

- SSE or bounded long-poll for policy/revocation/approval events.
- POST for acknowledgements and audit batches.
- A durable monotonically increasing event cursor in SQLite.
- A full reconciliation endpoint after a cursor gap or retention expiry.
- Exponential backoff with jitter, without extending offline authorization.

WebSocket and gRPC are not required for Phase 3. They may be introduced later
only for a demonstrated protocol or scaling requirement.

## 9. MCP endpoint

Each agent or workload receives an independent opaque random credential scoped
to one project and logical `AgentId`. Only a keyed digest of the credential is
stored. Sender-constrained credentials remain Phase 5 scope.

The Edge exposes one Streamable HTTP MCP endpoint:

```text
POST https://edge.example/mcp
Authorization: Bearer <agent-specific-credential>
```

Request path:

```text
MCP request
  -> authenticate agent credential
  -> validate protocol and typed tool schema
  -> map tool call to canonical ActionRequest
  -> connector canonicalization
  -> cached policy evaluation and budget reservation
  -> approval/lease validation
  -> connector execution
  -> response filtering and untrusted-content marking
  -> usage commit and audit
```

Use the official Rust MCP SDK instead of hand-writing JSON-RPC or Streamable
HTTP. Pin the supported MCP specification and SDK versions. The initial target
is MCP `2026-07-28`, with negotiated compatibility for at least one older
version used by beta clients.

Authorization state lives in LeaseGate services, not an MCP handler or MCP
session. Tool discovery is advisory; every `tools/call` is fully enforced.
Unknown tools, schema versions and fields fail closed. MCP cannot unlock a
vault, export plaintext, disable audit or activate policy.

The HTTP implementation validates `Host` and `Origin`, uses explicit public
host allowlists, enforces authentication, and binds a local-only endpoint to
loopback by default.

## 10. Remote approval

```text
Agent requests an action
       |
Edge canonicalizes it and creates an exact request digest
       |
Cloud stores the digest and a redacted semantic summary
       |
Human approves in Flutter Web using OIDC and step-up/WebAuthn as required
       |
Cloud publishes a signed ApprovalReceipt
       |
Edge verifies digest, policy version, approver, expiry and max uses
       |
Only that canonical request may execute
```

An `ApprovalReceipt` binds at least:

- organization/project;
- agent, workload and on-behalf-of identity;
- canonical action, resource and material arguments;
- request digest and policy version;
- approver identity and required quorum;
- issue time, expiry and `max_uses`.

Any change to a material argument produces a different digest and requires a
new decision. Approval delivery is idempotent. Concurrent consumption uses an
atomic reservation so the approved use count cannot be exceeded.

## 11. Offline rules and initial SLOs

Initial beta defaults:

| Condition | Required behavior |
|---|---|
| R0/R1 action while Edge is offline | Allowed for at most 15 minutes only when the policy explicitly permits it |
| R2 or higher while Edge is offline | Denied |
| Expired policy or lease | Denied |
| Revocation feed beyond its maximum staleness | Side-effecting actions denied |
| Approval receipt | Maximum five-minute TTL unless a stricter policy applies |
| Revocation while Edge is online | p99 propagation no greater than five seconds |
| Audit spool unavailable, corrupt or full | Side-effecting actions denied |
| Missing Edge heartbeat for two minutes | Cloud marks Edge unhealthy |

Organization policy may make these values stricter. It cannot exceed a hard
security maximum compiled/configured by the product. Offline time is measured
with clock-skew tolerance and a monotonic elapsed-time source where available.

## 12. Audit and observability

Edge appends audit events locally before reporting a successful side effect.
The spool is encrypted, bounded and replay-safe. Upload acknowledges event
ranges; deletion occurs only after durable acknowledgement.

Cloud indexes only audit-safe metadata. Raw secrets, document bodies, issue
text and sheet values are never emitted to application logs, tracing attributes
or the standard audit index.

Use Rust `tracing` as the primary instrumentation interface. OTLP export is an
optional adapter so the core does not depend on a specific observability
vendor. Metrics include revocation latency, event-feed staleness, policy age,
sync conflicts, denied requests, approval latency, budget exhaustion and audit
spool utilization.

## 13. Source layout

Proposed additions:

```text
crates/
  keylease-sync-protocol/       versioned production wire contracts
  leasegate-policy-bundle/      canonicalize, sign, verify and cache
  leasegate-cloud-store/        PostgreSQL repositories and migrations
  leasegate-cloud-api/          Axum control-plane API binary
  leasegate-cloud-worker/       outbox/background worker binary
  leasegate-edge/               Linux/device Edge daemon
  leasegate-mcp/                rmcp transport adapter
  leasegate-approval-protocol/  exact-request approval receipts

apps/
  approval-flutter/             responsive web/PWA; later mobile shell

deploy/
  compose/                      one-VPS deployment
  terraform/                    repeatable production infrastructure
```

Contracts shared by Cloud and Edge remain dependency-light. Storage, HTTP,
MCP and provider implementations depend inward on contracts, never the other
way around.

## 14. Delivery slices

1. Freeze wire contracts, policy bundle, approval receipt and threat-model
   updates.
2. Implement PostgreSQL schema, tenant isolation, outbox and Cloud API shell.
3. Replace sync simulation with the production push/pull protocol and encrypted
   attachment flow.
4. Implement device/Edge enrollment, mTLS, control feed and reconciliation.
5. Implement signed policy cache, revocation watermarks and offline rules.
6. Package LeaseGate Edge and its encrypted audit spool.
7. Add the `rmcp` adapter over the existing canonical action/service path.
8. Add Flutter Web approval and Edge-health UI.
9. Run end-to-end tests for two-device sync, conflict, replay, rollback,
   restart, offline policy, remote approval and revocation propagation.
10. Complete external security review before production vault data is accepted.

## 15. Explicit non-goals for Phase 3

- Managed Cloud execution of downstream credentials.
- Kubernetes as a mandatory deployment target.
- Kafka/NATS/Redis as mandatory infrastructure.
- Long-lived self-contained JWT execution leases.
- MCP-specific authorization outside the shared policy engine.
- Server-side plaintext vault indexing or conflict merge.
- SSO/SCIM, SIEM, HA Edge, BYOK/HSM and workload federation; these remain
  Phase 6 scope.

## 16. Normative references

- Existing product target architecture:
  `agent-friendly-keepass-app-proposal.md`, sections 19, 24 and Phase 3.
- MCP Streamable HTTP specification:
  <https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/transports/streamable-http.mdx>
- Official Rust MCP SDK:
  <https://github.com/modelcontextprotocol/rust-sdk>
- Axum documentation: <https://docs.rs/axum/latest/axum/>
- SQLx documentation: <https://docs.rs/sqlx/latest/sqlx/>
- PostgreSQL Row Security Policies:
  <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>
- RFC 8785 JSON Canonicalization Scheme:
  <https://www.rfc-editor.org/rfc/rfc8785.html>
