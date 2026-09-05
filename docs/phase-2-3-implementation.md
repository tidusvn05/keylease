# Phase 2 and Phase 3 implementation status

Status: implemented beta (live-provider and production-security validation still required)

Last updated: 2026-09-06

## Phase 2 — Connector hardening and local alpha

| Deliverable | Implementation |
|---|---|
| GitHub, Linear and Notion hardening | Fixed-origin HTTP adapters, typed/deny-unknown action schemas, stable resource identifiers, response hard limits and untrusted-content marking. GitHub issue/draft-PR, Linear issue/comment and Notion page actions are in the manifests. |
| OAuth recovery and health | Refresh rotates the encrypted credential. Rejection marks the connection expired/reauthorization-required. Local revoke is committed before any upstream call. Google, GitHub and Notion upstream revoke are implemented; Linear remains locally fail-closed because no public revoke endpoint is documented. |
| Incremental authorization | Provider scopes are normalized to stable action permissions. Reported permissions are checked for every call; unreported token types still rely on exact resource/action policy. |
| Deterministic templates | `keylease grant template` materializes provider-specific, exact-resource rules. Writes require approval by default. |
| Approval queue | Approval records bind task, request digest, policy version, action/resource and a semantic summary containing hashes/lengths rather than argument plaintext. |
| Budgets | Per-call item/cell/byte/row/concurrency limits plus cumulative request/item/cell/byte/row task limits. SQLite reserves lease use, idempotency and initial task usage in one immediate transaction. |
| Recovery | Durable execution failure states distinguish safe retry from uncertain side effect. `keylease audit recovery` exposes reconciliation work without replaying writes blindly. |
| Adversarial tests | Unknown actions/fields, resource aliases/path traversal, OAuth faults, rate limits, timeout, schema drift, partial failure, secret leak, response counts, sheet binding and replay/concurrency are covered. |

Live OAuth credentials and real provider sandboxes remain release evidence, not
something a Linux unit-test run can certify.

## Phase 3 — Cloud, Edge and MCP beta

| Deliverable | Implementation |
|---|---|
| Tenant registry | PostgreSQL account, organization, project, membership, human, agent, device and Edge records. Agent/Edge credentials are returned once and only SHA-256 digests are persisted. |
| E2EE sync | Signed ciphertext mutation envelopes, compare-and-swap revisions, per-device idempotency and cursor pull. Cloud tables contain ciphertext/encrypted headers, not vault keys or plaintext fields. |
| Policy control plane | Ed25519 signatures over RFC 8785 JSON, version/digest chaining, tenant binding, minimum Edge version, revocation epoch and rollback rejection. Control cursors are contiguous per organization. |
| Approval/revoke | Redacted exact-request approval records, active-approver RBAC check, signed five-minute receipts, strict revocation epochs and ordered Edge feed. |
| Edge | Encrypted SQLite policy/approval/revocation state, monotonic scoped control cursor, bounded offline policy (hard maximum 15 minutes, R0/R1 only), stale-revocation fail-close and a bounded encrypted hash-chained audit spool. |
| MCP | Official `rmcp` Streamable HTTP transport. One endpoint is cryptographically bound to one agent credential; Host, Origin and Bearer are checked before MCP dispatch. Calls become the same canonical `ActionRequest` used by the CLI. |
| Health/worker | Heartbeats include policy/cursor/revocation/audit/connector state. The worker marks Edge offline after two minutes, expires approvals and drains the transactional outbox. |
| Web | Responsive Flutter Web approval queue and Edge health view. Direct-operator beta keeps its token only in tab memory. |
| Self-host | Compose profile for Cloud API/worker, PostgreSQL, MinIO, Caddy TLS/web and optional same-VPS Edge. Secret files are generated mode `0600`; MCP publishes to loopback by default. |

## Security boundaries retained

- Cloud never receives the master password, root/vault/item keys or connector
  credentials. Sync accepts opaque ciphertext plus the minimum routing data.
- A policy activation revokes old local leases. Edge control activation enters
  deny-by-default before swapping the service rule set.
- MCP does not implement a second policy engine and cannot choose its own
  `AgentId`.
- A full/corrupt audit spool, expired policy, stale revocation state, cursor gap,
  invalid signature or R2+ offline action fails closed.

## Beta limitations

- Team-facing browser authentication should be placed behind an OIDC identity
  proxy. The checked-in direct-operator web flow is for a single-owner/VPN beta.
- The Phase 3 object store is provisioned for encrypted attachment chunks, but
  multipart attachment APIs and garbage collection remain a later hardening
  increment.
- mTLS termination is expected at the private-network/reverse-proxy boundary;
  the application also requires a scoped one-Edge bearer credential. Sender-
  constrained application tokens remain later scope.
- Provider availability SLO evidence requires real GitHub/Linear/Notion test
  tenants and is intentionally not claimed by local tests.
