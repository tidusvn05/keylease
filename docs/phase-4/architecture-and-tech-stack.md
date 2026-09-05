# Phase 4 architecture and technical stack

Status: implemented beta; see `implementation-status.md` for evidence and limits

Last updated: 2026-09-06

Scope: Connector Platform and Policy UX

## 1. Objective

Phase 4 turns the Phase 3 technical beta into a connector and policy platform
that an operator can understand and extend without weakening the existing
zero-knowledge Cloud/Edge boundary.

The release must let an agent connect through MCP in minutes, let a human see
and simulate effective permissions before activating them, and let connector
authors validate a versioned manifest against the same canonical action
boundary used by CLI, MCP and Edge.

Phase 4 remains deployable on one self-hosted VPS. Connector credentials and
provider execution remain at LeaseGate Edge; Cloud stores control metadata,
redacted audit indexes and signed connector metadata only.

## 2. Delivery scope

### 2.1 Policy-aware MCP discovery

- `tools/list` exposes only actions that the endpoint-bound agent may request
  for an active connection and policy snapshot.
- Discovery is an ergonomics filter, never an authorization boundary. Every
  call is canonicalized and evaluated again at execution time.
- Discovery changes when policy, connection health, provider permissions or
  agent status changes.
- Calls return stable structured states: `denied`, `approval_required`,
  `budget_exceeded`, `lease_expired`, `connection_expired` and
  `requires_user_action`.
- CLI and MCP reduce to the same `ActionRequest`; transport cannot select a
  different agent identity or bypass the policy engine.

### 2.2 Visual permission matrix

The operator UI presents effective access as:

```text
Agent -> Connection -> Resource -> Action -> Constraints
```

It distinguishes allow, deny and approval-required rules, identifies the
source rule, shows expiry and budgets, warns about broad resource prefixes and
renders a semantic policy diff and blast radius before activation.

### 2.3 Deterministic policy simulator

The simulator accepts a canonical request candidate, policy snapshot, risk and
time. It validates and canonicalizes the request, evaluates every rule in
deterministic order, and returns:

- normalized action/resource/arguments;
- final decision and matching rule;
- trace entries explaining matches and mismatches without secret values;
- policy version, approval requirement, maximum lease TTL/uses and budget;
- warnings such as broad resource scope or an unhealthy connection.

Simulation never invokes a provider, issues a lease, consumes a budget or
creates a side effect.

### 2.4 Agent propose-policy workflow

```text
agent draft -> deterministic validation -> human review
            -> approve/reject -> signed activation -> Edge distribution
```

An agent may propose exact resources, typed actions/constraints, validity and
budgets, but cannot activate its own proposal. Proposal review binds the draft
digest, reviewer, semantic diff and current base policy version. Activation
uses the existing signed bundle and rollback protections.

### 2.5 Connector SDK and schema registry

The Rust connector SDK provides a stable, deny-by-default contract for:

- versioned manifests and typed action schemas;
- resource hierarchy and canonicalization;
- authentication/OAuth lifecycle and normalized permissions;
- default risk, response filtering and budgets;
- idempotency and reconciliation behavior;
- provider health, refresh and revoke behavior;
- audit-safe field classification;
- outbound origins and custom-runtime isolation metadata.

The registry stores immutable connector versions by manifest digest, publisher
and status. Package digests and Ed25519 publisher signatures are
verified before publication. Publishing a new version never mutates an older
version. Built-in and third-party manifests pass the same conformance suite.

Custom connector code runs out of process with explicit outbound origins,
timeouts and response limits; registry publication does not grant execution
authority.

### 2.6 OAuth and connection onboarding

- One-click Notion connection is the first complete Phase 4 reference flow.
- Existing Google, GitHub and Linear lifecycle behavior is exposed through the
  same onboarding API and health UX.
- Authorization Code with PKCE is used where supported.
- Requested and granted scopes are previewed and normalized into stable action
  permissions; unknown scopes grant no authority.
- Refresh and reauthorization failures fail closed.
- Revoking an agent endpoint or LeaseGate lease does not delete the underlying
  OAuth connection. Provider revoke is a separate explicit operation.
- Additional connector priority is Slack, Jira, then Microsoft 365, based on
  real demand rather than connector count alone.

### 2.7 Budgets and audit explorer

Budgets may be scoped by organization, project, agent, task, connection,
action, resource and time window. Request/item/cell/row/byte and concurrent
execution reservations remain atomic at the enforcement point.

The Cloud audit explorer provides bounded, cursor-based search by time,
project, agent, connection, action, resource, policy version, decision and
outcome. Results contain only the existing redacted audit representation.
Raw secrets, provider response bodies and external document content are never
indexed. SIEM export and compliance retention remain Phase 6 work.

## 3. Technical stack

| Layer | Choice |
|---|---|
| Domain, policy, SDK and connector runtime | Rust 2024 |
| Async runtime | Tokio |
| Cloud/API | Axum + Tower |
| MCP | official Rust MCP SDK (`rmcp`) |
| Cloud persistence | PostgreSQL + SQLx |
| Edge/local persistence | SQLite + `rusqlite` |
| Policy/package signatures | Ed25519 over RFC 8785 canonical JSON |
| Operator UI | Flutter Web/Dart |
| Interchange schemas | JSON Schema; OpenAPI-compatible HTTP models |
| Package/object storage | S3-compatible storage; MinIO on one VPS |
| Telemetry | `tracing`, optional OpenTelemetry export |
| Deployment | OCI containers and Docker Compose |

The internal policy IR remains authoritative in Phase 4. Cedar or OPA is not
introduced without compatibility tests and a benchmark showing a concrete
need. PostgreSQL and the current worker/outbox are sufficient; Redis, Kafka,
NATS and Kubernetes are not required.

## 4. Data and API additions

Phase 4 adds these tenant-owned control-plane records:

```text
connector_publishers
connector_versions
connection_descriptors
policy_proposals (including digest-bound review evidence)
```

Budget constraints remain versioned inside policy rules and signed policy
bundles; they are not maintained as a second, potentially divergent policy
table.

Required API families:

```text
GET  /v1/connectors
POST /v1/connectors/validate
POST /v1/connectors/publish
GET  /v1/.../connections
POST /v1/.../policy/simulate
GET  /v1/.../permissions
POST /v1/.../policy/proposals
POST /v1/.../policy/proposals/{id}/review
GET  /v1/.../audit
```

All tenant queries set the PostgreSQL tenant context and all request bodies
deny unknown fields. List APIs are bounded and cursor based.

## 5. Delivery slices

1. Freeze Phase 4 policy trace, connector manifest and proposal contracts.
2. Implement policy simulation and effective-permission projection.
3. Implement policy-aware MCP discovery with per-call re-enforcement.
4. Add immutable connector registry and SDK conformance tooling.
5. Add policy proposal/review/activation workflow.
6. Expose connection onboarding/health and one-click Notion metadata flow.
7. Add hierarchical budgets and bounded audit search APIs.
8. Build Flutter permission matrix, simulator, proposals, connections,
   budgets and audit explorer.
9. Extend the one-VPS Compose profile without mandatory new infrastructure.
10. Run cross-transport, tenant-isolation, replay, concurrency, schema and
    canonicalization acceptance tests.

## 6. Exit criteria

- A mainstream MCP client can authenticate and discover usable actions in a
  few minutes.
- Identical canonical requests receive identical decisions through CLI and MCP.
- Tool discovery reflects policy while every call is independently enforced.
- Simulation explains the final result and rule trace without executing or
  leaking sensitive arguments.
- An agent cannot review or activate its own policy proposal.
- Endpoint/lease revocation does not destroy the original OAuth connection.
- At least one reference connector passes the SDK conformance suite.
- Unknown fields/actions, resource aliasing, schema downgrade, package digest
  tampering and canonicalization bypass fail closed.
- Concurrent calls cannot exceed configured reservations or cumulative task
  budgets.
- Audit search remains bounded, tenant isolated and secret-free.
- The complete Phase 4 profile still starts on one VPS with Compose.

## 7. Explicit non-goals

- AWS STS, SSH certificates and database credential leases.
- Managed Cloud provider execution.
- General DPoP/sender-constrained downstream credentials.
- Native mobile apps, SSO/SCIM, SIEM and compliance evidence workflows.
- HA/multi-region, BYOK/HSM and workload identity federation.

Those capabilities remain Phase 5 and Phase 6 scope.
