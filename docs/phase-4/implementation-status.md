# Phase 4 implementation status

Status: implemented beta (live OAuth/provider and production-security evidence
still required)

Last updated: 2026-09-06

## Delivered

| Area | Implementation |
|---|---|
| Policy-aware MCP | `tools/list` is generated from the active signed policy, endpoint-bound agent, revocation feed and healthy Edge connection state. Each discovered call is rebound to its advertised action/connection and still passes through the canonical service enforcement path. Errors are structured and redact internal or provider detail. |
| Permission UX | The Flutter Web operator app has agent/connection/resource/action access rows, constraints and budgets. It refreshes from the effective-permission projection rather than reconstructing policy in Dart. |
| Simulator | The Rust policy engine returns a deterministic final decision, matched rule, rule-by-rule reason codes, budget/lease constraints and broad-scope warnings. It never invokes a connector, issues a lease or copies argument values into the trace. |
| Policy proposals | An authenticated agent can submit only non-empty, self-bound rules against the current policy version. A human owner/admin/approver reviews the proposal digest and base version. Only an approved, unexpired proposal can atomically activate the exact next signed bundle; the worker expires stale drafts. |
| Connector SDK | `leasegate-connector` validates/inspects manifests, emits per-action JSON Schema and creates Ed25519-signed packages. The SDK checks schema version, fixed outbound origins, action/resource shape, response bounds and artifact/package digests. Built-ins run through the same conformance checks. |
| Schema registry | PostgreSQL stores tenant-scoped publishers and immutable provider/version packages. Publisher identity, verifying key, manifest digest, artifact digest and signature are checked before publication. |
| Connections/OAuth | Cloud exposes connection descriptors and provider onboarding metadata while OAuth token exchange/storage remains at Edge. Notion is the public reference flow; Google, GitHub and Linear share the lifecycle contract, and typed Slack/Jira connectors and OAuth metadata were added. Reported provider scopes normalize into stable LeaseGate permissions; unknown scopes grant nothing. |
| Budgets | Existing per-call and cumulative task request/item/cell/row/byte budgets and concurrency reservations remain enforced atomically. Phase 4 projects those signed policy constraints in the UI and simulator. |
| Audit explorer | Bounded cursor pagination filters redacted audit indexes by agent, connection, action, resource prefix, decision, outcome, policy version and time. Provider bodies, arguments and secret values are not indexed. |
| Self-hosting | Phase 4 reuses the Phase 3 Cloud, worker, PostgreSQL, Caddy/web and optional Edge Compose profile. Migration `0002_phase4_connector_policy_ux.sql` runs automatically; no Redis, broker or Kubernetes dependency was introduced. |

## Security properties checked in code

- Connector and connection IDs cannot be repointed across tenant, project,
  provider or authentication-method bindings.
- Invalid publisher signatures, manifest/artifact tampering, unknown fields,
  action aliases and cross-provider resources fail closed.
- An agent credential is hashed at rest and compared in constant time; the MCP
  transport cannot accept an agent identity from tool arguments.
- Policy proposal review and activation are bound to tenant, project, digest,
  current base version, next version, previous bundle digest and exact rule set.
- MCP discovery is only an ergonomics layer. Execution authorization remains
  mandatory, so a stale client-side catalog cannot grant access.
- Connection health, policy expiry, revocation staleness and audit-spool limits
  continue to fail closed at Edge.

## Main Phase 4 API surface

```text
POST /v1/connectors/validate
GET  /v1/organizations/{organization}/projects/{project}/connectors
POST /v1/organizations/{organization}/projects/{project}/connector-publishers
POST /v1/organizations/{organization}/projects/{project}/connectors
GET  /v1/organizations/{organization}/projects/{project}/connections
POST /v1/organizations/{organization}/projects/{project}/connections
POST /v1/organizations/{organization}/projects/{project}/connections/onboarding
POST /v1/organizations/{organization}/projects/{project}/policy/simulate
GET  /v1/organizations/{organization}/projects/{project}/agents/{agent}/permissions
POST /v1/organizations/{organization}/projects/{project}/agents/{agent}/policy/proposals
GET  /v1/organizations/{organization}/projects/{project}/policy/proposals
POST /v1/organizations/{organization}/projects/{project}/policy/proposals/{proposal}/review
POST /v1/organizations/{organization}/projects/{project}/policy/proposals/{proposal}/activate
GET  /v1/organizations/{organization}/projects/{project}/audit
```

All administrative endpoints retain the Phase 3 beta operator credential.
Agent proposal creation additionally requires that agent's own credential.

## Verification

The checked-in suites cover:

- deterministic/redacted simulation and permission projection;
- policy-filtered MCP discovery and per-call binding;
- signed connector package tamper detection and reference conformance;
- Slack/Jira typed action and exact-resource constraints;
- Edge policy/connection discovery behavior;
- PostgreSQL publisher, registry, connection, proposal activation/expiry,
  audit cursor and tenant isolation contracts.

Run the acceptance set with:

```sh
cargo fmt --all -- --check
cargo test --workspace --no-fail-fast
cargo clippy --workspace --all-targets -- -D warnings

# Uses a disposable or dedicated PostgreSQL database.
KEYLEASE_TEST_DATABASE_URL=postgresql://... \
  cargo test -p keylease-cloud --test postgres_phase3 --test postgres_phase4

docker build --target build -f deploy/compose/Dockerfile.approval .
docker compose -f deploy/compose/compose.yaml config
```

## Beta limits and release evidence

- Live authorization-code exchange, refresh, revoke and provider actions still
  require real Notion/Slack/Jira/Google/GitHub/Linear test tenants. Cloud only
  creates authorization metadata; client secrets, code verifiers and provider
  tokens must stay at Edge.
- Third-party packages are validated, signed and registered, but installing a
  custom executable remains an explicit operator action. Registry publication
  alone never grants process execution or network access.
- The direct operator token kept in browser-tab memory is appropriate for the
  documented single-owner/VPN beta. A public team deployment still needs an
  OIDC-aware proxy and an external security review.
- PostgreSQL integration tests skip when `KEYLEASE_TEST_DATABASE_URL` is not
  set; release evidence must include a run against PostgreSQL with migrations.
