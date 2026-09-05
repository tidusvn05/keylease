# Phase 0/1 implementation matrix

This file maps the proposal's deliverables to current evidence. “Implemented”
means covered by source and an automated test; it does not replace the external
acceptance checks listed below.

## Phase 0

| Deliverable | Implementation and evidence |
|---|---|
| Threat model | `docs/security/threat-model.md` covers prompt injection, confused deputy, token theft, malicious connectors, SSRF, replay and compromised cloud/edge. |
| Versioned domain contracts | `keylease-core`; `keylease contracts` emits 13 JSON Schemas and five connector manifests. Unknown versions/fields fail closed. |
| Policy contract and vectors | `leasegate-policy` plus `test-vectors/policy-golden.json`; explicit deny wins and default is deny. |
| Crypto/key hierarchy | `keylease-crypto` and ADR 0001; Argon2id password slot → random account root → vault key → per-item random key. Tests prove password changes do not rewrite item ciphertext and AAD tampering fails. |
| Edge/cloud boundary | ADR 0002 and explicit `TrustMode`; Phase 1 rejects managed execution. |
| Atomic native store | `keylease-store`; WAL/transactions, ciphertext-only objects, history, tombstones and vault-keyed mutation journal. Vault mutations commit ciphertext, revision, idempotency result and audit together. Rollback and password re-wrap have tests. |
| Sync simulation | `keylease-sync`; deterministic two-device conflict and idempotency vectors operate only on ciphertext digests. |
| Fake Connector conformance | OAuth expiry/denial/revoke/scope, pagination, 429, timeout, partial failure, schema drift, canonicalization, secret-in-error redaction, replay/restart and concurrent max-use tests. |

## Phase 1

| Deliverable | Current implementation |
|---|---|
| Rust CLI/headless Linux | One `keylease` binary with standalone administrative commands and Unix-socket `serve`; JSON stdout and stable structured errors. Master passwords are TTY-only and zeroized. |
| macOS Flutter | Checked-in macOS runner and capability-gated Material client with master-password unlock/manual lock, full group CRUD, metadata search, extensible entry templates and create/edit/delete, Rust password generation, separately authorized username/password reveal and copy, TOTP countdown/copy, basic history, connection add/enroll/test/refresh/disconnect/revoke, pending approval decisions, redacted audit view, token-file validation and bounded IPC. The native adapter uses a security-scoped token-file picker, clears sensitive clipboard content after 30 seconds, and requests daemon lock plus clipboard clearing on sleep/screen lock. Native build/exercise still requires macOS. |
| Native vault | Encrypted objects and groups, master-password unlock, inactivity auto-lock, manual lock, metadata search, custom fields, TOTP, password generator, optimistic revisions, history and recycle-bin tombstones. Lock/idle expiry revokes session grants, approvals and leases. |
| Native backup | Version 2 ciphertext-only backup/restore with a vault-keyed MAC over the complete manifest; excludes clients, grants, approvals, leases, execution sessions and audit. Restored connections are disconnected. Tampering and tombstone restoration have tests. |
| KDBX | Two-step preview/commit, source checksum, duplicate decisions, loss warnings, protected custom fields and both `otp`/KeePass `TimeOtp-*` forms. Whole-vault or selected-item export targets KDBX 4.1 and excludes agent authorization. |
| 1PUX | Isolated ZIP adapter with preview/explicit commit, stable IDs, account/vault hierarchy, sections, typed fields, history and attachment-byte preservation in encrypted item extensions. Parsing has source/archive/entry/expanded-size limits, rejects unsafe paths and future format versions, and requires CLI plaintext acknowledgement. |
| Agent authorization | Registered client token hash, exact-resource scoped grants, argument constraints, standing/lease TTLs, protected-field split, max item/cell/byte/row/concurrency budgets, service-layer enforcement and redacted audits. Entry and full group CRUD mutations have keyed idempotency and atomic success audit. Create/update returns metadata only. Debug formatting redacts vault values, TOTP seeds, lease tokens, request arguments and provider bodies. |
| LeaseGate local | Canonicalize → policy → exact approval → opaque session-bound lease → transactional use reservation → connector → response filter → atomic completion/audit. Approval creation/decision is audit-atomic; approval consumption and lease insertion are one transaction, so invalid limits, crashes or concurrent consumers cannot burn/reuse an approval. Revoke, idempotent restart behavior and global kill switch are implemented. |
| Connection lifecycle | Encrypted credential item plus separate connection registry; authenticated daemon RPC, CLI and desktop controls for add/enroll/unenroll/test/refresh/disconnect/revoke. Enrolled resources are exact canonical object IDs. Credential lookup verifies the dedicated active protected item. Only Edge-local trust mode executes. |
| Google Workspace | Typed action catalog, fixed origins, exact selected-file registry, local authorized-file listing, Drive/Docs/Sheets request builders, revision/value preconditions, bounded concrete A1 ranges, `RAW` writes and response budgets. The desktop/CLI system-browser flow uses Google's integrated Picker with loopback redirect, state, S256 PKCE, exact `drive.file` scope, bounded selections, fixed-origin token exchange and metadata-based resource canonicalization. Document/spreadsheet creation targets an exact enrolled folder and enrolls the returned stable ID. Forbidden formula/share/delete actions are absent. |
| GitHub/Linear/Notion beta | Action-specific typed schemas, fixed-origin request builders, stable canonical object IDs, resource scoping, digest preconditions, bounded payloads, unknown-field denial and shared redaction/conformance behavior. |

## External acceptance still required

The following proposal exit criteria cannot be honestly certified in this Linux
workspace and remain release blockers:

- Build and exercise the generated macOS runner, security-scoped bookmarks,
  clipboard timeout and sleep/session-lock hooks with a Flutter/macOS toolchain.
- Validate representative KDBX 4.0/4.1 fixtures produced by Strongbox and open
  KeyLease exports in current Strongbox and KeePassXC releases.
- Validate the 1PUX fixture matrix against exports produced by current 1Password
  desktop releases; the checked-in documented-format fixture is synthetic.
- Configure real Google desktop OAuth credentials, exercise the implemented
  system-browser Picker end to end, prove `drive.file` cannot enumerate
  unselected Drive files, and exercise Docs/Sheets revision behavior against
  the live APIs.
- Run live beta smoke tests for GitHub App, Linear OAuth PKCE `actor=app`, and a
  BYO Notion internal integration against separately scoped test workspaces.
- Obtain an external cryptographic/security review before production data.

Local verification baseline: `cargo test --workspace` (48 passed),
`cargo clippy --workspace --all-targets -- -D warnings`, and `keylease contracts`
(13 schemas, five connector manifests, 34 actions).
