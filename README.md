# KeyLease

KeyLease is a local-first encrypted vault and LeaseGate policy gateway for agents.
This repository contains the Phase 0 contracts and the locally testable portion
of the Phase 1 MVP from
[`agent-friendly-keepass-app-proposal.md`](agent-friendly-keepass-app-proposal.md).
Platform and live-provider release evidence is tracked separately and is not
claimed complete from this Linux workspace.

The security-sensitive implementation is Rust. The CLI and desktop clients are
transport/presentation adapters and cannot access persistence or connectors
without going through `KeyLeaseService`.

## Workspace

- `keylease-core`: versioned domain, request, identity and audit contracts.
- `keylease-crypto`: key hierarchy, password slots and item envelopes.
- `keylease-store`: atomic SQLite ciphertext store, authenticated native backup,
  audit, keyed mutation journal and lease/execution journal.
- `keylease-1pux`: bounded plaintext 1PUX ZIP importer and migration reports.
- `keylease-kdbx`: KDBX 4 import/export adapter and migration reports.
- `leasegate-policy`: deterministic deny-by-default policy and approvals.
- `leasegate-connectors`: connector trait, fake conformance connector and providers.
- `keylease-service`: the only mutation/policy/connector orchestration layer.
- `keylease-cli`: headless CLI and local Unix-socket daemon.
- `apps/desktop-flutter`: macOS presentation shell (requires Flutter locally).

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p keylease-cli -- --help
```

See `docs/security/threat-model.md` and `docs/adr/` before changing crypto,
identity, trust-mode or connector boundaries.

The proposed Phase 3 Cloud/Edge/MCP architecture, including the single-VPS
self-hosted profile and technical stack, is documented in
[`docs/phase-3/architecture-and-tech-stack.md`](docs/phase-3/architecture-and-tech-stack.md).

For an Intel Mac (`x86_64`) build and release-acceptance walkthrough, see
[`docs/macos-x86_64-build-test.md`](docs/macos-x86_64-build-test.md). The
companion `scripts/macos-x86_64-check.sh` runs the automated Rust, Flutter,
architecture and codesign checks.

## Local flow

```sh
# All password prompts read from a TTY without echo.
keylease --db work.sqlite vault init
keylease --db work.sqlite client register codex

# Save the returned client token in a chmod-0600 file, then create narrow grants.
keylease --db work.sqlite grant create \
  --client agent_codex \
  --resource kl://vault_ID/group/GROUP_ID \
  --allow entry:create,entry:update_standard_fields \
  --ttl-seconds 28800 \
  --max-lease-ttl-seconds 300

keylease --db work.sqlite serve --session-ttl-seconds 28800

# Or keep the daemon locked until an authenticated client supplies the password.
keylease --db work.sqlite serve --start-locked
keylease --agent-id agent_codex --client-token-file ./codex.token unlock

# In another shell, secret-bearing JSON is read from stdin or a file, never argv.
keylease --agent-id agent_codex --client-token-file ./codex.token \
  entries create --input-json - --idempotency-key task-001

# After granting connection:add, lifecycle also uses the daemon; credentials stay on stdin.
keylease --agent-id agent_codex --client-token-file ./codex.token \
  connection add github --input-json -

# Google uses a system-browser OAuth/Picker flow; client configuration is stdin JSON.
keylease --agent-id agent_codex --client-token-file ./codex.token \
  connection google-oauth-begin --input-json -
keylease --agent-id agent_codex --client-token-file ./codex.token \
  connection google-oauth-complete google_oauth_FLOW_ID

# 1PUX is plaintext. Preview first; add --commit only after reviewing the report.
keylease --db work.sqlite vault import-onepux account.1pux \
  --acknowledge-plaintext
```

`keylease contracts` emits the versioned request schemas and built-in connector
catalogs. `docs/phase-0-1-implementation-matrix.md` tracks acceptance evidence
and the macOS/provider checks that must happen in their real environments.
