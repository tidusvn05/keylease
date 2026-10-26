# KeyLease

KeyLease is a local-first encrypted vault and LeaseGate policy gateway for agents.
This repository contains the Phase 0 contracts through the locally testable
Phase 9 single-VPS onboarding and operations baseline from
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
- `leasegate-connectors`: connector trait, fake conformance connector and typed
  Google, GitHub, Linear, Notion, Slack and Jira providers.
- `leasegate-connector-sdk`: manifest validation, JSON Schema generation,
  conformance checks and signed immutable connector packaging CLI/library.
- `keylease-service`: the only mutation/policy/connector orchestration layer.
- `keylease-cli`: headless CLI and local Unix-socket daemon.
- `keylease-cloud`: PostgreSQL-backed control API, connector registry, policy
  proposals, dynamic-credential metadata, posture, rotation and worker.
- `leasegate-control` / `leasegate-policy-bundle`: versioned Cloud/Edge wire
  contracts and Ed25519/JCS signatures.
- `leasegate-credentials`: self-hosted AWS STS, SSH certificate, PostgreSQL role
  and OAuth token-exchange credential broker/backends.
- `leasegate-edge`: Linux local Gateway, signed control cache, credential API,
  offline enforcement and encrypted audit/credential state.
- `leasegate-mcp`: authenticated Streamable HTTP MCP adapter over the canonical
  service boundary.
- `keylease-rpc`: the single implementation of the local RPC contract, shared by
  the CLI daemon and the mobile FFI so the wire format cannot drift.
- `keylease-mobile`: the in-process C ABI the Android client calls; see
  `docs/adr/0004-mobile-in-process-boundary.md`.
- `packages/leasegate_vault_ui`: the shared vault client — models, state, design
  tokens and feature UI — used by both Flutter apps.
- `apps/desktop-flutter`: macOS presentation shell (requires Flutter locally).
- `apps/mobile-flutter`: the Android vault client.
- `apps/approval-flutter`: responsive remote approval and Edge-health web app.

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p keylease-cli -- --help
```

The Flutter side lives in three packages that are checked independently:

```sh
cd packages/leasegate_vault_ui && flutter analyze && flutter test
cd apps/desktop-flutter        && flutter analyze && flutter test
cd apps/mobile-flutter         && flutter analyze && flutter test
```

Building the Android client needs the toolchain described in
`apps/mobile-flutter/README.md`; `scripts/build-android.sh` drives it.

See `docs/security/threat-model.md` and `docs/adr/` before changing crypto,
identity, trust-mode or connector boundaries.

The proposed Phase 3 Cloud/Edge/MCP architecture, including the single-VPS
self-hosted profile and technical stack, is documented in
[`docs/phase-3/architecture-and-tech-stack.md`](docs/phase-3/architecture-and-tech-stack.md).
Implemented Phase 2/3 scope and explicit beta limitations are tracked in
[`docs/phase-2-3-implementation.md`](docs/phase-2-3-implementation.md). To run
the complete beta profile on one VPS, follow
[`docs/self-hosted-vps.md`](docs/self-hosted-vps.md).

The Phase 4 Connector Platform and Policy UX design is in
[`docs/phase-4/architecture-and-tech-stack.md`](docs/phase-4/architecture-and-tech-stack.md),
with implemented scope and verification evidence in
[`docs/phase-4/implementation-status.md`](docs/phase-4/implementation-status.md).

Phase 5 deliberately targets only the all-in-one `self_hosted/local_gateway`
profile. Its architecture and implementation evidence are in
[`docs/phase-5/architecture-and-tech-stack.md`](docs/phase-5/architecture-and-tech-stack.md)
and
[`docs/phase-5/implementation-status.md`](docs/phase-5/implementation-status.md).

Phase 6 keeps that ownership model and adds enterprise identity, device-bound
mobile approval, policy-as-code, SIEM/compliance and HA coordination. See
[`docs/phase-6/architecture-and-tech-stack.md`](docs/phase-6/architecture-and-tech-stack.md)
and [`docs/phase-6/implementation-status.md`](docs/phase-6/implementation-status.md).

Phase 7 deliberately narrows the release target to production readiness on one
self-hosted VPS. Enterprise and HA capabilities are excluded from its exit
criteria. Track implementation and operator evidence in
[`docs/phase-7/single-vps-checklist.md`](docs/phase-7/single-vps-checklist.md).

Phase 8 automates that single-VPS release gate: pinned runtime images,
content-addressed releases, SPDX SBOM/provenance, migration dry-runs, guarded
upgrade/rollback, systemd backup/monitor timers and redacted diagnostics. See
[`docs/phase-8/single-vps-operations-and-release.md`](docs/phase-8/single-vps-operations-and-release.md).

Phase 9 provides the stable single-VPS lifecycle CLI, guarded first-run
bootstrap, initial encrypted backup, redacted host-status dashboard and a
machine-readable acceptance report. See
[`docs/phase-9/single-vps-ga-and-onboarding.md`](docs/phase-9/single-vps-ga-and-onboarding.md).

For an Intel Mac (`x86_64`) build and release-acceptance walkthrough, see
[`docs/macos-x86_64-build-test.md`](docs/macos-x86_64-build-test.md). The
companion `scripts/macos-x86_64-check.sh` runs the automated Rust, Flutter,
architecture and codesign checks.

For subsequent local macOS app builds, use the faster incremental build and
installer:

```sh
./scripts/build-install-macos.sh
```

It verifies Flutter 3.47.2, builds the release app and safely replaces
`/Applications/KeyLease.app`, then links its CLI into `~/.local/bin/keylease`.
Pass `--full` to run the complete Rust and Flutter acceptance suite before
installing.

On first launch, the macOS app asks only whether to create a vault or use an
existing KeyLease, KDBX, or 1PUX file. The selected source is left unchanged;
KeyLease creates its managed vault and private runtime files under
`~/.keylease/`. Its signed background helper is embedded in `KeyLease.app` and
registered with macOS Login Items, so users do not configure sockets, client
IDs, token files, or `PATH`. This desktop runtime requires macOS 13 or newer.

Additional independent vaults can be created, imported, renamed, and switched
from Settings > Vaults. See [`docs/multi-vault.md`](docs/multi-vault.md).

After the desktop setup, the CLI automatically uses the managed runtime under
`~/.keylease`:

```sh
keylease status
keylease entries search "github"
keylease entries get ITEM_ID
keylease entries reveal ITEM_ID --field password
keylease entries totp ITEM_ID
```

The vault must be unlocked in the app. Every entry has a **Prompt** button that
copies safe, ready-to-paste instructions scoped to that exact item ID, without
including a token or secret value.

For a new item, the desktop's **Use Agent** mode copies only a short, temporary
handoff command. The handoff stays in daemon memory for two hours and is cleared
when the vault locks, switches, or the service restarts. The agent obtains the
version-matched workflow from the CLI:

```sh
keylease agent new-item handoff_ID
keylease agent new-item handoff_ID --json
```

The first form prints agent-readable Markdown; `--json` exposes the same guide
as a structured contract. The handoff ID is not a credential, and the command
still requires the active managed client and an unlocked matching vault.

## Agents: approvals and using secrets without disclosing them

[ADR 0005](docs/adr/0005-agent-trust-and-secret-use.md) adds a least-privilege
agent identity and brokers that let an agent use a credential without the value
reaching its model:

```sh
keylease agent enroll codex                     # own client, approval baseline
keylease ssh deploy@host 'systemctl status app' # SSH key stays in the vault
keylease db psql ITEM_ID -- -c 'select 1'       # Postgres password stays in the vault
keylease run --env API_KEY=ITEM_ID/password -- terraform plan
keylease approval decide APPROVAL_ID --approve --trust 1h
```

See [agent approvals and trust](docs/agent-approvals.md),
[SSH agent](docs/ssh-agent.md), [PostgreSQL proxy](docs/db-proxy.md),
[`keylease run`](docs/run-with-secrets.md) and
[remote approval for a VPS](docs/remote-approval.md).

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
