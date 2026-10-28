# KeyLease

KeyLease is a local-first encrypted vault with a policy gateway, built so that
AI agents can **use** credentials — sign in over SSH, connect to a database,
run a CLI that needs an API key — without the secret reaching the model, and
with a human approving what matters.

- **Separate identity per agent.** An enrolled agent can search and read
  metadata; using a secret or changing the vault waits for approval.
- **Approve once, or trust for a window.** 30 minutes to 7 days, capped by the
  action's risk tier; revocable at any time; every use audited.
- **Brokers instead of reveals.** `keylease ssh` signs inside the vault,
  `keylease db` answers the PostgreSQL SCRAM challenge inside the vault,
  `keylease run` injects into a child process and scrubs its output.
- **Your Mac or a VPS.** The same daemon runs under the macOS app or under
  systemd; a headless VPS can be approved from your Mac.
- **Any assistant.** CLI agents use `keylease` directly; Claude Desktop,
  Cursor and Codex start `keylease mcp`; ChatGPT and claude.ai connect to your
  self-hosted gateway with OAuth.
- **Share with a VPS, back up, recover.** Through your self-hosted cloud, a VPS
  receives only the items (or projects) you share or approve, backs up its own
  secrets sealed to you, and a recovery kit restores your vault on a new
  device. The cloud cannot read or forge any of it.

The security-sensitive implementation is Rust. The CLI, desktop and mobile
clients are transport/presentation adapters and cannot reach storage, policy
or connectors except through `KeyLeaseService`.

## Architecture

```text
 agent CLI (Claude Code, Codex, bots)          MCP clients: keylease mcp (stdio)
   └─ keylease ssh | db | run ──────────────────────► servers, databases
        │ (brokers in the agent's process)               (SSH, PostgreSQL wire)
        │ Unix socket, the agent's own token
        ▼
 ┌──────────────────────────────────────┐
 │ keylease serve — KeyLeaseService      │ ◄── macOS app (local approver)
 │ vault · policy · trust · audit        │
 │ signs SSH, answers SCRAM, injects     │ ◄── remote approver over HTTPS
 └──────────────────────────────────────┘     (Mac app / keylease remote;
        ▲                                        signed, approvals only)
        └── gateway: OAuth 2.1 + MCP over HTTPS ◄── ChatGPT, claude.ai
```

Roles, secret-handling tiers, the approval sequence and the component map are
in **[docs/architecture.md](docs/architecture.md)**. Design decisions are in
[ADR 0005](docs/adr/0005-agent-trust-and-secret-use.md); the security analysis
is the [threat model](docs/security/threat-model.md).

## Choose your setup

Step-by-step guides, with what is and is not implemented, are in
**[docs/use-cases.md](docs/use-cases.md)**:

| Setup | Status |
|---|---|
| Agent CLI (Claude Code, Codex…) on your Mac, approve in the Mac app | ✅ CLI/daemon · 🟡 trust UI in the native app |
| Agents on a VPS, approve on the VPS (self-trust) | ✅ |
| Agents on a VPS, approve from your Mac (paired approver) | ✅ CLI · 🟡 native Mac UI |
| Unattended automation with narrow grants | ✅ |
| Claude Desktop, Cursor, Codex through local MCP (`keylease mcp`) | ✅ |
| ChatGPT / claude.ai through your own HTTPS gateway (OAuth 2.1) | ✅ simulated client · not yet tried on the live services |

✅ implemented and tested on Linux · 🟡 written, not yet verified on a Mac ·
❌ not implemented.

## Install

With Rust 1.94+ ([rustup](https://rustup.rs)), on Linux or macOS:

```sh
cargo install --locked keylease
```

This builds `keylease` from crates.io into `~/.cargo/bin`. Releases do not ship
prebuilt binaries or apps; build the macOS app yourself (below).
Releases: [GitHub](https://github.com/tidusvn05/keylease/releases) ·
[how they are made](docs/releasing.md).

## Quick start: an agent on your Mac

```sh
keylease agent enroll claude                    # own client + approval baseline
# put KEYLEASE_AGENT_ID / KEYLEASE_CLIENT_TOKEN_FILE in the agent's env, then:
keylease --purpose "check the deploy" ssh deploy@host 'systemctl status app'
keylease db psql ITEM_ID -- -c 'select 1'       # Postgres password stays in the vault
keylease run --env API_KEY=ITEM_ID/password -- terraform plan
keylease approval decide APPROVAL_ID --approve --trust 1h
keylease trust list
```

For an MCP client instead of a CLI agent:

```sh
keylease mcp setup claude-desktop --write       # or cursor, claude-code, codex
```

## Quick start: agents on a VPS

As the user the agents run as (not root), on Linux with systemd:

```sh
cargo install --locked keylease
keylease vault init
keylease service install                 # unlocks at boot from a host-sealed credential (asks for sudo)
cd /srv/shop && keylease projects init --agent claude   # identity agent_claude-shop for this tree
```

Start the agent anywhere in `/srv/shop`; it needs no environment variables. Keep
`keylease approve` open in another SSH session to answer its requests (Enter trusts
everyday work in the project for an hour; a reveal is approved once)
([use case 2](docs/use-cases.md#2-agents-on-a-vps-self-trust)).

Guides: [agent approvals and trust](docs/agent-approvals.md) ·
[MCP clients](docs/mcp.md) · [self-hosted MCP gateway](docs/mcp-gateway.md) ·
[SSH agent](docs/ssh-agent.md) · [PostgreSQL proxy](docs/db-proxy.md) ·
[`keylease run`](docs/run-with-secrets.md) ·
[remote approval for a VPS](docs/remote-approval.md) ·
[cloud sharing, backup and recovery](docs/cloud-sharing.md) ·
[multiple vaults](docs/multi-vault.md).

## The macOS app

The macOS app is the native SwiftUI app in `apps/desktop-macos-app`
([README](apps/desktop-macos-app/README.md)) over the same daemon. Besides the
vault, it has the approval sheet with the trust picker, the Agents section
(enroll agents, list and revoke trusts), Remote Vaults (approve for a VPS) and
notifications with Touch ID. 🟡 It has not yet been built and tested on a Mac.

Build and install it on a Mac (Xcode 16+, Rust):

```sh
./scripts/package-macos-swift.sh --install   # replaces /Applications/KeyLease.app
./scripts/package-macos-swift.sh --dmg       # or a DMG to copy to another Mac
```

The build is signed ad-hoc unless you have an Apple certificate
(`EXPANDED_CODE_SIGN_IDENTITY`). A copy downloaded on another Mac is blocked on
first launch: allow it in System Settings → Privacy & Security → **Open
Anyway**, or run `xattr -dr com.apple.quarantine /Applications/KeyLease.app`.

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

## Headless CLI flow

Without the desktop app (a server, a script), the CLI manages the vault
directly:

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

## LeaseGate Cloud and Edge

The repository also contains a self-hosted control plane and gateway for
running agents against SaaS connectors with signed policy bundles: Cloud API
and worker, the Edge gateway with an MCP endpoint and dynamic credentials,
and the `approval-flutter` operator app. To run it on one VPS, follow
[`docs/self-hosted-vps.md`](docs/self-hosted-vps.md).

This work was built in phases from
the [original design proposal](docs/design/original-proposal-vi.md) (Vietnamese);
platform and live-provider release evidence is tracked separately and is not
claimed complete from a Linux workspace.

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
- `keylease` (`crates/keylease-cli`): headless CLI and local Unix-socket daemon.
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
  tokens and feature UI — used by the Flutter mobile app.
- `apps/desktop-macos` / `apps/desktop-macos-app`: native Swift client core
  (builds and tests on Linux too) and the SwiftUI app (needs a Mac).
- `apps/mobile-flutter`: the Android vault client.
- `apps/approval-flutter`: responsive remote approval and Edge-health web app.

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p keylease -- --help
```

The Flutter side lives in two packages that are checked independently:

```sh
cd packages/leasegate_vault_ui && flutter analyze && flutter test
cd apps/mobile-flutter         && flutter analyze && flutter test
```

Building the Android client needs the toolchain described in
`apps/mobile-flutter/README.md`; `scripts/build-android.sh` drives it.

See `docs/security/threat-model.md` and `docs/adr/` before changing crypto,
identity, trust-mode or connector boundaries.

The native Swift client is checked on a Mac:

```sh
cd apps/desktop-macos     && swift test     # also runs on Linux
cd apps/desktop-macos-app && swift build && swift test
```

## Security and license

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
KeyLease and LeaseGate are licensed under the [Apache License 2.0](LICENSE).
