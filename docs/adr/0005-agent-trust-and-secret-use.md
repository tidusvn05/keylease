# ADR 0005: Agent trust, secret use without disclosure, and time-boxed trust

Status: proposed

## Context

KeyLease already has a strong decision core: one service boundary (ADR 0003),
deny-by-default deterministic policy, approvals bound to a canonical request
digest and policy version, atomic lease issue, data budgets, a hash-chained
audit, a kill switch, typed connectors and Phase 5 dynamic credentials. What it
does not yet have is a way for an agent to **use** a vault secret without the
value reaching the agent's model context, nor a way for a human to approve a
vault use interactively.

Concretely, in the current code:

1. The only agent path to a login, SSH key, database password or API token
   stored as an item is `entries reveal` / `entries totp`
   (`reveal_field_authorized`, `totp_authorized` in `keylease-service`). The
   plaintext is returned to the agent process and, in practice, printed into
   the LLM transcript. The desktop's per-entry agent prompt
   (`AppController.agentPromptForEntry`) instructs the agent to do exactly this.
2. `authorize_vault` turns `PolicyDecision::RequireApproval` into `Denied`
   ("vault command requires explicit approval flow"). Approvals exist only for
   connector gates and credential leases, so a vault item is either pre-granted
   or unusable — there is no "ask me".
3. An agent's identity is a static bearer token from `register_client`. The
   threat model already records that it is replayable until revoked.
4. `ActionRequest` carries no human-readable purpose for an approver to judge.
5. Phase 5 credential backends return the issued material (STS keys, SSH
   certificate, PostgreSQL role password) to the agent once. It is short-lived
   and narrow, but it is still disclosed.

Comparable products (for example 1Password for Agents, October 2026) converge on
the same shape: the agent authenticates with its own key, the human approves a
specific use on their own device, and the credential is delivered into the
destination rather than to the model. This ADR adopts that shape on top of the
existing KeyLease boundaries, for three deployments:

- **Personal:** an agent CLI (Claude Code, Codex, …) plus the `keylease` CLI
  plus the macOS app on one machine.
- **Standalone VPS:** `keylease serve` headless on a Linux host, used by agents
  running on that host.
- **VPS with a paired approver:** the same VPS, with the macOS app (later the
  mobile app) as the remote approver.

## Decision

### 1. Two roles, one contract

| Role | Runs as | Responsibility |
|---|---|---|
| Vault node | macOS app's embedded helper, or `keylease serve` on a VPS | Holds plaintext, evaluates policy, executes on the agent's behalf, audits |
| Approver | macOS app; later the mobile app | Decides approvals, issues time-boxed trust, revokes |

Both deployments run the same service, policy engine and RPC contract. A
"gateway" is only a vault node that exposes an HTTPS endpoint for pairing and
approval; the personal deployment does not need one.

### 2. Disclosure tiers

Every agent-facing secret operation belongs to exactly one tier. A higher tier
is used only when no lower one fits the credential.

| Tier | Mechanism | What the agent receives | Used for |
|---|---|---|---|
| T0 Execute | KeyLease performs the call or query | The result only | SaaS APIs (existing connectors), bounded DB queries |
| T1 Proxy | A local socket or loopback listener attaches the credential | An endpoint, never the secret | SSH (ssh-agent), databases, HTTP APIs |
| T2 Ephemeral | Dynamic, narrowly scoped credential (Phase 5 backends) | Short-lived material | AWS STS, SSH certificates, PostgreSQL temporary roles |
| T3 Inject | `keylease run` puts the value into a child process environment or file | Indirectly, via the child | CLIs that only read environment variables |
| T4 Reveal | `entries reveal` / `entries totp` | Plaintext | Last resort |

T1 is preferred over T3 because no process the agent spawns ever holds the
secret. T2 is combined with T1 where possible: the proxy itself obtains the
dynamic credential, so even ephemeral material stays inside the vault node.

T4 always requires a per-use approval and is never eligible for time-boxed
trust (section 5). Existing pre-granted `entry:read_secret` rules keep working
for compatibility but the desktop stops recommending them.

### 3. Built-in brokers

**SSH agent (T1, optionally T2).** The vault node implements the OpenSSH agent
protocol on `~/.keylease/run/ssh-agent.sock` (mode 0600, peer-uid checked like
the RPC socket). Private keys stored as `core.ssh_key` items never leave the
service; it signs the challenge. `ssh`, `git`, `scp` and `rsync` work unchanged
with `SSH_AUTH_SOCK` set. Each signature is a policy decision:

- action `ssh:sign`, resource `kl://<vault>/<item>`, arguments include the
  destination host and user when the client supplies them (OpenSSH session-bind
  extension), otherwise the decision is made on the key alone and recorded as
  such;
- with an SSH CA backend configured, the node may instead mint an ephemeral key
  and a short certificate per session (Phase 5 `credential.ssh.issue`).

`keylease ssh <target> -- <command>` is a convenience wrapper that runs OpenSSH
through the agent socket and audits the command line. KeyLease does not ship its
own SSH client.

**Database proxy (T1 + T2, and T0).** `keylease db proxy <connection>` opens a
loopback listener (for PostgreSQL, `127.0.0.1:<port>`) that authenticates
upstream using a Phase 5 temporary role or a stored credential. The agent runs
`psql -h 127.0.0.1 -p <port>` without a password. Policy is expressed per
upstream **role**, so a read-only role can be trusted for a time window while a
write or migration role requires approval. `keylease db query <connection>
--sql …` is the T0 form, bounded by `DataBudget` (`max_items`,
`max_response_bytes`). PostgreSQL is first because its backend exists; other
engines follow the same pattern.

**HTTP header proxy (T1).** For APIs without a typed connector, a loopback
proxy attaches an `Authorization` header only for an allowlisted origin.
Redirects are disabled and SSRF rules match the existing connector rules.
Typed connectors remain the preferred path because their actions are
individually authorized.

**Run (T3).** `keylease run --env NAME=kl://<vault>/<item>/<field> -- <cmd>`
spawns the child with the value in its environment. The vault node scrubs exact
matches — and their base64 and URL-encoded forms — from the child's stdout and
stderr before returning them. Scrubbing is best-effort hygiene, not a security
boundary, and is documented as such.

**Browser login fill** (a later phase) follows the same rule: a new
`entry:use_login` action delivers the value into a fill sink bound to the item's
origin and returns only `{status}` to the agent.

### 4. Approvals for vault commands

`authorize_vault` creates a pending approval for `RequireApproval` instead of
denying, exactly as connector gates do, and the request returns
`approval_required` with the approval ID. The CLI may wait
(`--wait <seconds>`, bounded) or exit and retry later with the same idempotency
key. The existing guarantees apply unchanged: an approval is valid for one
canonical digest and policy version, expires, and is consumed atomically.

`ActionRequest` gains an optional `purpose` string (bounded length, no control
characters). It is part of the canonical digest, is shown to the approver, and
is labelled in the UI as agent-supplied and untrusted.

On the personal deployment the macOS app raises a native notification for each
pending approval and shows agent, action, resource, target and purpose.

### 5. Time-boxed trust

An approver may answer an approval with a scope and a duration instead of a
single use:

- **Scope:** this exact request · this item for this agent · this target
  (SSH host, database role, web origin) for this agent.
- **Duration:** once · 30 minutes · 1 hour · 6 hours · 1 day · 3 days · 7 days.

The answer is materialized as an ordinary `PolicyRule` with `effect: allow`,
the requesting `agent_id`, an exact `resource_prefix`, `argument_equals` for the
target, `expires_at`, `max_uses` and the budget of the matched rule. No new
policy model is introduced, so simulation, effective-permission listing and
audit already cover it. Each such rule carries a `trust_id` that every later
use records in its audit event.

Trust is granted to the pair **(agent identity, host device)**, never to a
device alone, because one machine runs many agents.

Maximum duration is capped by risk tier and the UI defaults to the shortest
option:

| Risk | Examples | Maximum trust |
|---|---|---|
| R0–R1 | metadata reads, read-only staging DB role, SSH to staging | 7 days |
| R2 | standard API writes, web login use | 1 day |
| R3 | SSH to production, DB write role | 1 hour |
| R4 | T4 reveal, DB migration/DDL role, root SSH to production | once only |

Expiry is absolute; use does not extend it. Trust rules survive a vault lock
but are only usable while the vault is unlocked; this refines security
invariant 8, which continues to apply to sessions and leases. The app gains an
**Active trusts** view to list and revoke them individually or per agent, and
the global kill switch revokes all of them.

### 6. Agent identity

`client register` accepts an Ed25519 public key generated by the agent's host
(`keylease client register <name> --public-key <file>`; the CLI can generate and
store the private key mode 0600 under `~/.keylease/clients/`). Each request is
signed over its canonical digest, a timestamp and a nonce; the node rejects
stale or replayed signatures. Bearer tokens remain accepted for clients
registered without a key and are marked `legacy` in the UI and audit.
Time-boxed trust may only be granted to key-bound clients.

### 7. Standalone VPS (mode A: self-trust)

The VPS runs `keylease serve` headless with the same Unix-socket transport as
the desktop. With no approver paired, every `RequireApproval` decision is denied
— today's behaviour, now made explicit with an `approver_unavailable` reason.
Agents on the host work only through narrow, pre-written `allow` rules with
TTLs, use counts and budgets.

Unlock after reboot is an operator choice, recorded in the node's status:

| Unlock method | Convenience | Protects against |
|---|---|---|
| Interactive `keylease unlock` over SSH | Low | Disk theft and a compromised host at rest |
| `systemd-creds` sealed to the TPM | High | Disk theft only; root on the running host wins |
| Remote unlock from a paired approver (mode B) | High | Disk theft and an unattended reboot |

### 8. VPS with a paired approver (mode B)

The node exposes pairing and approval endpoints on its existing HTTPS listener
(Caddy). No vault read or mutation endpoint is added.

- **Pairing:** `keylease pair` prints a one-time code and a QR that encodes the
  node URL, the node's public-key fingerprint and the code. The macOS app
  (Settings → Remote vaults) submits its device public key; both sides pin each
  other's key. The code is single-use and expires after ten minutes.
- **Approvals:** the app holds a WebSocket (or long-poll) to the node. A
  decision is signed by the device key over `request_digest`, `policy_version`,
  the chosen scope and duration, and the approval ID.
  `accept_remote_approval` already binds digest and version; it additionally
  verifies the signature and the device's pairing record.
- **Remote unlock:** optional. The node keeps an extra key slot wrapped to a
  secret the app holds in the Keychain; the app delivers it over the paired,
  end-to-end encrypted channel after a biometric check.
- **Data separation:** the VPS vault is independent of the personal vault. The
  approver neither decrypts nor syncs VPS items. Pushing a selected item from
  the Mac to the VPS (encrypted to the node's public key) is a separate,
  later feature.
- **Mobile:** uses the same pairing protocol. Push delivery requires a relay
  (APNs/FCM or self-hosted ntfy) that carries only "pending approval exists",
  never request content.

## Consequences

- The default agent experience changes from "reveal and paste" to "use through
  a broker". The desktop's per-entry prompt is rewritten to recommend the
  broker matching the item kind and to mention reveal only as a fallback.
- `keylease-service` gains approval creation for vault actions, the `purpose`
  field (a contract-version bump), trust-rule materialization and signed client
  requests. `keylease-rpc` parity tests must cover each new command.
- New long-lived local listeners (SSH agent socket, DB and HTTP proxies) enlarge
  the attack surface. Each one uses mode-0600 sockets or loopback-only
  listeners, peer-uid checks where the platform allows, bounded messages and
  the same rate limits as the RPC socket.
- **The same-UID limit is unchanged.** An agent CLI runs as the user, so T3
  secrets are reachable through `/proc` or `env`, and any agent may connect to
  the proxies while a trust rule is active. These tiers protect the **model
  context** and resist prompt-injected exfiltration; they do not defend
  against a malicious process running as the user, which remains a non-goal.
- Results are still disclosed. Rows returned by a database query or output of
  an SSH command reach the model; budgets and read-only roles bound this.
- Time-boxed trust trades approval fatigue for a window of standing access. The
  risk-tier caps, absolute expiry, per-use audit with `trust_id` and the Active
  trusts view are the controls.

## Rollout

1. Vault approvals, `purpose`, macOS notifications, optional key-bound client
   registration and time-boxed trust (granted only to key-bound clients).
2. SSH agent.
3. PostgreSQL proxy and `db query`.
4. Standalone VPS mode A, with `approver_unavailable` and unlock options.
5. Pairing, signed remote approvals and remote unlock (mode B); then mobile.
6. Signed client identity becomes required for new registrations.
7. `keylease run` with output scrubbing; then browser login fill.

Each step updates `docs/security/threat-model.md` in the same change.
