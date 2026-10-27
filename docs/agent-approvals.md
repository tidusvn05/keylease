# Agent approvals and time-boxed trust

This is the user guide for step 1 of
[ADR 0005](adr/0005-agent-trust-and-secret-use.md). It covers the personal
deployment (agent CLI + `keylease` CLI + the macOS app's daemon) and the
headless VPS deployment.

For complete setups (Mac, VPS, paired approver, automation) see
[use cases](use-cases.md).

## Why enroll an agent

Without enrollment, `keylease` defaults to the desktop owner's client
(`agent_desktop` and `~/.keylease/desktop.token`). An agent CLI using that
token has the owner's full authority, including approving its own requests.

An **enrolled agent** gets its own client and a baseline:

| Without asking | Queues an approval |
|---|---|
| `entry:search`, `entry:read_metadata`, `entry:read_fields` (redacted view), `ssh:list_keys` (public keys only) | `entry:read_username`, `entry:read_secret` (reveal, TOTP), `entry:inject_secret` ([`keylease run`](run-with-secrets.md)), entry create/update/move/delete, group create/update, `ssh:sign` ([SSH](ssh-agent.md)), `db:connect` ([PostgreSQL](db-proxy.md)) |

Search and metadata include each entry's username, so the separate
`entry:read_username` approval only gates the dedicated reveal command.
Turning on the kill switch stops every agent request, including baseline
reads and pre-written grants.

Known limits: an approval is consumed when its gate passes, so a create or
update that needs several gates (for example a password and a TOTP) asks for
one approval per gate, and `--dry-run` also uses them. `max_uses` on a
hand-written grant is not counted for vault commands.

Shared Prompt/Runbook/Note content keeps its own grant-free channel
(`docs/agent-content.md`).

## Personal setup

Run once, as yourself, with the vault unlocked in the app — or use
**Agents → Connect an agent** in the macOS app, which does the same and shows
the environment to copy:

```sh
keylease agent enroll codex
```

It writes the agent's token to `~/.keylease/clients/agent_codex.token`
(mode 0600) and prints the environment for the agent. The token is never
printed. Configure the agent CLI with:

```sh
export KEYLEASE_AGENT_ID=agent_codex
export KEYLEASE_CLIENT_TOKEN_FILE=~/.keylease/clients/agent_codex.token
export KEYLEASE_WAIT_APPROVAL=120   # optional: wait instead of exiting
```

Do not give the agent `~/.keylease/desktop.token`. Same-UID processes can read
it, so this is a convention the agent's sandbox or instructions must uphold;
see the threat model.

## What the agent sees

```sh
keylease --purpose "deploy staging" entries reveal ITEM_ID --field password
# {"error":"approval_required","approval_id":"approval_…"}   exit code 6
```

Retrying the identical command returns the same approval until it is decided.
With `--wait-approval 120` (or `KEYLEASE_WAIT_APPROVAL`) the CLI prints a note on
stderr and waits; the command completes as soon as you approve.

`--purpose` is shown to you and bound into the approval: the same request with a
different purpose needs a new approval. It is never written to the audit log.

## Deciding

In the native macOS app (`apps/desktop-macos-app`; the installed Flutter app
only approves or denies once), a new request raises a notification (agent and action only,
never the item) and a Dock badge. **Approvals → Approve…** opens a sheet with
the agent's stated purpose and an **Allow** menu offering only the durations
the request's risk tier admits, plus the scope when you pick a window.
Approving a trust, or any R3/R4 request, asks for Touch ID or the login
password. Active trusts are listed under **Agents**, with **Revoke**.

The app learns about new requests by polling `status`, which now includes a
`pending_approvals` count. That read is passive: it neither extends the idle
timeout nor writes audit. The list itself is reloaded only when the count
grows.

From a terminal (owner client):

```sh
keylease approval list
keylease approval decide APPROVAL_ID --approve
keylease approval decide APPROVAL_ID --deny
keylease approval decide APPROVAL_ID --approve --trust 1h --scope item
```

A plain approval authorizes **one** use. `--trust` turns it into a window:

| Duration | Allowed for |
|---|---|
| `30m`, `1h` | R0–R3 |
| `6h`, `1d` | R0–R2 |
| `3d`, `7d` | R0–R1 |
| none (once) | everything, including R4 |

`entry:read_secret` is R4, so a secret reveal is always approved per use.
`entry:read_username` is R1, `ssh:sign` and ordinary entry writes are R2,
protected-field/TOTP updates and deletes are R3.

`--scope resource` (default) covers the approved action on that resource;
`--scope item` covers the action on every field of the item.

```sh
keylease trust list
keylease trust revoke TRUST_ID
```

A trust survives a vault lock (it authorizes nothing while locked) and ends at
its expiry, on `trust revoke`, when the client is revoked, or when the kill
switch is turned on. Every use under a trust is audited with its `trust_id`.

## Headless VPS (self-trust)

Step 4 of the ADR. On a host with no desktop app, `keylease serve` is the vault
node and agents on the same host use it over the Unix socket, exactly as on a
Mac.

Register agents with the baseline, or with narrow `grant create --effect allow`
rules for unattended automation:

```sh
keylease --db /var/lib/keylease/vault.sqlite client register deployer --baseline
```

Approvals queued by a baseline agent are decided with the admin path, which
asks for the master password:

```sh
keylease --db /var/lib/keylease/vault.sqlite approval approve APPROVAL_ID
```

`approval approve` also takes `--trust 30m|1h|… --scope resource|item`, and
`approval deny ID` refuses a request. The running daemon notices admin
changes made from another process (decisions, grants, revocations) on its
next request, so it never needs a restart for them.

### Unlocking after a reboot

| Method | Command | Protects against |
|---|---|---|
| Interactive | `keylease serve` (TTY prompt), or `serve --start-locked` + `keylease unlock` over SSH | disk theft and a compromised host at rest |
| systemd credential | `LoadCredentialEncrypted=keylease-master-password:…` | disk theft only; root on the running host wins |
| Password file | `serve --password-file /path` (mode 0600, not a symlink) | little; prefer the systemd credential |

With systemd, seal the password to the host (and TPM where present) once:

```sh
systemd-ask-password -n "Master password:" \
  | sudo systemd-creds encrypt --name=keylease-master-password - \
      /etc/credstore.encrypted/keylease-master-password
```

and reference it from the unit; `keylease serve` picks it up from
`$CREDENTIALS_DIRECTORY` without any flag:

```ini
[Service]
User=keylease
LoadCredentialEncrypted=keylease-master-password
ExecStart=/usr/local/bin/keylease --db /var/lib/keylease/vault.sqlite \
  --socket /run/keylease/keylease.sock serve
RuntimeDirectory=keylease
RuntimeDirectoryMode=0700
```

The vault locks after `--session-ttl-seconds` of inactivity (8 hours by
default). An idle auto-unlocked daemon does not unlock itself again; restart
the unit (`Restart=on-failure` plus a timer, or a longer TTL) if it must stay
available.

An auto-unlocked host trusts itself: anything that becomes root while it runs
can use the vault. Keep such a vault separate from your personal one and give
it only the credentials that host needs. Remote approval and remote unlock
from the macOS app (mode B) are step 5 of the ADR and not implemented yet.
