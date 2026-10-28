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

In the macOS app (`apps/desktop-macos-app`), a new request raises a
notification (agent and action only, never the item) and a Dock badge. **Approvals → Approve…** opens a sheet with
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
protected-field/TOTP updates, deletes and `entry:inject_secret` (`keylease run`) are R3.

| Scope | Covers |
|---|---|
| `resource` (default) | the approved action on that resource |
| `item` | the approved action on every field of the item |
| `project` | the approved action **and every action up to R2** on every item of the item's vault project, for at most 1d (1h if the action is R3) |

A project trust is the "let it work on this project for an hour" answer; it
never covers a reveal, a delete or another project.

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

### One identity per project

On a server where agents work on several projects, give each working tree one
identity:

```sh
cd /srv/shop
keylease projects init
```

It creates the vault project `shop` (from the directory name, or `--project`),
registers `agent_shop` with the baseline, and writes `.keylease.json`
(`{"agent": "agent_shop", "project": "shop"}`, no token). Every agent CLI started
anywhere inside `/srv/shop` (Claude Code, Codex…) then uses that identity with no
environment variables, one trust answers for all of them, and entries they create
are filed in the project, so a project trust covers them. The audit log names the
project's identity, not the tool.

Store the project's secrets yourself, so they never pass through an agent:

```sh
cd /srv/shop
keylease add "Stripe key" --username ops     # master password, then the secret, typed hidden
# {"reference": "kl://VAULT/ITEM/password", "use": "keylease run --env API_KEY=kl://… -- COMMAND"}
```

It files the item in the directory's project (group `shop`, created if missing);
`--kind`, `--url`, `--project` and `--group` override the defaults.

To tell tools apart in approvals and the audit, give one its own identity:
`keylease projects init --agent claude` registers `agent_claude-shop` instead. A
tree holds one `.keylease.json`, so its other tools then use
`KEYLEASE_AGENT_ID` to pick their identity.
Owner commands (`approve`, `approval`, `trust`, `client`…) ignore the file.

The identities share one Unix user, so an agent could read another's token file:
this separates projects for an agent that follows its instructions, not against
one that does not. A file can never select the owner (`agent_desktop`).

### Registering by hand

Register agents; they get the baseline by default (`--no-baseline` and narrow
`grant create --effect allow` rules for unattended automation). The token goes to
`~/.keylease/clients/agent_NAME.token`, which the CLI finds from `KEYLEASE_AGENT_ID` alone:

```sh
keylease client register deployer
export KEYLEASE_AGENT_ID=agent_deployer
```

Approvals queued by a baseline agent are decided with the admin path, which
asks for the master password. The easy way is to keep this running in a terminal
while the agent works:

```sh
keylease approve
```
```
claude-shop wants entry:create on "Shop DB" in shop  [R2]
  purpose (from the agent): add the staging database
  [Enter] trust everyday work in project shop for 1h  [o] once  [d] deny  [s] skip  [q] quit:
  ✓ trusted until 15:42
Waiting for agent requests… (Ctrl-C to stop)
```

It asks for the password once, shows each request as it arrives and suggests the
widest one-hour trust the request allows (its project, else its item); a reveal is
only ever approved once. For scripts, or another duration:

```sh
keylease approval list
keylease approval approve APPROVAL_ID [--trust 30m|1h|… --scope resource|item|project]
keylease trust list
keylease trust revoke TRUST_ID
```

Without `~/.keylease/desktop.token`, all four use the master password, even with
`KEYLEASE_AGENT_ID` still exported in the shell (agents may not run them).

`approval approve` also takes `--trust 30m|1h|… --scope resource|item|project`, and
`approval deny ID` refuses a request. The running daemon notices admin
changes made from another process (decisions, grants, revocations) on its
next request, so it never needs a restart for them.

### Unlocking after a reboot

| Method | Command | Protects against |
|---|---|---|
| Interactive | `keylease serve` (TTY prompt), or `serve --start-locked` + `keylease unlock` over SSH | disk theft and a compromised host at rest |
| systemd credential | `LoadCredentialEncrypted=keylease-master-password:…` | disk theft only; root on the running host wins |
| Password file | `serve --password-file /path` (mode 0600, not a symlink) | little; prefer the systemd credential |

On Linux with systemd, one command sets this up, as the user that owns the vault and runs
the agents (not root):

```sh
keylease service install                 # --idle-lock 1d by default; --dry-run shows the unit
keylease service status
keylease service uninstall               # removes the unit and the credential, keeps the vault
```

It checks the master password against the vault, seals it to the host (and TPM where
present) with `sudo systemd-creds encrypt` into
`/etc/credstore.encrypted/keylease-master-password`, writes
`/etc/systemd/system/keylease.service` with `User=` set to you, and starts it. Only those steps
use `sudo`; the password reaches `systemd-creds` on stdin. The unit it writes:

```ini
[Service]
# The daemon accepts only its own Unix user: the user the agents run as.
User=deployer
LoadCredentialEncrypted=keylease-master-password:/etc/credstore.encrypted/keylease-master-password
ExecStart=/home/deployer/.cargo/bin/keylease --db /home/deployer/.keylease/keylease.sqlite \
  --socket /home/deployer/.keylease/run/keylease.sock serve --session-ttl-seconds 86400
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=full
```

`keylease serve` picks the credential up from `$CREDENTIALS_DIRECTORY` without any flag. A
systemd *user* service (`systemctl --user`) cannot decrypt a host-sealed credential, so the
service is a system unit. Use `--name work` for a second vault (`work.service`).

The vault locks after `--session-ttl-seconds` of inactivity (8 hours for `serve`, the
`--idle-lock` of `service install`, 1 day by default). An idle auto-unlocked daemon does not
unlock itself again; `sudo systemctl restart keylease` unlocks it, or install with a longer
`--idle-lock`.

An auto-unlocked host trusts itself: anything that becomes root while it runs
can use the vault. Keep such a vault separate from your personal one and give
it only the credentials that host needs. Remote approval and remote unlock
from the macOS app (mode B) are step 5 of the ADR and not implemented yet.
