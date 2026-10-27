# Use cases

Practical setups for letting agents use credentials without the model seeing
them. Read [the architecture overview](architecture.md) first for the roles
(vault node, agent, approver).

Status legend: ✅ implemented and tested end to end on Linux · 🟡 code written,
not yet verified on its platform · ❌ not implemented.

| # | Setup | Status |
|---|---|---|
| 1 | [Agent CLI on your Mac, approve in the Mac app](#1-agent-cli-on-your-mac) | ✅ daemon/CLI · 🟡 trust picker UI |
| 2 | [Agents on a VPS, approve on the VPS itself](#2-agents-on-a-vps-self-trust) | ✅ |
| 3 | [Move VPS approvals to your Mac](#3-move-vps-approvals-to-your-mac) | ✅ protocol + CLI · 🟡 Mac UI |
| 4 | [Approve and trust: the day-to-day loop](#4-approving-and-trusting) | ✅ |
| 5 | [Claude Desktop, Cursor, Codex (local MCP)](#5-claude-desktop-cursor-and-other-mcp-clients) | ✅ |
| 6 | [ChatGPT / claude.ai through your own gateway](#6-chatgpt-or-claudeai-through-your-own-gateway) | ✅ tested with a simulated OAuth client |
| 7 | [Unattended automation (CI, cron)](#7-unattended-automation) | ✅ |

---

## 1. Agent CLI on your Mac

For Claude Code, Codex CLI, Gemini CLI or any agent that runs shell commands.

1. Install and unlock the KeyLease macOS app. Its background daemon is the
   vault node; the CLI uses it automatically.
2. Give the agent its own identity, never `~/.keylease/desktop.token`:

   ```sh
   keylease agent enroll claude
   ```

   (or **Agents → Connect an agent** in the native app). The token goes to
   `~/.keylease/clients/agent_claude.token`, mode 0600; the command prints only
   the environment.
3. Put the environment in the agent's configuration, for example Claude Code's
   `~/.claude/settings.json`:

   ```json
   {
     "env": {
       "KEYLEASE_AGENT_ID": "agent_claude",
       "KEYLEASE_CLIENT_TOKEN_FILE": "/Users/you/.keylease/clients/agent_claude.token",
       "KEYLEASE_WAIT_APPROVAL": "120"
     }
   }
   ```

4. Copy an item's **Prompt** from the app into the chat. It names the item ID
   and the broker to use:

   | Item | The agent runs | The model sees |
   |---|---|---|
   | SSH key | `keylease ssh deploy@host 'systemctl status app'`, `GIT_SSH_COMMAND="keylease ssh" git push` | Command output |
   | PostgreSQL | `keylease db psql ITEM -- -c 'select count(*) from orders'` | Query results |
   | API key for a CLI | `keylease run --env STRIPE_KEY=ITEM/password -- stripe customers list` | Output, with the key scrubbed |
   | Anything else | `keylease entries reveal ITEM --field password` (last resort) | The plaintext |

5. When a command needs approval it waits; you get a notification and approve
   in the app (see [4](#4-approving-and-trusting)).

Status and gaps:

- ✅ Enrollment, approvals, trusts, SSH, PostgreSQL and `run` work through the
  daemon and CLI.
- The installed app is the **Flutter** desktop app
  (`scripts/build-install-macos.sh`). It approves or denies **once**; it has no
  trust picker, Agents section, Remote Vaults or notifications. Use
  `keylease approval decide ID --approve --trust 1h` for trusts there.
- 🟡 The trust picker, Agents, Remote Vaults, notifications and Touch ID are in
  the **native Swift app** (`apps/desktop-macos-app`), which is still a port in
  progress and not yet built on a Mac.
- Same-user limit: an agent running as you can read files you can read. The
  separate identity is a policy boundary, not an OS sandbox; run agents in a
  sandbox that hides `~/.keylease/desktop.token` where you can.

## 2. Agents on a VPS (self-trust)

Agents (a Claude Code session over SSH, a deploy bot) run on the server; the
vault lives there too. Mode A of ADR 0005.

1. Build and install the CLI: `cargo build --release -p keylease`, copy
   `target/release/keylease` to `/usr/local/bin/`.
2. Create the vault and fill it. Typing secrets on the server is optional:
   export from your Mac vault (`keylease vault export-kdbx`) and import, after
   reading the migration report:

   ```sh
   keylease --db /var/lib/keylease/vault.sqlite vault init
   keylease --db /var/lib/keylease/vault.sqlite vault import-kdbx vps.kdbx          # preview
   keylease --db /var/lib/keylease/vault.sqlite vault import-kdbx vps.kdbx --commit
   ```

3. Run the daemon under systemd and unlock it with a host-sealed credential
   ([unit and options](agent-approvals.md#unlocking-after-a-reboot)).
4. Register the agent with the approval baseline and store its token:

   ```sh
   keylease --db /var/lib/keylease/vault.sqlite client register deployer --baseline
   # save "client_token" to /home/deployer/.keylease/deployer.token, chmod 600
   export KEYLEASE_AGENT_ID=agent_deployer
   export KEYLEASE_CLIENT_TOKEN_FILE=/home/deployer/.keylease/deployer.token
   export KEYLEASE_SOCKET=/run/keylease/keylease.sock
   ```

5. The agent uses the same brokers as on a Mac. Requests that need approval
   are decided over SSH with the master password:

   ```sh
   keylease --db /var/lib/keylease/vault.sqlite approval approve APPROVAL_ID
   keylease --db /var/lib/keylease/vault.sqlite approval approve APPROVAL_ID --trust 1h
   keylease --db /var/lib/keylease/vault.sqlite approval deny APPROVAL_ID
   ```

   The running daemon sees admin decisions, grants and revocations at once; it
   never needs a restart for them.

Status and gaps:

- ✅ All of the above, including systemd-credential unlock.
- To approve from your laptop instead of SSH, see [3](#3-move-vps-approvals-to-your-mac).

## 3. Move VPS approvals to your Mac

Same VPS as in [2](#2-agents-on-a-vps-self-trust), but you decide from your
laptop instead of SSHing in. Mode B of ADR 0005.

1. On the VPS, add `--approver-listen 127.0.0.1:7443` to the daemon's
   `ExecStart` (after `serve`), restart it, and publish the port over TLS:

   ```caddyfile
   vault.example.com {
       reverse_proxy 127.0.0.1:7443
   }
   ```

   The API has no vault read or write endpoint: it pairs devices, lists and
   decides approvals, and lists and revokes trusts.
2. Create a one-time pairing code (valid 10 minutes):

   ```sh
   keylease --db /var/lib/keylease/vault.sqlite remote pairing-code
   ```

3. Pair the Mac:
   - Native app: **Remote Vaults → Pair a remote vault**, enter a name, the
     URL and the code. The Ed25519 key stays in the login Keychain.
   - Or the CLI: `keylease remote add vps --url https://vault.example.com --code CODE`.
4. From now on the VPS agents' requests appear on the Mac. Approve once or with
   a trust; every remote approval asks for Touch ID in the app.
5. If the laptop is lost: `keylease remote revoke-device DEVICE_ID` on the VPS,
   then revoke the trusts it granted (`keylease remote trusts`, `revoke-trust`).

Status and gaps:

- ✅ Pairing, signed requests, digest-bound decisions, trust and device
  revocation, tested between two machines with the CLI.
- 🟡 The Mac UI is in the native Swift app only and not yet built on a Mac.
- The Mac polls nodes only while its **own** vault is unlocked; the app needs a
  local vault set up even if you only approve for a VPS.
- ❌ No push notifications (polling every 15 s), no mobile approver, no remote
  unlock — after a reboot the VPS unlocks from its systemd credential or over
  SSH.

## 4. Approving and trusting

What happens when an agent asks:

1. The agent runs a command with a reason:
   `keylease --purpose "deploy release 42" ssh deploy@prod 'sudo systemctl restart app'`.
2. Policy sees `ssh:sign` on the item; the baseline says "require approval".
   The CLI waits (`--wait-approval`, default 120 s for `ssh` and `db`).
3. You see the agent, action, target, purpose and risk tier, and choose:

   | Choice | Effect |
   |---|---|
   | Approve once | This exact request runs once |
   | Trust 30m … 7d | The same agent may repeat this action on this resource for the window |
   | Scope: every field of this item | The trust covers the item, not just the one field |
   | Deny | The agent's waiting command fails immediately |

4. Windows are capped by risk: R0–R1 up to 7 days, R2 (SSH, DB, ordinary
   writes) up to 1 day, R3 (production items, deletes, protected fields) up to
   1 hour, R4 (reveal, `run`) once only. Mark production items with environment
   `production` to get R3.
5. Review and revoke: **Agents** in the app, or `keylease trust list` /
   `keylease trust revoke ID`. The kill switch revokes all trusts at once.
   Every use is in the audit log with its `trust_id`.

Good habits: trust per task window (1h) rather than per week; keep R4 reveals
rare by using brokers; give database items a read-only role where possible —
an approved connection can run any SQL that role allows.

## 5. Claude Desktop, Cursor and other MCP clients

These apps reach tools through MCP, not a shell. The client starts
`keylease mcp` itself; you configure it once:

```sh
keylease mcp setup claude-desktop --write    # or: cursor --write, claude-code, codex, json
```

This enrolls an agent for the client, writes its config, and leaves the rest
of the file alone. Restart the client and ask it, for example, "check disk
space on the staging server": it finds the SSH key with `vault_search`, runs
`ssh_exec`, and the call waits while you approve it in KeyLease.

Tools: `vault_search`, `vault_item`, `ssh_exec`, `db_query` (read-only by
default) and, with `--allow-run`, `run_with_secrets`. None returns a secret.
Details: [MCP clients](mcp.md).

Status: ✅ tested end to end over stdio against a real `sshd` and PostgreSQL
(approval wait, trust, read-only refusal, output scrubbing, retry after a
timed-out wait). ChatGPT Desktop does not start local MCP servers; use the
gateway in [6](#6-chatgpt-or-claudeai-through-your-own-gateway).

## 6. ChatGPT or claude.ai through your own gateway

Web assistants call **remote** MCP servers over HTTPS with OAuth sign-in. Run
the gateway on your VPS:

```sh
keylease … serve --gateway-url https://vault.example.com     # behind Caddy, see the guide
keylease … gateway connect-code chatgpt                       # one-time, 10 minutes
```

Add `https://vault.example.com/mcp` as a custom connector in ChatGPT or
claude.ai, enter the connect code on the KeyLease consent page, and the
assistant becomes an agent with the approval baseline. Approve its requests
on the VPS, or from your Mac as a paired approver — the approver API is
served on the same URL. Revoke with `keylease gateway revoke`.

Full guide: [self-hosted MCP gateway](mcp-gateway.md).

Status: ✅ OAuth 2.1 (discovery, dynamic registration, PKCE, refresh rotation
with reuse detection), consent page and MCP over Streamable HTTP are tested
with a client that follows the same steps as ChatGPT/claude.ai, against a real
`sshd`. Not yet tried against the live ChatGPT and claude.ai services.

The older `leasegate-edge` MCP endpoint (connector actions with a static
bearer token, [single-VPS LeaseGate install](self-hosted-vps.md)) remains for
the Cloud/Edge product.

## 7. Unattended automation

For CI or cron jobs with no human to approve, use an explicit allow grant
instead of approvals, narrowed to the exact resource and with a short lease:

```sh
keylease --db /var/lib/keylease/vault.sqlite client register ci
keylease --db /var/lib/keylease/vault.sqlite grant create \
  --client agent_ci \
  --resource kl://VAULT_ID/ITEM_ID \
  --allow ssh:sign \
  --ttl-seconds 2592000 --max-lease-ttl-seconds 300
```

`VAULT_ID` is the `vault_id` in `keylease status`. The running daemon picks
the grant up immediately. Prefer `keylease ssh` / `keylease db` over `reveal`
so the job's logs never contain the secret.

## Summary of gaps

| Gap | Affects |
|---|---|
| Native Swift app not yet at parity; the Flutter app lacks trust/Agents/Remote Vaults/notifications | 1, 3 |
| Mac Swift UI not compiled or tested on a Mac | 1, 3 |
| No push, mobile approver or remote unlock | 3, 6 |
| Gateway not yet tried against the live ChatGPT / claude.ai services | 6 |
| MCP database tool is PostgreSQL only; HTTP header proxy, browser login fill | all |
| Key-bound client identity (ADR 0005 step 6) | all |
