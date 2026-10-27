# Self-hosted MCP gateway for ChatGPT and claude.ai

Web assistants call **remote** MCP servers over HTTPS and sign in with OAuth.
`keylease serve --gateway-url` turns a vault node (usually a VPS) into one:
the same tools as [`keylease mcp`](mcp.md), an OAuth 2.1 authorization server,
and the [paired-approver API](remote-approval.md), all on one URL.

```text
ChatGPT / claude.ai ──HTTPS──► Caddy ──► 127.0.0.1:8787  keylease serve --gateway-url …
   (OAuth sign-in,                        /mcp  /authorize /token /register
    MCP tool calls)                       /.well-known/…  /v1/… (approvers)
                                                  │
                                       ssh / psql from the VPS ──► your servers
```

## 1. Run it

On the VPS, with the vault set up as in [use case 2](use-cases.md#2-agents-on-a-vps-self-trust),
add the gateway to the daemon's unit:

```ini
[Service]
User=keylease
LoadCredentialEncrypted=keylease-master-password
ExecStart=/usr/local/bin/keylease --db /var/lib/keylease/vault.sqlite \
  --socket /run/keylease/keylease.sock serve \
  --gateway-url https://vault.example.com
RuntimeDirectory=keylease
RuntimeDirectoryMode=0700
```

and publish it with TLS:

```caddyfile
vault.example.com {
    reverse_proxy 127.0.0.1:8787
}
```

| Flag | Default | |
|---|---|---|
| `--gateway-url URL` | — | the public HTTPS URL; also the OAuth issuer |
| `--gateway-listen ADDR` | `127.0.0.1:8787` | must be loopback; TLS is the proxy's job |
| `--gateway-allow-run` | off | offer `run_with_secrets` (runs programs on the VPS) |
| `--gateway-db-tls-ca FILE` | — | CA for database servers with a private certificate |
| `--wait-approval SECONDS` | 50 | how long a tool call waits for an approval |

## 2. Connect an assistant

1. On the VPS, create a one-time connect code (valid 10 minutes; asks for the
   master password):

   ```sh
   keylease --db /var/lib/keylease/vault.sqlite gateway connect-code chatgpt
   ```

2. In the assistant, add a custom MCP connector with the URL
   `https://vault.example.com/mcp` and OAuth authentication. The menus change
   often; at the time of writing:
   - **ChatGPT**: Settings → Apps & Connectors → Advanced → enable developer
     mode, then create a connector with the URL.
   - **claude.ai**: Settings → Connectors → Add custom connector.
3. The assistant registers itself and opens the KeyLease consent page. Check
   the name and return address it shows, enter the connect code, and choose
   **Connect**.

The connection is a new agent (`agent_gw_chatgpt_…`) with the approval
baseline. It can search item metadata and use SSH keys and databases; every
use that needs approval waits for you.

## 3. Approve its requests

Requests from a web assistant are ordinary approvals for that agent:

- On the VPS: `keylease … approval approve ID [--trust 1h]` or `approval deny ID`.
- From your Mac or laptop: pair it once as a [remote approver](remote-approval.md)
  (the approver API is already on the gateway URL), then approve in the app's
  Remote Vaults section or with `keylease remote decide`.

A tool call waits up to `--wait-approval` seconds, then tells the assistant to
ask you and call again. Admin decisions made from another process reach the
running daemon immediately; no restart is needed.

## 4. Manage connections

```sh
keylease --db /var/lib/keylease/vault.sqlite gateway connections
keylease --db /var/lib/keylease/vault.sqlite gateway revoke agent_gw_chatgpt_…
```

Revoking ends the connection's tokens, its agent client, its baseline and its
trusts at once. Connecting again needs a new code and creates a new agent.

## How sign-in is protected

- Discovery: `/.well-known/oauth-protected-resource` (RFC 9728) and
  `/.well-known/oauth-authorization-server` (RFC 8414); `/mcp` answers 401 with
  a `resource_metadata` challenge.
- Dynamic client registration (RFC 7591) accepts public clients only, with
  `https` redirect URIs (`http` only for localhost); at most 500 unused
  registrations are kept.
- Authorization code with PKCE S256 is required. A code lives 5 minutes and is
  single-use; a wrong verifier burns it. Errors about the client or redirect
  address are shown on the page, never redirected.
- The consent page is self-contained (no scripts, `frame-ancestors 'none'`),
  escapes everything the client supplied, and requires the connect code, an
  80-bit single-use secret that only someone with the master password can make.
- Access tokens live 1 hour; refresh tokens 30 days and rotate on use.
  Presenting a used refresh token revokes the whole token family.
- Only SHA-256 hashes of codes and tokens are stored. Every connection,
  revocation and tool use is audited under the connection's agent id.
- The MCP endpoint checks the `Host` header against the gateway URL.

## Limits

- Everything a tool returns — item titles and usernames, command output,
  query rows — goes to the assistant's provider.
- `ssh_exec` and `db_query` run from the VPS, with the VPS's network access and
  `~/.ssh/known_hosts`; `psql` must be installed there.
- The vault must be unlocked for tools to work; the gateway does not unlock it.
- MCP sessions live in memory: after a restart, clients reconnect on their own
  (their OAuth tokens stay valid).
- One VPS process serves one vault.
