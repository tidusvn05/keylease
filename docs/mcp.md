# KeyLease for MCP clients (Claude Desktop, Cursor, Codex)

Assistants that cannot run shell commands reach tools through MCP. `keylease
mcp` is an MCP server over stdio: the client **starts it itself** from its
configuration, as an agent with its own identity, and stops it when it quits.
You never start it by hand. For web assistants (ChatGPT, claude.ai) see the
[self-hosted gateway](mcp-gateway.md).

## Set up a client

With the vault unlocked (the macOS app, or `keylease serve`):

```sh
keylease mcp setup claude-desktop --write    # writes claude_desktop_config.json
keylease mcp setup cursor --write            # writes ~/.cursor/mcp.json
keylease mcp setup claude-code               # prints a `claude mcp add …` command
keylease mcp setup codex                     # prints a ~/.codex/config.toml block
keylease mcp setup json                      # prints a generic mcpServers block
```

The first run enrolls an agent named after the client (`agent_claude`,
`agent_cursor`, … — change it with `--agent NAME`) with the approval baseline,
and writes its token to `~/.keylease/clients/agent_NAME.token` (mode 0600).
`--write` keeps every other server in the file and leaves a `.bak` copy. Then
restart the client.

Options, passed through to `keylease mcp`:

| Option | Effect |
|---|---|
| `--allow-run` | also offer `run_with_secrets` |
| `--db-tls-ca FILE` | trust this CA for database servers with a private certificate |

`keylease mcp` refuses to run with the desktop owner's token, which has no
approvals.

## Tools

| Tool | Does | The model receives | Approval |
|---|---|---|---|
| `vault_search` | find items by title, username, URL, tag | ids, titles, kinds, usernames, URLs | no |
| `vault_item` | one item's fields without secret values | field names, hosts, ports | no |
| `ssh_exec` | run a command over SSH with a vault key | exit status, stdout, stderr | `ssh:sign` (R2; R3 for production items) |
| `db_query` | run SQL on a PostgreSQL item, read-only by default | CSV output | `db:connect` (R2; R3 for production) |
| `run_with_secrets` | run a local program with vault values in its environment (opt-in) | output with the values scrubbed | every run (R4) |

There is deliberately **no tool that returns a secret**. `ssh_exec` signs
inside the vault and never falls back to key files on disk; `db_query` answers
the SCRAM challenge inside the vault and sets `default_transaction_read_only`
unless `allow_writes` is true; `run_with_secrets` shows the approver the whole
command line.

Each tool takes an optional `purpose`, shown to you when you approve.

## Approvals

A call that needs approval waits up to 50 seconds (`--wait-approval` to
change it) while you approve it — in the macOS app, with
`keylease approval decide ID --approve [--trust 1h]`, or on a paired
approver. If time runs out the tool tells the model which approval is waiting
and to call again with the same arguments; the retry finds the same approval,
so approving it late still works. Trusts work as everywhere else
([agent approvals](agent-approvals.md)): approve an `ssh_exec` with a 1-hour
trust and the next calls run without asking.

## Limits

- Results — command output, query rows, item metadata — go to the model and
  its provider. Use a read-only database role where that is enough.
- `ssh_exec` accepts a new host key on first use (`StrictHostKeyChecking=accept-new`)
  and refuses a changed one.
- `db_query` needs `psql` installed; output is capped at 64 KiB per stream and
  commands time out after 120 s (`timeout_seconds`, at most 600).
- ChatGPT Desktop does not start local MCP servers; use the
  [gateway](mcp-gateway.md).
