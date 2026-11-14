# MCP Gateway

The MCP Gateway is a remote MCP endpoint that `keylease-server` publishes for
each organization (v2 plan, P5). Agents and assistants connect to it with a
gateway token and call HTTP APIs with the organization's Managed secrets,
which never leave the server. (A single node's own endpoint for ChatGPT and
claude.ai is the [remote MCP server](remote-mcp.md).)

## Set it up (console)

1. On a project's **Secrets** page, store the credential (e.g. `STRIPE_KEY` in
   `staging`) and add an **HTTP API**: a name (`stripe`), the base URL
   (`https://api.stripe.com`, https only) and the secret's name. The header
   defaults to `Authorization: Bearer {secret}`.
2. On the organization page (owners and admins), **MCP Gateway → Create
   client**: a name, the project environments it may use, and whether it may
   write (anything but GET, HEAD and OPTIONS). The token is shown once with
   the command to add it:

```sh
claude mcp add --transport http keylease https://vault.example.com/api/v1/orgs/ORG/mcp \
  --header "Authorization: Bearer klgw_…"
```

## What the agent gets

| Tool | |
|---|---|
| `list_apis` | the bindings it may call (project, environment, name, base URL); no credentials |
| `http_request` | `{project, environment, binding, method, path, headers?, json? or body?}`: the gateway adds the secret, sends the request (public addresses only, no redirects) and returns the status, content type and body with the secret replaced by `[REDACTED by keylease]` |

Each call is in the project's audit as `gateway:CLIENT`. Revoking a client
stops its token at once. Bodies are limited to 2 MiB each way and the text
returned to the model to 256 KiB.

Not yet: proxying other MCP servers (upstream MCP with OAuth) and per-call
approvals; until then, give clients only the environments and write access
they need.
