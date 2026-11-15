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
   client**: a name, the project environments it may use, whether it may
   write (anything but GET, HEAD and OPTIONS), and which calls need a
   person's approval (none, writes, or every call). The token is shown once
   with the command to add it:

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

## Base-URL proxy for tools and SDKs

The same bindings work without MCP: a gateway client's tools use

```text
https://vault.example.com/api/v1/orgs/ORG/gateway/http/PROJECT/ENVIRONMENT/BINDING
```

as the API's base URL and send the gateway token in the
`x-keylease-token` header (most SDKs take default headers). The gateway adds
the credential, forwards the request and returns the API's answer with the
secret scrubbed from the body and headers.

## Per-call approvals

A client set to need approval for writes (or for every call) does not send
such a call straight away:

1. The first call fails with `approval required (gwa_…)`. The base-URL proxy
   answers `403 {"error": "approval_required", "approval_id": "gwa_…"}`. The
   organization's owners and admins and the project's admins get a Web Push
   notification if they turned notifications on.
2. In the console, **Approvals → MCP Gateway calls** shows the client, the
   project environment, the method, binding and path, and the body size.
   Approve or deny it there.
3. The agent makes the same call again. An approval covers that exact call
   once (client, environment, binding, method, path and body digest) and
   lasts 15 minutes. A changed body needs a new approval. After a denial, the
   same call is refused until the request expires.

Decisions are in the project's audit (`gateway_call_approve`,
`gateway_call_deny`).

## Upstream MCP servers

A project can also list remote MCP servers (Streamable HTTP). Gateway
clients granted one of its environments then see the servers' tools next to
the gateway's own, named `SERVER__TOOL` (`PROJECT_ENVIRONMENT_SERVER__TOOL`
when the client sees two servers with the same name). The credential stays on
the server.

On the project's **Secrets** page, **MCP servers**: a name, the server's URL
and its credential:

| Credential | |
|---|---|
| OAuth | The gateway reads the server's protected resource metadata (RFC 9728) and its authorization server's metadata (RFC 8414), then registers itself as a client (RFC 7591), or uses a `client_id` you give. **Connect** signs in for the selected environment: the authorization code flow with PKCE (S256) and the server as `resource` (RFC 8707). The tokens are stored as the Managed secret `MCP_OAUTH_NAME` of that environment and refreshed when they expire or the server refuses them. |
| Bearer token | A Managed secret of each environment, sent as `Authorization: Bearer …`. |
| None | For servers that need no credential. |

Register `KEYLEASE_SERVER_PUBLIC_URL/v1/gateway/oauth/callback` as the
redirect URI when you give a `client_id`.

A tool call is audited as `gateway_mcp_call` and goes through the client's
per-call approvals. With `writes`, only tools that the server marks
`readOnlyHint` skip approval. An approval covers that tool with exactly those
arguments, once. The upstream tool list is cached for a minute. The answer
reaches the agent as the server sent it, with the credential scrubbed if the
server echoed it.

The gateway calls only public addresses. For MCP servers inside the server's
own network, set `KEYLEASE_GATEWAY_ALLOW_PRIVATE=1`; this also allows plain
`http://` URLs. Org admins can then point the gateway at private addresses.
