# Calling HTTP APIs without seeing the key

Tier T1 of [ADR 0005](adr/0005-agent-trust-and-secret-use.md); design in
[ADR 0007](adr/0007-http-credential-broker.md). The agent's program calls a
local URL; KeyLease adds the credential, sends the request to the real API and
returns the response with the secret scrubbed. The key stays in the daemon.

## 1. Bind the item to its API (once)

```sh
keylease http bind ITEM --base-url https://api.stripe.com
keylease http bind ITEM --base-url https://api.anthropic.com --header x-api-key --template '{secret}'
keylease http bind ITEM --base-url https://jira.example.com --template 'Basic {basic}'   # username:secret
keylease http show ITEM
```

`ITEM` is an item ID or a name (`kl://shop/production/Stripe`). The secret is
the item's `credential` field (else `password`; `--field` picks another).
Binding decides where the secret may go, so it is a protected change: an agent
needs the owner's approval. `--allow-private` lets the binding reach private
and loopback addresses (a service on your network); without it they are
refused.

## 2. Use it

```sh
keylease run --http STRIPE_API_BASE=kl://shop/production/Stripe -- \
  sh -c 'curl -s "$STRIPE_API_BASE/v1/charges?limit=3"'
```

`--http NAME=ITEM` sets `NAME` to a loopback base URL for the program's
lifetime. Point the tool's base URL at it (most SDKs and CLIs have one:
`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, `--api-base`, …). For a tool that is
configured once, run a standing proxy:

```sh
keylease http proxy kl://shop/dev/Anthropic       # prints http://127.0.0.1:PORT/kl-…
```

Each request is the policy action `http:request` on the item: GET, HEAD and
OPTIONS are R1, other methods R2, and R3 for an item in a protected
environment. An enrolled agent asks once; approve it with a trust (for
example an hour, or the whole project) so a session does not ask per request.

MCP clients get the same broker as the `http_request` tool:
`{"item": "kl://shop/production/Stripe", "method": "GET", "path": "/v1/charges?limit=3"}`.

## What the agent sees

- A refusal is JSON with an `x-keylease-decision` header:
  `approval_required` (with `approval_id`: ask the user to approve, then
  retry), `denied`, `not_found`, `invalid_request`.
- Responses are the API's, except that the secret and the header value are
  replaced by `[REDACTED by keylease]` wherever they appear.

## Limits (phase 1)

- Requests only go below the binding's base URL; redirects are not followed.
- Bodies are limited to 2 MiB each way and responses are buffered, so
  streamed responses arrive when complete.
- Requests signed with the secret (AWS SigV4, webhook HMAC) need the secret
  itself; use dynamic credentials or a connector.
- An approved trust lets the agent make any call the token allows on that API.
  Scope the token at the provider.
