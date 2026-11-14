# ADR 0007: The HTTP credential broker

Status: accepted (phases 1 and 2: base-URL and intercepting modes)

## Context

HTTP APIs hold most of the credentials agents need (payment, cloud, issue
trackers, model providers). ADR 0005 brokers SSH and PostgreSQL so the secret
never reaches the agent (tier T1), but for HTTP it only offered `keylease run`
(T3: the value is in the child's environment) and reveal (T4). An agent with a
token in its environment can print it, send it anywhere, or leave it in a
transcript.

What a broker needs to know about an API is small. Almost every HTTP API takes
its credential in one header (`Authorization: Bearer …`, `x-api-key: …`, Basic
authentication). The broker does not need to understand the API, only where
the secret may go and how to attach it.

## Decision

1. **An item opts in with an HTTP binding** (item extension `keylease.http`):
   the upstream base URL, the header, and a template (`Bearer {secret}`;
   `{basic}` is base64(username:secret)), optionally the field and whether
   private addresses are allowed. Setting or changing a binding decides where
   the secret may be sent, so it is a protected change
   (`entry:update_protected_fields`, R3).
2. **The service forwards.** The daemon builds the upstream request, adds the
   header and sends it; the secret never leaves the service process, the same
   guarantee as SSH signing and SCRAM. The agent-side proxy only relays
   requests and responses over the local RPC (`http_forward`).
3. **Policy action `http:request`** on the item, arguments `{host, method}`:
   R1 for GET, HEAD and OPTIONS, R2 for other methods, R3 when the item is in a
   protected environment. Enrolled agents get it in their approval baseline;
   approvals, time-boxed trust and project trust apply as for any action. The
   path is audited but not part of the approval, so one trust covers an API.
4. **Requests stay inside the binding:** the path is joined below the base URL
   (`.`/`..` segments, absolute and scheme-relative paths are refused); the
   host must resolve to public addresses unless the binding allows private
   ones, and the connection goes to the address that was checked (no DNS
   rebinding); redirects are not followed; the agent's own copy of the
   credential header and hop-by-hop headers are dropped.
5. **Responses are scrubbed:** the secret and the header value, raw and
   base64, are replaced in the response body and headers. Upstream content
   encoding is disabled (`accept-encoding: identity`) so scrubbing sees the
   bytes.
6. **Phase 1 is the base-URL mode.** `keylease run --http NAME=ITEM -- CMD`
   and `keylease http proxy ITEM` serve a loopback base URL
   (`http://127.0.0.1:PORT/kl-<capability>`); tools that accept a base URL
   (most SDKs and CLIs) use it directly, with no certificate authority. The
   random capability in the path keeps other local processes out.
7. **MCP clients** (stdio and the remote MCP server) get the tool
   `http_request` (tier T0): the same forwarder, the body returned as text and
   capped.
8. **Agents need few instructions:** refusals are self-explanatory JSON with
   an `x-keylease-decision` header (`approval_required` with the approval id,
   `denied`, `not_found`), and the instructions block mentions `--http`.

## Consequences

- HTTP credentials get the same T1 guarantee as SSH and PostgreSQL: an agent
  can use an API key it cannot read.
- A binding names one origin. A secret that several APIs accept needs one item
  (or binding) per API, which is also the safer default.
- Bodies are buffered (2 MiB each way) because the local RPC is one JSON line;
  streaming responses (server-sent events) arrive at the end. A streaming
  transport between the proxy and the daemon is the next step.
- Requests signed with the secret (AWS SigV4, HMAC webhooks) are not covered:
  they need the secret to compute a signature over the request. Use short-lived
  credentials (dynamic credentials) or a connector for those.
- The agent controls the request, so an approved trust lets it make any call
  the credential allows on that API, as a person with the token could. Scope
  the token at the provider.

## Intercepting mode (phase 2)

`keylease run --proxy ITEM -- CMD` serves `HTTPS_PROXY` (with a random
password in the URL) for tools that cannot change their base URL. A
certificate authority is generated for the run (ECDSA P-256, valid for a week,
key only in memory); the child gets a bundle with the system roots plus that
CA through the usual variables (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, …).
`CONNECT` to a bound host and port is terminated with a host certificate from
that CA and each request inside goes through the same daemon forwarder; paths
outside the binding's base path are refused. `CONNECT` to any other host is
tunneled without decryption. Plain HTTP is not proxied (only `HTTPS_PROXY` is
set), and the files are removed when the child exits.

Programs that ignore the proxy variables, pin certificates or trust only the
platform keychain (Go on macOS) cannot use this mode; the base-URL mode covers
them.

## Later phases

1. Streaming between the proxy and the daemon; WebSocket.
2. Placeholder substitution in bodies, OAuth 2 refresh, provider presets.
3. The same forwarder in `keylease-server` for Managed projects (MCP Gateway).
