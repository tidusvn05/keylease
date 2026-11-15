# Enterprise features

For organizations on a self-hosted `keylease-server` (v2 plan, P6). They all
need `KEYLEASE_KMS_ROOT_KEY_FILE` ([ADR 0010](adr/0010-managed-projects-and-kms.md))
and the [console](console.md) for setup.

## KMS API

Per-project keys that never leave the server, versioned for rotation:

| Purpose | Operations | Algorithm |
|---|---|---|
| `encrypt` | `encrypt`, `decrypt` (optional `context`, bound as associated data) | XChaCha20-Poly1305 |
| `sign` | `sign`, `verify` | Ed25519 |
| `mac` | `mac`, `verify` | HMAC-SHA256 |

```sh
POST /v1/orgs/ORG/projects/shop/kms/keys              {"name": "data", "purpose": "encrypt"}   # project admin
POST /v1/orgs/ORG/projects/shop/kms/keys/data/encrypt {"plaintext": "<base64>", "context": "order-1"}
# {"ciphertext": "kl:v1:…"}
POST /v1/orgs/ORG/projects/shop/kms/keys/data/rotate                                            # project admin
POST /v1/machine/kms/data/decrypt                      {"ciphertext": "kl:v1:…", "context": "order-1"}   # machine token
```

Outputs carry their key version (`kl:vN:…`), so after a rotation old
ciphertexts, signatures and MACs still verify; new ones use the latest
version. Members need the project's `write` role; machine identities of the
project may use its keys. Every operation is audited. Data is limited to
64 KiB per call.

## Audit export (SIEM)

`GET /v1/orgs/ORG/audit/export` (owners and admins) returns the
organization's audit (Managed secrets, change requests, gateway calls,
machine identities, dynamic logins, KMS) as JSON Lines, or RFC 5424 syslog with
`format=syslog`. Page with `after=<id>`: the `x-keylease-next` header is the
cursor for the next call, so a collector can poll and resume.

### Push

keylease-server can also send the audit itself. On the organization page,
**Audit to your SIEM** (owners and admins), or
`PUT /v1/orgs/ORG/audit/destinations/NAME`:

```json
{"url": "https://siem.example.com/services/collector", "format": "splunk_hec",
 "secret": "…", "start": "now"}
```

- **Formats:** `jsonl` (JSON Lines), `syslog` (RFC 5424, the same lines as the
  export), `splunk_hec` (HTTP Event Collector events, `sourcetype`
  `keylease:audit`).
- **Token:** sent as `Authorization: Bearer …` (Splunk: `Splunk …`). Change it
  with `header` and `template` (`{secret}` marks the token). It is encrypted
  with the KMS root key, so push needs `KEYLEASE_KMS_ROOT_KEY_FILE`.
- **Start:** `start` is `now` (default) or `beginning` (every past event too).

Every 15 seconds each destination gets the events after its cursor, up to 500
per request. When a collector fails, its cursor stays and the next attempt
waits 15 s, 30 s, 1 min and so on, up to an hour. The destination list shows
how many events are waiting and the last error, and **Send a test event**
checks a destination. Several server replicas can run at once; a destination
is locked while it is sent. Collectors must have public HTTPS addresses unless
`KEYLEASE_GATEWAY_ALLOW_PRIVATE=1` is set (see `docs/mcp-gateway.md`).

## SCIM 2.0 (deprovisioning)

An owner creates a SCIM token (`POST /v1/orgs/ORG/scim-tokens`) and configures
the identity provider with base URL `$KEYLEASE_SERVER_PUBLIC_URL/scim/v2/orgs/ORG`
and that bearer token. Supported: `GET /Users`, `GET /Users/{id}`,
`PATCH /Users/{id}` with `active: false`, and `DELETE /Users/{id}`, which
remove the member and their project access (the last owner stays). People
still join through invites: KeyLease accounts are created by the person's own
device, so the provider cannot create them.

## Not yet

- Hardware security modules (PKCS#11) and cloud KMS providers for the root key.
- Managed nodes: nodes receiving signed policy from the server (the earlier
  edge node covers part of this).
