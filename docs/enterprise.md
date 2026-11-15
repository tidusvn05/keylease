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

## Where the KMS root key lives

The root key wraps every Managed project's data keys. By default it is a file
(`KEYLEASE_KMS_ROOT_KEY_FILE`, 32 bytes in unpadded base64, mode 0600). It can
instead be wrapped by a key management service or an HSM. In that case only
the wrapped key is on disk (`KEYLEASE_KMS_WRAPPED_ROOT_KEY_FILE`), and the
server unwraps it at start and keeps the plaintext key only in memory. The
start log shows the key's fingerprint, never the key.

| `KEYLEASE_KMS_PROVIDER` | Settings |
|---|---|
| `file` (default when the file is set) | `KEYLEASE_KMS_ROOT_KEY_FILE` |
| `aws` | `AWS_REGION`, `KEYLEASE_AWS_KMS_KEY_ID` (key ID, ARN or alias), optionally `KEYLEASE_AWS_KMS_ENDPOINT` (VPC endpoint). Credentials come from `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN`, an ECS task role or an EC2 instance role (IMDSv2). The role needs `kms:Encrypt` (for `init` and `wrap`) and `kms:Decrypt`. |
| `gcp` | `KEYLEASE_GCP_KMS_KEY` (`projects/P/locations/L/keyRings/R/cryptoKeys/K`). The token comes from `GOOGLE_APPLICATION_CREDENTIALS` (a service account key) or the metadata server (GCE, GKE, Cloud Run). The account needs `roles/cloudkms.cryptoKeyEncrypterDecrypter`. |
| `pkcs11` | `KEYLEASE_PKCS11_MODULE` (the vendor's PKCS#11 library), `KEYLEASE_PKCS11_TOKEN_LABEL`, `KEYLEASE_PKCS11_PIN_FILE` (mode 0600) and `KEYLEASE_PKCS11_KEY_LABEL` (an AES key on the token, used with AES-GCM). The server image is built with PKCS#11 support. A source build needs `--features pkcs11`. |

With the provider's variables set:

```sh
keylease-server kms init                       # new deployment: a new root key, written wrapped
keylease-server kms wrap /etc/keylease/kms_root_key   # move an existing file key to the provider
keylease-server kms check                      # unwraps and prints the fingerprint
```

`init` and `wrap` never overwrite a wrapped file, and they check that the
provider gives the same key back. After `wrap`, start the server with the
provider and check that the fingerprint is unchanged. Then keep an offline
copy of the old file key somewhere separate (losing both it and the
provider's key loses every Managed secret), and remove it from the server.

## Not yet

- Managed nodes: nodes receiving signed policy from the server (the earlier
  edge node covers part of this).
