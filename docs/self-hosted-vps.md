# Self-host KeyLease Cloud and LeaseGate Edge on one VPS

This profile runs on one Linux VPS with Docker Engine, Compose v2, a DNS name
pointing to the VPS, and inbound TCP 80/443. It is suitable for a personal or
beta installation; it is not highly available.

## 1. Prepare the host

Use a dedicated non-root operator, enable the host firewall, expose only
80/443, and keep SSH key-only. Clone the repository and enter the Compose
directory:

```sh
git clone git@github.com:ai1-maker/leasegate.git
cd leasegate/deploy/compose
cp .env.example .env
./bootstrap-secrets.sh
```

Edit `.env` and set `LEASEGATE_DOMAIN`. The generated `secrets/` directory is
ignored by Git. Copy it to encrypted off-host backup storage before creating
production data.

## 2. Start the control plane

```sh
docker compose build cloud worker gateway
docker compose up -d postgres object-store cloud worker gateway
docker compose ps
curl --fail "https://${LEASEGATE_DOMAIN}/api/healthz"
```

Caddy obtains and renews the public TLS certificate. PostgreSQL and MinIO have
no published host ports.

Read the admin credential without putting it into shell history:

```sh
read -r KEYLEASE_ADMIN_TOKEN < secrets/admin_token
export KEYLEASE_ADMIN_TOKEN
```

Bootstrap the first account/organization/project. Choose a fresh opaque account
ID and save the returned organization, project, membership and human IDs:

```sh
curl --fail-with-body -sS \
  -H "Authorization: Bearer ${KEYLEASE_ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  "https://${LEASEGATE_DOMAIN}/api/v1/bootstrap" \
  --data '{
    "account_id":"acct_selfhosted_primary",
    "organization_name":"My organization",
    "project_name":"default",
    "oidc_issuer":"urn:leasegate:direct-operator",
    "oidc_subject":"owner",
    "human_name":"Owner"
  }'
```

Put the returned IDs in `.env`, rebuild `gateway`, and restart it. The IDs are
public routing configuration, not secrets.

```sh
docker compose build gateway
docker compose up -d gateway
```

The web UI is now at `https://$LEASEGATE_DOMAIN`. Paste the admin credential
only in a trusted single-owner browser tab. For team/Internet use, put an OIDC
identity-aware proxy in front of the UI/API and do not distribute the bootstrap
credential.

## 3. Activate the first signed policy

An empty first policy is a safe way to bring up Edge before granting actions.
Replace the IDs and timestamps; `expires_at` should be short enough for your
risk posture. Subsequent versions must include the previous bundle digest
returned by this call.

```sh
curl --fail-with-body -sS \
  -H "Authorization: Bearer ${KEYLEASE_ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  "https://${LEASEGATE_DOMAIN}/api/v1/policies/activate" \
  --data @policy-v1.json
```

`policy-v1.json` follows `PolicyBundlePayload`: schema version 1, a unique
`policy_bundle_...` ID, organization/project IDs, version 1, null predecessor,
issued/not-before/expiry timestamps, revocation epoch 0, minimum Edge version
`0.1.0`, an explicit offline object and a rule array. Start with:

```json
{
  "schema_version": 1,
  "bundle_id": "policy_bundle_initial",
  "organization_id": "org_REPLACE",
  "project_id": "project_REPLACE",
  "version": 1,
  "previous_bundle_digest": null,
  "issued_at": "2026-09-06T00:00:00Z",
  "not_before": "2026-09-06T00:00:00Z",
  "expires_at": "2026-09-07T00:00:00Z",
  "revocation_epoch": 0,
  "minimum_edge_version": "0.1.0",
  "offline": {"allow_r0_r1": false, "max_seconds": 0},
  "rules": []
}
```

Use `keylease grant template` to generate narrow provider rule shapes. Do not
enable broad prefixes just to make an initial test pass.

## 4. Enroll an Edge and agent

Generate an Ed25519 device key locally and retain the private key mode `0600`:

```sh
openssl genpkey -algorithm Ed25519 -out secrets/device_signing_key.pem
chmod 600 secrets/device_signing_key.pem
openssl pkey -in secrets/device_signing_key.pem -pubout -outform DER \
  | tail -c 32 | openssl base64 -A > /tmp/device_public_key.b64
```

Register the device, create a ten-minute one-use Edge enrollment, enroll it,
and register an agent using the Cloud API. Save the returned
`edge_credential` as `secrets/edge_credential` and agent `credential` as
`secrets/agent_credential`, both mode `0600`. Also copy the returned Edge ID,
agent ID and `control_verifying_key` into `.env`.

Create `secrets/vault_password` yourself (mode `0600`), initialize the local
vault once, then start the optional Edge profile:

```sh
docker compose --profile edge run --rm --entrypoint keylease edge \
  --db /var/lib/leasegate/vault.sqlite3 vault init
docker compose --profile edge up -d edge
curl --fail "https://${LEASEGATE_DOMAIN}/api/healthz"
```

The MCP endpoint is published only at VPS loopback `127.0.0.1:8090/mcp` by
default. Connect an agent over SSH forwarding or a private VPN and send its
individual bearer credential. If changing the host/listener, update
`LEASEGATE_MCP_ALLOWED_HOSTS`; Host and Origin validation fail closed.

## 5. Operate and recover

```sh
docker compose ps
docker compose logs --since=10m cloud worker edge
docker compose exec postgres pg_isready -U leasegate -d leasegate
```

Back up PostgreSQL, the Edge volume, Caddy state, and `secrets/` to another
machine using encryption. A backup on the same VPS is not disaster recovery.
Test restore quarterly. Never restore only Edge SQLite while discarding newer
policy/revocation state; version/digest/epoch checks deliberately reject
rollback.

To revoke an agent, call the project agent `DELETE` endpoint with a reason.
Cloud commits the registry revoke and ordered control event in one transaction;
an online Edge polls every two seconds. When Cloud is unavailable, only signed
R0/R1 offline authority can survive, for at most 15 minutes; side effects stop
earlier if revocation state is stale or audit storage is unavailable.

Upgrade one binary/image set at a time, run `cargo test --workspace` before the
build, retain the prior image digest, and activate a policy with an appropriate
`minimum_edge_version` only after Edge rollout.
