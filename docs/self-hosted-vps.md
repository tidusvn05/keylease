# Self-host LeaseGate all-in-one on one VPS

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

Edit `.env`, set `LEASEGATE_DOMAIN`, and set `LEASEGATE_RUNTIME_UID/GID` to the
output of `id -u` and `id -g`. This lets the unprivileged containers read the
mode-0600 files without broadening their permissions. The generated `secrets/` directory is
ignored by Git. Copy it to encrypted off-host backup storage before creating
production data.

The deployment is explicitly `self_hosted/local_gateway`: Control Plane,
operator UI, PostgreSQL and the credential-executing Gateway all run on this
VPS. No LeaseGate-operated service holds or uses your provider keys.

## 2. Start the control plane

```sh
docker compose build control-plane worker web
docker compose up -d postgres object-store control-plane worker web
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

Put the returned IDs in `.env`, rebuild `web`, and restart it. The IDs are
public routing configuration, not secrets.

```sh
docker compose build web
docker compose up -d web
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

## 4. Enroll the local Gateway and agent

Generate an Ed25519 device key locally and retain the private key mode `0600`:

```sh
openssl genpkey -algorithm Ed25519 -out secrets/device_signing_key.pem
chmod 600 secrets/device_signing_key.pem
openssl pkey -in secrets/device_signing_key.pem -pubout -outform DER \
  | tail -c 32 | openssl base64 -A > /tmp/device_public_key.b64
```

Register the device, create a ten-minute one-use Gateway enrollment, enroll it,
and register an agent using the Cloud API. Save the returned
`edge_credential` as `secrets/edge_credential` and agent `credential` as
`secrets/agent_credential`, both mode `0600`. Also copy the returned Edge ID,
agent ID and `control_verifying_key` into `.env`.

Create `secrets/vault_password` yourself (mode `0600`), initialize the local
vault once, then start the mandatory local Gateway:

```sh
docker compose run --rm --entrypoint keylease gateway \
  --db /var/lib/leasegate/vault.sqlite3 vault init
docker compose up -d gateway
curl --fail "https://${LEASEGATE_DOMAIN}/api/healthz"
```

The MCP endpoint and dynamic credential API are published only at VPS loopback
`127.0.0.1:8090` by
default. Connect an agent over SSH forwarding or a private VPN and send its
individual bearer credential. If changing the host/listener, update
`LEASEGATE_MCP_ALLOWED_HOSTS`; Host and Origin validation fail closed.

## 5. Configure local dynamic credential backends

`bootstrap-secrets.sh` creates `secrets/credential_backends.json` with an empty
backend list. This file must remain mode `0600`. Each backend is bound to one
registered connection; the agent cannot override that binding.

Example SSH CA backend:

```json
{
  "schema_version": 1,
  "deployment_mode": "self_hosted",
  "execution_mode": "local_gateway",
  "backends": [{
    "kind": "ssh_certificate",
    "id": "ssh-prod",
    "connection_id": "conn_REPLACE",
    "ca_private_key_file": "/run/leasegate-secrets/ssh_ca",
    "revoked_keys_file": "/var/lib/leasegate/revoked.krl",
    "allowed_principals": ["deploy"],
    "maximum_ttl_seconds": 300
  }]
}
```

Example PostgreSQL backend:

```json
{
  "kind": "postgresql_role",
  "id": "postgres-app",
  "connection_id": "conn_REPLACE",
  "database_url_file": "/run/leasegate-secrets/app_database_issuer_url",
  "advertised_host": "db.internal",
  "advertised_port": 5432,
  "advertised_database": "app",
  "grant_role": "leasegate_app_readonly",
  "role_prefix": "lgagent",
  "maximum_ttl_seconds": 300,
  "tls_required": true
}
```

AWS uses `kind: aws_sts_web_identity` with fixed `endpoint`, `role_arn`,
`web_identity_token_file`, and TTL 900–3600. OAuth uses
`kind: oauth_token_exchange` with fixed `token_endpoint`,
`subject_token_file`, `subject_token_type`, `client_id`, optional
`client_secret_file`, and audience/scope allowlists. Complete field definitions
and policy action names are in `phase-5/architecture-and-tech-stack.md`.

Add a signed policy rule for the exact `credential:*` resource and action before
testing. Credential issuance is R3, so it fails while the Control Plane is
offline. Restart `gateway` after changing backend configuration.

## 6. Operate and recover

```sh
docker compose ps
docker compose logs --since=10m control-plane worker gateway
docker compose exec postgres pg_isready -U leasegate -d leasegate
```

Back up PostgreSQL, the Edge volume, Caddy state, and `secrets/` to another
machine using encryption. A backup on the same VPS is not disaster recovery.
Test restore quarterly. Never restore only Edge SQLite while discarding newer
policy/revocation state; version/digest/epoch checks deliberately reject
rollback.

To revoke an agent, call the project agent `DELETE` endpoint with a reason.
Control Plane commits the registry revoke and ordered control event in one
transaction; the local Gateway polls every two seconds. When Control Plane is
unavailable, only signed
R0/R1 offline authority can survive, for at most 15 minutes; side effects stop
earlier if revocation state is stale or audit storage is unavailable.

Upgrade one binary/image set at a time, run `cargo test --workspace` before the
build, retain the prior image digest, and activate a policy with an appropriate
`minimum_edge_version` only after Edge rollout.
