# CI/CD with machine identities

A pipeline reads a Managed project environment ([teams](teams.md)) with the
OIDC token its platform already gives it: no long-lived secret is stored in
the pipeline (v2 plan, P4).

## 1. Create a machine identity

In the console, as a project admin (or with `POST /v1/orgs/{org}/projects/{slug}/machine-identities`):

| Field | GitHub Actions | GitLab CI | Kubernetes |
|---|---|---|---|
| Issuer | `https://token.actions.githubusercontent.com` | `https://gitlab.com` (or your instance) | the cluster's service-account issuer |
| Audience | `keylease` | the `aud` of your `id_tokens` entry | the audience of the projected token |
| Subject | `repo:acme/shop:ref:refs/heads/main` | `project_path:acme/shop:ref_type:branch:ref:main` | `system:serviceaccount:NAMESPACE:NAME` |
| Environment | the one environment it reads | | |

A subject ending in `*` matches by prefix (`repo:acme/shop:ref:refs/heads/*`);
`*` alone is refused. Each identity reads exactly one environment; revoking
it ends its tokens at once.

## 2. Use it in the job

```yaml
# GitHub Actions: the action loads the secrets into the job's environment,
# masked in the logs (needs only curl and jq, present on GitHub runners).
permissions:
  id-token: write
  contents: read
steps:
  - uses: tidusvn05/keylease/actions/secrets@main   # pin a commit or tag
    with:
      server: https://vault.example.com/api
      identity: mid_…
  - run: ./deploy.sh        # DATABASE_URL etc. are in the environment
```

Or keep the secrets inside one command, scrubbed from its output:

```yaml
  - run: cargo install --locked keylease
  - run: keylease ci run -- ./deploy.sh
    env:
      KEYLEASE_SERVER_URL: https://vault.example.com/api
      KEYLEASE_MACHINE_IDENTITY: mid_…
```

```yaml
# GitLab CI
deploy:
  id_tokens:
    KEYLEASE_OIDC_TOKEN:
      aud: keylease
  script:
    - keylease ci run --server https://vault.example.com/api --identity mid_… -- ./deploy.sh
```

```sh
# Kubernetes (projected service-account token)
keylease ci run --server … --identity mid_… --oidc-token-file /var/run/secrets/tokens/keylease -- ./job
```

`keylease ci run` exchanges the token for a 15-minute machine token, reads the
environment's secrets, runs the command with them as environment variables
and scrubs their values (raw, base64 and percent-encoded) from its output.
Every exchange and read is in the project's audit.


## Kubernetes with the External Secrets Operator

The operator's webhook provider cannot exchange OIDC tokens, so give it an
**access key** of a machine identity (Console → Secrets → Machine identities →
Key, or `POST …/machine-identities/{id}/keys` with `{"days": 90}`). The key is
shown once, expires (1–365 days) and stops working when the identity is
revoked.

```yaml
apiVersion: v1
kind: Secret
metadata: { name: keylease-key, namespace: shop }
stringData: { key: klmk_… }
---
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata: { name: keylease, namespace: shop }
spec:
  provider:
    webhook:
      url: "https://vault.example.com/api/v1/machine/secrets"
      headers:
        Authorization: "Bearer {{ .auth.key }}"
      secrets:
        - name: auth
          secretRef: { name: keylease-key }
      result:
        jsonPath: "$.secrets.{{ .remoteRef.key }}"
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata: { name: shop, namespace: shop }
spec:
  refreshInterval: 1h
  secretStoreRef: { name: keylease, kind: SecretStore }
  target: { name: shop-env }
  data:
    - secretKey: DATABASE_URL
      remoteRef: { key: DATABASE_URL }
```


## Dynamic PostgreSQL logins

Instead of a standing database password, a project admin stores an admin URL
as a Managed secret (e.g. `PG_ADMIN` in each environment) and configures

```sh
PUT /v1/orgs/ORG/projects/shop/dynamic/postgres/main
{"admin_secret": "PG_ADMIN", "grant_role": "app_migrations", "max_ttl_seconds": 3600}
```

A job with a machine token (or access key) then gets its own login that joins
`app_migrations` and expires (`VALID UNTIL`):

```sh
curl -X POST -H "Authorization: Bearer $KEYLEASE_MACHINE_TOKEN" \
  -d '{"ttl_seconds": 900}' https://vault.example.com/api/v1/machine/dynamic/postgres/main
# {"username": "kl_…", "password": "…", "url": "postgres://kl_…@db/app", "expires_at": …}
```

The role must exist and the admin URL's user must be able to create roles in
it (`CREATEROLE`). Expired logins can no longer sign in; dropping them is left
to a periodic `DROP ROLE` of `kl_%` roles past `rolvaliduntil`.
