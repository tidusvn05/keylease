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
# GitHub Actions
permissions:
  id-token: write
  contents: read
steps:
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
