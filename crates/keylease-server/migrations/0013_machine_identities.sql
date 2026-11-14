-- Machine identities (v2 plan, step 15): a CI/CD job or workload proves who
-- it is with its platform's OIDC token (GitHub Actions, GitLab, Kubernetes)
-- and gets a short-lived token that reads one Managed project environment.

CREATE TABLE machine_identities (
    identity_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    slug TEXT NOT NULL,
    environment TEXT NOT NULL,
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    issuer TEXT NOT NULL,
    audience TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES relay_accounts(account_id),
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    FOREIGN KEY (org_id, slug) REFERENCES team_projects(org_id, slug)
);

CREATE TABLE machine_tokens (
    token_hash TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL REFERENCES machine_identities(identity_id),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX machine_tokens_expiry_idx ON machine_tokens(expires_at);
