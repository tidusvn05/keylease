-- Enterprise features (v2 plan, step 19): a KMS API with per-project keys,
-- SCIM tokens for deprovisioning organization members.

CREATE TABLE kms_keys (
    key_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    slug TEXT NOT NULL,
    name TEXT NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,62}$'),
    purpose TEXT NOT NULL CHECK (purpose IN ('encrypt', 'sign', 'mac')),
    created_by TEXT NOT NULL REFERENCES relay_accounts(account_id),
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (org_id, slug, name),
    FOREIGN KEY (org_id, slug) REFERENCES team_projects(org_id, slug) ON DELETE CASCADE
);

CREATE TABLE kms_key_versions (
    key_id TEXT NOT NULL REFERENCES kms_keys(key_id) ON DELETE CASCADE,
    version INTEGER NOT NULL CHECK (version > 0),
    wrapped_json TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (key_id, version)
);

CREATE TABLE team_scim_tokens (
    token_hash TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES team_orgs(org_id),
    created_by TEXT NOT NULL REFERENCES relay_accounts(account_id),
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);
