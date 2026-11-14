-- Managed projects (v2 plan, step 13): organization secrets stored on the
-- server, encrypted with a per-project data key that is wrapped by the KMS
-- root key. Secret versions are append-only (history, restore).

CREATE TABLE managed_keys (
    org_id TEXT NOT NULL,
    slug TEXT NOT NULL,
    key_version INTEGER NOT NULL CHECK (key_version > 0),
    wrapped_json TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (org_id, slug, key_version),
    FOREIGN KEY (org_id, slug) REFERENCES team_projects(org_id, slug)
);

CREATE TABLE managed_secrets (
    org_id TEXT NOT NULL,
    slug TEXT NOT NULL,
    environment TEXT NOT NULL,
    name TEXT NOT NULL CHECK (name ~ '^[A-Za-z_][A-Za-z0-9_]{0,127}$'),
    version INTEGER NOT NULL CHECK (version > 0),
    deleted BOOLEAN NOT NULL,
    ciphertext_json TEXT,
    key_version INTEGER,
    created_by TEXT NOT NULL REFERENCES relay_accounts(account_id),
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (org_id, slug, environment, name, version),
    FOREIGN KEY (org_id, slug) REFERENCES team_projects(org_id, slug)
);

CREATE TABLE managed_audit (
    id BIGSERIAL PRIMARY KEY,
    org_id TEXT NOT NULL,
    slug TEXT NOT NULL,
    environment TEXT,
    name TEXT,
    action TEXT NOT NULL,
    account_id TEXT NOT NULL,
    at TIMESTAMPTZ NOT NULL
);
CREATE INDEX managed_audit_project_idx ON managed_audit(org_id, slug, at DESC);
