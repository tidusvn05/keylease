-- Teams (v2 plan, step 12): organizations of relay accounts, with roles,
-- projects (and their environments) and per-project access. Secret storage for
-- organization projects (Managed projects) comes with the KMS step.

CREATE TABLE team_orgs (
    org_id TEXT PRIMARY KEY,
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    created_by TEXT NOT NULL REFERENCES relay_accounts(account_id),
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE team_members (
    org_id TEXT NOT NULL REFERENCES team_orgs(org_id),
    account_id TEXT NOT NULL REFERENCES relay_accounts(account_id),
    display_name TEXT NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 100),
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    joined_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (org_id, account_id)
);
CREATE INDEX team_members_account_idx ON team_members(account_id);

CREATE TABLE team_invites (
    code_hash TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES team_orgs(org_id),
    role TEXT NOT NULL CHECK (role IN ('admin', 'member', 'viewer')),
    created_by TEXT NOT NULL REFERENCES relay_accounts(account_id),
    expires_at TIMESTAMPTZ NOT NULL,
    used_by TEXT REFERENCES relay_accounts(account_id),
    used_at TIMESTAMPTZ
);

CREATE TABLE team_projects (
    org_id TEXT NOT NULL REFERENCES team_orgs(org_id),
    slug TEXT NOT NULL CHECK (slug ~ '^[a-z][a-z0-9-]{0,62}$'),
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    environments JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (org_id, slug)
);

CREATE TABLE team_project_access (
    org_id TEXT NOT NULL,
    slug TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES relay_accounts(account_id),
    role TEXT NOT NULL CHECK (role IN ('read', 'write', 'admin')),
    granted_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (org_id, slug, account_id),
    FOREIGN KEY (org_id, slug) REFERENCES team_projects(org_id, slug) ON DELETE CASCADE
);
