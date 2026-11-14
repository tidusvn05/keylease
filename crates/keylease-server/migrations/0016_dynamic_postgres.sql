-- Dynamic PostgreSQL credentials (v2 plan, step 18): a Managed project names
-- the secret that holds an admin URL and the role new logins are granted; a
-- machine identity then gets a login that expires.

CREATE TABLE managed_dynamic_postgres (
    org_id TEXT NOT NULL,
    slug TEXT NOT NULL,
    name TEXT NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,62}$'),
    admin_secret TEXT NOT NULL,
    grant_role TEXT NOT NULL CHECK (grant_role ~ '^[a-z_][a-z0-9_]{0,62}$'),
    max_ttl_seconds INTEGER NOT NULL CHECK (max_ttl_seconds BETWEEN 60 AND 86400),
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (org_id, slug, name),
    FOREIGN KEY (org_id, slug) REFERENCES team_projects(org_id, slug) ON DELETE CASCADE
);

CREATE TABLE managed_dynamic_leases (
    lease_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    slug TEXT NOT NULL,
    environment TEXT NOT NULL,
    name TEXT NOT NULL,
    role_name TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
