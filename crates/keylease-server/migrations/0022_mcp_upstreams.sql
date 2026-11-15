-- Upstream MCP servers in the MCP Gateway: a project lists remote MCP servers
-- whose tools its granted gateway clients may call. The credential (a bearer
-- token or OAuth tokens) is a Managed secret of each environment.

CREATE TABLE managed_mcp_upstreams (
    org_id TEXT NOT NULL,
    slug TEXT NOT NULL,
    name TEXT NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,30}$'),
    url TEXT NOT NULL,
    auth TEXT NOT NULL CHECK (auth IN ('none', 'bearer', 'oauth')),
    secret_name TEXT,
    oauth JSONB,
    created_by TEXT NOT NULL REFERENCES relay_accounts(account_id),
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (org_id, slug, name),
    FOREIGN KEY (org_id, slug) REFERENCES team_projects(org_id, slug) ON DELETE CASCADE
);

-- An OAuth sign-in in progress (single use, ten minutes).
CREATE TABLE gateway_oauth_states (
    state_hash TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    environment TEXT NOT NULL,
    code_verifier TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES relay_accounts(account_id),
    expires_at TIMESTAMPTZ NOT NULL
);
