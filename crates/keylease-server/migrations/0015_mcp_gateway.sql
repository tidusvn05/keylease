-- MCP Gateway (v2 plan, step 17): organizations publish a remote MCP endpoint;
-- each gateway client (an agent, a team's assistant) gets a token and may use
-- the HTTP bindings of the project environments it is granted. Credentials
-- stay on the server.

CREATE TABLE managed_http_bindings (
    org_id TEXT NOT NULL,
    slug TEXT NOT NULL,
    name TEXT NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,62}$'),
    base_url TEXT NOT NULL,
    header TEXT NOT NULL,
    template TEXT NOT NULL,
    secret_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (org_id, slug, name),
    FOREIGN KEY (org_id, slug) REFERENCES team_projects(org_id, slug) ON DELETE CASCADE
);

CREATE TABLE gateway_clients (
    client_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES team_orgs(org_id),
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    token_hash TEXT NOT NULL UNIQUE,
    allow_writes BOOLEAN NOT NULL,
    created_by TEXT NOT NULL REFERENCES relay_accounts(account_id),
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE gateway_grants (
    client_id TEXT NOT NULL REFERENCES gateway_clients(client_id) ON DELETE CASCADE,
    org_id TEXT NOT NULL,
    slug TEXT NOT NULL,
    environment TEXT NOT NULL,
    PRIMARY KEY (client_id, slug, environment),
    FOREIGN KEY (org_id, slug) REFERENCES team_projects(org_id, slug) ON DELETE CASCADE
);
