-- Managed nodes (ADR 0012): nodes that joined an organization receive its
-- signed policy rules.

CREATE TABLE org_node_enrollments (
    code_hash TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES team_orgs(org_id) ON DELETE CASCADE,
    created_by TEXT NOT NULL REFERENCES relay_accounts(account_id),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_by TEXT REFERENCES relay_members(member_id),
    used_at TIMESTAMPTZ
);

CREATE TABLE org_nodes (
    member_id TEXT PRIMARY KEY REFERENCES relay_members(member_id),
    org_id TEXT NOT NULL REFERENCES team_orgs(org_id) ON DELETE CASCADE,
    joined_at TIMESTAMPTZ NOT NULL,
    applied_version BIGINT,
    last_seen_at TIMESTAMPTZ
);
CREATE INDEX org_nodes_org_idx ON org_nodes(org_id);

CREATE TABLE org_node_policies (
    org_id TEXT NOT NULL REFERENCES team_orgs(org_id) ON DELETE CASCADE,
    version BIGINT NOT NULL,
    payload TEXT NOT NULL,
    signature TEXT NOT NULL,
    key_id TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (org_id, version)
);
