-- Per-call approvals in the MCP Gateway: a client can be set to need a
-- project admin's approval for writes or for every call. An approval covers
-- one exact request (digest) once.

ALTER TABLE gateway_clients
    ADD COLUMN approval TEXT NOT NULL DEFAULT 'none' CHECK (approval IN ('none', 'writes', 'all'));

CREATE TABLE gateway_approvals (
    approval_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    client_id TEXT NOT NULL REFERENCES gateway_clients(client_id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    environment TEXT NOT NULL,
    binding TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    body_sha256 TEXT,
    body_bytes INTEGER NOT NULL,
    request_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'denied', 'consumed')),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    decided_by TEXT REFERENCES relay_accounts(account_id),
    decided_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    FOREIGN KEY (org_id, slug) REFERENCES team_projects(org_id, slug) ON DELETE CASCADE
);
CREATE INDEX gateway_approvals_digest_idx ON gateway_approvals(client_id, request_digest);
CREATE INDEX gateway_approvals_org_idx ON gateway_approvals(org_id, state, created_at DESC);
