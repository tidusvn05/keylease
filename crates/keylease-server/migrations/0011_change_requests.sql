-- Change requests (v2 plan, step 14): in a protected environment, a change by
-- someone who is not a project admin waits for another admin's approval.

CREATE TABLE managed_change_requests (
    request_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    slug TEXT NOT NULL,
    environment TEXT NOT NULL,
    name TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('set', 'delete', 'restore')),
    sealed_json TEXT,
    key_version INTEGER,
    restore_version INTEGER,
    requested_by TEXT NOT NULL REFERENCES relay_accounts(account_id),
    requested_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
    decided_by TEXT REFERENCES relay_accounts(account_id),
    decided_at TIMESTAMPTZ,
    FOREIGN KEY (org_id, slug) REFERENCES team_projects(org_id, slug)
);
CREATE INDEX managed_change_requests_project_idx ON managed_change_requests(org_id, slug, status);
