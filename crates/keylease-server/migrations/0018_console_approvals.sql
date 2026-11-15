-- Console approvals and node audit (ADR 0011). The server keeps each node's
-- latest list of pending approvals, the passkey-signed decisions on their way
-- to the node, and a bounded copy of the node's audit events.

CREATE TABLE console_node_reports (
    member_id TEXT PRIMARY KEY REFERENCES relay_members(member_id),
    account_id TEXT NOT NULL REFERENCES relay_accounts(account_id),
    approvals JSONB NOT NULL,
    reported_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX console_node_reports_account_idx ON console_node_reports(account_id);

CREATE TABLE console_decisions (
    decision_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES relay_accounts(account_id),
    member_id TEXT NOT NULL REFERENCES relay_members(member_id),
    approval_id TEXT NOT NULL,
    approve BOOLEAN NOT NULL,
    payload TEXT NOT NULL,
    assertion JSONB NOT NULL,
    passkey_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    delivered_at TIMESTAMPTZ,
    outcome TEXT CHECK (outcome IN ('approved', 'denied', 'rejected')),
    reason TEXT,
    resolved_at TIMESTAMPTZ
);
CREATE INDEX console_decisions_member_idx ON console_decisions(member_id, resolved_at);
CREATE INDEX console_decisions_account_idx ON console_decisions(account_id, created_at DESC);

CREATE TABLE console_node_audit (
    member_id TEXT NOT NULL REFERENCES relay_members(member_id),
    seq BIGINT NOT NULL,
    account_id TEXT NOT NULL REFERENCES relay_accounts(account_id),
    event JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (member_id, seq)
);
CREATE INDEX console_node_audit_account_idx ON console_node_audit(account_id, occurred_at DESC);
