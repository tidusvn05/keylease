-- Audit push: keylease-server sends each organization's audit to its SIEM
-- destinations (HTTPS collectors) as JSON Lines, RFC 5424 syslog or Splunk
-- HEC events, from a cursor, retrying with backoff.

CREATE TABLE org_siem_destinations (
    org_id TEXT NOT NULL REFERENCES team_orgs(org_id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,62}$'),
    url TEXT NOT NULL,
    format TEXT NOT NULL CHECK (format IN ('jsonl', 'syslog', 'splunk_hec')),
    header TEXT NOT NULL,
    template TEXT NOT NULL,
    -- The collector's token, sealed with the KMS root key.
    secret_sealed TEXT,
    cursor BIGINT NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    failures INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    last_error TEXT,
    created_by TEXT NOT NULL REFERENCES relay_accounts(account_id),
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (org_id, name)
);
