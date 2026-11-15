-- Web Push for the console (ADR 0011): server settings (the VAPID key) and
-- the browsers that asked to be told about new pending approvals.

CREATE TABLE console_settings (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE console_push_subscriptions (
    endpoint TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES relay_accounts(account_id),
    p256dh TEXT NOT NULL,
    auth TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ
);
CREATE INDEX console_push_subscriptions_account_idx ON console_push_subscriptions(account_id);
