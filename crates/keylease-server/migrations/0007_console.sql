-- KeyLease Console sign-in (ADR 0008). A console session belongs to one
-- relay account (the user). Tokens, sessions and challenges are stored as
-- SHA-256 hashes; passkeys as public keys.

CREATE TABLE console_login_tokens (
    lookup_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES relay_accounts(account_id),
    member_id TEXT NOT NULL REFERENCES relay_members(member_id),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE TABLE console_sessions (
    session_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES relay_accounts(account_id),
    via TEXT NOT NULL CHECK (via IN ('device_link', 'passkey')),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX console_sessions_account_idx ON console_sessions(account_id);

CREATE TABLE console_passkeys (
    credential_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES relay_accounts(account_id),
    name TEXT NOT NULL,
    public_key_b64 TEXT NOT NULL,
    sign_count BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ
);
CREATE INDEX console_passkeys_account_idx ON console_passkeys(account_id);

CREATE TABLE console_challenges (
    challenge_hash TEXT PRIMARY KEY,
    account_id TEXT REFERENCES relay_accounts(account_id),
    purpose TEXT NOT NULL CHECK (purpose IN ('register', 'login')),
    expires_at TIMESTAMPTZ NOT NULL
);
