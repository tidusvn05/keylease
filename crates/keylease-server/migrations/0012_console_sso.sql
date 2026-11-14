-- Console sign-in with an OpenID Connect provider (v2 plan, step 14). An
-- identity (issuer, subject) is linked to an account from a signed-in console.

CREATE TABLE console_sso_states (
    state_hash TEXT PRIMARY KEY,
    code_verifier TEXT NOT NULL,
    nonce TEXT NOT NULL,
    link_account TEXT REFERENCES relay_accounts(account_id),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE console_sso_identities (
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES relay_accounts(account_id),
    email TEXT,
    linked_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (issuer, subject)
);
CREATE INDEX console_sso_identities_account_idx ON console_sso_identities(account_id);

ALTER TABLE console_sessions DROP CONSTRAINT console_sessions_via_check;
ALTER TABLE console_sessions
    ADD CONSTRAINT console_sessions_via_check CHECK (via IN ('device_link', 'passkey', 'sso'));
