-- Access keys for machine identities (v2 plan, step 16): for consumers that
-- cannot exchange an OIDC token, such as the External Secrets Operator's
-- webhook provider. Stored as hashes; they expire.

CREATE TABLE machine_keys (
    key_hash TEXT PRIMARY KEY,
    key_id TEXT NOT NULL UNIQUE,
    identity_id TEXT NOT NULL REFERENCES machine_identities(identity_id),
    created_by TEXT NOT NULL REFERENCES relay_accounts(account_id),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
