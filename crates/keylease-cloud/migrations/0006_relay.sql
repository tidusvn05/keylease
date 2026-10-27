-- Cloud relay (ADR 0006): members' public keys, mailboxes and backups. Every
-- payload is sealed to its recipient and signed by its sender; this schema
-- stores no key that can open one.

CREATE TABLE relay_accounts (
    account_id TEXT PRIMARY KEY,
    owner_member_id TEXT NOT NULL UNIQUE,
    recovery_lookup_hash TEXT NOT NULL,
    recovery_kit TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE relay_members (
    member_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES relay_accounts(account_id),
    role TEXT NOT NULL CHECK (role IN ('owner', 'node')),
    name TEXT NOT NULL,
    sign_public_b64 TEXT NOT NULL UNIQUE,
    box_public_b64 TEXT NOT NULL,
    node_tag_b64 TEXT,
    invite_lookup_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX relay_members_account_idx ON relay_members(account_id);

CREATE TABLE relay_invites (
    lookup_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES relay_accounts(account_id),
    name TEXT NOT NULL,
    owner_tag_b64 TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE TABLE relay_messages (
    message_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES relay_accounts(account_id),
    from_member_id TEXT NOT NULL REFERENCES relay_members(member_id),
    to_member_id TEXT NOT NULL REFERENCES relay_members(member_id),
    envelope_json TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX relay_messages_inbox_idx ON relay_messages(to_member_id, created_at);

CREATE TABLE relay_backups (
    member_id TEXT NOT NULL REFERENCES relay_members(member_id),
    object_id TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES relay_accounts(account_id),
    revision BIGINT NOT NULL CHECK (revision > 0),
    deleted BOOLEAN NOT NULL,
    sealed_json TEXT NOT NULL,
    signature_b64 TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (member_id, object_id)
);
