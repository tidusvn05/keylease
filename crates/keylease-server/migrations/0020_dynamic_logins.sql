-- Dynamic database logins: MySQL next to PostgreSQL, and the reaper that drops
-- expired logins (and records why it could not).

ALTER TABLE managed_dynamic_postgres
    ADD COLUMN engine TEXT NOT NULL DEFAULT 'postgres' CHECK (engine IN ('postgres', 'mysql'));

ALTER TABLE managed_dynamic_leases
    ADD COLUMN engine TEXT NOT NULL DEFAULT 'postgres' CHECK (engine IN ('postgres', 'mysql')),
    ADD COLUMN revoked_at TIMESTAMPTZ,
    ADD COLUMN revoke_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN revoke_error TEXT;

CREATE INDEX managed_dynamic_leases_expiry_idx ON managed_dynamic_leases(expires_at)
    WHERE revoked_at IS NULL;
