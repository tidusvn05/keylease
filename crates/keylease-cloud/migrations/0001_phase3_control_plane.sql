CREATE TABLE accounts (
    account_id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE organizations (
    organization_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE projects (
    project_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);

CREATE TABLE human_principals (
    human_id TEXT PRIMARY KEY,
    oidc_issuer TEXT NOT NULL,
    oidc_subject TEXT NOT NULL,
    display_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (oidc_issuer, oidc_subject)
);

CREATE TABLE memberships (
    membership_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    human_id TEXT NOT NULL REFERENCES human_principals(human_id),
    role TEXT NOT NULL CHECK (role IN ('owner','admin','approver','member','auditor')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    UNIQUE (organization_id, human_id)
);

CREATE TABLE agents (
    agent_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    display_name TEXT NOT NULL,
    credential_digest TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE TABLE device_keys (
    device_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    verifying_key_base64 TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE TABLE edge_enrollments (
    enrollment_digest TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    name TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE TABLE edges (
    edge_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    device_id TEXT NOT NULL REFERENCES device_keys(device_id),
    name TEXT NOT NULL,
    public_key_base64 TEXT NOT NULL,
    credential_digest TEXT NOT NULL UNIQUE,
    certificate_fingerprint_sha256 TEXT,
    health TEXT NOT NULL CHECK (health IN ('enrolling','healthy','degraded','offline','revoked')),
    software_version TEXT NOT NULL,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE TABLE vaults (
    vault_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    organization_id TEXT REFERENCES organizations(organization_id),
    encrypted_header TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE vault_objects (
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    vault_id TEXT NOT NULL REFERENCES vaults(vault_id),
    object_id TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision >= 0),
    ciphertext TEXT NOT NULL,
    ciphertext_digest TEXT NOT NULL,
    tombstone BOOLEAN NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (vault_id, object_id)
);

CREATE TABLE sync_mutations (
    cursor BIGSERIAL PRIMARY KEY,
    mutation_id TEXT NOT NULL UNIQUE,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    vault_id TEXT NOT NULL REFERENCES vaults(vault_id),
    object_id TEXT NOT NULL,
    device_id TEXT NOT NULL REFERENCES device_keys(device_id),
    idempotency_key TEXT NOT NULL,
    ciphertext_digest TEXT NOT NULL,
    envelope_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (vault_id, device_id, idempotency_key)
);

CREATE INDEX sync_mutations_pull_idx ON sync_mutations(vault_id, cursor);

CREATE TABLE policy_bundles (
    bundle_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    version BIGINT NOT NULL CHECK (version > 0),
    payload_digest TEXT NOT NULL,
    bundle_json JSONB NOT NULL,
    activated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, version),
    UNIQUE (project_id, payload_digest)
);

CREATE TABLE approval_requests (
    approval_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    request_digest TEXT NOT NULL,
    policy_version BIGINT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending','approved','denied','expired','revoked','consumed')),
    request_json JSONB NOT NULL,
    receipt_json JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    decided_at TIMESTAMPTZ
);

CREATE TABLE revocations (
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    epoch BIGINT NOT NULL CHECK (epoch > 0),
    project_id TEXT REFERENCES projects(project_id),
    scope TEXT NOT NULL,
    target_id TEXT NOT NULL,
    revocation_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (organization_id, epoch)
);

CREATE TABLE control_events (
    control_event_row_id BIGSERIAL PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    project_id TEXT REFERENCES projects(project_id),
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    event_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    UNIQUE (organization_id, sequence)
);

CREATE INDEX control_events_feed_idx
    ON control_events(organization_id, project_id, sequence);

CREATE TABLE edge_event_acks (
    edge_id TEXT PRIMARY KEY REFERENCES edges(edge_id),
    sequence BIGINT NOT NULL CHECK (sequence >= 0),
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE edge_heartbeats (
    edge_id TEXT PRIMARY KEY REFERENCES edges(edge_id),
    heartbeat_json JSONB NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE audit_event_index (
    edge_id TEXT NOT NULL REFERENCES edges(edge_id),
    edge_sequence BIGINT NOT NULL,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    timestamp TIMESTAMPTZ NOT NULL,
    request_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    decision TEXT NOT NULL,
    outcome TEXT NOT NULL,
    event_json JSONB NOT NULL,
    PRIMARY KEY (edge_id, edge_sequence)
);

CREATE TABLE event_outbox (
    outbox_id BIGSERIAL PRIMARY KEY,
    topic TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX event_outbox_pending_idx
    ON event_outbox(outbox_id) WHERE delivered_at IS NULL;

-- RLS is a defense-in-depth tenant boundary. The application transaction sets
-- leasegate.organization_id before accessing tenant-owned rows. Bootstrap
-- account/organization operations use a distinct migration/bootstrap role.
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_bundles ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_event_index ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_projects ON projects
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_memberships ON memberships
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_agents ON agents
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_edges ON edges
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_policy_bundles ON policy_bundles
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_approval_requests ON approval_requests
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_control_events ON control_events
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_audit_index ON audit_event_index
    USING (organization_id = current_setting('leasegate.organization_id', true));
