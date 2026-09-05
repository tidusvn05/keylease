CREATE TABLE credential_lease_index (
    lease_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    edge_id TEXT NOT NULL REFERENCES edges(edge_id),
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    connection_id TEXT NOT NULL REFERENCES connection_descriptors(connection_id),
    backend_id TEXT NOT NULL,
    credential_kind TEXT NOT NULL CHECK (credential_kind IN ('aws_sts','ssh_certificate','postgresql_role','oauth_token_exchange')),
    target TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending','active','revoking','revoked','expired','failed')),
    policy_version BIGINT NOT NULL CHECK (policy_version > 0),
    request_digest_sha256 TEXT NOT NULL,
    sender_constraint_json JSONB NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    renewable BOOLEAN NOT NULL,
    failure_code TEXT,
    record_json JSONB NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    UNIQUE (organization_id, project_id, request_digest_sha256)
);

CREATE INDEX credential_lease_active_idx
    ON credential_lease_index(organization_id, project_id, state, expires_at);
CREATE INDEX credential_lease_agent_idx
    ON credential_lease_index(organization_id, project_id, agent_id, issued_at DESC);

CREATE TABLE connection_posture (
    connection_id TEXT PRIMARY KEY REFERENCES connection_descriptors(connection_id),
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    status TEXT NOT NULL CHECK (status IN ('healthy','expiring','rotation_due','stale','misconfigured','revoked')),
    checked_at TIMESTAMPTZ NOT NULL,
    secret_expires_at TIMESTAMPTZ,
    rotation_due_at TIMESTAMPTZ,
    last_rotated_at TIMESTAMPTZ,
    reason_codes_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    posture_json JSONB NOT NULL
);

CREATE INDEX connection_posture_attention_idx
    ON connection_posture(organization_id, project_id, status, rotation_due_at);

CREATE TABLE credential_rotation_requests (
    rotation_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    connection_id TEXT NOT NULL REFERENCES connection_descriptors(connection_id),
    state TEXT NOT NULL CHECK (state IN ('pending','rotating','verifying','activated','failed','rolled_back')),
    requested_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    expected_connection_updated_at TIMESTAMPTZ NOT NULL,
    record_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    failure_code TEXT
);

CREATE UNIQUE INDEX credential_rotation_one_open_idx
    ON credential_rotation_requests(connection_id)
    WHERE state IN ('pending','rotating','verifying');

ALTER TABLE credential_lease_index ENABLE ROW LEVEL SECURITY;
ALTER TABLE connection_posture ENABLE ROW LEVEL SECURITY;
ALTER TABLE credential_rotation_requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_credential_lease_index ON credential_lease_index
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_connection_posture ON connection_posture
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_credential_rotation_requests ON credential_rotation_requests
    USING (organization_id = current_setting('leasegate.organization_id', true));
