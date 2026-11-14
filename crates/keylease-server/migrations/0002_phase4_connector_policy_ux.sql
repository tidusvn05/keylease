CREATE TABLE connector_publishers (
    publisher_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    display_name TEXT NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 200),
    verifying_key_base64 TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE connector_versions (
    connector_version_row_id BIGSERIAL PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    publisher_id TEXT NOT NULL REFERENCES connector_publishers(publisher_id),
    provider TEXT NOT NULL,
    connector_version TEXT NOT NULL,
    manifest_digest_sha256 TEXT NOT NULL,
    artifact_digest_sha256 TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('published','deprecated','revoked')),
    package_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (organization_id, project_id, provider, connector_version),
    UNIQUE (organization_id, project_id, manifest_digest_sha256)
);

CREATE INDEX connector_versions_catalog_idx
    ON connector_versions(organization_id, project_id, provider, created_at DESC);

CREATE TABLE connection_descriptors (
    connection_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    provider TEXT NOT NULL,
    connector_version TEXT NOT NULL,
    display_name TEXT NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 200),
    auth_method TEXT NOT NULL,
    health TEXT NOT NULL CHECK (health IN ('connected','degraded','expired','revoked','disconnected')),
    health_reason TEXT,
    reauthorization_required BOOLEAN NOT NULL DEFAULT FALSE,
    granted_permissions_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    authorized_resources_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (organization_id, project_id, display_name)
);

CREATE INDEX connection_descriptors_project_idx
    ON connection_descriptors(organization_id, project_id, provider, updated_at DESC);

CREATE TABLE policy_proposals (
    proposal_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    proposed_by_agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    base_policy_version BIGINT NOT NULL CHECK (base_policy_version >= 0),
    proposal_digest_sha256 TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected','activated','expired')),
    proposal_json JSONB NOT NULL,
    review_json JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    reviewed_at TIMESTAMPTZ,
    activated_at TIMESTAMPTZ,
    UNIQUE (organization_id, project_id, proposal_digest_sha256)
);

CREATE INDEX policy_proposals_queue_idx
    ON policy_proposals(organization_id, project_id, status, created_at);

ALTER TABLE audit_event_index
    ADD COLUMN audit_event_row_id BIGSERIAL UNIQUE,
    ADD COLUMN connection_id TEXT,
    ADD COLUMN policy_version BIGINT;

CREATE INDEX audit_event_explorer_idx
    ON audit_event_index(organization_id, project_id, timestamp DESC, edge_id, edge_sequence);
CREATE INDEX audit_event_agent_idx
    ON audit_event_index(organization_id, project_id, agent_id, timestamp DESC);

ALTER TABLE connector_publishers ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE connection_descriptors ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_proposals ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_connector_publishers ON connector_publishers
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_connector_versions ON connector_versions
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_connection_descriptors ON connection_descriptors
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_policy_proposals ON policy_proposals
    USING (organization_id = current_setting('leasegate.organization_id', true));
