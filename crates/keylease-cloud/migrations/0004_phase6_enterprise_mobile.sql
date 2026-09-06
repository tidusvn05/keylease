ALTER TABLE memberships DROP CONSTRAINT memberships_role_check;
ALTER TABLE memberships ADD CONSTRAINT memberships_role_check
    CHECK (role IN ('owner','admin','security_admin','operator','approver','member','auditor'));

CREATE TABLE oidc_providers (
    organization_id TEXT PRIMARY KEY REFERENCES organizations(organization_id),
    issuer TEXT NOT NULL,
    audience TEXT NOT NULL,
    jwks_uri TEXT NOT NULL,
    allowed_email_domains_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    group_role_mapping_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    enabled BOOLEAN NOT NULL,
    provider_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE scim_tokens (
    token_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    token_digest_sha256 TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE access_reviews (
    review_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    state TEXT NOT NULL CHECK (state IN ('open','completed','expired')),
    created_by TEXT NOT NULL REFERENCES human_principals(human_id),
    due_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ
);

CREATE TABLE access_review_entries (
    review_id TEXT NOT NULL REFERENCES access_reviews(review_id) ON DELETE CASCADE,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    membership_id TEXT NOT NULL REFERENCES memberships(membership_id),
    human_id TEXT NOT NULL REFERENCES human_principals(human_id),
    role TEXT NOT NULL,
    decision TEXT CHECK (decision IN ('retain','revoke')),
    decided_by TEXT REFERENCES human_principals(human_id),
    decided_at TIMESTAMPTZ,
    PRIMARY KEY (review_id, membership_id)
);

CREATE TABLE operator_devices (
    device_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    human_id TEXT NOT NULL REFERENCES human_principals(human_id),
    platform TEXT NOT NULL CHECK (platform IN ('ios','android','web')),
    display_name TEXT NOT NULL,
    verifying_key_base64 TEXT NOT NULL,
    push_token_digest_sha256 TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    UNIQUE (organization_id, human_id, verifying_key_base64)
);

CREATE TABLE device_challenges (
    challenge_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    device_id TEXT NOT NULL REFERENCES operator_devices(device_id),
    challenge_json JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE TABLE policy_releases (
    release_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    source_revision TEXT NOT NULL,
    source_digest_sha256 TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('staged','canary','active','rolled_back','failed')),
    canary_percent SMALLINT NOT NULL CHECK (canary_percent BETWEEN 0 AND 100),
    bundle_version BIGINT NOT NULL,
    bundle_digest_sha256 TEXT NOT NULL,
    release_json JSONB NOT NULL,
    created_by TEXT NOT NULL REFERENCES human_principals(human_id),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    rollback_of TEXT REFERENCES policy_releases(release_id),
    UNIQUE (organization_id, project_id, source_revision, source_digest_sha256)
);

CREATE UNIQUE INDEX policy_release_one_live_idx
    ON policy_releases(project_id)
    WHERE state IN ('canary','active');

CREATE TABLE siem_destinations (
    destination_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    display_name TEXT NOT NULL,
    format TEXT NOT NULL CHECK (format IN ('json','cef')),
    endpoint TEXT NOT NULL,
    secret_ref TEXT NOT NULL,
    enabled BOOLEAN NOT NULL,
    destination_json JSONB NOT NULL,
    cursor BIGINT NOT NULL DEFAULT 0 CHECK (cursor >= 0),
    last_success_at TIMESTAMPTZ,
    last_error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (organization_id, project_id, display_name)
);

CREATE TABLE retention_policies (
    project_id TEXT PRIMARY KEY REFERENCES projects(project_id),
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    audit_days INTEGER NOT NULL CHECK (audit_days BETWEEN 30 AND 3650),
    approval_days INTEGER NOT NULL CHECK (approval_days BETWEEN 30 AND 3650),
    credential_metadata_days INTEGER NOT NULL CHECK (credential_metadata_days BETWEEN 30 AND 3650),
    policy_json JSONB NOT NULL,
    updated_by TEXT NOT NULL REFERENCES human_principals(human_id),
    updated_at TIMESTAMPTZ NOT NULL
);

ALTER TABLE audit_event_index ADD COLUMN chain_digest_sha256 TEXT;

CREATE TABLE audit_integrity_heads (
    project_id TEXT PRIMARY KEY REFERENCES projects(project_id),
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    chain_digest_sha256 TEXT NOT NULL,
    event_count BIGINT NOT NULL CHECK (event_count >= 0),
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE security_alerts (
    alert_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    severity TEXT NOT NULL CHECK (severity IN ('info','warning','critical')),
    code TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    alert_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    acknowledged_by TEXT REFERENCES human_principals(human_id),
    acknowledged_at TIMESTAMPTZ
);

CREATE INDEX security_alert_queue_idx
    ON security_alerts(organization_id, project_id, acknowledged_at, created_at DESC);

CREATE TABLE worker_leases (
    lease_name TEXT PRIMARY KEY,
    holder_id TEXT NOT NULL,
    lease_until TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE workload_identities (
    workload_identity_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    audience TEXT NOT NULL,
    certificate_sha256 TEXT,
    enabled BOOLEAN NOT NULL,
    binding_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (organization_id, project_id, issuer, subject, audience)
);

CREATE TABLE key_providers (
    key_provider_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    kind TEXT NOT NULL CHECK (kind IN ('file','pkcs11','aws_kms','gcp_kms','azure_key_vault')),
    key_reference TEXT NOT NULL,
    public_key_fingerprint_sha256 TEXT NOT NULL,
    enabled BOOLEAN NOT NULL,
    provider_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    last_verified_at TIMESTAMPTZ,
    UNIQUE (organization_id, kind, key_reference)
);

ALTER TABLE oidc_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_review_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE operator_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_releases ENABLE ROW LEVEL SECURITY;
ALTER TABLE siem_destinations ENABLE ROW LEVEL SECURITY;
ALTER TABLE retention_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_integrity_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE workload_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE key_providers ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_oidc_providers ON oidc_providers
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_scim_tokens ON scim_tokens
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_access_reviews ON access_reviews
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_access_review_entries ON access_review_entries
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_operator_devices ON operator_devices
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_device_challenges ON device_challenges
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_policy_releases ON policy_releases
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_siem_destinations ON siem_destinations
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_retention_policies ON retention_policies
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_audit_integrity_heads ON audit_integrity_heads
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_security_alerts ON security_alerts
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_workload_identities ON workload_identities
    USING (organization_id = current_setting('leasegate.organization_id', true));
CREATE POLICY tenant_key_providers ON key_providers
    USING (organization_id = current_setting('leasegate.organization_id', true));
