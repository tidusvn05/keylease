use crate::{CONTROL_CONTRACT_VERSION, MembershipRole, SignedPolicyBundle};
use chrono::{DateTime, Utc};
use keylease_core::{
    AccessReviewId, DeviceChallengeId, DeviceId, HumanId, KeyLeaseError, KeyProviderId,
    OperatorSessionId, OrganizationId, PolicyReleaseId, ProjectId, Result, SecurityAlertId,
    SiemDestinationId, WorkloadIdentityId,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnterprisePermission {
    OrganizationAdmin,
    SecurityAdmin,
    Operate,
    Approve,
    AuditRead,
    PolicyRelease,
    IdentityProvision,
}

impl MembershipRole {
    pub fn allows(&self, permission: EnterprisePermission) -> bool {
        use EnterprisePermission as Permission;
        match self {
            Self::Owner => true,
            Self::Admin => matches!(
                permission,
                Permission::OrganizationAdmin
                    | Permission::Operate
                    | Permission::Approve
                    | Permission::AuditRead
                    | Permission::IdentityProvision
            ),
            Self::SecurityAdmin => matches!(
                permission,
                Permission::SecurityAdmin
                    | Permission::Approve
                    | Permission::AuditRead
                    | Permission::PolicyRelease
            ),
            Self::Operator => matches!(permission, Permission::Operate | Permission::AuditRead),
            Self::Approver => matches!(permission, Permission::Approve | Permission::AuditRead),
            Self::Auditor => matches!(permission, Permission::AuditRead),
            Self::Member => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OidcProvider {
    pub schema_version: u32,
    pub organization_id: OrganizationId,
    pub issuer: String,
    pub audience: String,
    pub jwks_uri: String,
    pub allowed_email_domains: Vec<String>,
    pub group_role_mapping: BTreeMap<String, MembershipRole>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl OidcProvider {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CONTROL_CONTRACT_VERSION
            || !self.issuer.starts_with("https://")
            || !self.jwks_uri.starts_with("https://")
            || self.audience.is_empty()
            || self.audience.len() > 512
            || self.allowed_email_domains.len() > 100
            || self.group_role_mapping.len() > 200
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "invalid OIDC provider configuration".into(),
            });
        }
        if self.allowed_email_domains.iter().any(|domain| {
            domain.is_empty()
                || domain.len() > 253
                || domain.starts_with('.')
                || domain.ends_with('.')
                || domain.chars().any(char::is_whitespace)
        }) {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "invalid OIDC email-domain allowlist".into(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessReviewState {
    Open,
    Completed,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessReviewDecision {
    Retain,
    Revoke,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccessReview {
    pub schema_version: u32,
    pub review_id: AccessReviewId,
    pub organization_id: OrganizationId,
    pub state: AccessReviewState,
    pub created_by: HumanId,
    pub due_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccessReviewEntry {
    pub review_id: AccessReviewId,
    pub membership_id: keylease_core::MembershipId,
    pub human_id: HumanId,
    pub role: MembershipRole,
    pub decision: Option<AccessReviewDecision>,
    pub decided_by: Option<HumanId>,
    pub decided_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MobilePlatform {
    Ios,
    Android,
    Web,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorDevice {
    pub schema_version: u32,
    pub device_id: DeviceId,
    pub organization_id: OrganizationId,
    pub human_id: HumanId,
    pub platform: MobilePlatform,
    pub display_name: String,
    pub verifying_key_base64: String,
    pub push_token_digest_sha256: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceChallenge {
    pub schema_version: u32,
    pub challenge_id: DeviceChallengeId,
    pub organization_id: OrganizationId,
    pub device_id: DeviceId,
    pub nonce_base64: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl DeviceChallenge {
    pub fn signing_payload(&self) -> serde_json::Value {
        serde_json::json!({
            "schema_version": self.schema_version,
            "challenge_id": self.challenge_id,
            "organization_id": self.organization_id,
            "device_id": self.device_id,
            "nonce_base64": self.nonce_base64,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorSessionClaims {
    pub schema_version: u32,
    pub session_id: OperatorSessionId,
    pub organization_id: OrganizationId,
    pub human_id: HumanId,
    pub device_id: DeviceId,
    pub role: MembershipRole,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedOperatorSession {
    pub algorithm: String,
    pub signer_key_id: String,
    pub claims: OperatorSessionClaims,
    pub claims_digest_sha256: String,
    pub signature_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyReleaseState {
    Staged,
    Canary,
    Active,
    RolledBack,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyRelease {
    pub schema_version: u32,
    pub release_id: PolicyReleaseId,
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub source_revision: String,
    pub source_digest_sha256: String,
    pub state: PolicyReleaseState,
    pub canary_percent: u8,
    pub bundle: SignedPolicyBundle,
    pub created_by: HumanId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub rollback_of: Option<PolicyReleaseId>,
}

impl PolicyRelease {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CONTROL_CONTRACT_VERSION
            || self.bundle.payload.organization_id != self.organization_id
            || self.bundle.payload.project_id != self.project_id
            || self.source_revision.is_empty()
            || self.source_revision.len() > 256
            || self.source_digest_sha256.len() != 64
            || self.canary_percent > 100
            || (self.state == PolicyReleaseState::Canary && self.canary_percent == 0)
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "invalid policy-as-code release".into(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SiemFormat {
    Json,
    Cef,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SiemDestination {
    pub schema_version: u32,
    pub destination_id: SiemDestinationId,
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub display_name: String,
    pub format: SiemFormat,
    pub endpoint: String,
    /// Names a mode-0600 file in the worker's local SIEM configuration.
    pub secret_ref: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetentionPolicy {
    pub schema_version: u32,
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub audit_days: u32,
    pub approval_days: u32,
    pub credential_metadata_days: u32,
    pub updated_by: HumanId,
    pub updated_at: DateTime<Utc>,
}

impl RetentionPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CONTROL_CONTRACT_VERSION
            || !(30..=3650).contains(&self.audit_days)
            || !(30..=3650).contains(&self.approval_days)
            || !(30..=3650).contains(&self.credential_metadata_days)
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "retention must be between 30 and 3650 days".into(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyProviderKind {
    File,
    Pkcs11,
    AwsKms,
    GcpKms,
    AzureKeyVault,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyProvider {
    pub schema_version: u32,
    pub key_provider_id: KeyProviderId,
    pub organization_id: OrganizationId,
    pub kind: KeyProviderKind,
    pub key_reference: String,
    pub public_key_fingerprint_sha256: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub last_verified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkloadIdentityBinding {
    pub schema_version: u32,
    pub workload_identity_id: WorkloadIdentityId,
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub agent_id: keylease_core::AgentId,
    pub issuer: String,
    pub subject: String,
    pub audience: String,
    pub certificate_sha256: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecurityAlertSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecurityAlert {
    pub schema_version: u32,
    pub alert_id: SecurityAlertId,
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub severity: SecurityAlertSeverity,
    pub code: String,
    pub aggregate_id: String,
    pub details: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub acknowledged_by: Option<HumanId>,
    pub acknowledged_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ComplianceEvidence {
    pub schema_version: u32,
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub generated_at: DateTime<Utc>,
    pub audit_event_count: u64,
    pub approval_count: u64,
    pub denied_count: u64,
    pub active_membership_count: u64,
    pub audit_chain_head_sha256: Option<String>,
    pub controls: BTreeMap<String, String>,
}

impl ComplianceEvidence {
    pub fn digest_sha256(&self) -> String {
        let bytes = serde_json_canonicalizer::to_vec(self)
            .expect("serializing compliance evidence cannot fail");
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedComplianceEvidence {
    pub algorithm: String,
    pub signer_key_id: String,
    pub evidence: ComplianceEvidence,
    pub evidence_digest_sha256: String,
    pub signature_base64: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separated_roles_have_distinct_authority() {
        assert!(MembershipRole::SecurityAdmin.allows(EnterprisePermission::PolicyRelease));
        assert!(!MembershipRole::Operator.allows(EnterprisePermission::PolicyRelease));
        assert!(MembershipRole::Approver.allows(EnterprisePermission::Approve));
        assert!(!MembershipRole::Auditor.allows(EnterprisePermission::Approve));
    }

    #[test]
    fn compliance_digest_is_deterministic() {
        let evidence = ComplianceEvidence {
            schema_version: CONTROL_CONTRACT_VERSION,
            organization_id: OrganizationId::new(),
            project_id: ProjectId::new(),
            period_start: Utc::now(),
            period_end: Utc::now(),
            generated_at: Utc::now(),
            audit_event_count: 1,
            approval_count: 2,
            denied_count: 3,
            active_membership_count: 4,
            audit_chain_head_sha256: Some("a".repeat(64)),
            controls: BTreeMap::new(),
        };
        assert_eq!(evidence.digest_sha256(), evidence.digest_sha256());
    }
}
