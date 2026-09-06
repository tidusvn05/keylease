//! Versioned contracts shared by KeyLease Cloud and LeaseGate Edge.

mod enterprise;

pub use enterprise::*;

use chrono::{DateTime, Utc};
use keylease_core::{
    AccountId, AgentId, ApprovalId, ApprovalSemanticSummary, AuditEvent, ConnectionHealth,
    ConnectionId, ConnectorPublisherId, ControlEventId, DeviceId, EdgeId, HumanId, MembershipId,
    OrganizationId, PolicyBundleId, PolicyProposalId, PolicyRule, ProjectId, RiskTier,
    SyncMutationId, VaultId,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const CONTROL_CONTRACT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Organization {
    pub id: OrganizationId,
    pub account_id: AccountId,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub id: ProjectId,
    pub organization_id: OrganizationId,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MembershipRole {
    Owner,
    Admin,
    SecurityAdmin,
    Operator,
    Approver,
    Member,
    Auditor,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Membership {
    pub id: MembershipId,
    pub organization_id: OrganizationId,
    pub human_id: HumanId,
    pub role: MembershipRole,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EdgeHealth {
    Enrolling,
    Healthy,
    Degraded,
    Offline,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EdgeRecord {
    pub id: EdgeId,
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub device_id: DeviceId,
    pub name: String,
    pub public_key_base64: String,
    pub certificate_fingerprint_sha256: Option<String>,
    pub health: EdgeHealth,
    pub software_version: String,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentRegistration {
    pub agent_id: AgentId,
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub display_name: String,
    pub credential_digest: String,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyncMutationEnvelope {
    pub schema_version: u32,
    pub mutation_id: SyncMutationId,
    pub account_id: AccountId,
    pub vault_id: VaultId,
    pub object_id: String,
    pub device_id: DeviceId,
    pub base_revision: u64,
    pub result_revision: u64,
    pub idempotency_key: String,
    pub ciphertext: String,
    pub ciphertext_digest: String,
    pub tombstone: bool,
    pub created_at: DateTime<Utc>,
    pub device_signature_base64: String,
}

impl SyncMutationEnvelope {
    pub fn validate_shape(&self) -> keylease_core::Result<()> {
        if self.schema_version != CONTROL_CONTRACT_VERSION {
            return Err(keylease_core::KeyLeaseError::UnsupportedVersion {
                version: self.schema_version,
            });
        }
        if self.object_id.is_empty()
            || self.object_id.len() > 512
            || self.object_id.chars().any(char::is_control)
            || self.idempotency_key.is_empty()
            || self.idempotency_key.len() > 256
            || self.result_revision != self.base_revision.saturating_add(1)
        {
            return Err(keylease_core::KeyLeaseError::InvalidRequest {
                reason: "invalid sync mutation shape".into(),
            });
        }
        let digest = hex(&Sha256::digest(self.ciphertext.as_bytes()));
        if digest != self.ciphertext_digest {
            return Err(keylease_core::KeyLeaseError::InvalidRequest {
                reason: "sync ciphertext digest mismatch".into(),
            });
        }
        Ok(())
    }

    pub fn signing_payload(&self) -> Value {
        serde_json::json!({
            "schema_version": self.schema_version,
            "mutation_id": self.mutation_id,
            "account_id": self.account_id,
            "vault_id": self.vault_id,
            "object_id": self.object_id,
            "device_id": self.device_id,
            "base_revision": self.base_revision,
            "result_revision": self.result_revision,
            "idempotency_key": self.idempotency_key,
            "ciphertext_digest": self.ciphertext_digest,
            "tombstone": self.tombstone,
            "created_at": self.created_at,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyncPushRequest {
    pub schema_version: u32,
    pub mutations: Vec<SyncMutationEnvelope>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SyncMutationStatus {
    Applied,
    Replay,
    Conflict,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyncMutationResult {
    pub mutation_id: SyncMutationId,
    pub status: SyncMutationStatus,
    pub current_revision: u64,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyncPushResponse {
    pub schema_version: u32,
    pub cursor: u64,
    pub results: Vec<SyncMutationResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyncPullResponse {
    pub schema_version: u32,
    pub cursor: u64,
    pub has_more: bool,
    pub mutations: Vec<SyncMutationEnvelope>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundlePayload {
    pub schema_version: u32,
    pub bundle_id: PolicyBundleId,
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub version: u64,
    pub previous_bundle_digest: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revocation_epoch: u64,
    pub minimum_edge_version: String,
    /// Offline execution is disabled unless a signed bundle opts in. Edge
    /// still applies its compiled hard ceiling and never permits R2+ offline.
    #[serde(default)]
    pub offline: OfflineAuthorization,
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OfflineAuthorization {
    pub allow_r0_r1: bool,
    /// Requested low-risk offline window. Edge clamps this to its hard limit.
    pub max_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyBundle {
    pub algorithm: String,
    pub signer_key_id: String,
    pub payload: PolicyBundlePayload,
    pub payload_digest_sha256: String,
    pub signature_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalReceiptPayload {
    pub schema_version: u32,
    pub approval_id: ApprovalId,
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub agent_id: AgentId,
    pub workload_id: Option<String>,
    pub on_behalf_of: Option<String>,
    pub task_id: Option<String>,
    pub connection_id: ConnectionId,
    pub action: String,
    pub resource: String,
    pub request_digest_hex: String,
    pub policy_version: u64,
    pub approver_id: HumanId,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub max_uses: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedApprovalReceipt {
    pub algorithm: String,
    pub signer_key_id: String,
    pub payload: ApprovalReceiptPayload,
    pub payload_digest_sha256: String,
    pub signature_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RevocationScope {
    Lease,
    Approval,
    Task,
    Workload,
    Agent,
    Connection,
    Project,
    Organization,
    GlobalSideEffects,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    pub organization_id: OrganizationId,
    pub project_id: Option<ProjectId>,
    pub epoch: u64,
    pub scope: RevocationScope,
    pub target_id: String,
    pub reason: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum ControlEventKind {
    PolicyBundle(SignedPolicyBundle),
    ApprovalReceipt(SignedApprovalReceipt),
    Revocation(Revocation),
    ConnectionHealth {
        connection_id: ConnectionId,
        healthy: bool,
        reason: Option<String>,
    },
    ReconcileRequired {
        from_cursor: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ControlEvent {
    pub schema_version: u32,
    pub id: ControlEventId,
    pub organization_id: OrganizationId,
    pub project_id: Option<ProjectId>,
    pub sequence: u64,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub kind: ControlEventKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EdgeEventBatch {
    pub schema_version: u32,
    pub cursor: u64,
    pub has_more: bool,
    pub events: Vec<ControlEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    pub schema_version: u32,
    pub approval_id: ApprovalId,
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub agent_id: AgentId,
    pub workload_id: Option<String>,
    pub on_behalf_of: Option<String>,
    pub task_id: Option<String>,
    pub connection_id: ConnectionId,
    pub action: String,
    pub resource: String,
    pub request_digest_hex: String,
    pub policy_version: u64,
    pub risk: RiskTier,
    pub summary: ApprovalSemanticSummary,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approved,
    Denied,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDecisionRequest {
    pub schema_version: u32,
    pub decision: ApprovalDecision,
    pub approver_id: HumanId,
    pub expected_request_digest_hex: String,
    pub expected_policy_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EdgeHeartbeat {
    pub schema_version: u32,
    pub edge_id: EdgeId,
    pub software_version: String,
    pub policy_version: Option<u64>,
    pub revocation_epoch: u64,
    pub control_cursor: u64,
    pub audit_spool_bytes: u64,
    pub connector_health: BTreeMap<String, String>,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectionDescriptor {
    pub schema_version: u32,
    pub connection_id: ConnectionId,
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub provider: String,
    pub connector_version: String,
    pub display_name: String,
    pub auth_method: String,
    pub health: ConnectionHealth,
    pub health_reason: Option<String>,
    pub reauthorization_required: bool,
    /// Stable LeaseGate permissions, never raw OAuth tokens or grants.
    pub granted_permissions: Vec<String>,
    pub authorized_resources: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyProposalStatus {
    Pending,
    Approved,
    Rejected,
    Activated,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyProposal {
    pub schema_version: u32,
    pub proposal_id: PolicyProposalId,
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub proposed_by_agent_id: AgentId,
    pub base_policy_version: u64,
    pub title: String,
    pub reason: String,
    pub rules: Vec<PolicyRule>,
    pub proposal_digest_sha256: String,
    pub status: PolicyProposalStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl PolicyProposal {
    pub fn calculate_digest(&self) -> String {
        let value = serde_json::json!({
            "schema_version": self.schema_version,
            "proposal_id": self.proposal_id,
            "organization_id": self.organization_id,
            "project_id": self.project_id,
            "proposed_by_agent_id": self.proposed_by_agent_id,
            "base_policy_version": self.base_policy_version,
            "title": self.title,
            "reason": self.reason,
            "rules": self.rules,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        });
        hex(&Sha256::digest(
            serde_json::to_vec(&value).expect("serializing proposal JSON cannot fail"),
        ))
    }

    pub fn validate_shape(&self, now: DateTime<Utc>) -> keylease_core::Result<()> {
        if self.schema_version != CONTROL_CONTRACT_VERSION {
            return Err(keylease_core::KeyLeaseError::UnsupportedVersion {
                version: self.schema_version,
            });
        }
        if self.title.trim().is_empty()
            || self.title.len() > 200
            || self.reason.trim().is_empty()
            || self.reason.len() > 2_000
            || self.rules.is_empty()
            || self.rules.len() > 500
            || self.expires_at <= now
            || self.expires_at > now + chrono::Duration::days(7)
            || self.proposal_digest_sha256 != self.calculate_digest()
            || self.status != PolicyProposalStatus::Pending
        {
            return Err(keylease_core::KeyLeaseError::InvalidRequest {
                reason: "invalid policy proposal shape or digest".into(),
            });
        }
        if self.rules.iter().any(|rule| {
            rule.id.is_empty()
                || rule.actions.is_empty()
                || rule.resource_prefix.is_empty()
                || rule.max_lease_ttl_seconds == 0
                || rule.max_uses == 0
                || rule.agent_id.as_ref() != Some(&self.proposed_by_agent_id)
        }) {
            return Err(keylease_core::KeyLeaseError::Denied {
                reason: "agent proposals require explicit self-bound, non-empty rules".into(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyProposalDecision {
    Approve,
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyProposalReviewRequest {
    pub schema_version: u32,
    pub reviewer_id: HumanId,
    pub decision: PolicyProposalDecision,
    pub expected_proposal_digest_sha256: String,
    pub expected_base_policy_version: u64,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyProposalReview {
    pub proposal_id: PolicyProposalId,
    pub reviewer_id: HumanId,
    pub decision: PolicyProposalDecision,
    pub proposal_digest_sha256: String,
    pub base_policy_version: u64,
    pub note: String,
    pub reviewed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectorPublisher {
    pub id: ConnectorPublisherId,
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub display_name: String,
    pub verifying_key_base64: String,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuditBatch {
    pub schema_version: u32,
    pub edge_id: EdgeId,
    pub first_sequence: u64,
    pub events: Vec<AuditEvent>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_envelope_rejects_ciphertext_or_revision_tampering() {
        let ciphertext = "opaque-ciphertext";
        let mut mutation = SyncMutationEnvelope {
            schema_version: CONTROL_CONTRACT_VERSION,
            mutation_id: SyncMutationId::new(),
            account_id: AccountId::new(),
            vault_id: VaultId::new(),
            object_id: "item_1".into(),
            device_id: DeviceId::new(),
            base_revision: 0,
            result_revision: 1,
            idempotency_key: "m1".into(),
            ciphertext: ciphertext.into(),
            ciphertext_digest: hex(&Sha256::digest(ciphertext.as_bytes())),
            tombstone: false,
            created_at: Utc::now(),
            device_signature_base64: "signature".into(),
        };
        mutation.validate_shape().unwrap();
        mutation.ciphertext.push('!');
        assert!(mutation.validate_shape().is_err());
        mutation.ciphertext = ciphertext.into();
        mutation.result_revision = 3;
        assert!(mutation.validate_shape().is_err());
    }

    #[test]
    fn policy_proposal_is_digest_bound_and_agent_scoped() {
        let now = Utc::now();
        let agent = AgentId("agent_proposer".into());
        let mut proposal = PolicyProposal {
            schema_version: CONTROL_CONTRACT_VERSION,
            proposal_id: PolicyProposalId::new(),
            organization_id: OrganizationId("org_test".into()),
            project_id: ProjectId("project_test".into()),
            proposed_by_agent_id: agent.clone(),
            base_policy_version: 3,
            title: "Read one repository".into(),
            reason: "Complete task 42".into(),
            rules: vec![PolicyRule {
                id: "proposal-rule".into(),
                version: 4,
                effect: keylease_core::PolicyEffect::Allow,
                agent_id: Some(agent),
                connection_id: Some("conn_github".into()),
                resource_prefix: "github:repository/123".into(),
                actions: vec!["github.issue.get".into()],
                argument_equals: Default::default(),
                not_before: None,
                expires_at: Some(now + chrono::Duration::hours(1)),
                max_lease_ttl_seconds: 60,
                max_uses: 10,
                budget: Default::default(),
            }],
            proposal_digest_sha256: String::new(),
            status: PolicyProposalStatus::Pending,
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
        };
        proposal.proposal_digest_sha256 = proposal.calculate_digest();
        proposal.validate_shape(now).unwrap();
        proposal.rules[0].actions.push("github.issue.create".into());
        assert!(proposal.validate_shape(now).is_err());
    }
}
