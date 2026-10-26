use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! opaque_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn new() -> Self {
                Self(format!(concat!($prefix, "{}"), Uuid::now_v7().simple()))
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }
    };
}

opaque_id!(AccountId, "acct_");
opaque_id!(OrganizationId, "org_");
opaque_id!(ProjectId, "project_");
opaque_id!(HumanId, "human_");
opaque_id!(VaultId, "vault_");
opaque_id!(ItemId, "item_");
opaque_id!(FieldId, "field_");
opaque_id!(GroupId, "group_");
opaque_id!(AgentId, "agent_");
opaque_id!(WorkloadId, "workload_");
opaque_id!(TaskId, "task_");
opaque_id!(DeviceId, "device_");
opaque_id!(ClientSessionId, "client_session_");
opaque_id!(ConnectionId, "conn_");
opaque_id!(LeaseId, "lease_");
opaque_id!(CredentialLeaseId, "credential_lease_");
opaque_id!(RotationId, "rotation_");
opaque_id!(ApprovalId, "approval_");
opaque_id!(RequestId, "req_");
opaque_id!(ActionId, "action_");
opaque_id!(MembershipId, "membership_");
opaque_id!(EdgeId, "edge_");
opaque_id!(ControlEventId, "event_");
opaque_id!(SyncMutationId, "mutation_");
opaque_id!(PolicyBundleId, "policy_bundle_");
opaque_id!(PolicyProposalId, "policy_proposal_");
opaque_id!(ConnectorPublisherId, "connector_publisher_");
opaque_id!(AccessReviewId, "access_review_");
opaque_id!(DeviceChallengeId, "device_challenge_");
opaque_id!(OperatorSessionId, "operator_session_");
opaque_id!(PolicyReleaseId, "policy_release_");
opaque_id!(SecurityAlertId, "security_alert_");
opaque_id!(SiemDestinationId, "siem_destination_");
opaque_id!(WorkloadIdentityId, "workload_identity_");
opaque_id!(KeyProviderId, "key_provider_");

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActorContext {
    pub agent_id: AgentId,
    pub workload_id: Option<WorkloadId>,
    pub human_principal: Option<String>,
    pub on_behalf_of: Option<String>,
    pub client_session_id: String,
    /// Agent-supplied reason for this request, shown to an approver. It is
    /// part of the canonical digest when present, so an approval cannot be
    /// replayed under a different stated purpose. It is untrusted text and
    /// is never written to the audit log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

/// Longest accepted `ActorContext::purpose`, in characters.
pub const MAX_PURPOSE_CHARS: usize = 280;

/// Validates an agent-supplied purpose before it is bound into a request.
pub fn validate_purpose(purpose: &str) -> crate::Result<()> {
    if purpose.trim().is_empty()
        || purpose.chars().count() > MAX_PURPOSE_CHARS
        || purpose.chars().any(char::is_control)
    {
        return Err(crate::KeyLeaseError::InvalidRequest {
            reason: format!(
                "purpose must be 1..={MAX_PURPOSE_CHARS} characters without control characters"
            ),
        });
    }
    Ok(())
}
