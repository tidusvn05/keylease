use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{ApprovalId, ConnectionId, DataBudget, LeaseId};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustMode {
    EdgeLocal,
    ManagedGateway,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionHealth {
    Connected,
    Degraded,
    Expired,
    Revoked,
    Disconnected,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectionRecord {
    pub id: ConnectionId,
    pub provider: String,
    pub connector_version: String,
    pub auth_method: String,
    pub trust_mode: TrustMode,
    pub execution_location: String,
    pub credential_item_id: String,
    pub health: ConnectionHealth,
    pub authorized_resources: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    Pending,
    Approved,
    Consumed,
    Denied,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRecord {
    pub id: ApprovalId,
    pub request_digest_hex: String,
    pub policy_version: u64,
    pub state: ApprovalState,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub request_id: Option<crate::RequestId>,
    #[serde(default)]
    pub agent_id: Option<crate::AgentId>,
    #[serde(default)]
    pub connection_id: Option<ConnectionId>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccessLease {
    pub id: LeaseId,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token: String,
    pub request_digest_hex: String,
    pub policy_version: u64,
    pub action: String,
    pub resource: String,
    pub audience: String,
    pub expires_at: DateTime<Utc>,
    pub max_uses: u64,
    pub remaining_uses: u64,
    pub budget: DataBudget,
    pub approval_id: Option<ApprovalId>,
    pub session_id: String,
    pub revoked: bool,
}

impl std::fmt::Debug for AccessLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AccessLease")
            .field("id", &self.id)
            .field("token", &"[REDACTED]")
            .field("request_digest_hex", &self.request_digest_hex)
            .field("policy_version", &self.policy_version)
            .field("action", &self.action)
            .field("resource", &self.resource)
            .field("audience", &self.audience)
            .field("expires_at", &self.expires_at)
            .field("max_uses", &self.max_uses)
            .field("remaining_uses", &self.remaining_uses)
            .field("budget", &self.budget)
            .field("approval_id", &self.approval_id)
            .field("session_id", &self.session_id)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl Drop for AccessLease {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}
