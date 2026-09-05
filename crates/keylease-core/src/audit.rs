use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{AgentId, ConnectionId, RequestId};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub schema_version: u32,
    pub timestamp: DateTime<Utc>,
    pub request_id: RequestId,
    pub agent_id: AgentId,
    pub workload_id: Option<String>,
    pub on_behalf_of: Option<String>,
    pub action: String,
    pub resource: String,
    pub connection_id: Option<ConnectionId>,
    pub policy_version: Option<u64>,
    pub decision: String,
    pub connector: Option<String>,
    pub outcome: String,
    pub item_count: Option<u64>,
    pub cell_count: Option<u64>,
    pub byte_count: Option<u64>,
    pub changed_fields: Vec<String>,
}

impl AuditEvent {
    pub fn contains_forbidden_content(&self, fixtures: &[&str]) -> bool {
        let encoded = serde_json::to_string(self).unwrap_or_default();
        fixtures
            .iter()
            .any(|secret| !secret.is_empty() && encoded.contains(secret))
    }
}
