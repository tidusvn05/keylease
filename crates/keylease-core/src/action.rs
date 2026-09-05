use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{ActorContext, CONTRACT_VERSION, ConnectionId, RequestId, TaskId};

#[derive(Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ActionRequest {
    pub schema_version: u32,
    pub request_id: RequestId,
    pub subject: ActorContext,
    pub task_id: Option<TaskId>,
    pub connection_id: ConnectionId,
    pub resource: String,
    pub action: String,
    pub arguments: Value,
    pub idempotency_key: String,
}

impl std::fmt::Debug for ActionRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActionRequest")
            .field("schema_version", &self.schema_version)
            .field("request_id", &self.request_id)
            .field("subject", &self.subject)
            .field("task_id", &self.task_id)
            .field("connection_id", &self.connection_id)
            .field("resource", &self.resource)
            .field("action", &self.action)
            .field("arguments", &"[REDACTED]")
            .field("idempotency_key", &self.idempotency_key)
            .finish()
    }
}

impl ActionRequest {
    pub fn validate_version(&self) -> crate::Result<()> {
        if self.schema_version != CONTRACT_VERSION {
            return Err(crate::KeyLeaseError::UnsupportedVersion {
                version: self.schema_version,
            });
        }
        Ok(())
    }

    pub fn canonical_digest(&self, policy_version: u64) -> [u8; 32] {
        let value = serde_json::json!({
            "schema_version": self.schema_version, "subject": self.subject,
            "task_id": self.task_id, "connection_id": self.connection_id,
            "resource": self.resource, "action": self.action,
            "arguments": canonical_json(&self.arguments), "policy_version": policy_version,
        });
        Sha256::digest(serde_json::to_vec(&value).expect("serializing a JSON value cannot fail"))
            .into()
    }
}

pub fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            Value::Object(
                keys.into_iter()
                    .map(|k| (k.clone(), canonical_json(&map[k])))
                    .collect(),
            )
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical_json).collect()),
        _ => value.clone(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    R0,
    R1,
    R2,
    R3,
    R4,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContentAccess {
    None,
    Metadata,
    BoundedContent,
    FullSelectedResource,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct DataBudget {
    pub max_items: Option<u64>,
    pub max_cells: Option<u64>,
    pub max_response_bytes: Option<u64>,
    pub max_rows_changed: Option<u64>,
    pub max_concurrent: Option<u32>,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ActionResponse {
    pub provider: String,
    pub connection_id: ConnectionId,
    pub canonical_resource: String,
    pub revision: Option<String>,
    pub untrusted_content: bool,
    pub item_count: Option<u64>,
    pub cell_count: Option<u64>,
    pub body: Value,
}

impl std::fmt::Debug for ActionResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActionResponse")
            .field("provider", &self.provider)
            .field("connection_id", &self.connection_id)
            .field("canonical_resource", &self.canonical_resource)
            .field("revision", &self.revision)
            .field("untrusted_content", &self.untrusted_content)
            .field("item_count", &self.item_count)
            .field("cell_count", &self.cell_count)
            .field("body", &"[REDACTED]")
            .finish()
    }
}
