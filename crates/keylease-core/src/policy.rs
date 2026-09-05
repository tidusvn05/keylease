use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{ActionRequest, AgentId, DataBudget, RiskTier};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub id: String,
    pub version: u64,
    pub effect: PolicyEffect,
    pub agent_id: Option<AgentId>,
    pub connection_id: Option<String>,
    pub resource_prefix: String,
    pub actions: Vec<String>,
    #[serde(default)]
    pub argument_equals: std::collections::BTreeMap<String, Value>,
    pub not_before: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub max_lease_ttl_seconds: u64,
    pub max_uses: u64,
    pub budget: DataBudget,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Deny,
    Allow,
    RequireApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum PolicyDecision {
    Deny {
        reason: String,
        matched_rule: Option<String>,
    },
    Allow {
        policy_version: u64,
        matched_rule: String,
        max_ttl_seconds: u64,
        max_uses: u64,
        budget: DataBudget,
    },
    RequireApproval {
        policy_version: u64,
        matched_rule: String,
        request_digest_hex: String,
        risk: RiskTier,
        max_ttl_seconds: u64,
        max_uses: u64,
        budget: DataBudget,
    },
}

pub trait PolicyEngine: Send + Sync {
    fn evaluate(
        &self,
        request: &ActionRequest,
        risk: RiskTier,
        now: DateTime<Utc>,
    ) -> PolicyDecision;
}
