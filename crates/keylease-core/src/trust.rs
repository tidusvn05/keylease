//! Time-boxed trust: an approver's answer that covers more than one use.
//!
//! See `docs/adr/0005-agent-trust-and-secret-use.md`. A trust is materialized
//! as an ordinary allow `PolicyRule`, so it never widens what the policy
//! engine can express; these types only describe how an approver asked for it.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{AgentId, ApprovalId, RiskTier};

/// How far an approval answer reaches beyond the request that prompted it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustScope {
    /// The same action on the same resource (and anything beneath it), with
    /// any arguments. Exact-argument trust is not offered: approvals keep only
    /// argument fingerprints, never values that could hold secrets.
    Resource,
    /// The same action on any field of the same vault item.
    Item,
}

/// The durations an approver may choose. Anything else is rejected, so a UI
/// cannot be talked into an arbitrary window.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum TrustDuration {
    #[serde(rename = "once")]
    Once,
    #[serde(rename = "30m")]
    Minutes30,
    #[serde(rename = "1h")]
    Hour1,
    #[serde(rename = "6h")]
    Hours6,
    #[serde(rename = "1d")]
    Day1,
    #[serde(rename = "3d")]
    Days3,
    #[serde(rename = "7d")]
    Days7,
}

impl TrustDuration {
    pub const ALL: [Self; 7] = [
        Self::Once,
        Self::Minutes30,
        Self::Hour1,
        Self::Hours6,
        Self::Day1,
        Self::Days3,
        Self::Days7,
    ];

    pub fn seconds(self) -> u64 {
        match self {
            Self::Once => 0,
            Self::Minutes30 => 30 * 60,
            Self::Hour1 => 60 * 60,
            Self::Hours6 => 6 * 60 * 60,
            Self::Day1 => 24 * 60 * 60,
            Self::Days3 => 3 * 24 * 60 * 60,
            Self::Days7 => 7 * 24 * 60 * 60,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Minutes30 => "30m",
            Self::Hour1 => "1h",
            Self::Hours6 => "6h",
            Self::Day1 => "1d",
            Self::Days3 => "3d",
            Self::Days7 => "7d",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|duration| duration.label() == value)
    }
}

/// The longest trust a risk tier admits, in seconds. `None` means the action
/// may only ever be approved once.
pub fn max_trust_seconds(risk: &RiskTier) -> Option<u64> {
    match risk {
        RiskTier::R0 | RiskTier::R1 => Some(TrustDuration::Days7.seconds()),
        RiskTier::R2 => Some(TrustDuration::Day1.seconds()),
        RiskTier::R3 => Some(TrustDuration::Hour1.seconds()),
        RiskTier::R4 => None,
    }
}

/// The durations an approver is offered for a risk tier, shortest first.
pub fn allowed_trust_durations(risk: &RiskTier) -> Vec<TrustDuration> {
    let ceiling = max_trust_seconds(risk).unwrap_or(0);
    TrustDuration::ALL
        .into_iter()
        .filter(|duration| duration.seconds() <= ceiling)
        .collect()
}

/// An approver's request to turn an approval into a time-boxed trust.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustDecision {
    pub scope: TrustScope,
    pub duration: TrustDuration,
}

/// A granted trust, as listed in the Active trusts view.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustRecord {
    pub id: String,
    pub agent_id: AgentId,
    pub action: String,
    pub resource_prefix: String,
    pub connection_id: Option<String>,
    pub scope: TrustScope,
    pub duration: TrustDuration,
    pub risk: RiskTier,
    pub approval_id: ApprovalId,
    pub decided_by: AgentId,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Rule-ID prefix that marks a policy rule as a materialized trust.
pub const TRUST_RULE_PREFIX: &str = "trust_";

/// Policy version of trust rules. It is above the version of every
/// hand-written grant and baseline rule, so an active trust wins over the
/// `require_approval` rule that prompted it; an explicit deny still wins.
pub const TRUST_RULE_VERSION: u64 = 2;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn durations_round_trip_and_are_capped_by_risk() {
        for duration in TrustDuration::ALL {
            let encoded = serde_json::to_value(duration).unwrap();
            assert_eq!(encoded, Value::String(duration.label().into()));
            assert_eq!(TrustDuration::parse(duration.label()), Some(duration));
        }
        assert_eq!(TrustDuration::parse("2h"), None);
        assert_eq!(
            allowed_trust_durations(&RiskTier::R4),
            vec![TrustDuration::Once]
        );
        assert_eq!(
            allowed_trust_durations(&RiskTier::R3).last(),
            Some(&TrustDuration::Hour1)
        );
        assert_eq!(
            allowed_trust_durations(&RiskTier::R2).last(),
            Some(&TrustDuration::Day1)
        );
        assert_eq!(
            allowed_trust_durations(&RiskTier::R1).last(),
            Some(&TrustDuration::Days7)
        );
    }
}
