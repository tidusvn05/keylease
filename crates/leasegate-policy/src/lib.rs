//! Deterministic, versioned, deny-by-default policy evaluation.

use chrono::{DateTime, Utc};
use keylease_core::{
    ActionRequest, PolicyDecision, PolicyEffect, PolicyEngine, PolicyRule, RiskTier,
};

#[derive(Debug, Clone, Default)]
pub struct RulePolicyEngine {
    rules: Vec<PolicyRule>,
}

impl RulePolicyEngine {
    pub fn new(mut rules: Vec<PolicyRule>) -> Self {
        rules.sort_by(|a, b| a.id.cmp(&b.id));
        Self { rules }
    }
    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }
}

impl PolicyEngine for RulePolicyEngine {
    fn evaluate(
        &self,
        request: &ActionRequest,
        risk: RiskTier,
        now: DateTime<Utc>,
    ) -> PolicyDecision {
        if let Err(error) = request.validate_version() {
            return PolicyDecision::Deny {
                reason: error.to_string(),
                matched_rule: None,
            };
        }
        let matching: Vec<_> = self
            .rules
            .iter()
            .filter(|rule| matches_rule(rule, request, now))
            .collect();
        if matching.is_empty() {
            return PolicyDecision::Deny {
                reason: "default deny: no matching policy rule".into(),
                matched_rule: None,
            };
        }
        if let Some(rule) = matching.iter().find(|r| r.effect == PolicyEffect::Deny) {
            return PolicyDecision::Deny {
                reason: "explicit deny rule matched".into(),
                matched_rule: Some(rule.id.clone()),
            };
        }
        let rule = matching
            .into_iter()
            .max_by(|a, b| (a.version, &a.id).cmp(&(b.version, &b.id)))
            .expect("non-empty");
        let digest = hex(&request.canonical_digest(rule.version));
        match rule.effect {
            PolicyEffect::Deny => unreachable!(),
            PolicyEffect::Allow => PolicyDecision::Allow {
                policy_version: rule.version,
                matched_rule: rule.id.clone(),
                max_ttl_seconds: rule.max_lease_ttl_seconds,
                max_uses: rule.max_uses,
                budget: rule.budget.clone(),
            },
            PolicyEffect::RequireApproval => PolicyDecision::RequireApproval {
                policy_version: rule.version,
                matched_rule: rule.id.clone(),
                request_digest_hex: digest,
                risk,
                max_ttl_seconds: rule.max_lease_ttl_seconds,
                max_uses: rule.max_uses,
                budget: rule.budget.clone(),
            },
        }
    }
}

fn matches_rule(rule: &PolicyRule, request: &ActionRequest, now: DateTime<Utc>) -> bool {
    if rule
        .agent_id
        .as_ref()
        .is_some_and(|id| id != &request.subject.agent_id)
    {
        return false;
    }
    if rule
        .connection_id
        .as_ref()
        .is_some_and(|id| id != &request.connection_id.0)
    {
        return false;
    }
    if !resource_matches(&rule.resource_prefix, &request.resource) {
        return false;
    }
    if !rule.actions.iter().any(|action| action == &request.action) {
        return false;
    }
    if rule.not_before.is_some_and(|start| now < start)
        || rule.expires_at.is_some_and(|end| now >= end)
    {
        return false;
    }
    rule.argument_equals.iter().all(|(pointer, expected)| {
        request
            .arguments
            .pointer(pointer)
            .is_some_and(|actual| actual == expected)
    })
}

fn resource_matches(prefix: &str, resource: &str) -> bool {
    resource == prefix
        || resource
            .strip_prefix(prefix)
            .is_some_and(|tail| tail.starts_with('/') || tail.starts_with(':'))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keylease_core::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Vector {
        name: String,
        rules: Vec<PolicyRule>,
        request: ActionRequest,
        expected: String,
    }

    #[test]
    fn golden_policy_vectors() {
        let vectors: Vec<Vector> =
            serde_json::from_str(include_str!("../../../test-vectors/policy-golden.json")).unwrap();
        for vector in vectors {
            let decision = RulePolicyEngine::new(vector.rules).evaluate(
                &vector.request,
                RiskTier::R2,
                Utc::now(),
            );
            let actual = match decision {
                PolicyDecision::Deny { .. } => "deny",
                PolicyDecision::Allow { .. } => "allow",
                PolicyDecision::RequireApproval { .. } => "require_approval",
            };
            assert_eq!(actual, vector.expected, "vector {}", vector.name);
        }
    }

    #[test]
    fn approval_digest_changes_with_arguments() {
        let mut request = base_request();
        let rule = rule(PolicyEffect::RequireApproval);
        let engine = RulePolicyEngine::new(vec![rule]);
        let first = engine.evaluate(&request, RiskTier::R3, Utc::now());
        request.arguments = serde_json::json!({"title":"different"});
        let second = engine.evaluate(&request, RiskTier::R3, Utc::now());
        assert_ne!(digest(first), digest(second));
    }

    fn digest(d: PolicyDecision) -> String {
        if let PolicyDecision::RequireApproval {
            request_digest_hex, ..
        } = d
        {
            request_digest_hex
        } else {
            panic!()
        }
    }
    fn base_request() -> ActionRequest {
        ActionRequest {
            schema_version: 1,
            request_id: RequestId::new(),
            subject: ActorContext {
                agent_id: AgentId("agent_test".into()),
                workload_id: None,
                human_principal: None,
                on_behalf_of: None,
                client_session_id: "s".into(),
            },
            task_id: None,
            connection_id: ConnectionId("conn_test".into()),
            resource: "fake:resource/1".into(),
            action: "fake.write".into(),
            arguments: serde_json::json!({"title":"one"}),
            idempotency_key: "i".into(),
        }
    }
    fn rule(effect: PolicyEffect) -> PolicyRule {
        PolicyRule {
            id: "r".into(),
            version: 1,
            effect,
            agent_id: None,
            connection_id: None,
            resource_prefix: "fake:resource".into(),
            actions: vec!["fake.write".into()],
            argument_equals: Default::default(),
            not_before: None,
            expires_at: None,
            max_lease_ttl_seconds: 600,
            max_uses: 1,
            budget: Default::default(),
        }
    }
}
