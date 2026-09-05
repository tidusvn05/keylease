//! Deterministic, versioned, deny-by-default policy evaluation.

use chrono::{DateTime, Utc};
use keylease_core::{
    ActionRequest, AgentId, DataBudget, KeyLeaseError, PolicyDecision, PolicyEffect, PolicyEngine,
    PolicyRule, Result, RiskTier,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyTemplateKind {
    ReadOnly,
    Contributor,
}

#[derive(Debug, Clone)]
pub struct PolicyTemplateInput {
    pub rule_id: String,
    pub version: u64,
    pub agent_id: AgentId,
    pub connection_id: String,
    pub provider: String,
    pub exact_resource: String,
    pub kind: PolicyTemplateKind,
    pub expires_at: DateTime<Utc>,
}

/// Materializes a deterministic provider template into an explicit rule.
/// Templates are onboarding helpers; the returned rule is the authorization
/// artifact that is stored, reviewed and evaluated.
pub fn materialize_provider_template(input: PolicyTemplateInput) -> Result<PolicyRule> {
    if input.rule_id.is_empty()
        || input.connection_id.is_empty()
        || input.exact_resource.is_empty()
        || input.exact_resource.ends_with('/')
    {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "policy template requires exact non-empty identifiers".into(),
        });
    }
    let (prefix, read_actions, write_actions): (&str, &[&str], &[&str]) =
        match input.provider.as_str() {
            "github" => (
                "github:repository/",
                &[
                    "github.repository.get_metadata",
                    "github.issue.list",
                    "github.issue.get",
                    "github.pull_request.list",
                    "github.pull_request.get",
                    "github.checks.read",
                ],
                &[
                    "github.issue.create",
                    "github.issue.comment",
                    "github.pull_request.create_draft",
                    "github.pull_request.comment",
                ],
            ),
            "linear" => (
                "linear:team/",
                &["linear.issue.list", "linear.issue.get"],
                &["linear.issue.create", "linear.comment.create"],
            ),
            "notion" => (
                "notion:page/",
                &["notion.page.get_markdown"],
                &[
                    "notion.page.create",
                    "notion.page.append_markdown",
                    "notion.page.update_markdown",
                ],
            ),
            "google_workspace" => (
                "google:",
                &[
                    "google_drive.file.get_metadata",
                    "google_drive.file.export_text",
                    "google_docs.document.get",
                    "google_sheets.spreadsheet.get_metadata",
                    "google_sheets.values.read",
                    "google_sheets.values.batch_read",
                ],
                &[
                    "google_docs.document.create",
                    "google_docs.document.append",
                    "google_docs.document.update",
                    "google_sheets.rows.append",
                    "google_sheets.values.update",
                    "google_sheets.spreadsheet.create",
                ],
            ),
            _ => {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "unsupported provider policy template".into(),
                });
            }
        };
    if !input.exact_resource.starts_with(prefix) {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "resource does not belong to template provider".into(),
        });
    }
    let mut actions = read_actions
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    let effect = match input.kind {
        PolicyTemplateKind::ReadOnly => PolicyEffect::Allow,
        PolicyTemplateKind::Contributor => {
            actions.extend(write_actions.iter().map(|value| (*value).to_owned()));
            // A contributor template requires approval for all actions. A human
            // may split the materialized rule into read/allow and write/approval
            // rules after review; the safe one-rule default never silently
            // grants writes.
            PolicyEffect::RequireApproval
        }
    };
    actions.sort();
    actions.dedup();
    Ok(PolicyRule {
        id: input.rule_id,
        version: input.version,
        effect,
        agent_id: Some(input.agent_id),
        connection_id: Some(input.connection_id),
        resource_prefix: input.exact_resource,
        actions,
        argument_equals: Default::default(),
        not_before: None,
        expires_at: Some(input.expires_at),
        max_lease_ttl_seconds: 300,
        max_uses: 25,
        budget: DataBudget {
            max_items: Some(100),
            max_cells: Some(10_000),
            max_response_bytes: Some(1_048_576),
            max_rows_changed: Some(1_000),
            max_concurrent: Some(1),
            max_task_requests: Some(100),
            max_task_items: Some(1_000),
            max_task_cells: Some(50_000),
            max_task_response_bytes: Some(10 * 1_048_576),
            max_task_rows_changed: Some(5_000),
        },
    })
}

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

    #[test]
    fn provider_templates_are_exact_deterministic_and_write_safe() {
        let expires = Utc::now() + chrono::Duration::hours(1);
        let input = PolicyTemplateInput {
            rule_id: "github-contributor".into(),
            version: 2,
            agent_id: AgentId("agent_release".into()),
            connection_id: "conn_github".into(),
            provider: "github".into(),
            exact_resource: "github:repository/123".into(),
            kind: PolicyTemplateKind::Contributor,
            expires_at: expires,
        };
        let first = materialize_provider_template(input.clone()).unwrap();
        let second = materialize_provider_template(input).unwrap();
        assert_eq!(first.actions, second.actions);
        assert_eq!(first.resource_prefix, "github:repository/123");
        assert_eq!(first.effect, PolicyEffect::RequireApproval);
        assert!(
            first
                .actions
                .contains(&"github.pull_request.create_draft".into())
        );
        assert!(!first.actions.iter().any(|action| action.contains("delete")));
    }

    #[test]
    fn provider_template_rejects_cross_provider_resource() {
        let result = materialize_provider_template(PolicyTemplateInput {
            rule_id: "bad".into(),
            version: 1,
            agent_id: AgentId("agent".into()),
            connection_id: "conn".into(),
            provider: "github".into(),
            exact_resource: "notion:page/abc".into(),
            kind: PolicyTemplateKind::ReadOnly,
            expires_at: Utc::now() + chrono::Duration::hours(1),
        });
        assert!(matches!(result, Err(KeyLeaseError::InvalidRequest { .. })));
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
