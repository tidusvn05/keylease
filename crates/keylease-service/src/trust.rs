//! Vault approvals, agent baselines and time-boxed trust (ADR 0005).
//!
//! Vault commands used to turn `require_approval` into a denial. They now
//! queue an approval bound to the request digest; the agent retries the same
//! request and the approved approval is consumed atomically with the use. An
//! approver may instead answer with a time-boxed trust, which is stored as an
//! ordinary allow rule that survives a vault lock until it expires or is
//! revoked.

use super::*;

/// Vault approvals expire if nobody decides them, like connector approvals.
const VAULT_APPROVAL_TTL_MINUTES: i64 = 10;

/// Connection ID that vault commands are evaluated under.
pub(crate) const VAULT_CONNECTION_ID: &str = "conn_vault";

/// Prefix of the rules installed by [`KeyLeaseService::enroll_agent_authorized`].
const BASELINE_RULE_PREFIX: &str = "baseline_";

/// Vault actions an enrolled agent may use without asking. None of them
/// returns a secret value: `entry:read_fields` returns the redacted view and
/// `ssh:list_keys` only public keys.
const BASELINE_ALLOW_ACTIONS: &[&str] = &[
    "entry:search",
    "entry:read_metadata",
    "entry:read_fields",
    "ssh:list_keys",
];

/// Vault actions an enrolled agent may request, each needing an approval or a
/// trust.
const BASELINE_APPROVAL_ACTIONS: &[&str] = &[
    "entry:read_username",
    "entry:read_secret",
    "entry:inject_secret",
    "entry:create",
    "entry:update_standard_fields",
    "entry:update_protected_fields",
    "entry:update_totp",
    "entry:move",
    "entry:delete",
    "group:create",
    "group:update",
    "ssh:sign",
    "db:connect",
];

/// Risk of a vault command, which caps how long it may be trusted.
pub(crate) fn vault_action_risk(action: &str) -> RiskTier {
    match action {
        "entry:search" | "entry:read_metadata" | "entry:read_fields" | "ssh:list_keys" => {
            RiskTier::R0
        }
        "entry:read_username" | "group:create" | "group:update" => RiskTier::R1,
        "entry:create"
        | "entry:update_standard_fields"
        | "entry:move"
        | "ssh:sign"
        | "db:connect" => RiskTier::R2,
        "entry:update_protected_fields" | "entry:update_totp" | "entry:delete" | "group:delete" => {
            RiskTier::R3
        }
        // Disclosing a secret to an agent is the tier that ADR 0005 never lets
        // an approver trust for a window. Unknown actions are treated alike.
        _ => RiskTier::R4,
    }
}

fn blast_radius(risk: &RiskTier) -> &'static str {
    match risk {
        RiskTier::R0 => "metadata-only; no side effect",
        RiskTier::R1 => "bounded read from one enrolled resource",
        RiskTier::R2 => "reversible write to one enrolled resource",
        RiskTier::R3 => "high-impact write to one exact enrolled resource",
        RiskTier::R4 => "critical or destructive action",
    }
}

/// Fingerprints arguments for an approver without copying their values.
///
/// Vault commands pass `hash_values = false`: their arguments can carry a new
/// password, and an unsalted SHA-256 of it in a plaintext approval row could be
/// brute-forced offline. They keep only each argument's type and length.
pub(crate) fn semantic_summary(
    operation: &str,
    target: &str,
    arguments: &Value,
    risk: &RiskTier,
    hash_values: bool,
) -> ApprovalSemanticSummary {
    let mut changed_fields = arguments
        .as_object()
        .map(|arguments| arguments.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    changed_fields.sort();
    let argument_fingerprints = changed_fields
        .iter()
        .filter_map(|field| {
            let value = arguments.get(field)?;
            let canonical = serde_json::to_vec(&keylease_core::canonical_json(value)).ok()?;
            let value_type = match value {
                Value::Null => "null",
                Value::Bool(_) => "boolean",
                Value::Number(_) => "number",
                Value::String(_) => "string",
                Value::Array(_) => "array",
                Value::Object(_) => "object",
            };
            let length = match value {
                Value::String(value) => Some(value.len() as u64),
                Value::Array(value) => Some(value.len() as u64),
                Value::Object(value) => Some(value.len() as u64),
                _ => None,
            };
            Some(ArgumentFingerprint {
                field: field.clone(),
                value_type: value_type.into(),
                length,
                sha256: if hash_values {
                    hex(&Sha256::digest(canonical))
                } else {
                    String::new()
                },
            })
        })
        .collect();
    ApprovalSemanticSummary {
        operation: operation.into(),
        target: target.into(),
        changed_fields,
        argument_fingerprints,
        blast_radius: blast_radius(risk).into(),
    }
}

/// The `kl://<vault>/<item>` prefix of a vault resource, for item-scoped trust.
fn item_prefix(resource: &str) -> Option<String> {
    let rest = resource.strip_prefix("kl://")?;
    let mut parts = rest.split('/');
    let vault = parts.next().filter(|part| part.starts_with("vault_"))?;
    let item = parts.next().filter(|part| part.starts_with("item_"))?;
    Some(format!("kl://{vault}/{item}"))
}

/// The two rules every enrolled agent starts with.
pub(crate) fn agent_baseline_rules(agent_id: &AgentId, vault_id: &VaultId) -> Vec<PolicyRule> {
    let rule = |suffix: &str, effect: PolicyEffect, actions: &[&str]| PolicyRule {
        id: format!("{BASELINE_RULE_PREFIX}{suffix}_{}", agent_id.0),
        version: 1,
        effect,
        agent_id: Some(agent_id.clone()),
        connection_id: Some(VAULT_CONNECTION_ID.into()),
        resource_prefix: format!("kl://{}", vault_id.0),
        actions: actions.iter().map(|action| (*action).to_owned()).collect(),
        argument_equals: Default::default(),
        not_before: None,
        expires_at: None,
        max_lease_ttl_seconds: 600,
        max_uses: 100,
        budget: DataBudget::default(),
    };
    vec![
        rule("allow", PolicyEffect::Allow, BASELINE_ALLOW_ACTIONS),
        rule(
            "approval",
            PolicyEffect::RequireApproval,
            BASELINE_APPROVAL_ACTIONS,
        ),
    ]
}

/// What an approver's decision produced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDecisionOutcome {
    #[serde(flatten)]
    pub approval: ApprovalRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<TrustRecord>,
}

/// A newly enrolled agent and the token it authenticates with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrolledAgent {
    pub agent_id: AgentId,
    pub token: String,
    pub baseline_rule_ids: Vec<String>,
}

impl KeyLeaseService {
    /// Installs `rules` together with standing rules and the built-in owner
    /// rules already active, so a policy change made inside the daemon never
    /// drops the authority of the unlocked owner.
    pub(crate) fn install_policy(&self, mut rules: Vec<PolicyRule>) -> Result<()> {
        rules.extend(self.store.load_standing_rules(Utc::now())?);
        let mut engine = self.policy.write().map_err(|_| KeyLeaseError::Storage)?;
        rules.extend(
            engine
                .rules()
                .iter()
                .filter(|rule| rule.id.starts_with("builtin_"))
                .cloned(),
        );
        *engine = RulePolicyEngine::new(rules);
        Ok(())
    }

    /// Rechecks a standing rule against the store before it authorizes a use.
    ///
    /// The engine is an in-memory copy. A trust revoked by another process (an
    /// admin CLI, or the kill switch) must stop working immediately, not at the
    /// next unlock.
    pub(crate) fn confirm_standing_rule(&self, matched_rule: &str) -> Result<()> {
        if !matched_rule.starts_with(TRUST_RULE_PREFIX) {
            return Ok(());
        }
        let active = self
            .store
            .list_trusts(Utc::now())?
            .iter()
            .any(|trust| trust.id == matched_rule);
        if !active || self.store.kill_switch_enabled()? {
            self.drop_inactive_trust_rules()?;
            return Err(KeyLeaseError::Denied {
                reason: "trust was revoked or has expired".into(),
            });
        }
        Ok(())
    }

    /// Removes trust rules from the in-memory engine that the store no longer
    /// holds, keeping every other rule as it is.
    pub(crate) fn drop_inactive_trust_rules(&self) -> Result<()> {
        let active = self
            .store
            .list_trusts(Utc::now())?
            .into_iter()
            .map(|trust| trust.id)
            .collect::<std::collections::HashSet<_>>();
        let mut engine = self.policy.write().map_err(|_| KeyLeaseError::Storage)?;
        let rules = engine
            .rules()
            .iter()
            .filter(|rule| !rule.id.starts_with(TRUST_RULE_PREFIX) || active.contains(&rule.id))
            .cloned()
            .collect();
        *engine = RulePolicyEngine::new(rules);
        Ok(())
    }

    /// Queues or consumes an approval for a vault command.
    ///
    /// The first call queues a pending approval and returns
    /// `approval_required`. A retry of the identical request — same agent,
    /// session, purpose, resource, action and arguments — finds the approval;
    /// once it is approved the retry consumes it atomically with the audit of
    /// the use, so one approval authorizes exactly one use.
    pub(crate) fn vault_approval_gate(
        &self,
        actor: &ActorContext,
        request: &ActionRequest,
        policy_version: u64,
        request_digest_hex: &str,
        risk: RiskTier,
    ) -> Result<()> {
        if self.store.kill_switch_enabled()? {
            self.audit_vault(
                actor,
                &request.action,
                &request.resource,
                "deny",
                "kill_switch",
                vec![],
            )?;
            return Err(KeyLeaseError::Denied {
                reason: "global kill switch is enabled".into(),
            });
        }
        let now = Utc::now();
        if let Some(open) = self.store.find_open_approval(
            &actor.agent_id,
            request_digest_hex,
            policy_version,
            now,
        )? {
            if open.state == ApprovalState::Denied {
                self.store.retire_denied_approval(&open.id.0)?;
                self.audit_vault(
                    actor,
                    &request.action,
                    &request.resource,
                    "deny",
                    "approval_denied",
                    vec![],
                )?;
                return Err(KeyLeaseError::Denied {
                    reason: "the approver denied this request".into(),
                });
            }
            if open.state != ApprovalState::Approved {
                return Err(KeyLeaseError::ApprovalRequired {
                    approval_id: open.id.0,
                });
            }
            let mut event = self.vault_audit_event(
                actor,
                &request.action,
                &request.resource,
                "approved",
                "approval_consumed",
                vec![],
            );
            event.policy_version = Some(policy_version);
            self.store.consume_approval_with_audit(
                &open.id.0,
                request_digest_hex,
                policy_version,
                now,
                &event,
            )?;
            return Ok(());
        }
        let approval = ApprovalRecord {
            id: ApprovalId::new(),
            request_digest_hex: request_digest_hex.into(),
            policy_version,
            state: ApprovalState::Pending,
            expires_at: now + Duration::minutes(VAULT_APPROVAL_TTL_MINUTES),
            request_id: Some(request.request_id.clone()),
            agent_id: Some(actor.agent_id.clone()),
            connection_id: Some(request.connection_id.clone()),
            action: Some(request.action.clone()),
            resource: Some(request.resource.clone()),
            created_at: Some(now),
            task_id: request.task_id.clone(),
            semantic_summary: Some(semantic_summary(
                &request.action,
                &request.resource,
                &request.arguments,
                &risk,
                false,
            )),
            risk: Some(risk),
            purpose: actor.purpose.clone(),
        };
        let mut event = self.vault_audit_event(
            actor,
            &request.action,
            &request.resource,
            "require_approval",
            "pending",
            vec![],
        );
        event.policy_version = Some(policy_version);
        self.store.save_approval_with_audit(&approval, &event)?;
        Err(KeyLeaseError::ApprovalRequired {
            approval_id: approval.id.0,
        })
    }

    /// Decides a pending approval, optionally granting a time-boxed trust.
    pub fn decide_approval_with_trust_authorized(
        &self,
        actor: &ActorContext,
        id: &str,
        approve: bool,
        trust: Option<TrustDecision>,
    ) -> Result<ApprovalDecisionOutcome> {
        let trust = trust.filter(|decision| decision.duration != TrustDuration::Once);
        if trust.is_some() && !approve {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "only an approval can grant trust".into(),
            });
        }
        self.with_vault(|vault| {
            self.authorize_vault(
                actor,
                "approval:decide",
                &format!("kl://{}/approval/{id}", vault.vault_id.0),
                serde_json::json!({"approve":approve}),
            )
        })?;
        self.decide_approval_as(actor, id, approve, trust)
    }

    /// Records a decision whose authority the caller has already established:
    /// the policy engine for a local client, a verified device signature for a
    /// paired remote approver.
    pub(crate) fn decide_approval_as(
        &self,
        actor: &ActorContext,
        id: &str,
        approve: bool,
        trust: Option<TrustDecision>,
    ) -> Result<ApprovalDecisionOutcome> {
        let trust = trust.filter(|decision| decision.duration != TrustDuration::Once);
        if trust.is_some() && !approve {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "only an approval can grant trust".into(),
            });
        }
        if trust.is_some() && self.store.kill_switch_enabled()? {
            return Err(KeyLeaseError::Denied {
                reason: "trust cannot be granted while the kill switch is enabled".into(),
            });
        }
        let granted = self.with_vault(|vault| {
            let resource = format!("kl://{}/approval/{id}", vault.vault_id.0);
            let pending = self.store.get_approval(id)?;
            if pending.agent_id.as_ref() == Some(&actor.agent_id) {
                return Err(KeyLeaseError::Denied {
                    reason: "an agent cannot decide its own approval".into(),
                });
            }
            let materialized = trust
                .map(|decision| materialize_trust(&pending, decision, &actor.agent_id))
                .transpose()?;
            let event = self.vault_audit_event(
                actor,
                "approval:decide",
                &resource,
                "allow",
                match (&materialized, approve) {
                    (Some(_), _) => "approved_with_trust",
                    (None, true) => "approved",
                    (None, false) => "denied",
                },
                vec!["state".into()],
            );
            let approval = self.store.decide_pending_approval_with_trust(
                id,
                if approve {
                    ApprovalState::Approved
                } else {
                    ApprovalState::Denied
                },
                Utc::now(),
                Some(&event),
                materialized.as_ref().map(|(record, rule)| (record, rule)),
            )?;
            Ok((approval, materialized))
        })?;
        let (approval, materialized) = granted;
        if materialized.is_some() {
            let stored = self.store.load_policy_rules()?;
            self.install_policy(stored)?;
        }
        Ok(ApprovalDecisionOutcome {
            approval,
            trust: materialized.map(|(record, _)| record),
        })
    }

    pub fn list_trusts_authorized(&self, actor: &ActorContext) -> Result<Vec<TrustRecord>> {
        self.with_vault(|vault| {
            let resource = format!("kl://{}/trusts", vault.vault_id.0);
            self.authorize_vault(
                actor,
                "trust:list",
                &resource,
                Value::Object(Default::default()),
            )?;
            self.store.list_trusts(Utc::now())
        })
    }

    pub fn revoke_trust_authorized(&self, actor: &ActorContext, id: &str) -> Result<()> {
        self.with_vault(|vault| {
            let resource = format!("kl://{}/trust/{id}", vault.vault_id.0);
            self.authorize_vault(
                actor,
                "trust:revoke",
                &resource,
                Value::Object(Default::default()),
            )?;
            let event = self.vault_audit_event(
                actor,
                "trust:revoke",
                &resource,
                "allow",
                "revoked",
                vec![],
            );
            self.store.revoke_trust(id, &event)
        })?;
        let stored = self.store.load_policy_rules()?;
        self.install_policy(stored)
    }

    /// Registers a least-privilege agent for the open vault.
    ///
    /// The agent can search and view redacted entries; every secret read or
    /// write queues an approval. Only the desktop owner may enroll, because an
    /// agent able to mint clients could mint one to approve its own requests.
    pub fn enroll_agent_authorized(
        &self,
        actor: &ActorContext,
        name: &str,
    ) -> Result<EnrolledAgent> {
        if !self.desktop_owner_only(&actor.agent_id)? {
            return Err(KeyLeaseError::Denied {
                reason: "only the desktop owner can enroll an agent".into(),
            });
        }
        let vault_id = self.with_vault(|vault| {
            self.authorize_vault(
                actor,
                "client:enroll",
                &format!("kl://{}/clients", vault.vault_id.0),
                serde_json::json!({"name":name}),
            )?;
            Ok(vault.vault_id.clone())
        })?;
        let (agent_id, token) = self.register_client(name)?;
        let enrolled = self.install_agent_baseline(&agent_id, &vault_id);
        if let Err(error) = enrolled {
            // Never leave a client behind that has a token but no baseline.
            let _ = self.store.revoke_client(&agent_id);
            return Err(error);
        }
        self.audit_vault(
            actor,
            "client:enroll",
            &format!("kl://{}/clients/{}", vault_id.0, agent_id.0),
            "allow",
            "success",
            vec![],
        )?;
        Ok(EnrolledAgent {
            baseline_rule_ids: enrolled?,
            agent_id,
            token,
        })
    }

    /// Installs the enrolled-agent baseline for an existing client. Used by
    /// the headless admin path, where no desktop owner exists.
    pub fn install_agent_baseline(
        &self,
        agent_id: &AgentId,
        vault_id: &VaultId,
    ) -> Result<Vec<String>> {
        if self.is_local_owner(agent_id)? {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "an owner client does not take an agent baseline".into(),
            });
        }
        let rules = agent_baseline_rules(agent_id, vault_id);
        self.store.replace_agent_baseline_rules(agent_id, &rules)?;
        let stored = self.store.load_policy_rules()?;
        self.install_policy(stored)?;
        Ok(rules.into_iter().map(|rule| rule.id).collect())
    }

    /// The vault ID of the unlocked vault.
    pub fn current_vault_id(&self) -> Result<VaultId> {
        self.with_vault(|vault| Ok(vault.vault_id.clone()))
    }
}

/// Turns an approver's trust decision into a record and its allow rule.
fn materialize_trust(
    approval: &ApprovalRecord,
    decision: TrustDecision,
    decided_by: &AgentId,
) -> Result<(TrustRecord, PolicyRule)> {
    let invalid = |reason: &str| KeyLeaseError::InvalidRequest {
        reason: reason.into(),
    };
    let agent_id = approval
        .agent_id
        .clone()
        .ok_or_else(|| invalid("approval has no requesting agent"))?;
    let action = approval
        .action
        .clone()
        .ok_or_else(|| invalid("approval has no action"))?;
    let resource = approval
        .resource
        .clone()
        .ok_or_else(|| invalid("approval has no resource"))?;
    if approval.connection_id.as_ref().map(|id| id.0.as_str()) != Some(VAULT_CONNECTION_ID) {
        // A connector trust would need the matched rule's budget, use and TTL
        // limits, which the approval does not record yet.
        return Err(KeyLeaseError::InvalidRequest {
            reason: "time-boxed trust is only available for vault commands; approve once".into(),
        });
    }
    let risk = approval.risk.clone().unwrap_or(RiskTier::R4);
    let ceiling = max_trust_seconds(&risk).ok_or_else(|| KeyLeaseError::Denied {
        reason: "this risk tier may only be approved once".into(),
    })?;
    if decision.duration.seconds() > ceiling {
        return Err(KeyLeaseError::Denied {
            reason: "trust duration exceeds the ceiling for this risk tier".into(),
        });
    }
    let resource_prefix = match decision.scope {
        TrustScope::Resource => resource,
        TrustScope::Item => item_prefix(&resource)
            .ok_or_else(|| invalid("item scope needs a vault item resource"))?,
    };
    let now = Utc::now();
    let expires_at = now + Duration::seconds(decision.duration.seconds() as i64);
    let id = format!("{TRUST_RULE_PREFIX}{}", uuid::Uuid::now_v7().simple());
    let connection_id = approval.connection_id.as_ref().map(|id| id.0.clone());
    let rule = PolicyRule {
        id: id.clone(),
        version: TRUST_RULE_VERSION,
        effect: PolicyEffect::Allow,
        agent_id: Some(agent_id.clone()),
        connection_id: connection_id.clone(),
        resource_prefix: resource_prefix.clone(),
        actions: vec![action.clone()],
        argument_equals: Default::default(),
        not_before: None,
        expires_at: Some(expires_at),
        max_lease_ttl_seconds: 600,
        max_uses: 100,
        budget: DataBudget::default(),
    };
    let record = TrustRecord {
        id,
        agent_id,
        action,
        resource_prefix,
        connection_id,
        scope: decision.scope,
        duration: decision.duration,
        risk,
        approval_id: approval.id.clone(),
        decided_by: decided_by.clone(),
        created_at: now,
        expires_at,
    };
    Ok((record, rule))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _dir: tempfile::TempDir,
        service: KeyLeaseService,
        owner_id: AgentId,
        owner: ActorContext,
        agent: ActorContext,
        item: ItemId,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(NativeStore::open(dir.path().join("vault.sqlite")).unwrap());
        let service = KeyLeaseService::new(store).unwrap();
        service.initialize(b"password", Duration::hours(1)).unwrap();
        let (owner_id, owner_token) = service.register_desktop_client().unwrap();
        service.lock().unwrap();
        service
            .unlock_for_client(&owner_id, b"password", Duration::hours(1))
            .unwrap();
        let owner = service
            .authenticate(&owner_id, &owner_token, "desktop")
            .unwrap();
        let group = service.create_group("Servers", None).unwrap();
        let item = service
            .create_entry(
                &owner,
                NewEntryInput {
                    favorite: false,
                    group_id: group.id,
                    kind: "core.login".into(),
                    title: "Staging".into(),
                    project_slug: None,
                    username: Some("deploy".into()),
                    password: Some("trust-fixture-secret".into()),
                    url: Some("https://staging.example.com".into()),
                    notes: None,
                    custom_fields: vec![],
                    sections: vec![],
                    totp: None,
                    totp_uri: None,
                },
                "fixture-entry",
                false,
            )
            .unwrap()
            .id;
        let enrolled = service.enroll_agent_authorized(&owner, "codex").unwrap();
        let mut agent = service
            .authenticate(&enrolled.agent_id, &enrolled.token, "agent-session")
            .unwrap();
        agent.purpose = Some("deploy the staging release".into());
        Fixture {
            _dir: dir,
            service,
            owner_id,
            owner,
            agent,
            item,
        }
    }

    fn approval_id(result: Result<impl std::fmt::Debug>) -> String {
        match result {
            Err(KeyLeaseError::ApprovalRequired { approval_id }) => approval_id,
            other => panic!("expected approval_required, got {other:?}"),
        }
    }

    #[test]
    fn enrolled_agent_reveal_needs_one_approval_per_use() {
        let f = fixture();
        assert!(f.service.search_entries(&f.agent, "staging").is_ok());
        assert!(f.service.get_entry_view(&f.agent, &f.item).is_ok());

        let first = approval_id(
            f.service
                .reveal_field_authorized(&f.agent, &f.item, "password"),
        );
        let retried = approval_id(
            f.service
                .reveal_field_authorized(&f.agent, &f.item, "password"),
        );
        assert_eq!(
            first, retried,
            "a retry must not queue a duplicate approval"
        );
        assert_eq!(f.service.status().unwrap()["pending_approvals"], 1);

        let pending = f
            .service
            .list_pending_approvals_authorized(&f.owner, 10)
            .unwrap();
        let record = pending.iter().find(|a| a.id.0 == first).unwrap();
        assert_eq!(
            record.purpose.as_deref(),
            Some("deploy the staging release")
        );
        assert_eq!(record.risk, Some(RiskTier::R4));
        assert!(
            !serde_json::to_string(record)
                .unwrap()
                .contains("trust-fixture-secret")
        );

        assert!(matches!(
            f.service.decide_approval_authorized(&f.agent, &first, true),
            Err(KeyLeaseError::Denied { .. })
        ));
        assert!(matches!(
            f.service.decide_approval_with_trust_authorized(
                &f.owner,
                &first,
                true,
                Some(TrustDecision {
                    scope: TrustScope::Resource,
                    duration: TrustDuration::Minutes30,
                }),
            ),
            Err(KeyLeaseError::Denied { .. })
        ));

        f.service
            .decide_approval_authorized(&f.owner, &first, true)
            .unwrap();
        assert_eq!(
            f.service
                .reveal_field_authorized(&f.agent, &f.item, "password")
                .unwrap(),
            "trust-fixture-secret"
        );
        let next = approval_id(
            f.service
                .reveal_field_authorized(&f.agent, &f.item, "password"),
        );
        assert_ne!(next, first, "an approval authorizes exactly one use");
    }

    #[test]
    fn approval_is_bound_to_the_stated_purpose() {
        let f = fixture();
        let first = approval_id(
            f.service
                .reveal_field_authorized(&f.agent, &f.item, "password"),
        );
        f.service
            .decide_approval_authorized(&f.owner, &first, true)
            .unwrap();
        let mut other = f.agent.clone();
        other.purpose = Some("something else".into());
        let second = approval_id(
            f.service
                .reveal_field_authorized(&other, &f.item, "password"),
        );
        assert_ne!(first, second);
    }

    #[test]
    fn denied_approval_is_not_usable() {
        let f = fixture();
        let id = approval_id(
            f.service
                .reveal_field_authorized(&f.agent, &f.item, "password"),
        );
        f.service
            .decide_approval_authorized(&f.owner, &id, false)
            .unwrap();
        // The retry learns of the denial once, then may ask again.
        assert!(matches!(
            f.service
                .reveal_field_authorized(&f.agent, &f.item, "password"),
            Err(KeyLeaseError::Denied { .. })
        ));
        let next = approval_id(
            f.service
                .reveal_field_authorized(&f.agent, &f.item, "password"),
        );
        assert_ne!(next, id);
    }

    #[test]
    fn trust_covers_a_window_survives_lock_and_is_revocable() {
        let f = fixture();
        let id = approval_id(
            f.service
                .reveal_field_authorized(&f.agent, &f.item, "username"),
        );
        let outcome = f
            .service
            .decide_approval_with_trust_authorized(
                &f.owner,
                &id,
                true,
                Some(TrustDecision {
                    scope: TrustScope::Item,
                    duration: TrustDuration::Day1,
                }),
            )
            .unwrap();
        let trust = outcome.trust.unwrap();
        assert_eq!(trust.risk, RiskTier::R1);
        let before = f.service.audit_query(1000).unwrap().len();
        for _ in 0..3 {
            assert_eq!(
                f.service
                    .reveal_field_authorized(&f.agent, &f.item, "username")
                    .unwrap(),
                "deploy"
            );
        }
        let trusted_uses = f
            .service
            .audit_query(1000)
            .unwrap()
            .into_iter()
            .filter(|event| event.trust_id.as_deref() == Some(trust.id.as_str()))
            .count();
        assert_eq!(trusted_uses, 3);
        assert!(f.service.audit_query(1000).unwrap().len() > before);
        // The trust names one action: it never widens to secret reads.
        approval_id(
            f.service
                .reveal_field_authorized(&f.agent, &f.item, "password"),
        );

        f.service.lock().unwrap();
        f.service
            .unlock_for_client(&f.owner_id, b"password", Duration::hours(1))
            .unwrap();
        assert_eq!(
            f.service
                .reveal_field_authorized(&f.agent, &f.item, "username")
                .unwrap(),
            "deploy"
        );

        let listed = f.service.list_trusts_authorized(&f.owner).unwrap();
        assert_eq!(listed.len(), 1);
        assert!(f.service.list_trusts_authorized(&f.agent).is_err());
        f.service
            .revoke_trust_authorized(&f.owner, &trust.id)
            .unwrap();
        approval_id(
            f.service
                .reveal_field_authorized(&f.agent, &f.item, "username"),
        );
    }

    #[test]
    fn trust_duration_is_capped_by_risk() {
        let f = fixture();
        let id = approval_id(
            f.service
                .reveal_field_authorized(&f.agent, &f.item, "username"),
        );
        assert!(
            f.service
                .decide_approval_with_trust_authorized(
                    &f.owner,
                    &id,
                    true,
                    Some(TrustDecision {
                        scope: TrustScope::Resource,
                        duration: TrustDuration::Days7,
                    }),
                )
                .is_ok()
        );
        let pending = ApprovalRecord {
            risk: Some(RiskTier::R3),
            ..f.service.store.get_approval(&id).unwrap()
        };
        for (duration, allowed) in [
            (TrustDuration::Minutes30, true),
            (TrustDuration::Hour1, true),
            (TrustDuration::Hours6, false),
        ] {
            let decision = TrustDecision {
                scope: TrustScope::Resource,
                duration,
            };
            assert_eq!(
                materialize_trust(&pending, decision, &f.owner_id).is_ok(),
                allowed
            );
        }
    }

    #[test]
    fn kill_switch_and_client_revocation_end_standing_authority() {
        let f = fixture();
        let grant = |service: &KeyLeaseService| {
            let id = approval_id(service.reveal_field_authorized(&f.agent, &f.item, "username"));
            service
                .decide_approval_with_trust_authorized(
                    &f.owner,
                    &id,
                    true,
                    Some(TrustDecision {
                        scope: TrustScope::Resource,
                        duration: TrustDuration::Hour1,
                    }),
                )
                .unwrap();
            assert!(
                service
                    .reveal_field_authorized(&f.agent, &f.item, "username")
                    .is_ok()
            );
        };
        grant(&f.service);
        f.service.kill_switch(true).unwrap();
        assert!(matches!(
            f.service
                .reveal_field_authorized(&f.agent, &f.item, "username"),
            Err(KeyLeaseError::Denied { .. })
        ));
        f.service.kill_switch(false).unwrap();
        approval_id(
            f.service
                .reveal_field_authorized(&f.agent, &f.item, "username"),
        );

        f.service.store.revoke_client(&f.agent.agent_id).unwrap();
        assert!(
            f.service
                .store
                .load_standing_rules(Utc::now())
                .unwrap()
                .iter()
                .all(|rule| rule.agent_id.as_ref() != Some(&f.agent.agent_id))
        );
    }

    #[test]
    fn kill_switch_stops_baseline_allows_but_not_the_owner() {
        let f = fixture();
        assert!(f.service.search_entries(&f.agent, "").is_ok());
        f.service.kill_switch(true).unwrap();
        assert!(matches!(
            f.service.search_entries(&f.agent, ""),
            Err(KeyLeaseError::Denied { .. })
        ));
        assert!(f.service.search_entries(&f.owner, "").is_ok());
    }

    #[test]
    fn vault_approvals_keep_no_value_hashes_and_connector_trust_is_refused() {
        let f = fixture();
        let id = approval_id(
            f.service
                .reveal_field_authorized(&f.agent, &f.item, "username"),
        );
        let record = f.service.store.get_approval(&id).unwrap();
        let summary = record.semantic_summary.clone().unwrap();
        assert!(!summary.argument_fingerprints.is_empty());
        assert!(
            summary
                .argument_fingerprints
                .iter()
                .all(|fp| fp.sha256.is_empty())
        );
        let connector = ApprovalRecord {
            connection_id: Some(ConnectionId("conn_github".into())),
            risk: Some(RiskTier::R1),
            ..record
        };
        assert!(
            materialize_trust(
                &connector,
                TrustDecision {
                    scope: TrustScope::Resource,
                    duration: TrustDuration::Hour1,
                },
                &f.owner_id,
            )
            .is_err()
        );
    }

    #[test]
    fn only_the_desktop_owner_enrolls_agents() {
        let f = fixture();
        assert!(matches!(
            f.service.enroll_agent_authorized(&f.agent, "sneaky"),
            Err(KeyLeaseError::Denied { .. })
        ));
    }

    #[test]
    fn item_prefix_accepts_only_vault_item_resources() {
        assert_eq!(
            item_prefix("kl://vault_1/item_2/field_3").as_deref(),
            Some("kl://vault_1/item_2")
        );
        assert_eq!(
            item_prefix("kl://vault_1/item_2").as_deref(),
            Some("kl://vault_1/item_2")
        );
        assert_eq!(item_prefix("kl://vault_1"), None);
        assert_eq!(item_prefix("kl://vault_1/approval/x"), None);
        assert_eq!(item_prefix("google:drive/file/1"), None);
    }

    #[test]
    fn secret_disclosure_is_never_trustable() {
        assert_eq!(vault_action_risk("entry:read_secret"), RiskTier::R4);
        assert_eq!(vault_action_risk("unknown:action"), RiskTier::R4);
        assert!(max_trust_seconds(&vault_action_risk("entry:read_secret")).is_none());
        assert!(max_trust_seconds(&vault_action_risk("ssh:sign")).is_some());
    }
}
