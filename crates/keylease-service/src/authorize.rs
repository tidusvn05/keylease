//! Internal helpers: vault access, authorization and audit events.

use super::*;

impl KeyLeaseService {
    pub(crate) fn with_vault<T>(&self, f: impl FnOnce(&UnlockedVault) -> Result<T>) -> Result<T> {
        self.with_vault_touching(true, f)
    }
    /// Like `with_vault`, but not counted as activity: a poller (a remote
    /// approver listing requests) must not keep an idle vault unlocked.
    pub(crate) fn with_vault_passive<T>(
        &self,
        f: impl FnOnce(&UnlockedVault) -> Result<T>,
    ) -> Result<T> {
        self.with_vault_touching(false, f)
    }
    pub(crate) fn with_vault_touching<T>(
        &self,
        touch: bool,
        f: impl FnOnce(&UnlockedVault) -> Result<T>,
    ) -> Result<T> {
        let mut guard = self.session.lock().map_err(|_| KeyLeaseError::Storage)?;
        let now = Utc::now();
        if guard
            .as_ref()
            .is_some_and(|session| session.last_activity + session.idle_timeout <= now)
        {
            *guard = None;
            drop(guard);
            self.revoke_session_authority()?;
            return Err(KeyLeaseError::VaultLocked {
                requires_user_action: true,
            });
        }
        let session = guard.as_ref().ok_or(KeyLeaseError::VaultLocked {
            requires_user_action: true,
        })?;
        let result = f(&session.vault);
        if touch
            && result.is_ok()
            && let Some(session) = guard.as_mut()
        {
            session.last_activity = now;
        }
        result
    }
    pub(crate) fn current_vault_session_id(&self) -> Result<String> {
        self.with_vault(|vault| Ok(vault.session_id.clone()))
    }
    pub(crate) fn acquire_execution_slot(&self, lease: &AccessLease) -> Result<ExecutionSlot<'_>> {
        let maximum = lease.budget.max_concurrent.unwrap_or(u32::MAX);
        if maximum == 0 {
            return Err(KeyLeaseError::Denied {
                reason: "lease concurrency budget is zero".into(),
            });
        }
        let mut active = self
            .active_executions
            .lock()
            .map_err(|_| KeyLeaseError::Storage)?;
        let count = active.entry(lease.id.0.clone()).or_default();
        if *count >= maximum {
            return Err(KeyLeaseError::Denied {
                reason: "lease concurrency budget exceeded".into(),
            });
        }
        *count += 1;
        Ok(ExecutionSlot {
            active: &self.active_executions,
            lease_id: lease.id.0.clone(),
        })
    }
    pub(crate) fn revoke_session_authority(&self) -> Result<()> {
        self.store.revoke_session_authority()?;
        // Session grants and owner authority end here. Standing rules (agent
        // baselines and trusts) survive, but every use still needs an unlocked
        // vault, so they authorize nothing until the next unlock.
        *self.policy.write().map_err(|_| KeyLeaseError::Storage)? =
            RulePolicyEngine::new(trust::standing_rules(&self.store, Utc::now())?);
        self.agent_handoffs
            .lock()
            .map_err(|_| KeyLeaseError::Storage)?
            .clear();
        self.google_oauth_flows
            .lock()
            .map_err(|_| KeyLeaseError::Storage)?
            .clear();
        Ok(())
    }
    /// Rebuilds the in-memory policy when another process changed the
    /// database — a `grant create`, `client revoke` or admin approval with a
    /// trust — so the daemon never needs a restart to see it.
    pub(crate) fn sync_external_policy_changes(&self) -> Result<()> {
        use std::sync::atomic::Ordering;
        let current = self.store.data_version()?;
        if self.policy_data_version.load(Ordering::Acquire) != current {
            // Recorded only after a successful reload, so a failed one is
            // retried on the next request instead of leaving policy stale.
            let rules = self.store.load_policy_rules()?;
            self.install_policy(rules)?;
            self.policy_data_version.store(current, Ordering::Release);
        }
        Ok(())
    }
    pub(crate) fn reload_policy_for_client(
        &self,
        agent_id: &AgentId,
        vault_id: &VaultId,
    ) -> Result<()> {
        let mut rules = self.store.load_policy_rules()?;
        rules.extend(trust::standing_rules(&self.store, Utc::now())?);
        match self.store.local_owner_role(agent_id)? {
            Some(LocalOwnerRole::DesktopOwner) => {
                rules.push(desktop_owner_rule(agent_id.clone(), vault_id))
            }
            Some(LocalOwnerRole::MobileOwner) => {
                rules.push(mobile_owner_rule(agent_id.clone(), vault_id))
            }
            None => {}
        }
        *self.policy.write().map_err(|_| KeyLeaseError::Storage)? = RulePolicyEngine::new(rules);
        Ok(())
    }
    pub(crate) fn authorize_vault(
        &self,
        vault: &UnlockedVault,
        actor: &ActorContext,
        action: &str,
        resource: &str,
        arguments: Value,
    ) -> Result<()> {
        self.authorize_vault_at_risk(
            vault,
            actor,
            action,
            resource,
            arguments,
            vault_action_risk(action),
        )
    }
    /// Authorizes a vault command whose risk depends on the item (for
    /// example a production database), not only on the action.
    pub(crate) fn authorize_vault_at_risk(
        &self,
        vault: &UnlockedVault,
        actor: &ActorContext,
        action: &str,
        resource: &str,
        arguments: Value,
        risk: RiskTier,
    ) -> Result<()> {
        self.authorize_vault_grant(vault, actor, action, resource, arguments, risk)
            .map(drop)
    }

    /// Authorizes like `authorize_vault_at_risk` and returns what allowed the
    /// request: the matched rule (a `trust_…` id for a trust) or the consumed
    /// approval's id, for material that should name its grant.
    pub(crate) fn authorize_vault_grant(
        &self,
        vault: &UnlockedVault,
        actor: &ActorContext,
        action: &str,
        resource: &str,
        arguments: Value,
        risk: RiskTier,
    ) -> Result<String> {
        self.sync_external_policy_changes()?;
        self.refuse_personal_item(vault, actor, action, resource)?;
        let request = ActionRequest {
            schema_version: CONTRACT_VERSION,
            request_id: RequestId::new(),
            subject: actor.clone(),
            task_id: None,
            connection_id: ConnectionId(VAULT_CONNECTION_ID.into()),
            resource: resource.into(),
            action: action.into(),
            arguments,
            idempotency_key: "authorization-only".into(),
        };
        let evaluate = |request: &ActionRequest| {
            self.policy
                .read()
                .map(|engine| engine.evaluate(request, risk.clone(), Utc::now()))
                .map_err(|_| KeyLeaseError::Storage)
        };
        let mut decision = evaluate(&request)?;
        let mut project = None;
        if matches!(decision, PolicyDecision::RequireApproval { .. }) {
            // A project trust is a rule on the project's alias of the resource; it
            // answers only for a request that would otherwise ask the approver.
            project = self.resource_project(vault, resource, &request.arguments)?;
            if let Some(project) = &project {
                let alias = ActionRequest {
                    resource: project_alias(&vault.vault_id, project, resource),
                    ..request.clone()
                };
                let aliased = evaluate(&alias)?;
                if matches!(&aliased, PolicyDecision::Allow { matched_rule, .. }
                    if matched_rule.starts_with(TRUST_RULE_PREFIX))
                {
                    decision = aliased;
                }
            }
        }
        match decision {
            PolicyDecision::Allow { matched_rule, .. } => {
                self.confirm_standing_rule(&matched_rule)?;
                // The kill switch stops every agent, whatever rule allowed it;
                // only the vault's own owner clients keep working.
                if !self.is_local_owner(&actor.agent_id)? && self.store.kill_switch_enabled()? {
                    self.audit_vault(actor, action, resource, "deny", "kill_switch", vec![])?;
                    return Err(KeyLeaseError::Denied {
                        reason: "global kill switch is enabled".into(),
                    });
                }
                if matched_rule.starts_with(TRUST_RULE_PREFIX) {
                    let mut event = self.vault_audit_event(
                        actor,
                        action,
                        resource,
                        "allow",
                        "trust_used",
                        vec![],
                    );
                    event.trust_id = Some(matched_rule.clone());
                    self.store.append_audit(&event)?;
                }
                Ok(matched_rule)
            }
            PolicyDecision::RequireApproval {
                policy_version,
                request_digest_hex,
                ..
            } => self.vault_approval_gate(
                actor,
                &request,
                policy_version,
                &request_digest_hex,
                risk,
                project,
            ),
            PolicyDecision::Deny { reason, .. } => {
                self.audit_vault(actor, action, resource, "deny", "denied", vec![])?;
                Err(KeyLeaseError::Denied { reason })
            }
        }
    }
    /// Personal items do not exist for agents: any command on one fails as
    /// not found, before policy, so no grant or trust can reach it.
    pub(crate) fn refuse_personal_item(
        &self,
        vault: &UnlockedVault,
        actor: &ActorContext,
        action: &str,
        resource: &str,
    ) -> Result<()> {
        let Some(rest) = resource.strip_prefix(&format!("kl://{}/", vault.vault_id.0)) else {
            return Ok(());
        };
        let first = rest.split('/').next().unwrap_or_default();
        if !first.starts_with("item_") {
            return Ok(());
        }
        let Ok(item) = self.store.get_item(vault, &ItemId(first.into())) else {
            return Ok(());
        };
        if item.personal && !self.is_local_owner(&actor.agent_id)? {
            self.audit_vault(actor, action, resource, "deny", "personal", vec![])?;
            return Err(KeyLeaseError::NotFound {
                resource: first.into(),
            });
        }
        Ok(())
    }

    /// Whether `actor` may see `item` in a listing.
    pub(crate) fn item_visible_to(&self, actor: &ActorContext, item: &VaultItem) -> Result<bool> {
        Ok(!item.personal || self.is_local_owner(&actor.agent_id)?)
    }

    pub(crate) fn connection_credential(
        &self,
        id: &ConnectionId,
    ) -> Result<(ConnectionRecord, ConnectorCredential)> {
        let record = self.store.get_connection(id)?;
        let item_id = ItemId(record.credential_item_id.clone());
        let value = self.with_vault(|vault| {
            let item = self.store.get_item(vault, &item_id)?;
            if item.group_id.0 != "group_connections"
                || item.kind != "core.api_credential"
                || !item.tags.iter().any(|tag| tag == "keylease.connection")
                || item.issuer.as_deref() != Some(record.provider.as_str())
                || item.status != ItemStatus::Active
            {
                return Err(KeyLeaseError::Crypto);
            }
            item.fields
                .into_iter()
                .find(|f| {
                    f.key == "credential"
                        && f.protected
                        && f.sensitivity == Sensitivity::HighlySensitive
                })
                .and_then(|f| match f.value {
                    FieldValue::Concealed(v) => Some(v),
                    _ => None,
                })
                .ok_or(KeyLeaseError::Crypto)
        })?;
        Ok((record, ConnectorCredential::new(value)))
    }
    pub(crate) fn connector(&self, record: &ConnectionRecord) -> Result<Arc<dyn Connector>> {
        if record.trust_mode != TrustMode::EdgeLocal {
            return Err(KeyLeaseError::Denied {
                reason: "managed gateway is not available in Phase 1".into(),
            });
        }
        self.connectors
            .get(&record.provider)
            .cloned()
            .ok_or_else(|| KeyLeaseError::NotFound {
                resource: record.provider.clone(),
            })
    }
    pub(crate) fn authorize_connection_operation(
        &self,
        actor: &ActorContext,
        id: &ConnectionId,
        action: &str,
        arguments: Value,
    ) -> Result<String> {
        self.with_vault(|vault| {
            let resource = format!("kl://{}/connection/{}", vault.vault_id.0, id.0);
            self.authorize_vault(vault, actor, action, &resource, arguments)?;
            Ok(resource)
        })
    }
    pub(crate) fn audit_vault(
        &self,
        actor: &ActorContext,
        action: &str,
        resource: &str,
        decision: &str,
        outcome: &str,
        changed_fields: Vec<String>,
    ) -> Result<()> {
        self.store.append_audit(&self.vault_audit_event(
            actor,
            action,
            resource,
            decision,
            outcome,
            changed_fields,
        ))
    }
    pub(crate) fn vault_audit_event(
        &self,
        actor: &ActorContext,
        action: &str,
        resource: &str,
        decision: &str,
        outcome: &str,
        changed_fields: Vec<String>,
    ) -> AuditEvent {
        AuditEvent {
            schema_version: CONTRACT_VERSION,
            timestamp: Utc::now(),
            request_id: RequestId::new(),
            agent_id: actor.agent_id.clone(),
            workload_id: actor.workload_id.as_ref().map(|v| v.0.clone()),
            on_behalf_of: actor.on_behalf_of.clone(),
            action: action.into(),
            resource: resource.into(),
            connection_id: None,
            policy_version: None,
            decision: decision.into(),
            connector: None,
            outcome: outcome.into(),
            item_count: None,
            cell_count: None,
            byte_count: None,
            changed_fields,
            trust_id: None,
            client_auth: self.audit_client_auth(&actor.agent_id),
        }
    }
    pub(crate) fn audit_action(
        &self,
        actor: &ActorContext,
        action: &CanonicalAction,
        decision: &str,
        outcome: &str,
        policy_version: Option<u64>,
        response: Option<&ActionResponse>,
    ) -> Result<()> {
        self.store.append_audit(&self.action_audit_event(
            actor,
            action,
            decision,
            outcome,
            policy_version,
            response,
        ))
    }
    pub(crate) fn action_audit_event(
        &self,
        actor: &ActorContext,
        action: &CanonicalAction,
        decision: &str,
        outcome: &str,
        policy_version: Option<u64>,
        response: Option<&ActionResponse>,
    ) -> AuditEvent {
        AuditEvent {
            schema_version: CONTRACT_VERSION,
            timestamp: Utc::now(),
            request_id: action.request.request_id.clone(),
            agent_id: actor.agent_id.clone(),
            workload_id: actor.workload_id.as_ref().map(|v| v.0.clone()),
            on_behalf_of: actor.on_behalf_of.clone(),
            action: action.request.action.clone(),
            resource: action.request.resource.clone(),
            connection_id: Some(action.request.connection_id.clone()),
            policy_version,
            decision: decision.into(),
            connector: Some(response.map_or_else(|| "unknown".into(), |r| r.provider.clone())),
            outcome: outcome.into(),
            item_count: response.and_then(|r| r.item_count),
            cell_count: response.and_then(|r| r.cell_count),
            byte_count: response
                .and_then(|r| serde_json::to_vec(&r.body).ok().map(|v| v.len() as u64)),
            changed_fields: vec![],
            trust_id: None,
            client_auth: self.audit_client_auth(&actor.agent_id),
        }
    }
}
