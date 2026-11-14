//! Lease requests, approvals, the kill switch, execution and audit queries.

use super::*;

impl KeyLeaseService {
    pub async fn request_lease(
        &self,
        actor: &ActorContext,
        request: ActionRequest,
        ttl_seconds: u64,
        max_uses: u64,
        approval_id: Option<&str>,
    ) -> Result<LeaseRequestOutcome> {
        self.sync_external_policy_changes()?;
        if request.subject.agent_id != actor.agent_id {
            return Err(KeyLeaseError::Denied {
                reason: "request subject does not match authenticated client".into(),
            });
        }
        let vault_session_id = self.current_vault_session_id()?;
        let record = self.store.get_connection(&request.connection_id)?;
        let connector = self.connector(&record)?;
        let canonical = connector.canonicalize(&request).await?;
        validate_connection_permissions(&record, &canonical.spec)?;
        if !is_local_authorized_listing(&canonical)
            && !record
                .authorized_resources
                .contains(&canonical.request.resource)
        {
            return Err(KeyLeaseError::Denied {
                reason: "resource was not enrolled in connection".into(),
            });
        }
        let decision = self
            .policy
            .read()
            .map_err(|_| KeyLeaseError::Storage)?
            .evaluate(&canonical.request, canonical.spec.risk.clone(), Utc::now());
        let (policy_version, allowed_ttl, allowed_uses, policy_budget, approval, approval_binding) =
            match decision {
                PolicyDecision::Deny { reason, .. } => {
                    self.audit_action(actor, &canonical, "deny", "denied", None, None)?;
                    return Err(KeyLeaseError::Denied { reason });
                }
                PolicyDecision::Allow {
                    policy_version,
                    matched_rule,
                    max_ttl_seconds,
                    max_uses,
                    budget,
                } => {
                    self.confirm_standing_rule(&matched_rule)?;
                    if matched_rule.starts_with(TRUST_RULE_PREFIX) {
                        let mut event = self.action_audit_event(
                            actor,
                            &canonical,
                            "allow",
                            "trust_used",
                            Some(policy_version),
                            None,
                        );
                        event.trust_id = Some(matched_rule);
                        self.store.append_audit(&event)?;
                    }
                    (
                        policy_version,
                        max_ttl_seconds,
                        max_uses,
                        budget,
                        None,
                        None,
                    )
                }
                PolicyDecision::RequireApproval {
                    policy_version,
                    request_digest_hex,
                    risk: _,
                    max_ttl_seconds,
                    max_uses,
                    budget,
                    ..
                } => {
                    if let Some(id) = approval_id {
                        (
                            policy_version,
                            max_ttl_seconds,
                            max_uses,
                            budget,
                            Some(ApprovalId(id.into())),
                            Some((id.to_owned(), request_digest_hex)),
                        )
                    } else {
                        let now = Utc::now();
                        let approval = ApprovalRecord {
                            id: ApprovalId::new(),
                            request_digest_hex,
                            policy_version,
                            state: ApprovalState::Pending,
                            expires_at: now + Duration::minutes(10),
                            request_id: Some(canonical.request.request_id.clone()),
                            agent_id: Some(actor.agent_id.clone()),
                            connection_id: Some(canonical.request.connection_id.clone()),
                            action: Some(canonical.request.action.clone()),
                            resource: Some(canonical.request.resource.clone()),
                            created_at: Some(now),
                            task_id: canonical.request.task_id.clone(),
                            risk: Some(canonical.spec.risk.clone()),
                            semantic_summary: Some(approval_semantic_summary(&canonical)),
                            purpose: actor.purpose.clone(),
                            project_id: None,
                        };
                        let event = self.action_audit_event(
                            actor,
                            &canonical,
                            "require_approval",
                            "pending",
                            Some(policy_version),
                            None,
                        );
                        self.store.save_approval_with_audit(&approval, &event)?;
                        return Ok(LeaseRequestOutcome::ApprovalRequired {
                            approval: Box::new(approval),
                        });
                    }
                }
            };
        if ttl_seconds == 0 || ttl_seconds > allowed_ttl || max_uses == 0 || max_uses > allowed_uses
        {
            return Err(KeyLeaseError::Denied {
                reason: "requested TTL or max_uses exceeds policy".into(),
            });
        }
        let budget = intersect_budget(&policy_budget, &canonical.spec.default_budget);
        let token = random_token("kl_live_");
        let digest = hex(&canonical.request.canonical_digest(policy_version));
        let lease = AccessLease {
            id: LeaseId::new(),
            token,
            request_digest_hex: digest,
            policy_version,
            action: canonical.request.action.clone(),
            resource: canonical.request.resource.clone(),
            audience: record.provider,
            expires_at: Utc::now() + Duration::seconds(ttl_seconds as i64),
            max_uses,
            remaining_uses: max_uses,
            budget,
            approval_id: approval,
            session_id: vault_session_id,
            revoked: false,
        };
        if let Some((approval_id, approval_digest)) = approval_binding {
            self.store.save_lease_consuming_approval(
                &lease,
                &approval_id,
                &approval_digest,
                policy_version,
                Utc::now(),
            )?;
        } else {
            self.store.save_lease(&lease)?;
        }
        Ok(LeaseRequestOutcome::Issued {
            lease: Box::new(lease),
        })
    }
    pub fn approve(&self, id: &str) -> Result<()> {
        self.with_vault(|vault| {
            let actor = ActorContext {
                agent_id: AgentId("local-human".into()),
                workload_id: None,
                human_principal: Some("local-human".into()),
                on_behalf_of: None,
                purpose: None,
                client_session_id: vault.session_id.clone(),
            };
            let resource = format!("kl://{}/approval/{id}", vault.vault_id.0);
            let event = self.vault_audit_event(
                &actor,
                "approval:decide",
                &resource,
                "allow",
                "approved",
                vec!["state".into()],
            );
            self.store.decide_pending_approval(
                id,
                ApprovalState::Approved,
                Utc::now(),
                Some(&event),
            )?;
            Ok(())
        })
    }
    pub fn accept_remote_approval(
        &self,
        id: &str,
        request_digest: &str,
        policy_version: u64,
    ) -> Result<()> {
        let approval = self.store.get_approval(id)?;
        if approval.request_digest_hex != request_digest
            || approval.policy_version != policy_version
            || approval.state != ApprovalState::Pending
            || approval.expires_at <= Utc::now()
        {
            return Err(KeyLeaseError::Denied {
                reason: "remote approval is not bound to the pending local request".into(),
            });
        }
        self.store
            .decide_pending_approval(id, ApprovalState::Approved, Utc::now(), None)?;
        Ok(())
    }
    pub fn list_pending_approvals_authorized(
        &self,
        actor: &ActorContext,
        limit: u32,
    ) -> Result<Vec<ApprovalRecord>> {
        self.with_vault(|vault| {
            let resource = format!("kl://{}/approvals", vault.vault_id.0);
            self.authorize_vault(
                vault,
                actor,
                "approval:list",
                &resource,
                serde_json::json!({"limit":limit.min(1000)}),
            )?;
            let approvals = self.store.list_pending_approvals(limit, Utc::now())?;
            self.audit_vault(
                actor,
                "approval:list",
                &resource,
                "allow",
                "success",
                vec![],
            )?;
            Ok(approvals)
        })
    }
    pub fn decide_approval_authorized(
        &self,
        actor: &ActorContext,
        id: &str,
        approve: bool,
    ) -> Result<ApprovalRecord> {
        self.decide_approval_with_trust_authorized(actor, id, approve, None)
            .map(|outcome| outcome.approval)
    }
    pub fn revoke_lease(&self, id: &str) -> Result<()> {
        self.store.revoke_lease(id)
    }
    pub fn kill_switch(&self, enabled: bool) -> Result<()> {
        self.store.set_kill_switch(enabled)?;
        // Enabling the switch deletes every trust; drop them from the engine too.
        self.drop_inactive_trust_rules()
    }

    pub async fn execute(
        &self,
        actor: &ActorContext,
        token: &str,
        request: ActionRequest,
    ) -> Result<ActionResponse> {
        if request.subject.agent_id != actor.agent_id {
            return Err(KeyLeaseError::Denied {
                reason: "request subject does not match authenticated client".into(),
            });
        }
        let record = self.store.get_connection(&request.connection_id)?;
        if !matches!(
            record.health,
            ConnectionHealth::Connected | ConnectionHealth::Degraded
        ) {
            return Err(KeyLeaseError::Denied {
                reason: "connection is not active".into(),
            });
        }
        let connector = self.connector(&record)?;
        let canonical = connector.canonicalize(&request).await?;
        validate_connection_permissions(&record, &canonical.spec)?;
        if !is_local_authorized_listing(&canonical)
            && !record
                .authorized_resources
                .contains(&canonical.request.resource)
        {
            return Err(KeyLeaseError::Denied {
                reason: "resource is no longer enrolled in connection".into(),
            });
        }
        let lease = self.store.lookup_lease(token)?;
        if lease.session_id != self.current_vault_session_id()?
            || lease.action != canonical.request.action
            || lease.resource != canonical.request.resource
        {
            return Err(KeyLeaseError::Denied {
                reason: "lease scope mismatch".into(),
            });
        }
        let digest = hex(&canonical.request.canonical_digest(lease.policy_version));
        let current = self
            .policy
            .read()
            .map_err(|_| KeyLeaseError::Storage)?
            .evaluate(&canonical.request, canonical.spec.risk.clone(), Utc::now());
        let current_version = match current {
            PolicyDecision::Deny { reason, .. } => return Err(KeyLeaseError::Denied { reason }),
            PolicyDecision::Allow {
                policy_version,
                matched_rule,
                ..
            } => {
                self.confirm_standing_rule(&matched_rule)?;
                policy_version
            }
            PolicyDecision::RequireApproval { policy_version, .. }
                if lease.approval_id.is_some() =>
            {
                policy_version
            }
            PolicyDecision::RequireApproval { .. } => {
                return Err(KeyLeaseError::Denied {
                    reason: "approval is required".into(),
                });
            }
        };
        if current_version != lease.policy_version {
            return Err(KeyLeaseError::Denied {
                reason: "lease policy version is stale".into(),
            });
        }
        validate_action_budget(&canonical, &lease.budget)?;
        let task_budget = task_budget_context(&canonical, &lease)?;
        let _execution_slot = self.acquire_execution_slot(&lease)?;
        match self.store.consume_lease_with_budget(
            token,
            &digest,
            &request.idempotency_key,
            Utc::now(),
            task_budget.as_ref(),
        )? {
            LeaseConsume::Replay {
                response_json: Some(raw),
            } => serde_json::from_str(&raw).map_err(|_| KeyLeaseError::Storage),
            LeaseConsume::Replay {
                response_json: None,
            } => Err(KeyLeaseError::ConnectorUnavailable { retryable: false }),
            LeaseConsume::Reserved { lease } => {
                let execution = if is_local_authorized_listing(&canonical) {
                    let prefix = if canonical.request.action == "google_drive.file.list_authorized"
                    {
                        "google:"
                    } else {
                        "notion:page/"
                    };
                    let resources = record
                        .authorized_resources
                        .iter()
                        .filter(|resource| resource.starts_with(prefix))
                        .cloned()
                        .collect::<Vec<_>>();
                    Ok(ActionResponse {
                        provider: record.provider.clone(),
                        connection_id: record.id.clone(),
                        canonical_resource: canonical.request.resource.clone(),
                        revision: None,
                        untrusted_content: true,
                        item_count: Some(resources.len() as u64),
                        cell_count: None,
                        body: serde_json::json!({"authorized_resources":resources}),
                    })
                } else {
                    let (_, credential) = self.connection_credential(&record.id)?;
                    connector.execute(&canonical, &credential).await
                };
                match execution
                    .and_then(|response| enforce_response_budget(response, &lease.budget))
                {
                    Ok(response) => {
                        if is_create_action(&canonical) {
                            let created = validate_enrolled_resource(
                                &connector.manifest(),
                                &response.canonical_resource,
                            )?;
                            let mut updated_record = record.clone();
                            if !updated_record.authorized_resources.contains(&created) {
                                updated_record.authorized_resources.push(created);
                                updated_record.authorized_resources.sort();
                                updated_record.updated_at = Utc::now();
                                self.store.save_connection(&updated_record)?;
                            }
                        }
                        let audit = self.action_audit_event(
                            actor,
                            &canonical,
                            "allow",
                            "success",
                            Some(lease.policy_version),
                            Some(&response),
                        );
                        let usage = completion_usage(&response, canonical.spec.idempotent)?;
                        if let Err(error) = self.store.complete_execution_with_usage(
                            &request.idempotency_key,
                            &serde_json::to_string(&response)
                                .map_err(|_| KeyLeaseError::Storage)?,
                            Some(&audit),
                            task_budget.as_ref(),
                            &usage,
                            !canonical.spec.idempotent,
                        ) {
                            self.audit_action(
                                actor,
                                &canonical,
                                "deny",
                                "task_budget_exceeded",
                                Some(lease.policy_version),
                                None,
                            )?;
                            return Err(error);
                        }
                        Ok(response)
                    }
                    Err(error) => {
                        self.store.mark_execution_failed(
                            &request.idempotency_key,
                            &error,
                            !canonical.spec.idempotent,
                        )?;
                        self.audit_action(
                            actor,
                            &canonical,
                            "allow",
                            "failure",
                            Some(lease.policy_version),
                            None,
                        )?;
                        Err(error)
                    }
                }
            }
        }
    }

    pub fn audit_query(&self, limit: u32) -> Result<Vec<AuditEvent>> {
        self.store.query_audit(limit.min(1000))
    }
    pub fn list_execution_recovery(
        &self,
        limit: u32,
    ) -> Result<Vec<keylease_store::ExecutionRecoveryRecord>> {
        self.store.list_execution_recovery(limit)
    }
    pub fn audit_query_authorized(
        &self,
        actor: &ActorContext,
        limit: u32,
    ) -> Result<Vec<AuditEvent>> {
        self.with_vault(|vault| {
            let resource = format!("kl://{}/audit", vault.vault_id.0);
            self.authorize_vault(
                vault,
                actor,
                "audit:query",
                &resource,
                serde_json::json!({"limit":limit.min(1000)}),
            )?;
            self.audit_vault(actor, "audit:query", &resource, "allow", "success", vec![])?;
            self.store.query_audit(limit.min(1000))
        })
    }
}
