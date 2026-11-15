//! Console approvals and node audit, node side (ADR 0011).
//!
//! The owner turns console approvals on with the master password; the node
//! then pins the account's passkeys (public keys, relying party and origin).
//! The daemon reports pending approvals to keylease-server and applies the
//! decisions that come back, but only after checking, here, that one of the
//! pinned passkeys signed exactly that decision for this node, and that it
//! names the pending request's digest and policy version.

use super::*;
use keylease_core::console::{
    AccountPasskeys, AuditEntry, ConsoleDecision, DECISION_MAX_AGE_SECONDS, DecisionPayload,
    DecisionResult, PinnedPasskey, decision_challenge,
};
use keylease_crypto::webauthn;

const RECORD_KIND: &str = "console";
const CONFIG_ID: &str = "approvals";

/// What the node keeps after `keylease cloud console-approvals enable`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsoleApprovalsConfig {
    pub rp_id: String,
    pub origin: String,
    pub passkeys: Vec<PinnedPasskey>,
    /// Upload audit events so the console can list them.
    pub share_audit: bool,
    pub enabled_at: DateTime<Utc>,
}

fn base64url(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text.trim_end_matches('=')).ok()
}

fn rejected(id: &str, reason: impl Into<String>) -> DecisionResult {
    DecisionResult {
        id: id.to_owned(),
        outcome: "rejected".into(),
        reason: Some(reason.into()),
    }
}

impl KeyLeaseService {
    /// Turns console approvals on and pins the account's passkeys. Needs the
    /// unlocked vault (master password), like pairing an approver device.
    pub fn console_approvals_enable(
        &self,
        passkeys: AccountPasskeys,
        share_audit: bool,
    ) -> Result<ConsoleApprovalsConfig> {
        self.with_vault(|_| {
            self.cloud_link()?
                .filter(|link| !link.member_id.is_empty())
                .ok_or_else(|| KeyLeaseError::InvalidRequest {
                    reason: "this vault is not linked to a cloud (keylease cloud init / join)"
                        .into(),
                })?;
            if passkeys.passkeys.is_empty() {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "the account has no passkey yet: register one in the console first"
                        .into(),
                });
            }
            for passkey in &passkeys.passkeys {
                let valid = base64url(&passkey.credential_id).is_some_and(|id| !id.is_empty())
                    && base64::engine::general_purpose::STANDARD
                        .decode(&passkey.public_key_b64)
                        .is_ok_and(|key| webauthn::valid_public_key(&key));
                if !valid {
                    return Err(KeyLeaseError::InvalidRequest {
                        reason: format!("passkey {} is malformed", passkey.name),
                    });
                }
            }
            let config = ConsoleApprovalsConfig {
                rp_id: passkeys.rp_id,
                origin: passkeys.origin,
                passkeys: passkeys.passkeys,
                share_audit,
                enabled_at: Utc::now(),
            };
            self.store.cloud_put(
                RECORD_KIND,
                CONFIG_ID,
                &serde_json::to_string(&config).map_err(|_| KeyLeaseError::Storage)?,
            )?;
            Ok(config)
        })
    }

    /// Turns console approvals off. Returns whether they were on.
    pub fn console_approvals_disable(&self) -> Result<bool> {
        self.with_vault(|_| {
            let was = self.console_approvals_config()?.is_some();
            self.store.cloud_delete(RECORD_KIND, CONFIG_ID)?;
            Ok(was)
        })
    }

    pub fn console_approvals_config(&self) -> Result<Option<ConsoleApprovalsConfig>> {
        self.store
            .cloud_get(RECORD_KIND, CONFIG_ID)?
            .map(|json| serde_json::from_str(&json).map_err(|_| KeyLeaseError::Storage))
            .transpose()
    }

    /// The pending approvals to report. Does not count as vault activity.
    pub fn console_pending_approvals(&self) -> Result<Vec<ApprovalRecord>> {
        self.with_vault_passive(|_| {
            self.store.list_pending_approvals(
                keylease_core::console::MAX_REPORTED_APPROVALS as u32,
                Utc::now(),
            )
        })
    }

    /// Audit events after `after_seq`, oldest first.
    pub fn console_audit_after(&self, after_seq: i64, limit: u32) -> Result<Vec<AuditEntry>> {
        Ok(self
            .store
            .query_audit_after(after_seq, limit)?
            .into_iter()
            .map(|(seq, event)| AuditEntry { seq, event })
            .collect())
    }

    /// Checks a decision from the console and applies it. Never fails: a
    /// decision that cannot be applied comes back `rejected` with the reason.
    pub fn console_apply_decision(&self, decision: &ConsoleDecision) -> DecisionResult {
        match self.console_apply_checked(decision) {
            Ok(outcome) => outcome,
            Err(KeyLeaseError::Denied { reason })
            | Err(KeyLeaseError::InvalidRequest { reason }) => rejected(&decision.id, reason),
            Err(KeyLeaseError::VaultLocked { .. }) => rejected(&decision.id, "the vault is locked"),
            Err(KeyLeaseError::NotFound { .. }) => {
                rejected(&decision.id, "the approval no longer exists")
            }
            Err(_) => rejected(&decision.id, "the node could not apply the decision"),
        }
    }

    fn console_apply_checked(&self, decision: &ConsoleDecision) -> Result<DecisionResult> {
        let denied = |reason: &str| KeyLeaseError::Denied {
            reason: reason.into(),
        };
        let config = self
            .console_approvals_config()?
            .ok_or_else(|| denied("console approvals are off on this node"))?;
        let link = self
            .cloud_link()?
            .filter(|link| !link.member_id.is_empty())
            .ok_or_else(|| denied("this node is not linked to a cloud"))?;
        let assertion = &decision.assertion;
        let credential = assertion.credential_id.trim_end_matches('=');
        let passkey = config
            .passkeys
            .iter()
            .find(|passkey| passkey.credential_id.trim_end_matches('=') == credential)
            .ok_or_else(|| {
                denied("signed with a passkey this node has not pinned (run console-approvals enable again)")
            })?;
        let public_key = base64::engine::general_purpose::STANDARD
            .decode(&passkey.public_key_b64)
            .map_err(|_| KeyLeaseError::Storage)?;
        let field =
            |text: &str| base64url(text).ok_or_else(|| denied("malformed passkey response"));
        webauthn::verify_assertion(
            &field(&assertion.client_data_json)?,
            &field(&assertion.authenticator_data)?,
            &field(&assertion.signature)?,
            &public_key,
            0,
            &decision_challenge(&decision.payload),
            &config.origin,
            &config.rp_id,
        )
        .map_err(|_| denied("the passkey signature does not match the decision"))?;
        let payload: DecisionPayload =
            serde_json::from_str(&decision.payload).map_err(|_| denied("malformed decision"))?;
        let age = (Utc::now() - payload.issued_at).num_seconds();
        if payload.v != 1 {
            return Err(denied("unknown decision version"));
        }
        if payload.account_id != link.account_id || payload.node != link.member_id {
            return Err(denied("the decision is for another node"));
        }
        if !(-120..=DECISION_MAX_AGE_SECONDS).contains(&age) {
            return Err(denied("the decision expired"));
        }
        let pending = self.store.get_approval(&payload.approval_id)?;
        if pending.state != ApprovalState::Pending
            || pending.request_digest_hex != payload.request_digest_hex
            || pending.policy_version != payload.policy_version
        {
            return Err(denied("the approval is no longer pending as decided"));
        }
        let actor = ActorContext {
            agent_id: AgentId(format!(
                "console:{}",
                &credential[..credential.len().min(16)]
            )),
            workload_id: None,
            human_principal: Some(passkey.name.clone()),
            on_behalf_of: None,
            client_session_id: "console-approval".into(),
            purpose: None,
        };
        self.decide_approval_as(&actor, &payload.approval_id, payload.approve, payload.trust)?;
        Ok(DecisionResult {
            id: decision.id.clone(),
            outcome: if payload.approve {
                "approved"
            } else {
                "denied"
            }
            .into(),
            reason: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keylease_core::console::{AccountPasskeys, PasskeyAssertion};
    use keylease_core::relay::RelayAccountCreated;
    use keylease_crypto::webauthn::testing::{
        ORIGIN, RP_ID, authenticator_data, client_data, sign,
    };
    use keylease_store::NativeStore;
    use p256::ecdsa::SigningKey;

    const CREDENTIAL: &str = "Y3JlZC0x"; // "cred-1"

    fn linked_service() -> (tempfile::TempDir, KeyLeaseService) {
        let directory = tempfile::tempdir().unwrap();
        let service = KeyLeaseService::new(Arc::new(
            NativeStore::open(directory.path().join("vault.sqlite")).unwrap(),
        ))
        .unwrap();
        service
            .initialize(b"correct horse battery staple", Duration::hours(1))
            .unwrap();
        let setup = service
            .cloud_owner_prepare("https://cloud.example", "laptop")
            .unwrap();
        service
            .cloud_owner_commit(&RelayAccountCreated {
                account_id: setup.request.account_id.clone(),
                owner_member_id: setup.request.owner.member_id(),
            })
            .unwrap();
        (directory, service)
    }

    fn pending(service: &KeyLeaseService, id: &str) -> ApprovalRecord {
        let record = ApprovalRecord {
            id: ApprovalId(id.into()),
            request_digest_hex: "ab".repeat(32),
            policy_version: 3,
            state: ApprovalState::Pending,
            expires_at: Utc::now() + Duration::minutes(10),
            request_id: None,
            agent_id: Some(AgentId("agent-1".into())),
            connection_id: None,
            action: Some("ssh:sign".into()),
            resource: Some("kl://vault/item/1".into()),
            created_at: Some(Utc::now()),
            task_id: None,
            risk: None,
            semantic_summary: None,
            purpose: None,
            project_id: None,
        };
        service.store.save_approval(&record).unwrap();
        record
    }

    fn enable(service: &KeyLeaseService, key: &SigningKey) {
        let point = key.verifying_key().to_encoded_point(false);
        service
            .console_approvals_enable(
                AccountPasskeys {
                    rp_id: RP_ID.into(),
                    origin: ORIGIN.into(),
                    passkeys: vec![PinnedPasskey {
                        credential_id: CREDENTIAL.into(),
                        public_key_b64: base64::engine::general_purpose::STANDARD
                            .encode(point.as_bytes()),
                        name: "phone".into(),
                    }],
                },
                true,
            )
            .unwrap();
    }

    fn payload(
        service: &KeyLeaseService,
        approval: &ApprovalRecord,
        approve: bool,
    ) -> DecisionPayload {
        let link = service.cloud_link().unwrap().unwrap();
        DecisionPayload {
            v: 1,
            account_id: link.account_id,
            node: link.member_id,
            approval_id: approval.id.0.clone(),
            approve,
            request_digest_hex: approval.request_digest_hex.clone(),
            policy_version: approval.policy_version,
            trust: None,
            issued_at: Utc::now(),
            nonce: "n".into(),
        }
    }

    fn signed(key: &SigningKey, id: &str, payload: &DecisionPayload) -> ConsoleDecision {
        let payload = serde_json::to_string(payload).unwrap();
        let client = client_data("webauthn.get", &decision_challenge(&payload));
        let auth = authenticator_data(0, None);
        ConsoleDecision {
            id: id.into(),
            assertion: PasskeyAssertion {
                credential_id: CREDENTIAL.into(),
                client_data_json: URL_SAFE_NO_PAD.encode(&client),
                authenticator_data: URL_SAFE_NO_PAD.encode(&auth),
                signature: URL_SAFE_NO_PAD.encode(sign(key, &auth, &client)),
            },
            payload,
        }
    }

    fn key() -> SigningKey {
        SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng)
    }

    #[test]
    fn a_pinned_passkey_decides_a_pending_approval_once() {
        let (_dir, service) = linked_service();
        let key = key();
        let approval = pending(&service, "ap-1");
        // Off until the owner turns it on.
        let early = service.console_apply_decision(&signed(
            &key,
            "d0",
            &payload(&service, &approval, true),
        ));
        assert_eq!(early.outcome, "rejected");
        enable(&service, &key);
        assert_eq!(service.console_pending_approvals().unwrap().len(), 1);

        let decision = signed(&key, "d1", &payload(&service, &approval, true));
        let result = service.console_apply_decision(&decision);
        assert_eq!(result.outcome, "approved", "{result:?}");
        assert_eq!(
            service.store.get_approval("ap-1").unwrap().state,
            ApprovalState::Approved
        );
        // A replay finds nothing pending.
        assert_eq!(
            service.console_apply_decision(&decision).outcome,
            "rejected"
        );
        assert!(service.console_pending_approvals().unwrap().is_empty());
        // The decision is audited under the passkey's name.
        let audit = service.console_audit_after(0, 500).unwrap();
        assert!(audit.windows(2).all(|pair| pair[0].seq < pair[1].seq));
        assert!(
            audit
                .iter()
                .any(|entry| entry.event.action == "approval:decide"
                    && entry.event.outcome == "approved")
        );
    }

    #[test]
    fn decisions_that_do_not_match_are_rejected() {
        let (_dir, service) = linked_service();
        let key = key();
        enable(&service, &key);
        let approval = pending(&service, "ap-2");

        // Signed by a passkey the node did not pin.
        let stranger = signed(&self::key(), "d1", &payload(&service, &approval, true));
        assert_eq!(
            service.console_apply_decision(&stranger).outcome,
            "rejected"
        );

        // The payload was changed after signing.
        let mut tampered = signed(&key, "d2", &payload(&service, &approval, false));
        tampered.payload = tampered
            .payload
            .replace("\"approve\":false", "\"approve\":true");
        assert_eq!(
            service.console_apply_decision(&tampered).outcome,
            "rejected"
        );

        // For another node.
        let mut other = payload(&service, &approval, true);
        other.node = "someone-else".into();
        assert_eq!(
            service
                .console_apply_decision(&signed(&key, "d3", &other))
                .outcome,
            "rejected"
        );

        // Too old.
        let mut old = payload(&service, &approval, true);
        old.issued_at = Utc::now() - Duration::minutes(30);
        assert_eq!(
            service
                .console_apply_decision(&signed(&key, "d4", &old))
                .outcome,
            "rejected"
        );

        // The request changed since the person decided.
        let mut stale = payload(&service, &approval, true);
        stale.policy_version = 2;
        assert_eq!(
            service
                .console_apply_decision(&signed(&key, "d5", &stale))
                .outcome,
            "rejected"
        );

        assert_eq!(
            service.store.get_approval("ap-2").unwrap().state,
            ApprovalState::Pending
        );
        // A denial works.
        let deny = signed(&key, "d6", &payload(&service, &approval, false));
        assert_eq!(service.console_apply_decision(&deny).outcome, "denied");
    }

    #[test]
    fn turning_console_approvals_off_stops_decisions() {
        let (_dir, service) = linked_service();
        let key = key();
        enable(&service, &key);
        assert!(service.console_approvals_disable().unwrap());
        let approval = pending(&service, "ap-3");
        let result = service.console_apply_decision(&signed(
            &key,
            "d1",
            &payload(&service, &approval, true),
        ));
        assert_eq!(result.outcome, "rejected");
        assert!(!service.console_approvals_disable().unwrap());
    }
}
