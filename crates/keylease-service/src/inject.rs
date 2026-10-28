//! Injecting secrets into a child process (ADR 0005, tier T3).
//!
//! `keylease run --env NAME=kl://… -- CMD` needs field values in the
//! environment of a program the agent starts. That is a disclosure to a
//! process the agent controls, so it is risk R4: one approval per run, never
//! a trust. What it buys over `entries reveal` is hygiene — the value is never
//! printed, and the CLI scrubs it from the program's output — not a boundary.

use super::*;

/// Upper bound on fields one run may inject.
const MAX_INJECTED_FIELDS: usize = 32;

/// One field to inject, by item and field key.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InjectRequest {
    pub item_id: ItemId,
    pub field: String,
}

impl KeyLeaseService {
    /// Returns the requested values after one approval per item.
    ///
    /// The approval names the program that will receive the values and the
    /// field keys, so the approver sees "password and token into `terraform`".
    pub fn inject_fields_authorized(
        &self,
        actor: &ActorContext,
        program: &str,
        argv: &[String],
        requests: &[InjectRequest],
    ) -> Result<Vec<String>> {
        let program = program.rsplit('/').next().unwrap_or(program);
        if argv.len() > 256 || argv.iter().map(String::len).sum::<usize>() > 8192 {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "command line is too long".into(),
            });
        }
        if requests.is_empty()
            || requests.len() > MAX_INJECTED_FIELDS
            || program.is_empty()
            || program.len() > 128
            || program.chars().any(char::is_control)
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: format!("inject 1..={MAX_INJECTED_FIELDS} fields into a named program"),
            });
        }
        self.with_vault(|vault| {
            let mut by_item: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for request in requests {
                if request.field.is_empty() || request.field.len() > 128 || request.field == "otp" {
                    return Err(KeyLeaseError::InvalidRequest {
                        reason: "invalid field to inject".into(),
                    });
                }
                by_item
                    .entry(request.item_id.0.clone())
                    .or_default()
                    .push(request.field.clone());
            }
            for (item_id, fields) in &mut by_item {
                fields.sort();
                fields.dedup();
                self.authorize_vault(
                    vault,
                    actor,
                    "entry:inject_secret",
                    &format!("kl://{}/{}", vault.vault_id.0, item_id),
                    if argv.is_empty() {
                        serde_json::json!({"program": program, "fields": fields})
                    } else {
                        serde_json::json!({"program": program, "argv": argv, "fields": fields})
                    },
                )?;
            }
            let mut values = Vec::with_capacity(requests.len());
            for request in requests {
                let item = self.store.get_item(vault, &request.item_id)?;
                let value = if request.field == "notes" {
                    item.notes.clone().filter(|notes| !notes.trim().is_empty())
                } else {
                    item.fields
                        .iter()
                        .find(|field| field.key == request.field)
                        .map(|field| field_value_string(&field.value))
                }
                .ok_or_else(|| KeyLeaseError::NotFound {
                    resource: format!("{}/{}", request.item_id.0, request.field),
                })?;
                values.push(value);
            }
            for (item_id, fields) in by_item {
                self.audit_vault(
                    actor,
                    "entry:inject_secret",
                    &format!("kl://{}/{}", vault.vault_id.0, item_id),
                    "allow",
                    "success",
                    fields,
                )?;
            }
            Ok(values)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injection_is_approved_per_run_or_trusted_for_an_hour() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(NativeStore::open(dir.path().join("vault.sqlite")).unwrap());
        let service = KeyLeaseService::new(store).unwrap();
        service.initialize(b"password", Duration::hours(1)).unwrap();
        let (owner_id, owner_token) = service.register_desktop_client().unwrap();
        service.lock().unwrap();
        service
            .unlock_for_client(&owner_id, b"password", Duration::hours(1))
            .unwrap();
        let owner = service.authenticate(&owner_id, &owner_token, "d").unwrap();
        let group = service.create_group("Ops", None).unwrap();
        let item = service
            .create_entry(
                &owner,
                NewEntryInput {
                    favorite: false,
                    group_id: group.id,
                    kind: "core.login".into(),
                    title: "Stripe".into(),
                    project_slug: None,
                    username: Some("ops".into()),
                    password: Some("sk_live_fixture".into()),
                    url: None,
                    notes: None,
                    custom_fields: vec![],
                    sections: vec![],
                    totp: None,
                    totp_uri: None,
                },
                "inject-item",
                false,
            )
            .unwrap();
        let enrolled = service.enroll_agent_authorized(&owner, "runner").unwrap();
        let agent = service
            .authenticate(&enrolled.agent_id, &enrolled.token, "a")
            .unwrap();
        let requests = vec![
            InjectRequest {
                item_id: item.id.clone(),
                field: "password".into(),
            },
            InjectRequest {
                item_id: item.id.clone(),
                field: "username".into(),
            },
        ];
        let id = match service.inject_fields_authorized(&agent, "/usr/bin/stripe", &[], &requests) {
            Err(KeyLeaseError::ApprovalRequired { approval_id }) => approval_id,
            other => panic!("expected approval_required, got {other:?}"),
        };
        let pending = service
            .list_pending_approvals_authorized(&owner, 10)
            .unwrap();
        let record = pending.iter().find(|a| a.id.0 == id).unwrap();
        assert_eq!(record.risk, Some(RiskTier::R3));
        let trust = |duration| {
            Some(TrustDecision {
                scope: TrustScope::Resource,
                duration,
            })
        };
        assert!(
            service
                .decide_approval_with_trust_authorized(
                    &owner,
                    &id,
                    true,
                    trust(TrustDuration::Hours6)
                )
                .is_err(),
            "injection is trusted for an hour at most"
        );
        service
            .decide_approval_authorized(&owner, &id, true)
            .unwrap();
        assert_eq!(
            service
                .inject_fields_authorized(&agent, "stripe", &[], &requests)
                .unwrap(),
            vec!["sk_live_fixture".to_owned(), "ops".to_owned()]
        );
        // A plain approval is one run: a different program, or the same program
        // with other arguments, is a different approval.
        assert!(matches!(
            service.inject_fields_authorized(
                &agent,
                "stripe",
                &["stripe".into(), "x".into()],
                &requests
            ),
            Err(KeyLeaseError::ApprovalRequired { .. })
        ));
        let id = match service.inject_fields_authorized(&agent, "curl", &[], &requests) {
            Err(KeyLeaseError::ApprovalRequired { approval_id }) => approval_id,
            other => panic!("expected approval_required, got {other:?}"),
        };
        // An hour's trust covers every run on the item.
        service
            .decide_approval_with_trust_authorized(&owner, &id, true, trust(TrustDuration::Hour1))
            .unwrap();
        for program in ["curl", "stripe", "deploy"] {
            assert!(
                service
                    .inject_fields_authorized(&agent, program, &[], &requests)
                    .is_ok()
            );
        }
    }
}
