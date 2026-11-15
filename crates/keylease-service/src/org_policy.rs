//! Managed nodes, node side (ADR 0012). The owner joins the vault to an
//! organization (`keylease cloud org join`, master password); the vault pins
//! the server's signing key. The daemon then fetches the organization's
//! signed policy, and this module checks it (signature, organization,
//! version never going back, validity) before its rules join the vault's
//! policy as `managed_` rules. Leaving removes them.

use super::*;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use keylease_core::managed::{
    MANAGED_RULE_PREFIX, MANAGED_RULE_VERSION_BASE, ManagedPolicy, OrgNodeJoined,
    SignedManagedPolicy, managed_policy_signing_input,
};

const RECORD_KIND: &str = "org";
const MEMBERSHIP_ID: &str = "membership";
const POLICY_ID: &str = "policy";

/// The organization this vault joined.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OrgMembership {
    pub org_id: String,
    pub org_name: String,
    pub key_id: String,
    pub verifying_key: String,
    pub joined_at: DateTime<Utc>,
}

/// The policy the vault applies, as received.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppliedOrgPolicy {
    signed: SignedManagedPolicy,
    version: u64,
    expires_at: DateTime<Utc>,
}

fn denied(reason: impl Into<String>) -> KeyLeaseError {
    KeyLeaseError::Denied {
        reason: reason.into(),
    }
}

/// The rules of an applied policy as the vault's engine uses them.
pub(crate) fn managed_rules(store: &NativeStore, now: DateTime<Utc>) -> Result<Vec<PolicyRule>> {
    let Some(json) = store.cloud_get(RECORD_KIND, POLICY_ID)? else {
        return Ok(Vec::new());
    };
    let applied: AppliedOrgPolicy =
        serde_json::from_str(&json).map_err(|_| KeyLeaseError::Storage)?;
    // An expired copy still constrains: dropping deny rules because the
    // server was unreachable would loosen the vault.
    let _ = now;
    let policy: ManagedPolicy =
        serde_json::from_str(&applied.signed.payload).map_err(|_| KeyLeaseError::Storage)?;
    Ok(policy
        .rules
        .into_iter()
        .map(|mut rule| {
            rule.id = format!("{MANAGED_RULE_PREFIX}{}", rule.id);
            // The organization does not know each vault's id: an empty
            // prefix means every resource of this vault (`kl://VAULT/…`).
            if rule.resource_prefix.is_empty() {
                rule.resource_prefix = "kl:".into();
            }
            rule.version = MANAGED_RULE_VERSION_BASE + policy.version;
            rule
        })
        .collect())
}

impl KeyLeaseService {
    pub fn org_membership(&self) -> Result<Option<OrgMembership>> {
        self.store
            .cloud_get(RECORD_KIND, MEMBERSHIP_ID)?
            .map(|json| serde_json::from_str(&json).map_err(|_| KeyLeaseError::Storage))
            .transpose()
    }

    /// The version of the organization policy in force, if any.
    pub fn org_policy_version(&self) -> Result<Option<u64>> {
        Ok(self
            .store
            .cloud_get(RECORD_KIND, POLICY_ID)?
            .and_then(|json| serde_json::from_str::<AppliedOrgPolicy>(&json).ok())
            .map(|applied| applied.version))
    }

    /// Records the organization the server enrolled this vault in and pins
    /// its signing key. Needs the unlocked vault (master password).
    pub fn org_join_commit(&self, joined: &OrgNodeJoined) -> Result<OrgMembership> {
        self.with_vault(|_| {
            let key = STANDARD_NO_PAD
                .decode(joined.verifying_key.trim_end_matches('='))
                .ok()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
                .filter(|bytes| VerifyingKey::from_bytes(bytes).is_ok());
            if key.is_none() {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "the server sent a malformed signing key".into(),
                });
            }
            let membership = OrgMembership {
                org_id: joined.org_id.clone(),
                org_name: joined.org_name.clone(),
                key_id: joined.key_id.clone(),
                verifying_key: joined.verifying_key.clone(),
                joined_at: Utc::now(),
            };
            self.store.cloud_delete(RECORD_KIND, POLICY_ID)?;
            self.store.cloud_put(
                RECORD_KIND,
                MEMBERSHIP_ID,
                &serde_json::to_string(&membership).map_err(|_| KeyLeaseError::Storage)?,
            )?;
            Ok(membership)
        })?;
        let stored = self.store.load_policy_rules()?;
        self.install_policy(stored)?;
        self.org_membership()?.ok_or(KeyLeaseError::Storage)
    }

    /// Leaves the organization: its rules stop applying. Needs the unlocked
    /// vault (master password). Returns whether the vault was a member.
    pub fn org_leave(&self) -> Result<bool> {
        let was = self.with_vault(|_| {
            let was = self.org_membership()?.is_some();
            self.store.cloud_delete(RECORD_KIND, POLICY_ID)?;
            self.store.cloud_delete(RECORD_KIND, MEMBERSHIP_ID)?;
            Ok(was)
        })?;
        let stored = self.store.load_policy_rules()?;
        self.install_policy(stored)?;
        Ok(was)
    }

    /// Checks a policy from the server and applies it. Returns the version in
    /// force afterwards. The same version again changes nothing; an older one
    /// is refused.
    pub fn org_apply_policy(&self, signed: &SignedManagedPolicy) -> Result<u64> {
        let membership = self
            .org_membership()?
            .ok_or_else(|| denied("this vault has not joined an organization"))?;
        let key_bytes: [u8; 32] = STANDARD_NO_PAD
            .decode(membership.verifying_key.trim_end_matches('='))
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(KeyLeaseError::Storage)?;
        let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| KeyLeaseError::Storage)?;
        let signature: [u8; 64] = STANDARD_NO_PAD
            .decode(signed.signature.trim_end_matches('='))
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| denied("malformed policy signature"))?;
        key.verify(
            &managed_policy_signing_input(&signed.payload),
            &Ed25519Signature::from_bytes(&signature),
        )
        .map_err(|_| denied("the organization policy is not signed by the pinned server key"))?;
        let policy: ManagedPolicy = serde_json::from_str(&signed.payload)
            .map_err(|_| denied("malformed organization policy"))?;
        if policy.v != 1 || policy.org_id != membership.org_id {
            return Err(denied("the policy is for another organization"));
        }
        if policy.expires_at <= Utc::now() {
            return Err(denied("the organization policy expired"));
        }
        if !policy.only_tightens() {
            return Err(denied(
                "an organization policy may only deny or require approval",
            ));
        }
        let current = self.org_policy_version()?;
        if let Some(current) = current {
            if policy.version < current {
                return Err(denied(
                    "the organization policy went back to an older version",
                ));
            }
            if policy.version == current {
                return Ok(current);
            }
        }
        let applied = AppliedOrgPolicy {
            signed: signed.clone(),
            version: policy.version,
            expires_at: policy.expires_at,
        };
        self.store.cloud_put(
            RECORD_KIND,
            POLICY_ID,
            &serde_json::to_string(&applied).map_err(|_| KeyLeaseError::Storage)?,
        )?;
        let stored = self.store.load_policy_rules()?;
        self.install_policy(stored)?;
        Ok(policy.version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use keylease_store::NativeStore;

    fn service() -> (tempfile::TempDir, KeyLeaseService) {
        let directory = tempfile::tempdir().unwrap();
        let service = KeyLeaseService::new(Arc::new(
            NativeStore::open(directory.path().join("vault.sqlite")).unwrap(),
        ))
        .unwrap();
        service
            .initialize(b"correct horse battery staple", Duration::hours(1))
            .unwrap();
        (directory, service)
    }

    fn rule(id: &str, effect: PolicyEffect) -> PolicyRule {
        PolicyRule {
            id: id.into(),
            version: 0,
            effect,
            agent_id: None,
            connection_id: None,
            resource_prefix: String::new(),
            actions: vec!["entry:read_secret".into()],
            argument_equals: Default::default(),
            not_before: None,
            expires_at: None,
            max_lease_ttl_seconds: 300,
            max_uses: 1,
            budget: Default::default(),
        }
    }

    fn signed(
        key: &SigningKey,
        org: &str,
        version: u64,
        rules: Vec<PolicyRule>,
    ) -> SignedManagedPolicy {
        let payload = serde_json::to_string(&ManagedPolicy {
            v: 1,
            org_id: org.into(),
            version,
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::days(30),
            rules,
        })
        .unwrap();
        SignedManagedPolicy {
            signature: STANDARD_NO_PAD
                .encode(key.sign(&managed_policy_signing_input(&payload)).to_bytes()),
            key_id: "k".into(),
            payload,
        }
    }

    fn engine_has(service: &KeyLeaseService, id: &str) -> bool {
        service
            .policy
            .read()
            .unwrap()
            .rules()
            .iter()
            .any(|rule| rule.id == id)
    }

    #[test]
    fn a_joined_vault_applies_only_its_organizations_signed_policy() {
        let (_dir, service) = service();
        let server = SigningKey::from_bytes(&[7; 32]);
        let stranger = SigningKey::from_bytes(&[8; 32]);
        let deny = signed(
            &server,
            "org_1",
            1,
            vec![rule("no-prod", PolicyEffect::Deny)],
        );
        // Not joined yet.
        assert!(service.org_apply_policy(&deny).is_err());
        service
            .org_join_commit(&OrgNodeJoined {
                org_id: "org_1".into(),
                org_name: "Acme".into(),
                key_id: "k".into(),
                verifying_key: STANDARD_NO_PAD.encode(server.verifying_key().to_bytes()),
            })
            .unwrap();
        assert_eq!(service.org_apply_policy(&deny).unwrap(), 1);
        assert!(engine_has(&service, "managed_no-prod"));
        let installed = service
            .policy
            .read()
            .unwrap()
            .rules()
            .iter()
            .find(|r| r.id == "managed_no-prod")
            .cloned()
            .unwrap();
        assert_eq!(installed.version, MANAGED_RULE_VERSION_BASE + 1);
        // The same version again is a no-op.
        assert_eq!(service.org_apply_policy(&deny).unwrap(), 1);

        // Refused: another signer, another organization, a loosening rule,
        // an older version, a tampered payload.
        assert!(
            service
                .org_apply_policy(&signed(&stranger, "org_1", 5, vec![]))
                .is_err()
        );
        assert!(
            service
                .org_apply_policy(&signed(&server, "org_2", 5, vec![]))
                .is_err()
        );
        assert!(
            service
                .org_apply_policy(&signed(
                    &server,
                    "org_1",
                    5,
                    vec![rule("x", PolicyEffect::Allow)]
                ))
                .is_err()
        );
        let v3 = signed(
            &server,
            "org_1",
            3,
            vec![rule("ask", PolicyEffect::RequireApproval)],
        );
        assert_eq!(service.org_apply_policy(&v3).unwrap(), 3);
        assert!(!engine_has(&service, "managed_no-prod") && engine_has(&service, "managed_ask"));
        assert!(service.org_apply_policy(&deny).is_err(), "rollback");
        let mut tampered = signed(
            &server,
            "org_1",
            4,
            vec![rule("ask", PolicyEffect::RequireApproval)],
        );
        tampered.payload = tampered.payload.replace("require_approval", "deny");
        assert!(service.org_apply_policy(&tampered).is_err());
        assert_eq!(service.org_policy_version().unwrap(), Some(3));

        // The rules survive a reinstall (unlock, grant changes) and go on leave.
        let stored = service.store.load_policy_rules().unwrap();
        service.install_policy(stored).unwrap();
        assert!(engine_has(&service, "managed_ask"));
        assert!(service.org_leave().unwrap());
        assert!(!engine_has(&service, "managed_ask"));
        assert_eq!(service.org_policy_version().unwrap(), None);
    }
}
