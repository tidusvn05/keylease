//! Paired remote approvers (ADR 0005 mode B).
//!
//! A headless vault node (a VPS) has no desktop to approve on. The owner pairs
//! an approver device — the macOS app or `keylease remote` on a laptop — with a
//! one-time code. The device keeps an Ed25519 key; the node keeps its public
//! key. Every approver request is signed, and a decision is accepted only if it
//! names the exact digest and policy version of a pending approval, so a
//! replayed or stale decision cannot approve a different request.
//!
//! The approver endpoint exposes no vault read or mutation: only approvals and
//! trusts.

use super::*;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};

/// Pairing codes are single-use and short-lived.
const PAIRING_CODE_TTL_MINUTES: i64 = 10;
/// Signed approver requests must be this fresh.
const REQUEST_SKEW_SECONDS: i64 = 120;
/// Domain separation for approver request signatures.
pub const APPROVER_SIGNATURE_CONTEXT: &str = "KEYLEASE-APPROVER-V1";

/// A paired approver device, as the node stores it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApproverDevice {
    pub id: String,
    pub name: String,
    /// Base64 Ed25519 public key.
    pub public_key: String,
    pub created_at: DateTime<Utc>,
}

/// A one-time pairing code shown to the operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingCode {
    pub code: String,
    pub expires_at: DateTime<Utc>,
}

/// The bytes an approver signs for one request.
pub fn approver_signing_input(method: &str, path: &str, timestamp: i64, body: &[u8]) -> Vec<u8> {
    format!(
        "{APPROVER_SIGNATURE_CONTEXT}\n{method}\n{path}\n{timestamp}\n{}",
        hex(&Sha256::digest(body))
    )
    .into_bytes()
}

fn pairing_code_hash(code: &str) -> String {
    hex(&Sha256::digest(
        format!("keylease-pairing-v1:{}", code.trim().to_ascii_uppercase()).as_bytes(),
    ))
}

impl KeyLeaseService {
    /// Creates a one-time pairing code. Requires the unlocked vault, so only
    /// someone holding the master password (or the running owner) can pair.
    pub fn create_pairing_code(&self) -> Result<PairingCode> {
        self.with_vault(|_| {
            let mut raw = [0_u8; 10];
            rand::rng().fill_bytes(&mut raw);
            // Crockford-style base32 without padding: easy to read aloud.
            let code = data_encoding_base32(&raw);
            let expires_at = Utc::now() + Duration::minutes(PAIRING_CODE_TTL_MINUTES);
            self.store
                .save_pairing_code(&pairing_code_hash(&code), expires_at)?;
            Ok(PairingCode { code, expires_at })
        })
    }

    /// Pairs an approver device, consuming the code.
    pub fn pair_approver(
        &self,
        code: &str,
        name: &str,
        public_key: &str,
    ) -> Result<ApproverDevice> {
        if name.trim().is_empty() || name.len() > 64 || name.chars().any(char::is_control) {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "device name must be 1..=64 characters".into(),
            });
        }
        let key_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(public_key)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| KeyLeaseError::InvalidRequest {
                reason: "public key must be a base64 Ed25519 key".into(),
            })?;
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "public key must be a base64 Ed25519 key".into(),
        })?;
        let device = ApproverDevice {
            id: format!("device_{}", uuid::Uuid::now_v7().simple()),
            name: name.trim().into(),
            public_key: public_key.into(),
            created_at: Utc::now(),
        };
        let event = AuditEvent {
            agent_id: AgentId(device.id.clone()),
            ..self.vault_audit_event(
                &self.remote_actor(&device),
                "approver:pair",
                "kl://approvers",
                "allow",
                "paired",
                vec![],
            )
        };
        self.store.pair_approver_device(
            &pairing_code_hash(code),
            &device,
            &device.id,
            Utc::now(),
            &event,
        )?;
        Ok(device)
    }

    /// Verifies a signed approver request and returns its device.
    pub fn verify_approver_request(
        &self,
        device_id: &str,
        method: &str,
        path: &str,
        timestamp: i64,
        body: &[u8],
        signature: &str,
    ) -> Result<ApproverDevice> {
        let denied = || KeyLeaseError::Denied {
            reason: "approver request signature is invalid".into(),
        };
        if (Utc::now().timestamp() - timestamp).abs() > REQUEST_SKEW_SECONDS {
            return Err(KeyLeaseError::Denied {
                reason: "approver request is stale; check the device clock".into(),
            });
        }
        let device: ApproverDevice = self
            .store
            .get_approver_device(device_id)?
            .ok_or_else(denied)?;
        let key: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(&device.public_key)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(KeyLeaseError::Storage)?;
        let signature: [u8; 64] = base64::engine::general_purpose::STANDARD
            .decode(signature)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(denied)?;
        VerifyingKey::from_bytes(&key)
            .map_err(|_| KeyLeaseError::Storage)?
            .verify(
                &approver_signing_input(method, path, timestamp, body),
                &Ed25519Signature::from_bytes(&signature),
            )
            .map_err(|_| denied())?;
        Ok(device)
    }

    fn remote_actor(&self, device: &ApproverDevice) -> ActorContext {
        ActorContext {
            agent_id: AgentId(device.id.clone()),
            workload_id: None,
            human_principal: Some(device.name.clone()),
            on_behalf_of: None,
            client_session_id: "remote-approver".into(),
            purpose: None,
        }
    }

    pub fn remote_list_approvals(&self, _device: &ApproverDevice) -> Result<Vec<ApprovalRecord>> {
        self.with_vault_passive(|_| self.store.list_pending_approvals(200, Utc::now()))
    }

    pub fn remote_list_trusts(&self, _device: &ApproverDevice) -> Result<Vec<TrustRecord>> {
        self.with_vault_passive(|_| self.store.list_trusts(Utc::now()))
    }

    /// Decides an approval for a paired device. The decision must name the
    /// pending approval's exact digest and policy version.
    pub fn remote_decide(
        &self,
        device: &ApproverDevice,
        id: &str,
        approve: bool,
        request_digest_hex: &str,
        policy_version: u64,
        trust: Option<TrustDecision>,
    ) -> Result<ApprovalDecisionOutcome> {
        let pending = self.store.get_approval(id)?;
        if pending.request_digest_hex != request_digest_hex
            || pending.policy_version != policy_version
        {
            return Err(KeyLeaseError::Denied {
                reason: "decision is not bound to the pending request".into(),
            });
        }
        self.decide_approval_as(&self.remote_actor(device), id, approve, trust)
    }

    pub fn remote_revoke_trust(&self, device: &ApproverDevice, id: &str) -> Result<()> {
        let actor = self.remote_actor(device);
        self.with_vault(|vault| {
            let resource = format!("kl://{}/trust/{id}", vault.vault_id.0);
            let event = self.vault_audit_event(
                &actor,
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

    pub fn list_approver_devices(&self) -> Result<Vec<ApproverDevice>> {
        self.store.list_approver_devices()
    }

    pub fn revoke_approver_device(&self, id: &str) -> Result<()> {
        self.store.revoke_approver_device(id)
    }
}

/// RFC 4648 base32 without padding, upper case.
pub(crate) fn data_encoding_base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = String::new();
    let mut buffer = 0_u32;
    let mut bits = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        output.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// The macOS app's `RemoteApproverTests` asserts the same bytes.
    #[test]
    fn signing_input_is_frozen() {
        assert_eq!(
            String::from_utf8(approver_signing_input(
                "POST",
                "/v1/approvals/a/decide",
                1_700_000_000,
                br#"{"approve":true}"#,
            ))
            .unwrap(),
            "KEYLEASE-APPROVER-V1\nPOST\n/v1/approvals/a/decide\n1700000000\n\
             d80736cb968002b333b9dbd349375db423a42c381558798f8abba960c41a5862"
        );
    }

    fn signed(key: &SigningKey, method: &str, path: &str, timestamp: i64, body: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(
            key.sign(&approver_signing_input(method, path, timestamp, body))
                .to_bytes(),
        )
    }

    #[test]
    fn polling_an_approver_list_does_not_keep_the_vault_unlocked() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(NativeStore::open(dir.path().join("vault.sqlite")).unwrap());
        let service = KeyLeaseService::new(store).unwrap();
        service.initialize(b"password", Duration::hours(1)).unwrap();
        let device = ApproverDevice {
            id: "device_test".into(),
            name: "laptop".into(),
            public_key: String::new(),
            created_at: Utc::now(),
        };
        let idle = |service: &KeyLeaseService| service.status().unwrap()["idle_expires_at"].clone();
        let before = idle(&service);
        std::thread::sleep(std::time::Duration::from_millis(20));
        service.remote_list_approvals(&device).unwrap();
        service.remote_list_trusts(&device).unwrap();
        assert_eq!(idle(&service), before);
        service.current_vault_id().unwrap();
        assert_ne!(idle(&service), before, "ordinary use still counts");
    }

    #[test]
    fn a_paired_device_decides_only_the_exact_pending_request() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(NativeStore::open(dir.path().join("vault.sqlite")).unwrap());
        let service = KeyLeaseService::new(store).unwrap();
        service.initialize(b"password", Duration::hours(1)).unwrap();
        let vault_id = service.current_vault_id().unwrap();
        let (agent_id, token) = service.register_client("vps-bot").unwrap();
        service
            .install_agent_baseline(&agent_id, &vault_id)
            .unwrap();
        let agent = service.authenticate(&agent_id, &token, "s").unwrap();

        let code = service.create_pairing_code().unwrap();
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let public =
            base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes());
        assert!(
            service
                .pair_approver("WRONGCODE", "laptop", &public)
                .is_err()
        );
        let device = service
            .pair_approver(&code.code.to_lowercase(), "laptop", &public)
            .unwrap();
        assert!(
            service.pair_approver(&code.code, "again", &public).is_err(),
            "a pairing code is single-use"
        );

        let now = Utc::now().timestamp();
        let signature = signed(&key, "GET", "/v1/approvals", now, b"");
        assert!(
            service
                .verify_approver_request(&device.id, "GET", "/v1/approvals", now, b"", &signature)
                .is_ok()
        );
        for (method, path, timestamp, body) in [
            ("POST", "/v1/approvals", now, &b""[..]),
            ("GET", "/v1/trusts", now, &b""[..]),
            ("GET", "/v1/approvals", now - 600, &b""[..]),
            ("GET", "/v1/approvals", now, &b"x"[..]),
        ] {
            assert!(
                service
                    .verify_approver_request(&device.id, method, path, timestamp, body, &signature)
                    .is_err()
            );
        }

        let id = match service.create_group_authorized(&agent, "Deploy", None, "g-1", false) {
            Err(KeyLeaseError::ApprovalRequired { approval_id }) => approval_id,
            other => panic!("expected approval_required, got {other:?}"),
        };
        let pending = service.remote_list_approvals(&device).unwrap();
        let record = pending.iter().find(|a| a.id.0 == id).unwrap().clone();
        assert!(
            service
                .remote_decide(
                    &device,
                    &id,
                    true,
                    "0".repeat(64).as_str(),
                    record.policy_version,
                    None
                )
                .is_err()
        );
        let outcome = service
            .remote_decide(
                &device,
                &id,
                true,
                &record.request_digest_hex,
                record.policy_version,
                Some(TrustDecision {
                    scope: TrustScope::Resource,
                    duration: TrustDuration::Hour1,
                }),
            )
            .unwrap();
        assert_eq!(
            outcome.trust.unwrap().decided_by,
            AgentId(device.id.clone())
        );

        service.revoke_approver_device(&device.id).unwrap();
        assert!(
            service
                .verify_approver_request(&device.id, "GET", "/v1/approvals", now, b"", &signature)
                .is_err()
        );
    }

    #[test]
    fn pairing_codes_are_readable_base32() {
        assert_eq!(data_encoding_base32(b"foobar"), "MZXW6YTBOI");
    }
}
