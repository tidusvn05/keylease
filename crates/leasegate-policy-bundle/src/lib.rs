//! Signing and rollback-safe verification for Phase 3 control artifacts.

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use keylease_core::{KeyLeaseError, OrganizationId, ProjectId, Result};
use leasegate_control::{
    ApprovalReceiptPayload, PolicyBundlePayload, SignedApprovalReceipt, SignedPolicyBundle,
    SyncMutationEnvelope,
};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const ALGORITHM: &str = "ed25519-jcs-rfc8785-v1";

pub struct ControlSigner {
    key_id: String,
    key: SigningKey,
}

impl std::fmt::Debug for ControlSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControlSigner")
            .field("key_id", &self.key_id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl ControlSigner {
    pub fn generate(key_id: impl Into<String>) -> Result<Self> {
        let mut bytes = [0_u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        let key = SigningKey::from_bytes(&bytes);
        bytes.zeroize();
        Self::from_signing_key(key_id, key)
    }

    pub fn from_bytes(key_id: impl Into<String>, bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| KeyLeaseError::InvalidRequest {
                reason: "Ed25519 signing key must contain 32 bytes".into(),
            })?;
        Self::from_signing_key(key_id, SigningKey::from_bytes(&bytes))
    }

    fn from_signing_key(key_id: impl Into<String>, key: SigningKey) -> Result<Self> {
        let key_id = key_id.into();
        if key_id.is_empty() || key_id.len() > 128 || key_id.chars().any(char::is_control) {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "invalid signing key identifier".into(),
            });
        }
        Ok(Self { key_id, key })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn verifying_key_base64(&self) -> String {
        STANDARD_NO_PAD.encode(self.key.verifying_key().to_bytes())
    }

    pub fn sign_policy(&self, payload: PolicyBundlePayload) -> Result<SignedPolicyBundle> {
        let bytes = canonical_bytes(&payload)?;
        Ok(SignedPolicyBundle {
            algorithm: ALGORITHM.into(),
            signer_key_id: self.key_id.clone(),
            payload,
            payload_digest_sha256: hex(&Sha256::digest(&bytes)),
            signature_base64: STANDARD_NO_PAD.encode(self.key.sign(&bytes).to_bytes()),
        })
    }

    pub fn sign_approval(&self, payload: ApprovalReceiptPayload) -> Result<SignedApprovalReceipt> {
        let bytes = canonical_bytes(&payload)?;
        Ok(SignedApprovalReceipt {
            algorithm: ALGORITHM.into(),
            signer_key_id: self.key_id.clone(),
            payload,
            payload_digest_sha256: hex(&Sha256::digest(&bytes)),
            signature_base64: STANDARD_NO_PAD.encode(self.key.sign(&bytes).to_bytes()),
        })
    }

    pub fn sign_sync_mutation(&self, mutation: &mut SyncMutationEnvelope) -> Result<()> {
        mutation.validate_shape()?;
        let bytes = canonical_bytes(&mutation.signing_payload())?;
        mutation.device_signature_base64 = STANDARD_NO_PAD.encode(self.key.sign(&bytes).to_bytes());
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleAcceptanceState {
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub version: u64,
    pub payload_digest_sha256: String,
    pub revocation_epoch: u64,
}

pub fn verify_policy_bundle(
    bundle: &SignedPolicyBundle,
    verifying_key_base64: &str,
    now: DateTime<Utc>,
    previous: Option<&BundleAcceptanceState>,
) -> Result<BundleAcceptanceState> {
    verify_signed_payload(
        &bundle.algorithm,
        &bundle.payload,
        &bundle.payload_digest_sha256,
        &bundle.signature_base64,
        verifying_key_base64,
    )?;
    if bundle.payload.schema_version != leasegate_control::CONTROL_CONTRACT_VERSION {
        return Err(KeyLeaseError::UnsupportedVersion {
            version: bundle.payload.schema_version,
        });
    }
    if bundle.payload.not_before > now || bundle.payload.expires_at <= now {
        return Err(KeyLeaseError::Denied {
            reason: "policy bundle is outside its validity window".into(),
        });
    }
    if bundle.payload.version == 0 || bundle.payload.expires_at <= bundle.payload.not_before {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "invalid policy bundle version or validity interval".into(),
        });
    }
    if let Some(previous) = previous {
        if bundle.payload.organization_id != previous.organization_id
            || bundle.payload.project_id != previous.project_id
        {
            return Err(KeyLeaseError::Denied {
                reason: "policy bundle tenant mismatch".into(),
            });
        }
        if bundle.payload.version <= previous.version
            || bundle.payload.revocation_epoch < previous.revocation_epoch
            || bundle.payload.previous_bundle_digest.as_deref()
                != Some(previous.payload_digest_sha256.as_str())
        {
            return Err(KeyLeaseError::Denied {
                reason: "policy rollback or chain discontinuity detected".into(),
            });
        }
    } else if bundle.payload.previous_bundle_digest.is_some() {
        return Err(KeyLeaseError::Denied {
            reason: "initial policy bundle cannot reference an unknown predecessor".into(),
        });
    }
    Ok(BundleAcceptanceState {
        organization_id: bundle.payload.organization_id.clone(),
        project_id: bundle.payload.project_id.clone(),
        version: bundle.payload.version,
        payload_digest_sha256: bundle.payload_digest_sha256.clone(),
        revocation_epoch: bundle.payload.revocation_epoch,
    })
}

pub fn verify_approval_receipt(
    receipt: &SignedApprovalReceipt,
    verifying_key_base64: &str,
    now: DateTime<Utc>,
    expected_request_digest: &str,
    expected_policy_version: u64,
    organization_id: &OrganizationId,
    project_id: &ProjectId,
) -> Result<()> {
    verify_signed_payload(
        &receipt.algorithm,
        &receipt.payload,
        &receipt.payload_digest_sha256,
        &receipt.signature_base64,
        verifying_key_base64,
    )?;
    let payload = &receipt.payload;
    if payload.schema_version != leasegate_control::CONTROL_CONTRACT_VERSION {
        return Err(KeyLeaseError::UnsupportedVersion {
            version: payload.schema_version,
        });
    }
    if payload.request_digest_hex != expected_request_digest
        || payload.policy_version != expected_policy_version
        || &payload.organization_id != organization_id
        || &payload.project_id != project_id
        || payload.expires_at <= now
        || payload.expires_at <= payload.issued_at
        || payload.max_uses == 0
    {
        return Err(KeyLeaseError::Denied {
            reason: "approval receipt does not bind the exact live request".into(),
        });
    }
    Ok(())
}

pub fn verify_sync_mutation_signature(
    mutation: &SyncMutationEnvelope,
    verifying_key_base64: &str,
) -> Result<()> {
    mutation.validate_shape()?;
    let bytes = canonical_bytes(&mutation.signing_payload())?;
    verify_signature(
        &bytes,
        &mutation.device_signature_base64,
        verifying_key_base64,
    )
}

fn verify_signed_payload<T: Serialize>(
    algorithm: &str,
    payload: &T,
    claimed_digest: &str,
    signature_base64: &str,
    verifying_key_base64: &str,
) -> Result<()> {
    if algorithm != ALGORITHM {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "unsupported control signature algorithm".into(),
        });
    }
    let bytes = canonical_bytes(payload)?;
    let digest = hex(&Sha256::digest(&bytes));
    if digest != claimed_digest {
        return Err(KeyLeaseError::Denied {
            reason: "signed payload digest mismatch".into(),
        });
    }
    verify_signature(&bytes, signature_base64, verifying_key_base64)
}

fn verify_signature(
    bytes: &[u8],
    signature_base64: &str,
    verifying_key_base64: &str,
) -> Result<()> {
    let public: [u8; 32] = STANDARD_NO_PAD
        .decode(verifying_key_base64)
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid verifying key encoding".into(),
        })?
        .try_into()
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid Ed25519 verifying key length".into(),
        })?;
    let signature: [u8; 64] = STANDARD_NO_PAD
        .decode(signature_base64)
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid signature encoding".into(),
        })?
        .try_into()
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid Ed25519 signature length".into(),
        })?;
    let verifying_key = VerifyingKey::from_bytes(&public).map_err(|_| KeyLeaseError::Crypto)?;
    verifying_key
        .verify(bytes, &Signature::from_bytes(&signature))
        .map_err(|_| KeyLeaseError::Denied {
            reason: "control signature verification failed".into(),
        })
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(value).map_err(|_| KeyLeaseError::InvalidRequest {
        reason: "control artifact cannot be canonicalized as RFC 8785 JSON".into(),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use keylease_core::{AccountId, DeviceId, PolicyBundleId, SyncMutationId, VaultId};
    use leasegate_control::CONTROL_CONTRACT_VERSION;

    fn payload(version: u64, previous: Option<String>) -> PolicyBundlePayload {
        PolicyBundlePayload {
            schema_version: CONTROL_CONTRACT_VERSION,
            bundle_id: PolicyBundleId::new(),
            organization_id: OrganizationId("org_test".into()),
            project_id: ProjectId("project_test".into()),
            version,
            previous_bundle_digest: previous,
            issued_at: Utc::now(),
            not_before: Utc::now() - Duration::seconds(1),
            expires_at: Utc::now() + Duration::minutes(15),
            revocation_epoch: version,
            minimum_edge_version: "0.1.0".into(),
            offline: Default::default(),
            rules: vec![],
        }
    }

    #[test]
    fn policy_chain_detects_tamper_replay_and_discontinuity() {
        let signer = ControlSigner::generate("control-1").unwrap();
        let public = signer.verifying_key_base64();
        let first = signer.sign_policy(payload(1, None)).unwrap();
        let state = verify_policy_bundle(&first, &public, Utc::now(), None).unwrap();

        let second = signer
            .sign_policy(payload(2, Some(state.payload_digest_sha256.clone())))
            .unwrap();
        verify_policy_bundle(&second, &public, Utc::now(), Some(&state)).unwrap();
        assert!(verify_policy_bundle(&first, &public, Utc::now(), Some(&state)).is_err());

        let discontinuous = signer
            .sign_policy(payload(3, Some("wrong".into())))
            .unwrap();
        assert!(verify_policy_bundle(&discontinuous, &public, Utc::now(), Some(&state)).is_err());

        let mut tampered = second;
        tampered.payload.minimum_edge_version = "99.0.0".into();
        assert!(verify_policy_bundle(&tampered, &public, Utc::now(), Some(&state)).is_err());
    }

    #[test]
    fn device_signature_binds_sync_metadata_and_ciphertext_digest() {
        let signer = ControlSigner::generate("device-1").unwrap();
        let ciphertext = "ciphertext";
        let mut mutation = SyncMutationEnvelope {
            schema_version: CONTROL_CONTRACT_VERSION,
            mutation_id: SyncMutationId::new(),
            account_id: AccountId::new(),
            vault_id: VaultId::new(),
            object_id: "item_1".into(),
            device_id: DeviceId::new(),
            base_revision: 0,
            result_revision: 1,
            idempotency_key: "one".into(),
            ciphertext: ciphertext.into(),
            ciphertext_digest: hex(&Sha256::digest(ciphertext.as_bytes())),
            tombstone: false,
            created_at: Utc::now(),
            device_signature_base64: String::new(),
        };
        signer.sign_sync_mutation(&mut mutation).unwrap();
        verify_sync_mutation_signature(&mutation, &signer.verifying_key_base64()).unwrap();
        mutation.object_id = "item_2".into();
        assert!(verify_sync_mutation_signature(&mutation, &signer.verifying_key_base64()).is_err());
    }
}
