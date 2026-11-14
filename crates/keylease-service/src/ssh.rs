//! SSH agent signing inside the service boundary (ADR 0005, tier T1).
//!
//! Private keys stored as `core.ssh_key` items never leave the service. A
//! client — normally `keylease ssh-agent`, which speaks the OpenSSH agent
//! protocol to `ssh` and `git` — asks for the public identities and for a
//! signature over session data. Every signature is a policy decision on
//! `ssh:sign` for that exact key item, so it can require an approval or be
//! covered by a time-boxed trust.

use super::*;
use schemars::JsonSchema;
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey, Signature, private::KeypairData};

/// `SSH_AGENT_RSA_SHA2_256` from the agent protocol draft.
pub const SSH_AGENT_RSA_SHA2_256: u32 = 2;
/// `SSH_AGENT_RSA_SHA2_512` from the agent protocol draft.
pub const SSH_AGENT_RSA_SHA2_512: u32 = 4;

/// Largest blob a sign request may carry. OpenSSH session data is a few
/// hundred bytes; `ssh-keygen -Y sign` sends a hash, not the file.
const MAX_SIGN_DATA_BYTES: usize = 64 * 1024;

/// A public identity the agent may offer. Contains no secret material.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SshIdentity {
    pub item_id: ItemId,
    /// Base64 of the SSH wire-format public key blob.
    pub public_key_blob: String,
    pub comment: String,
    pub fingerprint: String,
    pub algorithm: String,
}

/// A signature in SSH wire format, base64-encoded.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SshSignature {
    pub signature_blob: String,
    pub fingerprint: String,
}

/// Parses the stored OpenSSH private key of an SSH key item, if it has one.
/// The key may still be passphrase-encrypted; its public half is readable
/// either way, so listing never pays for the KDF.
fn item_stored_key(item: &VaultItem) -> Option<PrivateKey> {
    if item.kind != "core.ssh_key" {
        return None;
    }
    let pem = item.fields.iter().find_map(|field| match &field.value {
        FieldValue::KeyPair { private, .. } => Some(Zeroizing::new(private.clone())),
        FieldValue::Concealed(value) | FieldValue::Text(value)
            if field.key == "private_key"
                || field.semantic_role.as_deref() == Some("private_key") =>
        {
            Some(Zeroizing::new(value.clone()))
        }
        _ => None,
    })?;
    PrivateKey::from_openssh(pem.trim()).ok()
}

/// Decrypts a stored key with the item's `passphrase` field when needed.
fn unlock_key(item: &VaultItem, key: PrivateKey) -> Result<PrivateKey> {
    if !key.is_encrypted() {
        return Ok(key);
    }
    let passphrase = item
        .fields
        .iter()
        .find_map(|field| match &field.value {
            FieldValue::Concealed(value) | FieldValue::Text(value) if field.key == "passphrase" => {
                Some(Zeroizing::new(value.clone()))
            }
            _ => None,
        })
        .ok_or_else(|| KeyLeaseError::InvalidRequest {
            reason: "SSH key is encrypted and the item has no passphrase field".into(),
        })?;
    key.decrypt(passphrase.as_bytes())
        .map_err(|_| KeyLeaseError::Crypto)
}

fn identity(item: &VaultItem, public: &PublicKey) -> Result<SshIdentity> {
    let blob = public.to_bytes().map_err(|_| KeyLeaseError::Crypto)?;
    Ok(SshIdentity {
        item_id: item.id.clone(),
        public_key_blob: base64::engine::general_purpose::STANDARD.encode(blob),
        comment: item.title.clone(),
        fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
        algorithm: public.algorithm().as_str().into(),
    })
}

/// Rebuilds an `rsa` private key from OpenSSH components.
///
/// `ssh-key` 0.6.7's own `TryFrom<&RsaKeypair>` passes `p` twice as the prime
/// factors, so it cannot be used.
fn rsa_private_key(keypair: &ssh_key::private::RsaKeypair) -> Result<rsa::RsaPrivateKey> {
    let integer = |value: &ssh_key::Mpint| {
        value
            .as_positive_bytes()
            .map(rsa::BigUint::from_bytes_be)
            .ok_or(KeyLeaseError::Crypto)
    };
    let key = rsa::RsaPrivateKey::from_components(
        integer(&keypair.public.n)?,
        integer(&keypair.public.e)?,
        integer(&keypair.private.d)?,
        vec![integer(&keypair.private.p)?, integer(&keypair.private.q)?],
    )
    .map_err(|_| KeyLeaseError::Crypto)?;
    if rsa::traits::PublicKeyParts::size(&key) * 8 < 2048 {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "RSA keys shorter than 2048 bits are not supported".into(),
        });
    }
    Ok(key)
}

/// Signs `data` the way the agent protocol asks: RSA honours the SHA-2 flags,
/// every other algorithm has a single signature form.
fn sign(key: &PrivateKey, data: &[u8], flags: u32) -> Result<Signature> {
    use signature::Signer;
    match key.key_data() {
        KeypairData::Rsa(keypair) => {
            let private = rsa_private_key(keypair)?;
            let (hash, bytes) = if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(private);
                (
                    HashAlg::Sha512,
                    signer.try_sign(data).map_err(|_| KeyLeaseError::Crypto)?,
                )
            } else if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private);
                (
                    HashAlg::Sha256,
                    signer.try_sign(data).map_err(|_| KeyLeaseError::Crypto)?,
                )
            } else {
                // Legacy `ssh-rsa` (SHA-1) signatures are refused outright.
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "SHA-1 RSA signatures are not supported; use rsa-sha2-256/512".into(),
                });
            };
            Signature::new(
                Algorithm::Rsa { hash: Some(hash) },
                signature::SignatureEncoding::to_vec(&bytes),
            )
            .map_err(|_| KeyLeaseError::Crypto)
        }
        _ => key.try_sign(data).map_err(|_| KeyLeaseError::Crypto),
    }
}

impl KeyLeaseService {
    /// Lists the SSH public keys the agent may offer.
    ///
    /// Listing reveals only public keys and item titles, but it is still a
    /// policy decision so a client without SSH authority learns nothing.
    pub fn ssh_identities_authorized(&self, actor: &ActorContext) -> Result<Vec<SshIdentity>> {
        self.with_vault(|vault| {
            let resource = format!("kl://{}", vault.vault_id.0);
            self.authorize_vault(
                vault,
                actor,
                "ssh:list_keys",
                &resource,
                Value::Object(Default::default()),
            )?;
            let mut identities = Vec::new();
            for item in self.store.list_items(vault)? {
                if item.status != ItemStatus::Active || item.kind != "core.ssh_key" {
                    continue;
                }
                if let Some(key) = item_stored_key(&item) {
                    identities.push(identity(&item, key.public_key())?);
                }
            }
            self.audit_vault(
                actor,
                "ssh:list_keys",
                &resource,
                "allow",
                "success",
                vec![],
            )?;
            Ok(identities)
        })
    }

    /// Signs agent-protocol session data with the vault key matching
    /// `public_key_blob`.
    ///
    /// The authorization arguments hold only the key fingerprint, never the
    /// session data, so a retried sign request finds the same approval.
    pub fn ssh_sign_authorized(
        &self,
        actor: &ActorContext,
        public_key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> Result<SshSignature> {
        if data.is_empty() || data.len() > MAX_SIGN_DATA_BYTES {
            return Err(KeyLeaseError::InvalidRequest {
                reason: format!("sign data must be 1..={MAX_SIGN_DATA_BYTES} bytes"),
            });
        }
        let requested = PublicKey::from_bytes(public_key_blob)
            .map_err(|_| KeyLeaseError::InvalidRequest {
                reason: "invalid SSH public key blob".into(),
            })?
            .key_data()
            .clone();
        self.with_vault(|vault| {
            let (item, key) = self
                .store
                .list_items(vault)?
                .into_iter()
                .filter(|item| item.status == ItemStatus::Active)
                .find_map(|item| {
                    let key = item_stored_key(&item)?;
                    (key.public_key().key_data() == &requested).then_some((item, key))
                })
                .ok_or_else(|| KeyLeaseError::NotFound {
                    resource: "ssh identity".into(),
                })?;
            let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
            let resource = format!("kl://{}/{}", vault.vault_id.0, item.id.0);
            let risk = match item.environment.as_deref().map(str::to_ascii_lowercase) {
                Some(environment) if environment.starts_with("prod") => RiskTier::R3,
                _ => RiskTier::R2,
            };
            self.authorize_vault_at_risk(
                vault,
                actor,
                "ssh:sign",
                &resource,
                serde_json::json!({"fingerprint": fingerprint}),
                risk,
            )?;
            // Decrypt only after the use is authorized.
            let key = unlock_key(&item, key)?;
            let signature = sign(&key, data, flags)?;
            let encoded = Vec::<u8>::try_from(signature).map_err(|_| KeyLeaseError::Crypto)?;
            self.audit_vault(actor, "ssh:sign", &resource, "allow", "success", vec![])?;
            Ok(SshSignature {
                signature_blob: base64::engine::general_purpose::STANDARD.encode(encoded),
                fingerprint,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{LineEnding, rand_core::OsRng};

    fn service_with_key(
        algorithm: Algorithm,
    ) -> (
        tempfile::TempDir,
        KeyLeaseService,
        ActorContext,
        ActorContext,
        PrivateKey,
    ) {
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
        let key = match algorithm {
            // The default RSA size is slow to generate in a debug build.
            Algorithm::Rsa { .. } => {
                PrivateKey::from(ssh_key::private::RsaKeypair::random(&mut OsRng, 2048).unwrap())
            }
            other => PrivateKey::random(&mut OsRng, other).unwrap(),
        };
        let pem = key.to_openssh(LineEnding::LF).unwrap();
        let group = service.create_group("Keys", None).unwrap();
        let mut input = NewEntryInput {
            favorite: false,
            group_id: group.id,
            kind: "core.ssh_key".into(),
            title: "Deploy key".into(),
            project_slug: None,
            username: None,
            password: None,
            url: None,
            notes: None,
            custom_fields: vec![],
            sections: vec![],
            totp: None,
            totp_uri: None,
        };
        input.custom_fields.push(field(
            "private_key",
            "Private key",
            FieldValue::Concealed(pem.to_string()),
            Sensitivity::Secret,
            true,
        ));
        service
            .create_entry(&owner, input, "ssh-key", false)
            .unwrap();
        let enrolled = service.enroll_agent_authorized(&owner, "ssh").unwrap();
        let agent = service
            .authenticate(&enrolled.agent_id, &enrolled.token, "agent")
            .unwrap();
        (dir, service, owner, agent, key)
    }

    fn approval(result: Result<impl std::fmt::Debug>) -> String {
        match result {
            Err(KeyLeaseError::ApprovalRequired { approval_id }) => approval_id,
            other => panic!("expected approval_required, got {other:?}"),
        }
    }

    #[test]
    fn signing_needs_approval_and_verifies_against_the_public_key() {
        let (_dir, service, owner, agent, key) = service_with_key(Algorithm::Ed25519);
        let identities = service.ssh_identities_authorized(&agent).unwrap();
        assert_eq!(identities.len(), 1);
        let encoded = serde_json::to_string(&identities).unwrap();
        assert!(!encoded.contains("PRIVATE"));
        let blob = base64::engine::general_purpose::STANDARD
            .decode(&identities[0].public_key_blob)
            .unwrap();

        let data = b"session-data-to-sign";
        let id = approval(service.ssh_sign_authorized(&agent, &blob, data, 0));
        // Fresh session data for the retry, as a real ssh client would send.
        assert_eq!(
            approval(service.ssh_sign_authorized(&agent, &blob, b"other-session", 0)),
            id
        );
        service
            .decide_approval_authorized(&owner, &id, true)
            .unwrap();
        let signed = service.ssh_sign_authorized(&agent, &blob, data, 0).unwrap();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(signed.signature_blob)
            .unwrap();
        let signature = Signature::try_from(raw.as_slice()).unwrap();
        signature::Verifier::verify(key.public_key(), data, &signature).unwrap();
        approval(service.ssh_sign_authorized(&agent, &blob, data, 0));
    }

    #[test]
    fn rsa_honours_sha2_flags_and_refuses_sha1() {
        let (_dir, service, owner, agent, key) = service_with_key(Algorithm::Rsa { hash: None });
        let blob = key.public_key().to_bytes().unwrap();
        let id =
            approval(service.ssh_sign_authorized(&agent, &blob, b"data", SSH_AGENT_RSA_SHA2_256));
        service
            .decide_approval_with_trust_authorized(
                &owner,
                &id,
                true,
                Some(TrustDecision {
                    scope: TrustScope::Resource,
                    duration: TrustDuration::Hour1,
                }),
            )
            .unwrap();
        for (flags, algorithm) in [
            (SSH_AGENT_RSA_SHA2_256, "rsa-sha2-256"),
            (SSH_AGENT_RSA_SHA2_512, "rsa-sha2-512"),
        ] {
            let signed = service
                .ssh_sign_authorized(&agent, &blob, b"data", flags)
                .unwrap();
            let raw = base64::engine::general_purpose::STANDARD
                .decode(signed.signature_blob)
                .unwrap();
            let signature = Signature::try_from(raw.as_slice()).unwrap();
            assert_eq!(signature.algorithm().as_str(), algorithm);
            signature::Verifier::verify(key.public_key(), b"data", &signature).unwrap();
        }
        assert!(matches!(
            service.ssh_sign_authorized(&agent, &blob, b"data", 0),
            Err(KeyLeaseError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn an_encrypted_key_lists_without_its_passphrase_and_signs_with_it() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let encrypted = key.encrypt(&mut OsRng, "item-passphrase").unwrap();
        let pem = encrypted.to_openssh(LineEnding::LF).unwrap();
        let mut item_fields = vec![field(
            "private_key",
            "Private key",
            FieldValue::Concealed(pem.to_string()),
            Sensitivity::Secret,
            true,
        )];
        let item = |fields: Vec<ItemField>| VaultItem {
            kind: "core.ssh_key".into(),
            fields,
            ..serde_json::from_value(serde_json::json!({
                "id": "item_x", "vault_id": "vault_x", "group_id": "group_x",
                "kind": "core.ssh_key", "title": "k", "sections": [], "fields": [],
                "urls": [], "tags": [], "attachments": [], "notes": null,
                "schema_version": 1, "revision": 1,
                "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
                "secret_changed_at": null, "expires_at": null,
                "rotation_interval_days": null, "issuer": null, "environment": null,
                "status": "active"
            }))
            .unwrap()
        };
        let stored = item_stored_key(&item(item_fields.clone())).unwrap();
        assert_eq!(stored.public_key().key_data(), key.public_key().key_data());
        assert!(unlock_key(&item(item_fields.clone()), stored.clone()).is_err());
        item_fields.push(field(
            "passphrase",
            "Passphrase",
            FieldValue::Concealed("item-passphrase".into()),
            Sensitivity::Secret,
            true,
        ));
        let unlocked = unlock_key(&item(item_fields), stored).unwrap();
        let signature = sign(&unlocked, b"data", 0).unwrap();
        signature::Verifier::verify(key.public_key(), b"data", &signature).unwrap();
    }

    #[test]
    fn an_unknown_key_is_not_found_and_reveals_nothing() {
        let (_dir, service, _owner, agent, _key) = service_with_key(Algorithm::Ed25519);
        let other = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let blob = other.public_key().to_bytes().unwrap();
        assert!(matches!(
            service.ssh_sign_authorized(&agent, &blob, b"data", 0),
            Err(KeyLeaseError::NotFound { .. })
        ));
    }
}
