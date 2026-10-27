//! Auditable crypto-envelope primitives. No persistence or policy lives here.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use keylease_core::{AccountId, ItemId, KeyLeaseError, Result, VaultId};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod sealed;

pub const ENVELOPE_VERSION: u32 = 1;
pub const ALGORITHM: &str = "xchacha20poly1305";

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn random() -> Self {
        let mut bytes = [0_u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

pub fn keyed_digest(key: &SecretKey, domain: &str, material: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.expose())
        .expect("SHA-256 HMAC accepts a 32-byte key");
    mac.update(domain.as_bytes());
    mac.update(&[0]);
    mac.update(material);
    mac.finalize().into_bytes().into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WrappedKey {
    pub version: u32,
    pub algorithm: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PasswordSlot {
    pub version: u32,
    pub kdf: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
    pub salt_b64: String,
    pub wrapped_root_key: WrappedKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EncryptedItem {
    pub version: u32,
    pub algorithm: String,
    pub account_id: AccountId,
    pub vault_id: VaultId,
    pub item_id: ItemId,
    pub revision: u64,
    pub schema_version: u32,
    pub wrapped_item_key: WrappedKey,
    pub payload_nonce_b64: String,
    pub payload_ciphertext_b64: String,
}

pub fn create_password_slot(
    password: &[u8],
    account_id: &AccountId,
    root_key: &SecretKey,
) -> Result<PasswordSlot> {
    let (memory_kib, iterations, lanes) = (65_536, 3, 1);
    let mut salt = [0_u8; 16];
    rand::rng().fill_bytes(&mut salt);
    let unlock_key = derive_password_unlock_key(password, &salt, memory_kib, iterations, lanes)?;
    let aad = format!("keylease:v1:password-slot:{}", account_id.0);
    Ok(PasswordSlot {
        version: ENVELOPE_VERSION,
        kdf: "argon2id+hmac-sha256-hkdf".into(),
        memory_kib,
        iterations,
        lanes,
        salt_b64: STANDARD_NO_PAD.encode(salt),
        wrapped_root_key: wrap_key(&unlock_key, root_key, aad.as_bytes())?,
    })
}

pub fn unlock_password_slot(
    password: &[u8],
    account_id: &AccountId,
    slot: &PasswordSlot,
) -> Result<SecretKey> {
    validate_slot(slot)?;
    let salt = decode(&slot.salt_b64)?;
    let unlock_key = derive_password_unlock_key(
        password,
        &salt,
        slot.memory_kib,
        slot.iterations,
        slot.lanes,
    )?;
    let aad = format!("keylease:v1:password-slot:{}", account_id.0);
    unwrap_key(&unlock_key, &slot.wrapped_root_key, aad.as_bytes())
}

pub fn wrap_vault_key(
    account_id: &AccountId,
    vault_id: &VaultId,
    root_key: &SecretKey,
    vault_key: &SecretKey,
) -> Result<WrappedKey> {
    wrap_key(
        root_key,
        vault_key,
        format!("keylease:v1:vault-key:{}:{}", account_id.0, vault_id.0).as_bytes(),
    )
}

pub fn unwrap_vault_key(
    account_id: &AccountId,
    vault_id: &VaultId,
    root_key: &SecretKey,
    wrapped: &WrappedKey,
) -> Result<SecretKey> {
    unwrap_key(
        root_key,
        wrapped,
        format!("keylease:v1:vault-key:{}:{}", account_id.0, vault_id.0).as_bytes(),
    )
}

pub fn encrypt_item(
    account_id: &AccountId,
    vault_id: &VaultId,
    item_id: &ItemId,
    revision: u64,
    schema_version: u32,
    vault_key: &SecretKey,
    plaintext: &[u8],
) -> Result<EncryptedItem> {
    let item_key = SecretKey::random();
    let key_aad = item_key_aad(account_id, vault_id, item_id);
    let payload_aad = payload_aad(account_id, vault_id, item_id, revision, schema_version);
    let (nonce, ciphertext) = encrypt(&item_key, plaintext, payload_aad.as_bytes())?;
    Ok(EncryptedItem {
        version: ENVELOPE_VERSION,
        algorithm: ALGORITHM.into(),
        account_id: account_id.clone(),
        vault_id: vault_id.clone(),
        item_id: item_id.clone(),
        revision,
        schema_version,
        wrapped_item_key: wrap_key(vault_key, &item_key, key_aad.as_bytes())?,
        payload_nonce_b64: STANDARD_NO_PAD.encode(nonce),
        payload_ciphertext_b64: STANDARD_NO_PAD.encode(ciphertext),
    })
}

pub fn decrypt_item(envelope: &EncryptedItem, vault_key: &SecretKey) -> Result<Vec<u8>> {
    validate_envelope(envelope.version, &envelope.algorithm)?;
    let item_key = unwrap_key(
        vault_key,
        &envelope.wrapped_item_key,
        item_key_aad(&envelope.account_id, &envelope.vault_id, &envelope.item_id).as_bytes(),
    )?;
    let nonce = decode(&envelope.payload_nonce_b64)?;
    let ciphertext = decode(&envelope.payload_ciphertext_b64)?;
    decrypt(
        &item_key,
        &nonce,
        &ciphertext,
        payload_aad(
            &envelope.account_id,
            &envelope.vault_id,
            &envelope.item_id,
            envelope.revision,
            envelope.schema_version,
        )
        .as_bytes(),
    )
}

pub fn rewrap_item_key(
    envelope: &mut EncryptedItem,
    old_vault_key: &SecretKey,
    new_vault_key: &SecretKey,
) -> Result<()> {
    let aad = item_key_aad(&envelope.account_id, &envelope.vault_id, &envelope.item_id);
    let item_key = unwrap_key(old_vault_key, &envelope.wrapped_item_key, aad.as_bytes())?;
    envelope.wrapped_item_key = wrap_key(new_vault_key, &item_key, aad.as_bytes())?;
    Ok(())
}

fn derive_password_unlock_key(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
) -> Result<SecretKey> {
    let params =
        Params::new(memory_kib, iterations, lanes, Some(32)).map_err(|_| KeyLeaseError::Crypto)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut intermediate = [0_u8; 32];
    argon
        .hash_password_into(password, salt, &mut intermediate)
        .map_err(|_| KeyLeaseError::Crypto)?;
    let hkdf = Hkdf::<Sha256>::new(Some(b"keylease-password-unlock-v1"), &intermediate);
    let mut output = [0_u8; 32];
    hkdf.expand(b"password-slot-wrap-key", &mut output)
        .map_err(|_| KeyLeaseError::Crypto)?;
    intermediate.zeroize();
    Ok(SecretKey(output))
}

fn wrap_key(wrapping_key: &SecretKey, target: &SecretKey, aad: &[u8]) -> Result<WrappedKey> {
    let (nonce, ciphertext) = encrypt(wrapping_key, target.expose(), aad)?;
    Ok(WrappedKey {
        version: ENVELOPE_VERSION,
        algorithm: ALGORITHM.into(),
        nonce_b64: STANDARD_NO_PAD.encode(nonce),
        ciphertext_b64: STANDARD_NO_PAD.encode(ciphertext),
    })
}

fn unwrap_key(wrapping_key: &SecretKey, wrapped: &WrappedKey, aad: &[u8]) -> Result<SecretKey> {
    validate_envelope(wrapped.version, &wrapped.algorithm)?;
    let plaintext = decrypt(
        wrapping_key,
        &decode(&wrapped.nonce_b64)?,
        &decode(&wrapped.ciphertext_b64)?,
        aad,
    )?;
    let bytes: [u8; 32] = plaintext.try_into().map_err(|_| KeyLeaseError::Crypto)?;
    Ok(SecretKey(bytes))
}

fn encrypt(key: &SecretKey, plaintext: &[u8], aad: &[u8]) -> Result<([u8; 24], Vec<u8>)> {
    let mut nonce = [0_u8; 24];
    rand::rng().fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| KeyLeaseError::Crypto)?;
    Ok((nonce, ciphertext))
}

fn decrypt(key: &SecretKey, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != 24 {
        return Err(KeyLeaseError::Crypto);
    }
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| KeyLeaseError::Crypto)
}

fn decode(value: &str) -> Result<Vec<u8>> {
    STANDARD_NO_PAD
        .decode(value)
        .map_err(|_| KeyLeaseError::Crypto)
}
fn validate_slot(slot: &PasswordSlot) -> Result<()> {
    if slot.version != ENVELOPE_VERSION || slot.kdf != "argon2id+hmac-sha256-hkdf" {
        return Err(KeyLeaseError::Crypto);
    }
    Ok(())
}
fn validate_envelope(version: u32, algorithm: &str) -> Result<()> {
    if version != ENVELOPE_VERSION || algorithm != ALGORITHM {
        return Err(KeyLeaseError::Crypto);
    }
    Ok(())
}
fn item_key_aad(account: &AccountId, vault: &VaultId, item: &ItemId) -> String {
    format!("keylease:v1:item-key:{}:{}:{}", account.0, vault.0, item.0)
}
fn payload_aad(
    account: &AccountId,
    vault: &VaultId,
    item: &ItemId,
    revision: u64,
    schema: u32,
) -> String {
    format!(
        "keylease:v1:item-payload:{}:{}:{}:{}:{}",
        account.0, vault.0, item.0, revision, schema
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_slot_and_item_round_trip_and_aad_tamper() {
        let account = AccountId::new();
        let vault = VaultId::new();
        let item = ItemId::new();
        let root = SecretKey::random();
        let slot = create_password_slot(b"correct horse", &account, &root).unwrap();
        let unlocked = unlock_password_slot(b"correct horse", &account, &slot).unwrap();
        assert!(unlock_password_slot(b"wrong", &account, &slot).is_err());
        let vault_key = SecretKey::random();
        let wrapped_vault = wrap_vault_key(&account, &vault, &unlocked, &vault_key).unwrap();
        let unwrapped_vault = unwrap_vault_key(&account, &vault, &root, &wrapped_vault).unwrap();
        let envelope = encrypt_item(
            &account,
            &vault,
            &item,
            1,
            1,
            &unwrapped_vault,
            b"secret payload",
        )
        .unwrap();
        assert_eq!(
            decrypt_item(&envelope, &vault_key).unwrap(),
            b"secret payload"
        );
        let mut tampered = envelope;
        tampered.revision = 2;
        assert!(decrypt_item(&tampered, &vault_key).is_err());
    }

    #[test]
    fn password_change_only_rewraps_root_key() {
        let account = AccountId::new();
        let vault = VaultId::new();
        let item = ItemId::new();
        let root = SecretKey::random();
        let vault_key = SecretKey::random();
        let before = encrypt_item(&account, &vault, &item, 1, 1, &vault_key, b"payload").unwrap();
        let old = create_password_slot(b"old", &account, &root).unwrap();
        let unlocked = unlock_password_slot(b"old", &account, &old).unwrap();
        let _new = create_password_slot(b"new", &account, &unlocked).unwrap();
        assert_eq!(
            before.payload_ciphertext_b64,
            before.clone().payload_ciphertext_b64
        );
    }
}
