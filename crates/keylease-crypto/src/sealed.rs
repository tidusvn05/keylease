//! Public-key sealing for the cloud relay (ADR 0006).
//!
//! `seal` encrypts to a recipient's X25519 public key with a fresh ephemeral
//! key: the shared secret goes through HKDF-SHA256 (salted with both public
//! keys) into an XChaCha20-Poly1305 key. The caller's `aad` binds the box to
//! its context (account, sender, recipient, kind, object, revision), so a box
//! cannot be replayed under another label. `seal_symmetric` is the same AEAD
//! under a key the caller already holds (local secrets, the recovery kit).

use super::{SecretKey, decode, decrypt, derive_password_unlock_key, encrypt};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use hkdf::Hkdf;
use keylease_core::{KeyLeaseError, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const SEALED_VERSION: u32 = 1;
pub const SEALED_ALGORITHM: &str = "x25519-hkdf-sha256-xchacha20poly1305";
pub const SYMMETRIC_ALGORITHM: &str = "xchacha20poly1305";

/// An X25519 key pair for receiving sealed boxes.
pub struct BoxKeypair {
    secret: StaticSecret,
}

impl BoxKeypair {
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        rand::rng().fill_bytes(bytes.as_mut());
        Self {
            secret: StaticSecret::from(*bytes),
        }
    }

    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(bytes),
        }
    }

    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        PublicKey::from(&self.secret).to_bytes()
    }
}

impl std::fmt::Debug for BoxKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BoxKeypair([REDACTED])")
    }
}

/// A box sealed to one recipient's public key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SealedBox {
    pub version: u32,
    pub algorithm: String,
    pub ephemeral_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

/// Ciphertext under a symmetric key the holder already has.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SymmetricBox {
    pub version: u32,
    pub algorithm: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

fn box_key(shared: &[u8; 32], ephemeral: &[u8; 32], recipient: &[u8; 32]) -> Result<SecretKey> {
    let mut salt = [0_u8; 64];
    salt[..32].copy_from_slice(ephemeral);
    salt[32..].copy_from_slice(recipient);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = [0_u8; 32];
    hkdf.expand(b"keylease-sealed-box-v1", &mut key)
        .map_err(|_| KeyLeaseError::Crypto)?;
    Ok(SecretKey::from_bytes(key))
}

/// Seals `plaintext` to `recipient` (an X25519 public key).
pub fn seal(recipient: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<SealedBox> {
    let ephemeral = BoxKeypair::generate();
    let ephemeral_public = ephemeral.public_bytes();
    let shared = ephemeral
        .secret
        .diffie_hellman(&PublicKey::from(*recipient));
    if !shared.was_contributory() {
        return Err(KeyLeaseError::Crypto);
    }
    let key = box_key(shared.as_bytes(), &ephemeral_public, recipient)?;
    let (nonce, ciphertext) = encrypt(&key, plaintext, aad)?;
    Ok(SealedBox {
        version: SEALED_VERSION,
        algorithm: SEALED_ALGORITHM.into(),
        ephemeral_b64: STANDARD_NO_PAD.encode(ephemeral_public),
        nonce_b64: STANDARD_NO_PAD.encode(nonce),
        ciphertext_b64: STANDARD_NO_PAD.encode(ciphertext),
    })
}

/// Opens a box sealed to `keypair` with the same `aad` it was sealed with.
pub fn open(keypair: &BoxKeypair, sealed: &SealedBox, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.version != SEALED_VERSION || sealed.algorithm != SEALED_ALGORITHM {
        return Err(KeyLeaseError::Crypto);
    }
    let ephemeral: [u8; 32] = decode(&sealed.ephemeral_b64)?
        .try_into()
        .map_err(|_| KeyLeaseError::Crypto)?;
    let shared = keypair.secret.diffie_hellman(&PublicKey::from(ephemeral));
    if !shared.was_contributory() {
        return Err(KeyLeaseError::Crypto);
    }
    let key = box_key(shared.as_bytes(), &ephemeral, &keypair.public_bytes())?;
    decrypt(
        &key,
        &decode(&sealed.nonce_b64)?,
        &decode(&sealed.ciphertext_b64)?,
        aad,
    )
    .map(Zeroizing::new)
}

pub fn seal_symmetric(key: &SecretKey, plaintext: &[u8], aad: &[u8]) -> Result<SymmetricBox> {
    let (nonce, ciphertext) = encrypt(key, plaintext, aad)?;
    Ok(SymmetricBox {
        version: SEALED_VERSION,
        algorithm: SYMMETRIC_ALGORITHM.into(),
        nonce_b64: STANDARD_NO_PAD.encode(nonce),
        ciphertext_b64: STANDARD_NO_PAD.encode(ciphertext),
    })
}

pub fn open_symmetric(
    key: &SecretKey,
    sealed: &SymmetricBox,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.version != SEALED_VERSION || sealed.algorithm != SYMMETRIC_ALGORITHM {
        return Err(KeyLeaseError::Crypto);
    }
    decrypt(
        key,
        &decode(&sealed.nonce_b64)?,
        &decode(&sealed.ciphertext_b64)?,
        aad,
    )
    .map(Zeroizing::new)
}

/// Keys derived from a recovery code: one encrypts the owner keys, the other
/// is the lookup value whose hash the cloud stores. Argon2id makes guessing a
/// code expensive even for the cloud; the account id is the salt.
pub struct RecoveryKeys {
    pub wrap_key: SecretKey,
    pub lookup: [u8; 32],
}

pub fn derive_recovery_keys(code: &str, account_id: &str) -> Result<RecoveryKeys> {
    let normalized: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if normalized.len() < 20 {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "recovery code is too short".into(),
        });
    }
    let salt = format!("keylease-recovery-v1:{account_id}");
    let root = derive_password_unlock_key(normalized.as_bytes(), salt.as_bytes(), 65536, 3, 1)?;
    let hkdf = Hkdf::<Sha256>::new(Some(b"keylease-recovery-v1"), root.expose());
    let mut wrap = [0_u8; 32];
    let mut lookup = [0_u8; 32];
    hkdf.expand(b"wrap", &mut wrap)
        .map_err(|_| KeyLeaseError::Crypto)?;
    hkdf.expand(b"lookup", &mut lookup)
        .map_err(|_| KeyLeaseError::Crypto)?;
    Ok(RecoveryKeys {
        wrap_key: SecretKey::from_bytes(wrap),
        lookup,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_box_opens_only_for_its_recipient_and_context() {
        let recipient = BoxKeypair::generate();
        let other = BoxKeypair::generate();
        let sealed = seal(&recipient.public_bytes(), b"db password", b"ctx-1").unwrap();
        assert_eq!(
            open(&recipient, &sealed, b"ctx-1").unwrap().as_slice(),
            b"db password"
        );
        assert!(open(&recipient, &sealed, b"ctx-2").is_err());
        assert!(open(&other, &sealed, b"ctx-1").is_err());
        let restored = BoxKeypair::from_secret_bytes(*recipient.secret_bytes());
        assert_eq!(restored.public_bytes(), recipient.public_bytes());
        assert!(open(&restored, &sealed, b"ctx-1").is_ok());
    }

    #[test]
    fn a_low_order_recipient_key_is_refused() {
        assert!(seal(&[0_u8; 32], b"x", b"ctx").is_err());
    }

    #[test]
    fn recovery_keys_depend_on_code_and_account() {
        let a = derive_recovery_keys("ABCD-EFGH-JKLM-NPQR-STUV-WXYZ", "acct_1").unwrap();
        let b = derive_recovery_keys("abcd efgh jklm npqr stuv wxyz", "acct_1").unwrap();
        let c = derive_recovery_keys("ABCD-EFGH-JKLM-NPQR-STUV-WXYZ", "acct_2").unwrap();
        assert_eq!(a.lookup, b.lookup);
        assert_ne!(a.lookup, c.lookup);
        let boxed = seal_symmetric(&a.wrap_key, b"owner keys", b"kit").unwrap();
        assert_eq!(
            open_symmetric(&b.wrap_key, &boxed, b"kit")
                .unwrap()
                .as_slice(),
            b"owner keys"
        );
        assert!(open_symmetric(&c.wrap_key, &boxed, b"kit").is_err());
        assert!(derive_recovery_keys("short", "acct_1").is_err());
    }
}
