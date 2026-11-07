//! Key-bound client identity (ADR 0005 section 6).
//!
//! A key-bound client holds an Ed25519 private key; the service keeps only the
//! public half. Each request carries `auth.signature`:
//!
//! ```json
//! {"timestamp": 1730000000, "nonce": "<base64>", "sig": "<base64>"}
//! ```
//!
//! `sig` is an Ed25519 signature over SHA-256 of [`DOMAIN`] followed by the
//! request as canonical JSON (keys sorted) with `auth.signature.sig` removed,
//! so it covers the command, every argument, the agent id, the timestamp and
//! the nonce. The service rejects a timestamp more than [`MAX_SKEW_SECONDS`]
//! away and a nonce it has already seen in that window.
//!
//! The credential file a client reads holds either a legacy bearer token
//! (`kl_client_...`) or a private key line (`kl_ed25519_...`).

use super::*;
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde_json::Value;

/// Prefix of a private key line in a client credential file.
pub const PRIVATE_PREFIX: &str = "kl_ed25519_";
/// Prefix of a public key as `client register --public-key` reads it.
pub const PUBLIC_PREFIX: &str = "kl_ed25519_pub_";
/// How far a signed request's timestamp may be from the service's clock.
pub const MAX_SKEW_SECONDS: i64 = 120;
/// Domain separation, so a client signature can never be valid elsewhere.
const DOMAIN: &[u8] = b"keylease client request v1\0";
/// Nonces remembered at once; beyond it, signed requests are refused until old
/// ones age out rather than letting the cache grow.
const MAX_NONCES: usize = 100_000;

/// A new private key line and its public key line.
pub fn generate() -> (Zeroizing<String>, String) {
    let mut seed = Zeroizing::new([0_u8; 32]);
    rand::rng().fill_bytes(seed.as_mut());
    let key = SigningKey::from_bytes(&seed);
    (
        Zeroizing::new(format!("{PRIVATE_PREFIX}{}", STANDARD_NO_PAD.encode(*seed))),
        encode_public(&key.verifying_key()),
    )
}

/// Whether a credential file's contents are a private key rather than a token.
pub fn is_private_key(credential: &str) -> bool {
    credential.trim().starts_with(PRIVATE_PREFIX) && !credential.trim().starts_with(PUBLIC_PREFIX)
}

/// The signing key in a private key line.
pub fn decode_private(line: &str) -> Result<SigningKey> {
    let invalid = || KeyLeaseError::InvalidRequest {
        reason: "the client key file is not a KeyLease private key".into(),
    };
    let encoded = line
        .trim()
        .strip_prefix(PRIVATE_PREFIX)
        .filter(|_| is_private_key(line))
        .ok_or_else(invalid)?;
    let seed = Zeroizing::new(STANDARD_NO_PAD.decode(encoded).map_err(|_| invalid())?);
    let seed: &[u8; 32] = seed.as_slice().try_into().map_err(|_| invalid())?;
    Ok(SigningKey::from_bytes(seed))
}

/// The public key line for a private key line.
pub fn public_of(line: &str) -> Result<String> {
    Ok(encode_public(&decode_private(line)?.verifying_key()))
}

fn encode_public(key: &VerifyingKey) -> String {
    format!("{PUBLIC_PREFIX}{}", STANDARD_NO_PAD.encode(key.as_bytes()))
}

/// A public key as KeyLease stores it, from `kl_ed25519_pub_...` or an OpenSSH
/// `ssh-ed25519 AAAA... [comment]` line.
pub fn parse_public(text: &str) -> Result<String> {
    let invalid = || KeyLeaseError::InvalidRequest {
        reason: "not an Ed25519 public key (expected kl_ed25519_pub_... or ssh-ed25519 ...)".into(),
    };
    let text = text.trim();
    let bytes: Vec<u8> = if let Some(encoded) = text.strip_prefix(PUBLIC_PREFIX) {
        STANDARD_NO_PAD.decode(encoded).map_err(|_| invalid())?
    } else if let Some(rest) = text.strip_prefix("ssh-ed25519 ") {
        let blob = base64::engine::general_purpose::STANDARD
            .decode(rest.split_whitespace().next().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
        // string "ssh-ed25519", string key (RFC 8709).
        let mut parts = vec![];
        let mut cursor = blob.as_slice();
        while cursor.len() >= 4 {
            let length =
                u32::from_be_bytes(cursor[..4].try_into().map_err(|_| invalid())?) as usize;
            cursor = &cursor[4..];
            if cursor.len() < length {
                return Err(invalid());
            }
            parts.push(&cursor[..length]);
            cursor = &cursor[length..];
        }
        match parts.as_slice() {
            [kind, key] if *kind == b"ssh-ed25519" && cursor.is_empty() => key.to_vec(),
            _ => return Err(invalid()),
        }
    } else {
        return Err(invalid());
    };
    let bytes: [u8; 32] = bytes.as_slice().try_into().map_err(|_| invalid())?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| invalid())?;
    Ok(encode_public(&key))
}

fn signed_digest(request: &Value) -> [u8; 32] {
    let mut unsigned = request.clone();
    if let Some(signature) = unsigned
        .pointer_mut("/auth/signature")
        .and_then(Value::as_object_mut)
    {
        signature.remove("sig");
    }
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(
        serde_json::to_vec(&canonical_json(&unsigned))
            .expect("serializing a JSON value cannot fail"),
    );
    hasher.finalize().into()
}

/// Signs `request` in place for the agent its `auth` block names.
pub fn sign_request(request: &mut Value, key: &SigningKey, timestamp: i64) -> Result<()> {
    let mut nonce = [0_u8; 16];
    rand::rng().fill_bytes(&mut nonce);
    let auth = request
        .get_mut("auth")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| KeyLeaseError::InvalidRequest {
            reason: "request has no auth block to sign".into(),
        })?;
    auth.insert(
        "signature".into(),
        serde_json::json!({"timestamp": timestamp, "nonce": STANDARD_NO_PAD.encode(nonce)}),
    );
    let signature = key.sign(&signed_digest(request));
    request["auth"]["signature"]["sig"] =
        Value::String(STANDARD_NO_PAD.encode(signature.to_bytes()));
    Ok(())
}

impl KeyLeaseService {
    /// Registers `name` as a key-bound client of `public_key`.
    pub fn register_client_with_key(&self, name: &str, public_key: &str) -> Result<AgentId> {
        let id = client_agent_id(name)?;
        self.store
            .register_client_key(&id, &parse_public(public_key)?)?;
        Ok(id)
    }

    /// Binds an existing agent client to `public_key`; its bearer token stops
    /// working. Its agent id, rules and trusts are unchanged.
    pub fn bind_client_key(&self, agent_id: &AgentId, public_key: &str) -> Result<()> {
        if self.store.local_owner_role(agent_id)?.is_some() {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "the owner app's credential is not an agent client".into(),
            });
        }
        self.store
            .bind_client_key(agent_id, &parse_public(public_key)?)
    }

    /// Every active client with how it authenticates (`key`, `legacy`,
    /// `owner`, `gateway`).
    pub fn list_clients_with_auth(&self) -> Result<Vec<(AgentId, &'static str)>> {
        self.store.list_clients_with_auth()
    }

    /// For the audit log: `legacy` for an agent that still uses a bearer
    /// token, `key` for a signing one, nothing for others.
    pub(crate) fn audit_client_auth(&self, agent_id: &AgentId) -> Option<String> {
        match self.store.client_auth_kind(agent_id) {
            Ok(Some(kind @ ("key" | "legacy"))) => Some(kind.into()),
            _ => None,
        }
    }

    /// Checks `request`'s client signature. `Ok(None)` when it carries none
    /// (a token-authenticated request); the signing agent when it verifies.
    pub fn verify_signed_request(&self, request: &Value) -> Result<Option<AgentId>> {
        self.verify_signed_request_at(request, Utc::now().timestamp())
    }

    fn verify_signed_request_at(&self, request: &Value, now: i64) -> Result<Option<AgentId>> {
        let Some(signature) = request.pointer("/auth/signature") else {
            return Ok(None);
        };
        let denied = |reason: &str| KeyLeaseError::Denied {
            reason: reason.into(),
        };
        let agent_id = request
            .pointer("/auth/agent_id")
            .and_then(Value::as_str)
            .map(|id| AgentId(id.into()))
            .ok_or_else(|| denied("signed request names no agent"))?;
        let timestamp = signature
            .get("timestamp")
            .and_then(Value::as_i64)
            .ok_or_else(|| denied("signed request has no timestamp"))?;
        let nonce = signature
            .get("nonce")
            .and_then(Value::as_str)
            .filter(|nonce| (16..=64).contains(&nonce.len()))
            .ok_or_else(|| denied("signed request has no valid nonce"))?;
        let sig = signature
            .get("sig")
            .and_then(Value::as_str)
            .and_then(|sig| STANDARD_NO_PAD.decode(sig).ok())
            .and_then(|sig| Signature::from_slice(&sig).ok())
            .ok_or_else(|| denied("client signature is malformed"))?;
        let public = self
            .store
            .client_public_key(&agent_id)?
            .ok_or_else(|| denied("client authentication failed"))?;
        let key = public
            .strip_prefix(PUBLIC_PREFIX)
            .and_then(|encoded| STANDARD_NO_PAD.decode(encoded).ok())
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
            .ok_or(KeyLeaseError::Storage)?;
        key.verify(&signed_digest(request), &sig)
            .map_err(|_| denied("client authentication failed"))?;
        if (now - timestamp).abs() > MAX_SKEW_SECONDS {
            return Err(denied(
                "signed request is stale; check this host's clock (allowed skew 120s)",
            ));
        }
        let mut nonces = self
            .signature_nonces
            .lock()
            .map_err(|_| KeyLeaseError::Storage)?;
        nonces.retain(|_, seen| (now - *seen).abs() <= 2 * MAX_SKEW_SECONDS);
        if nonces.len() >= MAX_NONCES {
            return Err(denied("too many signed requests; retry shortly"));
        }
        if nonces
            .insert(format!("{}\n{nonce}", agent_id.0), timestamp)
            .is_some()
        {
            return Err(denied("signed request was replayed"));
        }
        Ok(Some(agent_id))
    }
}

/// `agent_<name>` for a valid client name.
pub(crate) fn client_agent_id(name: &str) -> Result<AgentId> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "client name must be ASCII letters, digits, '-' or '_'".into(),
        });
    }
    Ok(AgentId(format!("agent_{name}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use keylease_store::NativeStore;

    fn service() -> (tempfile::TempDir, KeyLeaseService) {
        let directory = tempfile::tempdir().unwrap();
        let store = NativeStore::open(directory.path().join("v.sqlite")).unwrap();
        let service = KeyLeaseService::new(Arc::new(store)).unwrap();
        (directory, service)
    }

    fn request(agent: &str) -> Value {
        serde_json::json!({
            "command": "entries_search",
            "auth": {"agent_id": agent, "token": "", "session_id": "default"},
            "query": "db",
        })
    }

    #[test]
    fn a_signed_request_verifies_once_and_only_unaltered() {
        let (_dir, service) = service();
        let (private, public) = generate();
        let agent = service.register_client_with_key("bot", &public).unwrap();
        let key = decode_private(&private).unwrap();
        let now = Utc::now().timestamp();

        let mut signed = request("agent_bot");
        sign_request(&mut signed, &key, now).unwrap();
        assert_eq!(
            service.verify_signed_request_at(&signed, now).unwrap(),
            Some(agent)
        );
        // The same bytes again: a replay.
        assert!(service.verify_signed_request_at(&signed, now).is_err());

        // Any change to the request breaks the signature.
        let mut altered = request("agent_bot");
        sign_request(&mut altered, &key, now).unwrap();
        altered["query"] = "prod".into();
        assert!(service.verify_signed_request_at(&altered, now).is_err());

        // Another key, or another agent's name, does not pass.
        let (other, _) = generate();
        let mut forged = request("agent_bot");
        sign_request(&mut forged, &decode_private(&other).unwrap(), now).unwrap();
        assert!(service.verify_signed_request_at(&forged, now).is_err());

        // An unsigned request is left to token authentication.
        assert_eq!(
            service
                .verify_signed_request_at(&request("agent_bot"), now)
                .unwrap(),
            None
        );
    }

    #[test]
    fn a_stale_or_future_timestamp_is_refused() {
        let (_dir, service) = service();
        let (private, public) = generate();
        service.register_client_with_key("bot", &public).unwrap();
        let key = decode_private(&private).unwrap();
        let now = Utc::now().timestamp();
        for skew in [-(MAX_SKEW_SECONDS + 1), MAX_SKEW_SECONDS + 1] {
            let mut signed = request("agent_bot");
            sign_request(&mut signed, &key, now + skew).unwrap();
            let error = service.verify_signed_request_at(&signed, now).unwrap_err();
            assert!(format!("{error:?}").contains("stale"), "{error:?}");
        }
        let mut signed = request("agent_bot");
        sign_request(&mut signed, &key, now - 60).unwrap();
        assert!(service.verify_signed_request_at(&signed, now).is_ok());
    }

    #[test]
    fn a_key_bound_client_has_no_usable_token_and_upgrading_keeps_its_id() {
        let (_dir, service) = service();
        let (_, public) = generate();
        let keyed = service.register_client_with_key("keyed", &public).unwrap();
        assert!(service.authenticate(&keyed, "", "s").is_err());

        // A legacy client keeps working until it is upgraded…
        let (legacy, token) = service.register_client("legacy").unwrap();
        assert!(service.authenticate(&legacy, &token, "s").is_ok());
        assert_eq!(
            service.list_clients_with_auth().unwrap(),
            vec![(keyed.clone(), "key"), (legacy.clone(), "legacy")]
        );
        // …then signs as the same agent, and its token is dead.
        let (private, public) = generate();
        service.bind_client_key(&legacy, &public).unwrap();
        assert!(service.authenticate(&legacy, &token, "s").is_err());
        let mut signed = request("agent_legacy");
        sign_request(
            &mut signed,
            &decode_private(&private).unwrap(),
            Utc::now().timestamp(),
        )
        .unwrap();
        assert_eq!(
            service.verify_signed_request(&signed).unwrap(),
            Some(legacy.clone())
        );
        assert_eq!(service.audit_client_auth(&legacy).as_deref(), Some("key"));

        // A revoked client's key no longer verifies.
        service.revoke_client(&legacy).unwrap();
        let mut signed = request("agent_legacy");
        sign_request(
            &mut signed,
            &decode_private(&private).unwrap(),
            Utc::now().timestamp(),
        )
        .unwrap();
        assert!(service.verify_signed_request(&signed).is_err());
    }

    #[test]
    fn audit_events_say_whether_an_agent_signs_or_uses_a_legacy_token() {
        let (_dir, service) = service();
        service
            .initialize(b"audit-master-password", Duration::minutes(5))
            .unwrap();
        let (_, public) = generate();
        let keyed = service.register_client_with_key("keyed", &public).unwrap();
        let (legacy, token) = service.register_client("legacy").unwrap();
        let actor = |agent: &AgentId| ActorContext {
            agent_id: agent.clone(),
            workload_id: None,
            human_principal: None,
            on_behalf_of: None,
            client_session_id: "s".into(),
            purpose: None,
        };
        for agent in [&keyed, &legacy] {
            service
                .audit_vault(
                    &actor(agent),
                    "entry:search",
                    "kl://v",
                    "allow",
                    "success",
                    vec![],
                )
                .unwrap();
        }
        let events = service.store.query_audit(10).unwrap();
        let auth_of = |agent: &AgentId| {
            events
                .iter()
                .find(|event| &event.agent_id == agent)
                .and_then(|event| event.client_auth.clone())
        };
        assert_eq!(auth_of(&keyed).as_deref(), Some("key"));
        assert_eq!(auth_of(&legacy).as_deref(), Some("legacy"));
        assert!(service.authenticate(&legacy, &token, "s").is_ok());
    }

    #[test]
    fn public_keys_parse_from_keylease_and_openssh_forms() {
        let (private, public) = generate();
        assert_eq!(parse_public(&public).unwrap(), public);
        assert_eq!(public_of(&private).unwrap(), public);
        let raw = STANDARD_NO_PAD
            .decode(public.strip_prefix(PUBLIC_PREFIX).unwrap())
            .unwrap();
        let mut blob = vec![];
        for part in [b"ssh-ed25519".as_slice(), raw.as_slice()] {
            blob.extend((part.len() as u32).to_be_bytes());
            blob.extend(part);
        }
        let openssh = format!(
            "ssh-ed25519 {} me@host",
            base64::engine::general_purpose::STANDARD.encode(blob)
        );
        assert_eq!(parse_public(&openssh).unwrap(), public);
        assert!(parse_public("ssh-rsa AAAA").is_err());
        assert!(parse_public(&private).is_err());
        assert!(is_private_key(&private) && !is_private_key(&public));
    }
}
