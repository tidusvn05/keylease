//! SSH agent signing inside the service boundary (ADR 0005, tier T1).
//!
//! Private keys stored as `core.ssh_key` items never leave the service. A
//! client — normally `keylease ssh-agent`, which speaks the OpenSSH agent
//! protocol to `ssh` and `git` — asks for the public identities and for a
//! signature over session data. Every signature is a policy decision on
//! `ssh:sign` for that exact key item, so it can require an approval or be
//! covered by a time-boxed trust.
//!
//! Two refinements bind a key to where it is used:
//!
//! - **Host binding.** OpenSSH 8.9+ tells its agent which host a connection
//!   authenticates to (`session-bind@openssh.com`: the host key, signed over
//!   the session identifier). The client passes those records with each sign
//!   request; the service verifies them, checks that the data to sign belongs
//!   to that session, shows the host to the approver and binds the approval
//!   to it. An item with a `host_keys` field signs only for those hosts.
//! - **Certificates.** An SSH key item with a `ca_principals` field is a
//!   certificate authority. It never signs logins itself; it issues short-lived
//!   user certificates (`ssh:issue_cert`) for keys the client generates per
//!   session, so servers trust the CA once instead of each agent key.

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

/// Most `session-bind@openssh.com` records one agent connection may carry:
/// the destination and the hosts the agent is forwarded through.
pub const MAX_SESSION_BINDS: usize = 8;

/// The item field listing the host keys an SSH key may sign for.
const HOST_KEYS_FIELD: &str = "host_keys";
/// The item field that makes an SSH key a certificate authority: the
/// principals (login names) its certificates may name.
const CA_PRINCIPALS_FIELD: &str = "ca_principals";

/// How long an issued certificate is valid unless the client asks for less.
pub const DEFAULT_CERT_TTL_SECONDS: u64 = 300;
/// The longest certificate the service issues.
pub const MAX_CERT_TTL_SECONDS: u64 = 3600;

/// `SSH_MSG_USERAUTH_REQUEST` (RFC 4252).
const SSH_MSG_USERAUTH_REQUEST: u8 = 50;

/// One `session-bind@openssh.com` record an agent connection received, as the
/// client relays it. Fields are base64 of the SSH wire values.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SshSessionBind {
    /// The server's host key blob.
    pub host_key_blob: String,
    /// The SSH session identifier (exchange hash).
    pub session_id: String,
    /// The host key's signature over `session_id`.
    pub signature_blob: String,
    /// Whether the connection is a forwarded agent on that host.
    pub forwarding: bool,
}

/// A certificate the service issued for a client-generated key.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SshCertificate {
    /// The certificate in OpenSSH format (`…-cert-v01@openssh.com AAAA…`).
    pub certificate: String,
    /// Names the agent, the grant (trust, approval or rule) and the CA item;
    /// sshd logs it on each login.
    pub key_id: String,
    pub serial: u64,
    pub principals: Vec<String>,
    pub valid_before: DateTime<Utc>,
}

/// A verified session binding.
struct BoundHost {
    fingerprint: String,
    host_key_blob: Vec<u8>,
    session_id: Vec<u8>,
}

fn take_string<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    let length = u32::from_be_bytes(input.get(..4)?.try_into().ok()?) as usize;
    let value = input.get(4..4 + length)?;
    *input = &input[4 + length..];
    Some(value)
}

/// Verifies each binding's host signature. Only the last may be a
/// non-forwarding binding: anything bound after a login is not OpenSSH.
fn verify_binds(binds: &[SshSessionBind]) -> Result<Vec<BoundHost>> {
    let invalid = |reason: &str| KeyLeaseError::InvalidRequest {
        reason: reason.into(),
    };
    if binds.len() > MAX_SESSION_BINDS {
        return Err(invalid("too many session bindings"));
    }
    if binds.iter().rev().skip(1).any(|bind| !bind.forwarding) {
        return Err(invalid("a session binding follows a non-forwarding one"));
    }
    let decode = |value: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|_| invalid("invalid base64 in a session binding"))
    };
    binds
        .iter()
        .map(|bind| {
            let host_key_blob = decode(&bind.host_key_blob)?;
            let host_key = PublicKey::from_bytes(&host_key_blob)
                .map_err(|_| invalid("invalid host key in a session binding"))?;
            let session_id = decode(&bind.session_id)?;
            if session_id.is_empty() || session_id.len() > 128 {
                return Err(invalid("invalid session identifier"));
            }
            let signature = Signature::try_from(decode(&bind.signature_blob)?.as_slice())
                .map_err(|_| invalid("invalid signature in a session binding"))?;
            signature::Verifier::verify(&host_key, &session_id, &signature).map_err(|_| {
                KeyLeaseError::Denied {
                    reason: "the host's session-bind signature does not verify".into(),
                }
            })?;
            Ok(BoundHost {
                fingerprint: host_key.fingerprint(HashAlg::Sha256).to_string(),
                host_key_blob,
                session_id,
            })
        })
        .collect()
}

/// The session identifier and, for `publickey-hostbound-v00@openssh.com`, the
/// host key of an SSH userauth request (RFC 4252 section 7), if `data` is one.
fn parse_userauth(mut data: &[u8]) -> Option<(&[u8], Option<&[u8]>)> {
    let session_id = take_string(&mut data)?;
    let (&kind, rest) = data.split_first()?;
    if kind != SSH_MSG_USERAUTH_REQUEST {
        return None;
    }
    data = rest;
    take_string(&mut data)?; // user
    take_string(&mut data)?; // service
    let hostbound = match take_string(&mut data)? {
        b"publickey" => false,
        b"publickey-hostbound-v00@openssh.com" => true,
        _ => return None,
    };
    let (&has_signature, rest) = data.split_first()?;
    if has_signature != 1 {
        return None;
    }
    data = rest;
    take_string(&mut data)?; // algorithm
    take_string(&mut data)?; // public key
    let host_key = if hostbound {
        Some(take_string(&mut data)?)
    } else {
        None
    };
    data.is_empty().then_some((session_id, host_key))
}

/// Checks the data to sign against the connection's bindings and the item's
/// pins, returning the destination host when the connection is bound.
///
/// A bound login must be for the bound session (and host), so a binding for
/// one host cannot authorize a login elsewhere. A pinned key signs only bound
/// logins, and every host on the way (forwarding hosts included) must be one
/// of its pins: forwarding through an unlisted host is refused.
fn check_binding<'a>(
    pins: Option<&[String]>,
    bound: &'a [BoundHost],
    data: &[u8],
) -> Result<Option<&'a BoundHost>> {
    let refuse = |reason: String| Err(KeyLeaseError::Denied { reason });
    let Some(last) = bound.last() else {
        if pins.is_some() {
            return refuse(
                "this key is pinned to host keys and the ssh client did not say which host it                  connects to; use OpenSSH 8.9 or later"
                    .into(),
            );
        }
        return Ok(None);
    };
    match parse_userauth(data) {
        Some((session_id, host_key)) => {
            if session_id != last.session_id {
                return refuse("the login is for another session than the bound one".into());
            }
            if host_key.is_some_and(|host_key| host_key != last.host_key_blob) {
                return refuse("the login names another host key than the bound one".into());
            }
        }
        None if pins.is_some() => {
            return refuse("a key pinned to hosts signs only SSH logins".into());
        }
        None => {}
    }
    if let Some(pins) = pins
        && let Some(host) = bound.iter().find(|host| !pins.contains(&host.fingerprint))
    {
        return refuse(format!(
            "this key is pinned to other hosts; {} is not one of its host_keys",
            host.fingerprint
        ));
    }
    Ok(Some(last))
}

/// A text field's value by key.
fn field_text<'a>(item: &'a VaultItem, key: &str) -> Option<&'a str> {
    item.fields.iter().find_map(|field| match &field.value {
        FieldValue::Text(value) | FieldValue::Concealed(value) if field.key == key => {
            Some(value.as_str())
        }
        _ => None,
    })
}

/// One `host_keys` line as a fingerprint: `SHA256:…`, an OpenSSH public key,
/// or a `known_hosts` / `ssh-keyscan` line.
fn parse_host_pin(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if let Some(fingerprint) = tokens.iter().find(|token| token.starts_with("SHA256:")) {
        return Some((*fingerprint).to_owned());
    }
    tokens.windows(2).find_map(|pair| {
        PublicKey::from_openssh(&format!("{} {}", pair[0], pair[1]))
            .ok()
            .map(|key| key.fingerprint(HashAlg::Sha256).to_string())
    })
}

/// The host key fingerprints an item is pinned to; `None` without pins. A
/// field with text but no usable line pins to nothing, refusing every host.
fn item_host_pins(item: &VaultItem) -> Option<Vec<String>> {
    let text = field_text(item, HOST_KEYS_FIELD)?;
    if text.trim().is_empty() {
        return None;
    }
    Some(text.lines().filter_map(parse_host_pin).collect())
}

/// The principals a CA item issues for; `None` when the item is not a CA.
fn item_ca_principals(item: &VaultItem) -> Option<Vec<String>> {
    if item.kind != "core.ssh_key" {
        return None;
    }
    let text = field_text(item, CA_PRINCIPALS_FIELD)?;
    Some(
        text.split(|character: char| character == ',' || character.is_whitespace())
            .filter(|principal| !principal.is_empty())
            .map(str::to_owned)
            .collect(),
    )
}

/// R2, or R3 when the item's environment is production.
fn environment_risk(item: &VaultItem) -> RiskTier {
    match item.environment.as_deref().map(str::to_ascii_lowercase) {
        Some(environment) if environment.starts_with("prod") => RiskTier::R3,
        _ => RiskTier::R2,
    }
}

/// The actor with a service-written note before its purpose, so the approver
/// sees it and the approval is bound to it (the purpose is in the digest).
fn noted(actor: &ActorContext, note: &str) -> ActorContext {
    let mut actor = actor.clone();
    actor.purpose = Some(match actor.purpose.as_deref().map(str::trim) {
        Some(purpose) if !purpose.is_empty() => format!("[{note}] {purpose}"),
        _ => format!("[{note}]"),
    });
    actor
}

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
                // A CA only issues certificates; it is never offered for a login.
                if item.status != ItemStatus::Active
                    || item.kind != "core.ssh_key"
                    || item_ca_principals(&item).is_some()
                {
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
    /// The authorization arguments hold the key fingerprint and, when the
    /// connection is bound (`binds`), the destination host key fingerprint,
    /// never the session data: a retried sign request to the same host finds
    /// the same approval, and an approval for one host does not sign for
    /// another.
    pub fn ssh_sign_authorized(
        &self,
        actor: &ActorContext,
        public_key_blob: &[u8],
        data: &[u8],
        flags: u32,
        binds: &[SshSessionBind],
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
        let bound = verify_binds(binds)?;
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
            if item_ca_principals(&item).is_some() {
                return Err(KeyLeaseError::Denied {
                    reason: "this key is a certificate authority; KeyLease uses it only to issue \
                             certificates (`keylease ssh --cert`)"
                        .into(),
                });
            }
            let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
            let resource = format!("kl://{}/{}", vault.vault_id.0, item.id.0);
            let pins = item_host_pins(&item);
            let destination = check_binding(pins.as_deref(), &bound, data)?;
            let mut arguments = serde_json::json!({"fingerprint": fingerprint});
            let actor = match destination {
                Some(host) => {
                    let via: Vec<&str> = bound[..bound.len() - 1]
                        .iter()
                        .map(|hop| hop.fingerprint.as_str())
                        .collect();
                    arguments["host"] = host.fingerprint.clone().into();
                    let mut note = format!("host {}", host.fingerprint);
                    if !via.is_empty() {
                        arguments["via"] = via.clone().into();
                        note.push_str(&format!(" via forwarded agent on {}", via.join(", ")));
                    }
                    noted(actor, &note)
                }
                None => actor.clone(),
            };
            self.authorize_vault_at_risk(
                vault,
                &actor,
                "ssh:sign",
                &resource,
                arguments,
                environment_risk(&item),
            )?;
            // Decrypt only after the use is authorized.
            let key = unlock_key(&item, key)?;
            let signature = sign(&key, data, flags)?;
            let encoded = Vec::<u8>::try_from(signature).map_err(|_| KeyLeaseError::Crypto)?;
            self.audit_vault(&actor, "ssh:sign", &resource, "allow", "success", vec![])?;
            Ok(SshSignature {
                signature_blob: base64::engine::general_purpose::STANDARD.encode(encoded),
                fingerprint,
            })
        })
    }

    /// Issues a short-lived user certificate from the CA item `id` for
    /// `public_key`, a key the client generated for this session.
    ///
    /// `principals` narrows the CA's `ca_principals` (empty: all of them).
    /// The CA private key never leaves the service; the approval names the
    /// principals and lifetime, not the per-session key, so a retry with a new
    /// key finds the same approval.
    pub fn ssh_issue_certificate_authorized(
        &self,
        actor: &ActorContext,
        id: &ItemId,
        public_key: &str,
        principals: &[String],
        ttl_seconds: Option<u64>,
    ) -> Result<SshCertificate> {
        let invalid = |reason: &str| KeyLeaseError::InvalidRequest {
            reason: reason.into(),
        };
        let subject = PublicKey::from_openssh(public_key.trim())
            .map_err(|_| invalid("invalid OpenSSH public key"))?;
        let ttl = ttl_seconds.unwrap_or(DEFAULT_CERT_TTL_SECONDS);
        if ttl == 0 || ttl > MAX_CERT_TTL_SECONDS {
            return Err(invalid(&format!(
                "certificate lifetime must be 1..={MAX_CERT_TTL_SECONDS} seconds"
            )));
        }
        self.with_vault(|vault| {
            let item = self.store.get_item(vault, id)?;
            let (Some(allowed), Some(ca), ItemStatus::Active) =
                (item_ca_principals(&item), item_stored_key(&item), &item.status)
            else {
                return Err(invalid(
                    "not an SSH certificate authority: an SSH key item with a `ca_principals` field",
                ));
            };
            if matches!(ca.algorithm(), Algorithm::Rsa { .. }) {
                return Err(invalid(
                    "RSA certificate authorities are not supported; use Ed25519 or ECDSA",
                ));
            }
            let principals = if principals.is_empty() {
                allowed.clone()
            } else {
                principals.to_vec()
            };
            if principals.is_empty() {
                return Err(invalid("the CA lists no principals in `ca_principals`"));
            }
            if let Some(principal) = principals.iter().find(|p| !allowed.contains(p)) {
                return Err(KeyLeaseError::Denied {
                    reason: format!("this CA does not issue certificates for `{principal}`"),
                });
            }
            let resource = format!("kl://{}/{}", vault.vault_id.0, item.id.0);
            let actor = noted(
                actor,
                &format!(
                    "certificate for {} valid {}s",
                    principals.join(", "),
                    ttl
                ),
            );
            let grant = self.authorize_vault_grant(
                vault,
                &actor,
                "ssh:issue_cert",
                &resource,
                serde_json::json!({"principals": principals, "ttl_seconds": ttl}),
                environment_risk(&item),
            )?;
            let ca = unlock_key(&item, ca)?;
            let now = Utc::now();
            let valid_before = now + Duration::seconds(ttl as i64);
            let serial = ssh_key::rand_core::RngCore::next_u64(&mut ssh_key::rand_core::OsRng);
            let key_id = format!(
                "keylease agent={} grant={} ca={}",
                actor.agent_id.0, grant, item.id.0
            );
            let crypto = |_| KeyLeaseError::Crypto;
            let mut builder = ssh_key::certificate::Builder::new_with_random_nonce(
                &mut ssh_key::rand_core::OsRng,
                subject.key_data().clone(),
                // A minute of slack for a server clock that runs behind.
                (now - Duration::minutes(1)).timestamp() as u64,
                valid_before.timestamp() as u64,
            )
            .map_err(crypto)?;
            builder
                .serial(serial)
                .and_then(|builder| builder.cert_type(ssh_key::certificate::CertType::User))
                .and_then(|builder| builder.key_id(key_id.clone()))
                .and_then(|builder| builder.extension("permit-pty", ""))
                .map_err(crypto)?;
            for principal in &principals {
                builder.valid_principal(principal.clone()).map_err(crypto)?;
            }
            let certificate = builder.sign(&ca).map_err(crypto)?;
            self.audit_vault(
                &actor,
                "ssh:issue_cert",
                &resource,
                "allow",
                "success",
                vec![],
            )?;
            Ok(SshCertificate {
                certificate: certificate.to_openssh().map_err(crypto)?,
                key_id,
                serial,
                principals,
                valid_before,
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
        let id = approval(service.ssh_sign_authorized(&agent, &blob, data, 0, &[]));
        // Fresh session data for the retry, as a real ssh client would send.
        assert_eq!(
            approval(service.ssh_sign_authorized(&agent, &blob, b"other-session", 0, &[])),
            id
        );
        service
            .decide_approval_authorized(&owner, &id, true)
            .unwrap();
        let signed = service
            .ssh_sign_authorized(&agent, &blob, data, 0, &[])
            .unwrap();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(signed.signature_blob)
            .unwrap();
        let signature = Signature::try_from(raw.as_slice()).unwrap();
        signature::Verifier::verify(key.public_key(), data, &signature).unwrap();
        approval(service.ssh_sign_authorized(&agent, &blob, data, 0, &[]));
    }

    #[test]
    fn rsa_honours_sha2_flags_and_refuses_sha1() {
        let (_dir, service, owner, agent, key) = service_with_key(Algorithm::Rsa { hash: None });
        let blob = key.public_key().to_bytes().unwrap();
        let id = approval(service.ssh_sign_authorized(
            &agent,
            &blob,
            b"data",
            SSH_AGENT_RSA_SHA2_256,
            &[],
        ));
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
                .ssh_sign_authorized(&agent, &blob, b"data", flags, &[])
                .unwrap();
            let raw = base64::engine::general_purpose::STANDARD
                .decode(signed.signature_blob)
                .unwrap();
            let signature = Signature::try_from(raw.as_slice()).unwrap();
            assert_eq!(signature.algorithm().as_str(), algorithm);
            signature::Verifier::verify(key.public_key(), b"data", &signature).unwrap();
        }
        assert!(matches!(
            service.ssh_sign_authorized(&agent, &blob, b"data", 0, &[]),
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

    /// Adds a text field to the vault's only SSH key item.
    fn set_field(
        service: &KeyLeaseService,
        owner: &ActorContext,
        key: &str,
        value: &str,
    ) -> ItemId {
        let item = service
            .with_vault(|vault| service.store.list_items(vault))
            .unwrap()
            .into_iter()
            .find(|item| item.kind == "core.ssh_key")
            .unwrap();
        service
            .update_entry(
                owner,
                &item.id,
                EntryPatch {
                    field_updates: vec![field(
                        key,
                        key,
                        FieldValue::Text(value.into()),
                        Sensitivity::PrivateMetadata,
                        false,
                    )],
                    ..Default::default()
                },
                item.revision,
                &format!("set-{key}-{}", value.len()),
                false,
            )
            .unwrap();
        item.id
    }

    /// A host key and its binding for `session`, as OpenSSH would send it.
    fn host(session: &[u8], forwarding: bool) -> (PrivateKey, SshSessionBind) {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let bind = bind_for(&key, session, forwarding);
        (key, bind)
    }

    fn bind_for(key: &PrivateKey, session: &[u8], forwarding: bool) -> SshSessionBind {
        let signature: Signature = signature::Signer::try_sign(key, session).unwrap();
        let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        SshSessionBind {
            host_key_blob: encode(&key.public_key().to_bytes().unwrap()),
            session_id: encode(session),
            signature_blob: encode(&Vec::<u8>::try_from(signature).unwrap()),
            forwarding,
        }
    }

    /// A `publickey` userauth request for `session`, the data ssh asks to sign.
    fn userauth(session: &[u8], user_key: &PublicKey) -> Vec<u8> {
        let mut data = Vec::new();
        let mut put = |value: &[u8]| {
            data.extend_from_slice(&(value.len() as u32).to_be_bytes());
            data.extend_from_slice(value);
        };
        put(session);
        let mut data = {
            let mut prefix = data;
            prefix.push(SSH_MSG_USERAUTH_REQUEST);
            prefix
        };
        for value in [&b"deploy"[..], b"ssh-connection", b"publickey"] {
            data.extend_from_slice(&(value.len() as u32).to_be_bytes());
            data.extend_from_slice(value);
        }
        data.push(1);
        for value in [b"ssh-ed25519".to_vec(), user_key.to_bytes().unwrap()] {
            data.extend_from_slice(&(value.len() as u32).to_be_bytes());
            data.extend_from_slice(&value);
        }
        data
    }

    #[test]
    fn a_bound_login_shows_and_binds_its_host() {
        let (_dir, service, owner, agent, key) = service_with_key(Algorithm::Ed25519);
        let blob = key.public_key().to_bytes().unwrap();
        let (host_a, bind_a) = host(b"session-a", false);
        let data = userauth(b"session-a", key.public_key());
        let id = approval(service.ssh_sign_authorized(
            &agent,
            &blob,
            &data,
            0,
            std::slice::from_ref(&bind_a),
        ));
        let pending = service.store.get_approval(&id).unwrap();
        let fingerprint = host_a.public_key().fingerprint(HashAlg::Sha256).to_string();
        assert!(
            pending
                .purpose
                .as_deref()
                .is_some_and(|purpose| purpose.contains(&format!("host {fingerprint}")))
        );
        // Another host is another request.
        let (_, bind_b) = host(b"session-b", false);
        let other = approval(service.ssh_sign_authorized(
            &agent,
            &blob,
            &userauth(b"session-b", key.public_key()),
            0,
            &[bind_b],
        ));
        assert_ne!(other, id);
        service
            .decide_approval_authorized(&owner, &id, true)
            .unwrap();
        service
            .ssh_sign_authorized(&agent, &blob, &data, 0, std::slice::from_ref(&bind_a))
            .unwrap();
        // A binding for host A cannot sign a login for another session.
        assert!(matches!(
            service.ssh_sign_authorized(
                &agent,
                &blob,
                &userauth(b"session-x", key.public_key()),
                0,
                std::slice::from_ref(&bind_a)
            ),
            Err(KeyLeaseError::Denied { .. })
        ));
        // Nor can a binding whose signature is not the host's.
        let mut forged = bind_a;
        forged.session_id = base64::engine::general_purpose::STANDARD.encode(b"session-x");
        assert!(matches!(
            service.ssh_sign_authorized(
                &agent,
                &blob,
                &userauth(b"session-x", key.public_key()),
                0,
                &[forged]
            ),
            Err(KeyLeaseError::Denied { .. })
        ));
    }

    #[test]
    fn a_pinned_key_signs_only_bound_logins_to_its_hosts() {
        let (_dir, service, owner, agent, key) = service_with_key(Algorithm::Ed25519);
        let blob = key.public_key().to_bytes().unwrap();
        let (host_a, bind_a) = host(b"session-a", false);
        let pin = format!(
            "# production web\nweb.example.com {}\n",
            host_a.public_key().to_openssh().unwrap()
        );
        set_field(&service, &owner, "host_keys", &pin);
        let denied = |result: Result<SshSignature>| {
            assert!(
                matches!(result, Err(KeyLeaseError::Denied { .. })),
                "{result:?}"
            )
        };
        let data = userauth(b"session-a", key.public_key());
        // No binding (old OpenSSH, ssh-keygen -Y sign): refused.
        denied(service.ssh_sign_authorized(&agent, &blob, &data, 0, &[]));
        // Another host: refused without asking.
        let (_, bind_b) = host(b"session-b", false);
        denied(service.ssh_sign_authorized(
            &agent,
            &blob,
            &userauth(b"session-b", key.public_key()),
            0,
            &[bind_b],
        ));
        // Forwarded through an unpinned host to the pinned one: refused.
        let (hop, _) = host(b"hop", true);
        let hop_bind = bind_for(&hop, b"session-hop", true);
        denied(service.ssh_sign_authorized(&agent, &blob, &data, 0, &[hop_bind, bind_a.clone()]));
        // Data that is not a login: refused.
        denied(service.ssh_sign_authorized(
            &agent,
            &blob,
            b"SSHSIG...",
            0,
            std::slice::from_ref(&bind_a),
        ));
        // The pinned host: an ordinary approval.
        let id = approval(service.ssh_sign_authorized(
            &agent,
            &blob,
            &data,
            0,
            std::slice::from_ref(&bind_a),
        ));
        service
            .decide_approval_authorized(&owner, &id, true)
            .unwrap();
        service
            .ssh_sign_authorized(&agent, &blob, &data, 0, &[bind_a])
            .unwrap();
    }

    #[test]
    fn host_pins_read_fingerprints_keys_and_known_hosts_lines() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        let openssh = key.public_key().to_openssh().unwrap();
        assert_eq!(parse_host_pin(&fingerprint), Some(fingerprint.clone()));
        assert_eq!(
            parse_host_pin(&format!("{fingerprint} web")),
            Some(fingerprint.clone())
        );
        assert_eq!(parse_host_pin(&openssh), Some(fingerprint.clone()));
        assert_eq!(
            parse_host_pin(&format!("[web]:2222,10.0.0.1 {openssh}")),
            Some(fingerprint)
        );
        assert_eq!(parse_host_pin("# comment"), None);
        assert_eq!(parse_host_pin("not a key"), None);
    }

    #[test]
    fn a_ca_issues_short_certificates_and_never_signs_logins() {
        let (_dir, service, owner, agent, ca) = service_with_key(Algorithm::Ed25519);
        let ca_item = set_field(&service, &owner, "ca_principals", "deploy, ops");
        // The CA is not offered, and does not sign data.
        assert!(
            service
                .ssh_identities_authorized(&agent)
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            service.ssh_sign_authorized(
                &agent,
                &ca.public_key().to_bytes().unwrap(),
                b"tbs-certificate",
                0,
                &[]
            ),
            Err(KeyLeaseError::Denied { .. })
        ));
        let session = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let public = session.public_key().to_openssh().unwrap();
        let deploy = vec!["deploy".to_owned()];
        assert!(matches!(
            service.ssh_issue_certificate_authorized(
                &agent,
                &ca_item,
                &public,
                &["root".to_owned()],
                None
            ),
            Err(KeyLeaseError::Denied { .. })
        ));
        assert!(matches!(
            service.ssh_issue_certificate_authorized(
                &agent,
                &ca_item,
                &public,
                &deploy,
                Some(7200)
            ),
            Err(KeyLeaseError::InvalidRequest { .. })
        ));
        let id = approval(
            service.ssh_issue_certificate_authorized(&agent, &ca_item, &public, &deploy, None),
        );
        // A new session key finds the same approval.
        let next = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let next_public = next.public_key().to_openssh().unwrap();
        assert_eq!(
            approval(service.ssh_issue_certificate_authorized(
                &agent,
                &ca_item,
                &next_public,
                &deploy,
                None
            )),
            id
        );
        service
            .decide_approval_authorized(&owner, &id, true)
            .unwrap();
        let issued = service
            .ssh_issue_certificate_authorized(&agent, &ca_item, &next_public, &deploy, None)
            .unwrap();
        let certificate = ssh_key::Certificate::from_openssh(&issued.certificate).unwrap();
        certificate
            .validate([&ca.public_key().fingerprint(HashAlg::Sha256)])
            .unwrap();
        assert_eq!(certificate.public_key(), next.public_key().key_data());
        assert_eq!(certificate.valid_principals(), ["deploy"]);
        assert_eq!(
            certificate.cert_type(),
            ssh_key::certificate::CertType::User
        );
        assert!(certificate.key_id().contains(&id));
        assert!(certificate.key_id().contains(&agent.agent_id.0));
        let lifetime = certificate.valid_before() - certificate.valid_after();
        assert!(lifetime <= DEFAULT_CERT_TTL_SECONDS + 60, "{lifetime}");
        assert!(!issued.certificate.contains("PRIVATE"));
    }

    #[test]
    fn an_unknown_key_is_not_found_and_reveals_nothing() {
        let (_dir, service, _owner, agent, _key) = service_with_key(Algorithm::Ed25519);
        let other = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let blob = other.public_key().to_bytes().unwrap();
        assert!(matches!(
            service.ssh_sign_authorized(&agent, &blob, b"data", 0, &[]),
            Err(KeyLeaseError::NotFound { .. })
        ));
    }
}
