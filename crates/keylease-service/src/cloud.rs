//! Cloud relay member (ADR 0006): links this vault to a KeyLease Cloud as the
//! account owner or as a workload node, shares items and projects with
//! nodes, files and decides share requests, backs up this member's items
//! sealed to the owner, and restores them.
//!
//! The service holds every key and builds every signed, sealed payload; the
//! CLI only carries them over HTTP (`keylease cloud …` and the sync loop in
//! `keylease serve`). Every step is idempotent so a sync can be retried.

use super::*;
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use keylease_core::relay::{
    CreateRelayAccount, CreateRelayInvite, JoinRelay, RelayAccountCreated, RelayBackup,
    RelayEnvelope, RelayInvite, RelayJoined, RelayMember, RelayMemberKeys, RelayPayloadLabel,
    RelayRole, kind, relay_digest, relay_request_signing_input,
};
use keylease_crypto::sealed::{
    BoxKeypair, SealedBox, SymmetricBox, derive_recovery_keys, open, open_symmetric, seal,
    seal_symmetric,
};
use keylease_crypto::{SecretKey, keyed_digest};
use keylease_store::cloud::record;

const LINK_ID: &str = "self";
const SECRET_ID: &str = "secret";
const SECRET_LABEL: &str = "cloud-relay-keys";
const INVITE_TTL_MINUTES: i64 = 30;
const MAX_PENDING_REQUESTS_PER_AGENT: usize = 10;
/// Extension on an item received through a share.
pub const SHARE_EXTENSION: &str = "keylease.cloud_share";
/// Groups that hold shared-in and restored items.
pub const SHARED_GROUP: &str = "group_cloud_shared";
pub const RESTORED_GROUP: &str = "group_cloud_restored";

/// This vault's link to a cloud. Public material only; keys are sealed apart.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct CloudLink {
    pub url: String,
    pub account_id: String,
    /// Empty until the cloud confirmed the registration.
    pub member_id: String,
    pub role: CloudRole,
    pub name: String,
    pub sign_public_b64: String,
    pub box_public_b64: String,
    pub owner_member_id: String,
    pub owner_sign_public_b64: String,
    pub owner_box_public_b64: String,
    pub linked_at: DateTime<Utc>,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CloudRole {
    Owner,
    Node,
}

impl CloudLink {
    fn keys(&self) -> RelayMemberKeys {
        RelayMemberKeys {
            sign_public_b64: self.sign_public_b64.clone(),
            box_public_b64: self.box_public_b64.clone(),
        }
    }
    fn owner_keys(&self) -> RelayMemberKeys {
        RelayMemberKeys {
            sign_public_b64: self.owner_sign_public_b64.clone(),
            box_public_b64: self.owner_box_public_b64.clone(),
        }
    }
    pub fn fingerprint(&self) -> String {
        self.keys().fingerprint()
    }
    pub fn owner_fingerprint(&self) -> String {
        self.owner_keys().fingerprint()
    }
    fn active(&self) -> Result<()> {
        if self.member_id.is_empty() {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "the cloud link is not complete; run the link command again".into(),
            });
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct RelaySecrets {
    sign_secret_b64: String,
    box_secret_b64: String,
}

/// Owner keys inside the recovery kit.
#[derive(Serialize, Deserialize)]
struct RecoveryKitPlain {
    owner_member_id: String,
    sign_secret_b64: String,
    box_secret_b64: String,
}

/// A node this owner verified (its keys match the invite's secret).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct CloudNode {
    pub member_id: String,
    pub name: String,
    pub sign_public_b64: String,
    pub box_public_b64: String,
    pub fingerprint: String,
    pub verified_at: DateTime<Utc>,
    pub removed_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize)]
struct InviteRecord {
    name: String,
    expires_at: DateTime<Utc>,
    secret_sealed: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShareScope {
    Item { item_id: ItemId },
    Project { project_id: ProjectId },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct CloudShare {
    pub share_id: String,
    pub scope: ShareScope,
    pub node_member_id: String,
    pub node_name: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus {
    Pending,
    Approved,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct CloudShareRequest {
    pub request_id: String,
    pub agent_id: String,
    pub purpose: String,
    pub hint: Option<String>,
    /// Owner side: the node that asked.
    pub node_member_id: Option<String>,
    pub node_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub status: RequestStatus,
    pub share_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ReceivedRecord {
    local_item_id: ItemId,
    owner_revision: u64,
}

#[derive(Serialize, Deserialize)]
struct BackupState {
    revision: u64,
    digest: String,
}

/// What a backup object holds. The owner also backs up its verified nodes and
/// its shares, so a recovered owner keeps them.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum BackupPayload {
    Item { item: Box<VaultItem> },
    Node { node: CloudNode },
    Share { share: CloudShare },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum MessagePayload {
    Share {
        share_id: String,
        item: Box<VaultItem>,
        expires_at: Option<DateTime<Utc>>,
    },
    Unshare {
        share_id: String,
        item_id: ItemId,
    },
    Restore {
        item: Box<VaultItem>,
    },
    ShareRequest {
        request_id: String,
        agent_id: String,
        purpose: String,
        hint: Option<String>,
    },
    RequestDecision {
        request_id: String,
        approved: bool,
        share_id: Option<String>,
    },
}

/// What one owner setup produces: the request for the cloud and the recovery
/// code to show once.
pub struct OwnerSetup {
    pub request: CreateRelayAccount,
    pub recovery_code: String,
}

/// What one invite produces: the code to show the operator and the request
/// for the cloud.
pub struct InviteSetup {
    pub code: String,
    pub request: CreateRelayInvite,
}

/// A backup ready to upload, with the digest of what it seals so that
/// [`KeyLeaseService::cloud_backup_stored`] can record it after the cloud
/// accepts it.
#[derive(Debug, Clone)]
pub struct PendingBackup {
    pub backup: RelayBackup,
    pub digest: String,
}

/// A signed relay request.
#[derive(Debug, Clone)]
pub struct RelaySignature {
    pub member_id: String,
    pub timestamp: i64,
    pub signature_b64: String,
}

/// The outcome of applying a mailbox.
#[derive(Debug, Default, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InboxOutcome {
    pub applied: usize,
    pub rejected: Vec<String>,
    pub acknowledged: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CloudStatus {
    pub link: Option<CloudLink>,
    pub fingerprint: Option<String>,
    pub owner_fingerprint: Option<String>,
    pub nodes: usize,
    pub active_shares: usize,
    pub pending_requests: usize,
    pub received_items: usize,
    pub backed_up_objects: usize,
    pub outbox: usize,
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
fn unb64_32(value: &str) -> Result<[u8; 32]> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(KeyLeaseError::Crypto)
}
fn to_json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|_| KeyLeaseError::Storage)
}
fn from_json<T: serde::de::DeserializeOwned>(value: &str) -> Result<T> {
    serde_json::from_str(value).map_err(|_| KeyLeaseError::Storage)
}
fn invalid(reason: impl Into<String>) -> KeyLeaseError {
    KeyLeaseError::InvalidRequest {
        reason: reason.into(),
    }
}
fn random_base32(bytes: usize) -> String {
    let mut raw = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut raw);
    remote::data_encoding_base32(&raw)
}
fn group(code: &str, size: usize) -> String {
    code.as_bytes()
        .chunks(size)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}
fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}
fn invite_tag(secret: &str, material: &[u8]) -> String {
    let key = SecretKey::from_bytes(Sha256::digest(secret.as_bytes()).into());
    b64(&keyed_digest(
        &key,
        "keylease-relay-invite-tag-v1",
        material,
    ))
}
fn tags_match(expected: &str, presented: &str) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(expected.as_bytes().ct_eq(presented.as_bytes()))
}
fn valid_member_name(name: &str) -> Result<()> {
    if name.trim().is_empty() || name.len() > 64 || name.chars().any(char::is_control) {
        return Err(invalid("name must be 1..=64 characters"));
    }
    Ok(())
}
fn valid_url(url: &str) -> Result<String> {
    let trimmed = url.trim().trim_end_matches('/');
    let parsed = url::Url::parse(trimmed).map_err(|_| invalid("cloud URL is not a URL"))?;
    let local = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && local) {
        return Err(invalid("cloud URL must be https (http only for localhost)"));
    }
    Ok(trimmed.to_owned())
}
fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", uuid::Uuid::now_v7().simple())
}

struct Keys {
    sign: SigningKey,
    boxed: BoxKeypair,
}

impl Keys {
    fn generate() -> Self {
        let mut seed = Zeroizing::new([0_u8; 32]);
        rand::rng().fill_bytes(seed.as_mut());
        Self {
            sign: SigningKey::from_bytes(&seed),
            boxed: BoxKeypair::generate(),
        }
    }
    fn public(&self) -> RelayMemberKeys {
        RelayMemberKeys {
            sign_public_b64: b64(self.sign.verifying_key().as_bytes()),
            box_public_b64: b64(&self.boxed.public_bytes()),
        }
    }
    fn secrets(&self) -> RelaySecrets {
        RelaySecrets {
            sign_secret_b64: b64(&self.sign.to_bytes()),
            box_secret_b64: b64(self.boxed.secret_bytes().as_ref()),
        }
    }
    fn from_secrets(secrets: &RelaySecrets) -> Result<Self> {
        Ok(Self {
            sign: SigningKey::from_bytes(&unb64_32(&secrets.sign_secret_b64)?),
            boxed: BoxKeypair::from_secret_bytes(unb64_32(&secrets.box_secret_b64)?),
        })
    }
}

fn verify_signature(public_b64: &str, input: &[u8], signature_b64: &str) -> Result<()> {
    let key =
        VerifyingKey::from_bytes(&unb64_32(public_b64)?).map_err(|_| KeyLeaseError::Crypto)?;
    let signature: [u8; 64] = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(KeyLeaseError::Crypto)?;
    key.verify(input, &Ed25519Signature::from_bytes(&signature))
        .map_err(|_| KeyLeaseError::Crypto)
}

impl KeyLeaseService {
    fn cloud_actor(&self) -> ActorContext {
        ActorContext {
            agent_id: AgentId("local-human".into()),
            workload_id: None,
            human_principal: Some("local-human".into()),
            on_behalf_of: None,
            client_session_id: "cloud".into(),
            purpose: None,
        }
    }

    fn cloud_audit(&self, action: &str, resource: &str, outcome: &str) -> Result<()> {
        self.store.append_audit(&self.vault_audit_event(
            &self.cloud_actor(),
            action,
            resource,
            "allow",
            outcome,
            vec![],
        ))
    }

    /// The link, if this vault is linked (or linking).
    pub fn cloud_link(&self) -> Result<Option<CloudLink>> {
        self.store
            .cloud_get(record::LINK, LINK_ID)?
            .map(|json| from_json(&json))
            .transpose()
    }

    fn require_link(&self) -> Result<CloudLink> {
        let link = self.cloud_link()?.ok_or_else(|| {
            invalid("this vault is not linked to a cloud (keylease cloud init / join)")
        })?;
        link.active()?;
        Ok(link)
    }

    fn require_owner(&self) -> Result<CloudLink> {
        let link = self.require_link()?;
        if link.role != CloudRole::Owner {
            return Err(KeyLeaseError::Denied {
                reason: "only the owner's device can do this".into(),
            });
        }
        Ok(link)
    }

    fn save_link(&self, link: &CloudLink) -> Result<()> {
        self.store.cloud_put(record::LINK, LINK_ID, &to_json(link)?)
    }

    fn save_keys(&self, vault: &keylease_store::UnlockedVault, keys: &Keys) -> Result<()> {
        let sealed = self.store.seal_local_secret(
            vault,
            SECRET_LABEL,
            to_json(&keys.secrets())?.as_bytes(),
        )?;
        self.store.cloud_put(record::LINK, SECRET_ID, &sealed)
    }

    fn load_keys(&self, vault: &keylease_store::UnlockedVault) -> Result<Keys> {
        let sealed = self
            .store
            .cloud_get(record::LINK, SECRET_ID)?
            .ok_or(KeyLeaseError::Storage)?;
        let plain = self.store.open_local_secret(vault, SECRET_LABEL, &sealed)?;
        let secrets: RelaySecrets =
            serde_json::from_slice(&plain).map_err(|_| KeyLeaseError::Storage)?;
        Keys::from_secrets(&secrets)
    }

    fn ensure_unlinked(&self) -> Result<()> {
        if let Some(link) = self.cloud_link()?
            && !link.member_id.is_empty()
        {
            return Err(invalid(format!(
                "this vault is already linked to {} as {}",
                link.url, link.member_id
            )));
        }
        Ok(())
    }

    /// Owner, step 1: makes the owner keys and the recovery kit. Send
    /// `request` to `POST /v1/relay/accounts` with the admin token, then call
    /// [`Self::cloud_owner_commit`]. Show `recovery_code` once.
    pub fn cloud_owner_prepare(&self, url: &str, name: &str) -> Result<OwnerSetup> {
        let url = valid_url(url)?;
        valid_member_name(name)?;
        self.ensure_unlinked()?;
        self.with_vault(|vault| {
            let keys = Keys::generate();
            let account_id = vault.account_id.0.clone();
            let recovery_code = random_base32(17); // 136 bits, 28 characters
            let recovery = derive_recovery_keys(&recovery_code, &account_id)?;
            let kit = RecoveryKitPlain {
                owner_member_id: String::new(),
                sign_secret_b64: keys.secrets().sign_secret_b64,
                box_secret_b64: keys.secrets().box_secret_b64,
            };
            let sealed_kit = seal_symmetric(
                &recovery.wrap_key,
                to_json(&kit)?.as_bytes(),
                format!("keylease-recovery-kit-v1:{account_id}").as_bytes(),
            )?;
            self.save_keys(vault, &keys)?;
            let public = keys.public();
            self.save_link(&CloudLink {
                url,
                account_id: account_id.clone(),
                member_id: String::new(),
                role: CloudRole::Owner,
                name: name.trim().into(),
                sign_public_b64: public.sign_public_b64.clone(),
                box_public_b64: public.box_public_b64.clone(),
                owner_member_id: String::new(),
                owner_sign_public_b64: public.sign_public_b64.clone(),
                owner_box_public_b64: public.box_public_b64.clone(),
                linked_at: Utc::now(),
                last_sync_at: None,
                last_error: None,
            })?;
            Ok(OwnerSetup {
                request: CreateRelayAccount {
                    account_id,
                    owner_name: name.trim().into(),
                    owner: public,
                    recovery_lookup_hash: relay_digest(&recovery.lookup),
                    recovery_kit: to_json(&sealed_kit)?,
                },
                recovery_code: group(&recovery_code, 4),
            })
        })
    }

    pub fn cloud_owner_commit(&self, created: &RelayAccountCreated) -> Result<CloudLink> {
        let mut link = self
            .cloud_link()?
            .ok_or_else(|| invalid("no pending owner link"))?;
        if link.role != CloudRole::Owner || link.account_id != created.account_id {
            return Err(invalid("the cloud answered for another account"));
        }
        link.member_id = created.owner_member_id.clone();
        link.owner_member_id = created.owner_member_id.clone();
        self.save_link(&link)?;
        self.cloud_audit("cloud:link", "kl://cloud", "owner")?;
        Ok(link)
    }

    /// Owner: a one-time code for a new node. Send `request` to
    /// `POST /v1/relay/invites` (signed).
    pub fn cloud_create_invite(&self, name: &str) -> Result<InviteSetup> {
        valid_member_name(name)?;
        let link = self.require_owner()?;
        self.with_vault(|vault| {
            let lookup = random_base32(7)[..10].to_owned();
            let secret = random_base32(10);
            let lookup_hash = relay_digest(lookup.as_bytes());
            let expires_at = Utc::now() + Duration::minutes(INVITE_TTL_MINUTES);
            let owner_tag = invite_tag(
                &secret,
                &link.keys().tag_material(&link.account_id, RelayRole::Owner),
            );
            let record = InviteRecord {
                name: name.trim().into(),
                expires_at,
                secret_sealed: self.store.seal_local_secret(
                    vault,
                    &format!("cloud-invite:{lookup_hash}"),
                    secret.as_bytes(),
                )?,
            };
            self.store
                .cloud_put(record::INVITE, &lookup_hash, &to_json(&record)?)?;
            Ok(InviteSetup {
                code: format!("{}-{}", group(&lookup, 5), group(&secret, 4)),
                request: CreateRelayInvite {
                    lookup_hash,
                    name: name.trim().into(),
                    expires_at,
                    owner_tag_b64: owner_tag,
                },
            })
        })
    }

    /// Splits an invite code into its lookup half (sent to the cloud) and its
    /// secret half (never sent).
    pub fn cloud_invite_lookup(code: &str) -> Result<String> {
        let code = normalize_code(code);
        if code.len() != 26 {
            return Err(invalid("an invite code has 26 letters and digits"));
        }
        Ok(code[..10].to_owned())
    }

    /// Node, step 1: checks the invite against the code's secret half, makes
    /// this node's keys and returns the join request for `POST /v1/relay/join`.
    pub fn cloud_node_prepare(
        &self,
        url: &str,
        code: &str,
        invite: &RelayInvite,
    ) -> Result<JoinRelay> {
        let url = valid_url(url)?;
        self.ensure_unlinked()?;
        let normalized = normalize_code(code);
        let lookup = Self::cloud_invite_lookup(code)?;
        let secret = &normalized[10..];
        let expected = invite_tag(
            secret,
            &invite
                .owner
                .tag_material(&invite.account_id, RelayRole::Owner),
        );
        if !tags_match(&expected, &invite.owner_tag_b64) {
            return Err(KeyLeaseError::Denied {
                reason: "the invite does not match the code: the cloud may have altered the owner's keys".into(),
            });
        }
        self.with_vault(|vault| {
            let keys = Keys::generate();
            let public = keys.public();
            let node_tag = invite_tag(
                secret,
                &public.tag_material(&invite.account_id, RelayRole::Node),
            );
            self.save_keys(vault, &keys)?;
            self.save_link(&CloudLink {
                url,
                account_id: invite.account_id.clone(),
                member_id: String::new(),
                role: CloudRole::Node,
                name: invite.name.clone(),
                sign_public_b64: public.sign_public_b64.clone(),
                box_public_b64: public.box_public_b64.clone(),
                owner_member_id: invite.owner_member_id.clone(),
                owner_sign_public_b64: invite.owner.sign_public_b64.clone(),
                owner_box_public_b64: invite.owner.box_public_b64.clone(),
                linked_at: Utc::now(),
                last_sync_at: None,
                last_error: None,
            })?;
            Ok(JoinRelay {
                lookup,
                keys: public,
                node_tag_b64: node_tag,
            })
        })
    }

    pub fn cloud_node_commit(&self, joined: &RelayJoined) -> Result<CloudLink> {
        let mut link = self
            .cloud_link()?
            .ok_or_else(|| invalid("no pending node link"))?;
        if link.role != CloudRole::Node || link.account_id != joined.account_id {
            return Err(invalid("the cloud answered for another account"));
        }
        link.member_id = joined.member_id.clone();
        self.save_link(&link)?;
        self.cloud_audit("cloud:link", "kl://cloud", "node")?;
        Ok(link)
    }

    /// Owner, on a new device: restores the owner keys from the recovery kit.
    pub fn cloud_recover(
        &self,
        url: &str,
        account_id: &str,
        owner_member_id: &str,
        kit_json: &str,
        code: &str,
        name: &str,
    ) -> Result<CloudLink> {
        let url = valid_url(url)?;
        valid_member_name(name)?;
        self.ensure_unlinked()?;
        let recovery = derive_recovery_keys(code, account_id)?;
        let sealed: SymmetricBox = from_json(kit_json)?;
        let plain = open_symmetric(
            &recovery.wrap_key,
            &sealed,
            format!("keylease-recovery-kit-v1:{account_id}").as_bytes(),
        )
        .map_err(|_| KeyLeaseError::Denied {
            reason: "the recovery code does not open this kit".into(),
        })?;
        let kit: RecoveryKitPlain =
            serde_json::from_slice(&plain).map_err(|_| KeyLeaseError::Storage)?;
        let keys = Keys::from_secrets(&RelaySecrets {
            sign_secret_b64: kit.sign_secret_b64,
            box_secret_b64: kit.box_secret_b64,
        })?;
        self.with_vault(|vault| {
            self.save_keys(vault, &keys)?;
            let public = keys.public();
            let link = CloudLink {
                url,
                account_id: account_id.into(),
                member_id: owner_member_id.into(),
                role: CloudRole::Owner,
                name: name.trim().into(),
                sign_public_b64: public.sign_public_b64.clone(),
                box_public_b64: public.box_public_b64.clone(),
                owner_member_id: owner_member_id.into(),
                owner_sign_public_b64: public.sign_public_b64,
                owner_box_public_b64: public.box_public_b64,
                linked_at: Utc::now(),
                last_sync_at: None,
                last_error: None,
            };
            self.save_link(&link)?;
            self.cloud_audit("cloud:recover", "kl://cloud", "owner")?;
            Ok(link)
        })
    }

    /// Recovery lookup for `POST /v1/relay/recovery` (hex).
    pub fn cloud_recovery_lookup(code: &str, account_id: &str) -> Result<String> {
        Ok(hex(&derive_recovery_keys(code, account_id)?.lookup))
    }

    /// Forgets the link (keys included). The cloud keeps the member until the
    /// owner removes it.
    pub fn cloud_unlink(&self) -> Result<()> {
        self.with_vault(|_| {
            for kind in [
                record::LINK,
                record::NODE,
                record::INVITE,
                record::SHARE,
                record::SHARE_ITEM,
                record::RECEIVED,
                record::BACKUP,
                record::REQUEST,
                record::APPLIED,
                record::OUTBOX,
            ] {
                for (id, _) in self.store.cloud_list(kind, "")? {
                    self.store.cloud_delete(kind, &id)?;
                }
            }
            self.cloud_audit("cloud:unlink", "kl://cloud", "unlinked")
        })
    }

    /// Signs one relay request without extending the idle lock.
    pub fn cloud_sign_request(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<RelaySignature> {
        let link = self.require_link()?;
        self.with_vault_passive(|vault| {
            let keys = self.load_keys(vault)?;
            let timestamp = Utc::now().timestamp();
            let signature = keys
                .sign
                .sign(&relay_request_signing_input(method, path, timestamp, body));
            Ok(RelaySignature {
                member_id: link.member_id.clone(),
                timestamp,
                signature_b64: b64(&signature.to_bytes()),
            })
        })
    }

    pub fn cloud_record_sync(&self, error: Option<String>) -> Result<()> {
        if let Some(mut link) = self.cloud_link()? {
            link.last_sync_at = Some(Utc::now());
            link.last_error = error.map(|e| e.chars().take(300).collect());
            self.save_link(&link)?;
        }
        Ok(())
    }

    pub fn cloud_status(&self) -> Result<CloudStatus> {
        let link = self.cloud_link()?;
        let count = |kind: &str| self.store.cloud_list(kind, "").map(|v| v.len());
        let shares = self
            .store
            .cloud_list(record::SHARE, "")?
            .into_iter()
            .filter_map(|(_, json)| from_json::<CloudShare>(&json).ok())
            .filter(|share| share.revoked_at.is_none())
            .count();
        let pending = self
            .store
            .cloud_list(record::REQUEST, "")?
            .into_iter()
            .filter_map(|(_, json)| from_json::<CloudShareRequest>(&json).ok())
            .filter(|request| request.status == RequestStatus::Pending)
            .count();
        Ok(CloudStatus {
            fingerprint: link.as_ref().map(CloudLink::fingerprint),
            owner_fingerprint: link.as_ref().map(CloudLink::owner_fingerprint),
            link,
            nodes: count(record::NODE)?,
            active_shares: shares,
            pending_requests: pending,
            received_items: count(record::RECEIVED)?,
            backed_up_objects: count(record::BACKUP)?,
            outbox: count(record::OUTBOX)?,
        })
    }

    // ---- owner: nodes ------------------------------------------------------

    /// Owner: checks every member the cloud lists against this device's
    /// invites. A node whose tag matches is trusted; one that does not is
    /// reported and never receives anything.
    pub fn cloud_verify_members(&self, members: &[RelayMember]) -> Result<Vec<String>> {
        let link = self.require_owner()?;
        let mut problems = Vec::new();
        self.with_vault_passive(|vault| {
            for member in members.iter().filter(|m| m.role == RelayRole::Node) {
                let known = self.store.cloud_get(record::NODE, &member.member_id)?;
                if let Some(json) = known {
                    let mut node: CloudNode = from_json(&json)?;
                    if node.sign_public_b64 != member.keys.sign_public_b64
                        || node.box_public_b64 != member.keys.box_public_b64
                    {
                        problems.push(format!(
                            "{} ({}) now shows different keys; it is not trusted",
                            node.name, node.member_id
                        ));
                        continue;
                    }
                    if member.revoked_at.is_some() && node.removed_at.is_none() {
                        node.removed_at = member.revoked_at;
                        self.store
                            .cloud_put(record::NODE, &node.member_id, &to_json(&node)?)?;
                    }
                    continue;
                }
                let (Some(lookup_hash), Some(tag)) =
                    (&member.invite_lookup_hash, &member.node_tag_b64)
                else {
                    continue;
                };
                let Some(invite_json) = self.store.cloud_get(record::INVITE, lookup_hash)? else {
                    // An invite from another owner device (or a recovered
                    // owner whose backup has not been restored yet).
                    continue;
                };
                let invite: InviteRecord = from_json(&invite_json)?;
                let secret = self.store.open_local_secret(
                    vault,
                    &format!("cloud-invite:{lookup_hash}"),
                    &invite.secret_sealed,
                )?;
                let secret = String::from_utf8_lossy(&secret).into_owned();
                let expected = invite_tag(
                    &secret,
                    &member.keys.tag_material(&link.account_id, RelayRole::Node),
                );
                self.store.cloud_delete(record::INVITE, lookup_hash)?;
                if !tags_match(&expected, tag) {
                    problems.push(format!(
                        "{} ({}) registered keys that do not match the invite; it is not trusted",
                        member.name, member.member_id
                    ));
                    continue;
                }
                let node = CloudNode {
                    member_id: member.member_id.clone(),
                    name: member.name.clone(),
                    sign_public_b64: member.keys.sign_public_b64.clone(),
                    box_public_b64: member.keys.box_public_b64.clone(),
                    fingerprint: member.keys.fingerprint(),
                    verified_at: Utc::now(),
                    removed_at: member.revoked_at,
                };
                self.store
                    .cloud_put(record::NODE, &node.member_id, &to_json(&node)?)?;
                self.cloud_audit(
                    "cloud:node:verify",
                    &format!("kl://cloud/nodes/{}", node.member_id),
                    "verified",
                )?;
            }
            // Expired invites are useless.
            for (id, json) in self.store.cloud_list(record::INVITE, "")? {
                if from_json::<InviteRecord>(&json)?.expires_at < Utc::now() - Duration::days(1) {
                    self.store.cloud_delete(record::INVITE, &id)?;
                }
            }
            Ok(problems)
        })
    }

    pub fn cloud_nodes(&self) -> Result<Vec<CloudNode>> {
        self.store
            .cloud_list(record::NODE, "")?
            .into_iter()
            .map(|(_, json)| from_json(&json))
            .collect()
    }

    /// A verified node by member id or name.
    fn find_node(&self, node: &str) -> Result<CloudNode> {
        let nodes = self.cloud_nodes()?;
        let matches: Vec<_> = nodes
            .into_iter()
            .filter(|n| n.member_id == node || n.name == node)
            .collect();
        match matches.as_slice() {
            [one] => Ok(one.clone()),
            [] => Err(KeyLeaseError::NotFound {
                resource: format!("verified node {node} (run keylease cloud sync after it joins)"),
            }),
            _ => Err(invalid(format!(
                "several nodes are named {node}; use the member id"
            ))),
        }
    }

    /// Owner: marks a node removed locally and revokes its shares. Call
    /// `DELETE /v1/relay/members/{id}` too.
    pub fn cloud_remove_node(&self, node: &str) -> Result<CloudNode> {
        self.require_owner()?;
        let mut node = self.find_node(node)?;
        node.removed_at = Some(Utc::now());
        self.store
            .cloud_put(record::NODE, &node.member_id, &to_json(&node)?)?;
        for mut share in self.cloud_shares()? {
            if share.node_member_id == node.member_id && share.revoked_at.is_none() {
                share.revoked_at = Some(Utc::now());
                self.store
                    .cloud_put(record::SHARE, &share.share_id, &to_json(&share)?)?;
            }
        }
        self.cloud_audit(
            "cloud:node:remove",
            &format!("kl://cloud/nodes/{}", node.member_id),
            "removed",
        )?;
        Ok(node)
    }

    // ---- owner: shares -----------------------------------------------------

    pub fn cloud_shares(&self) -> Result<Vec<CloudShare>> {
        self.store
            .cloud_list(record::SHARE, "")?
            .into_iter()
            .map(|(_, json)| from_json(&json))
            .collect()
    }

    /// Owner: shares one item (the default) or a whole project with a node.
    pub fn cloud_share(
        &self,
        scope: ShareScope,
        node: &str,
        ttl: Option<Duration>,
        request_id: Option<String>,
    ) -> Result<CloudShare> {
        self.require_owner()?;
        let node = self.find_node(node)?;
        if node.removed_at.is_some() {
            return Err(KeyLeaseError::Denied {
                reason: format!("{} was removed", node.name),
            });
        }
        self.with_vault(|vault| {
            match &scope {
                ShareScope::Item { item_id } => {
                    let item = self.store.get_item(vault, item_id)?;
                    if item.extensions.contains_key(SHARE_EXTENSION) {
                        return Err(invalid("this item was itself shared to this vault"));
                    }
                }
                ShareScope::Project { project_id } => {
                    self.store.get_project(vault, project_id)?;
                }
            }
            if let Some(ttl) = ttl
                && (ttl <= Duration::zero() || ttl > Duration::days(365))
            {
                return Err(invalid("a share lasts at most 365 days"));
            }
            let share = CloudShare {
                share_id: new_id("share"),
                scope: scope.clone(),
                node_member_id: node.member_id.clone(),
                node_name: node.name.clone(),
                created_at: Utc::now(),
                expires_at: ttl.map(|ttl| Utc::now() + ttl),
                revoked_at: None,
                request_id,
            };
            self.store
                .cloud_put(record::SHARE, &share.share_id, &to_json(&share)?)?;
            let resource = match &scope {
                ShareScope::Item { item_id } => {
                    format!("kl://{}/item/{}", vault.vault_id.0, item_id.0)
                }
                ShareScope::Project { project_id } => {
                    format!("kl://{}/project/{}", vault.vault_id.0, project_id.0)
                }
            };
            self.cloud_audit(
                "cloud:share",
                &resource,
                &format!("shared with {}", node.member_id),
            )?;
            Ok(share)
        })
    }

    /// A project by slug or id, for `cloud share --project`.
    pub fn cloud_project_id(&self, slug_or_id: &str) -> Result<ProjectId> {
        self.with_vault(|vault| {
            self.store
                .list_projects(vault)?
                .into_iter()
                .find(|p| p.slug == slug_or_id || p.id.0 == slug_or_id)
                .map(|p| p.id)
                .ok_or_else(|| KeyLeaseError::NotFound {
                    resource: format!("project {slug_or_id}"),
                })
        })
    }

    pub fn cloud_revoke_share(&self, share_id: &str) -> Result<CloudShare> {
        self.require_owner()?;
        let mut share: CloudShare = from_json(
            &self
                .store
                .cloud_get(record::SHARE, share_id)?
                .ok_or_else(|| KeyLeaseError::NotFound {
                    resource: format!("share {share_id}"),
                })?,
        )?;
        if share.revoked_at.is_none() {
            share.revoked_at = Some(Utc::now());
            self.store
                .cloud_put(record::SHARE, share_id, &to_json(&share)?)?;
            self.cloud_audit(
                "cloud:unshare",
                &format!("kl://cloud/shares/{share_id}"),
                "revoked",
            )?;
        }
        Ok(share)
    }

    // ---- requests ----------------------------------------------------------

    /// Node: an agent asks the owner for an item. Any enrolled agent may ask;
    /// the request is audited under it and decided on the owner's device.
    pub fn cloud_request_share_authorized(
        &self,
        actor: &ActorContext,
        purpose: &str,
        hint: Option<&str>,
    ) -> Result<CloudShareRequest> {
        let link = self.require_link()?;
        if link.role != CloudRole::Node {
            return Err(invalid(
                "share requests are made on a node; the owner shares directly",
            ));
        }
        validate_purpose(purpose)?;
        if let Some(hint) = hint {
            validate_purpose(hint)?;
        }
        let pending = self
            .store
            .cloud_list(record::REQUEST, "")?
            .into_iter()
            .filter_map(|(_, json)| from_json::<CloudShareRequest>(&json).ok())
            .filter(|r| r.agent_id == actor.agent_id.0 && r.status == RequestStatus::Pending)
            .count();
        if pending >= MAX_PENDING_REQUESTS_PER_AGENT {
            return Err(KeyLeaseError::Denied {
                reason: "this agent already has 10 pending share requests".into(),
            });
        }
        let request = CloudShareRequest {
            request_id: new_id("request"),
            agent_id: actor.agent_id.0.clone(),
            purpose: purpose.into(),
            hint: hint.map(Into::into),
            node_member_id: None,
            node_name: None,
            created_at: Utc::now(),
            status: RequestStatus::Pending,
            share_id: None,
        };
        self.with_vault_passive(|vault| {
            let keys = self.load_keys(vault)?;
            self.queue_message(
                &link,
                &keys,
                &link.owner_member_id,
                &link.owner_box_public_b64,
                kind::SHARE_REQUEST,
                &request.request_id,
                1,
                &MessagePayload::ShareRequest {
                    request_id: request.request_id.clone(),
                    agent_id: request.agent_id.clone(),
                    purpose: request.purpose.clone(),
                    hint: request.hint.clone(),
                },
            )
        })?;
        self.store
            .cloud_put(record::REQUEST, &request.request_id, &to_json(&request)?)?;
        self.store.append_audit(&self.vault_audit_event(
            actor,
            "cloud:request",
            &format!("kl://cloud/requests/{}", request.request_id),
            "allow",
            "requested",
            vec![],
        ))?;
        Ok(request)
    }

    pub fn cloud_requests(&self) -> Result<Vec<CloudShareRequest>> {
        self.store
            .cloud_list(record::REQUEST, "")?
            .into_iter()
            .map(|(_, json)| from_json(&json))
            .collect()
    }

    fn pending_request(&self, request_id: &str) -> Result<CloudShareRequest> {
        let request: CloudShareRequest = from_json(
            &self
                .store
                .cloud_get(record::REQUEST, request_id)?
                .ok_or_else(|| KeyLeaseError::NotFound {
                    resource: format!("request {request_id}"),
                })?,
        )?;
        if request.status != RequestStatus::Pending || request.node_member_id.is_none() {
            return Err(invalid("this request is not pending on this owner device"));
        }
        Ok(request)
    }

    /// Owner: approves a request by sharing `item_id` with the node that asked.
    pub fn cloud_approve_request(
        &self,
        request_id: &str,
        item_id: &ItemId,
        ttl: Option<Duration>,
    ) -> Result<CloudShare> {
        let link = self.require_owner()?;
        let mut request = self.pending_request(request_id)?;
        let node_id = request.node_member_id.clone().unwrap_or_default();
        let share = self.cloud_share(
            ShareScope::Item {
                item_id: item_id.clone(),
            },
            &node_id,
            ttl,
            Some(request_id.into()),
        )?;
        request.status = RequestStatus::Approved;
        request.share_id = Some(share.share_id.clone());
        self.decide_request_message(&link, &request, true)?;
        Ok(share)
    }

    pub fn cloud_deny_request(&self, request_id: &str) -> Result<CloudShareRequest> {
        let link = self.require_owner()?;
        let mut request = self.pending_request(request_id)?;
        request.status = RequestStatus::Denied;
        self.decide_request_message(&link, &request, false)?;
        Ok(request)
    }

    fn decide_request_message(
        &self,
        link: &CloudLink,
        request: &CloudShareRequest,
        approved: bool,
    ) -> Result<()> {
        let node = self.find_node(request.node_member_id.as_deref().unwrap_or_default())?;
        self.with_vault(|vault| {
            let keys = self.load_keys(vault)?;
            self.queue_message(
                link,
                &keys,
                &node.member_id,
                &node.box_public_b64,
                kind::REQUEST_DECISION,
                &request.request_id,
                1,
                &MessagePayload::RequestDecision {
                    request_id: request.request_id.clone(),
                    approved,
                    share_id: request.share_id.clone(),
                },
            )
        })?;
        self.store
            .cloud_put(record::REQUEST, &request.request_id, &to_json(request)?)?;
        self.cloud_audit(
            if approved {
                "cloud:request:approve"
            } else {
                "cloud:request:deny"
            },
            &format!("kl://cloud/requests/{}", request.request_id),
            if approved { "approved" } else { "denied" },
        )
    }

    // ---- messages ----------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn queue_message(
        &self,
        link: &CloudLink,
        keys: &Keys,
        to_member_id: &str,
        to_box_public_b64: &str,
        message_kind: &str,
        object_id: &str,
        revision: u64,
        payload: &MessagePayload,
    ) -> Result<()> {
        let label = RelayPayloadLabel {
            account_id: &link.account_id,
            from_member_id: &link.member_id,
            to_member_id,
            kind: message_kind,
            object_id,
            revision,
        };
        let plain =
            Zeroizing::new(serde_json::to_vec(payload).map_err(|_| KeyLeaseError::Storage)?);
        let sealed = to_json(&seal(&unb64_32(to_box_public_b64)?, &plain, &label.aad())?)?;
        let signature = keys.sign.sign(&label.signing_input(&sealed));
        let envelope = RelayEnvelope {
            message_id: new_id("msg"),
            account_id: link.account_id.clone(),
            from_member_id: link.member_id.clone(),
            to_member_id: to_member_id.into(),
            kind: message_kind.into(),
            object_id: object_id.into(),
            revision,
            sealed_json: sealed,
            signature_b64: b64(&signature.to_bytes()),
            created_at: Utc::now(),
        };
        self.store
            .cloud_put(record::OUTBOX, &envelope.message_id, &to_json(&envelope)?)
    }

    /// Messages waiting to be sent, oldest first.
    pub fn cloud_outbox(&self) -> Result<Vec<RelayEnvelope>> {
        let mut messages: Vec<RelayEnvelope> = self
            .store
            .cloud_list(record::OUTBOX, "")?
            .into_iter()
            .map(|(_, json)| from_json(&json))
            .collect::<Result<_>>()?;
        messages.sort_by_key(|m| m.created_at);
        Ok(messages)
    }

    pub fn cloud_outbox_sent(&self, message_id: &str) -> Result<()> {
        self.store.cloud_delete(record::OUTBOX, message_id)
    }

    /// Owner: queues what the shares need: new item revisions, items that left
    /// a project or were deleted, and revoked or expired shares.
    pub fn cloud_publish_shares(&self) -> Result<usize> {
        let link = self.require_owner()?;
        let mut queued = 0;
        self.with_vault_passive(|vault| {
            let keys = self.load_keys(vault)?;
            let items = self.store.list_items(vault)?;
            for mut share in self.cloud_shares()? {
                let node = match self.store.cloud_get(record::NODE, &share.node_member_id)? {
                    Some(json) => from_json::<CloudNode>(&json)?,
                    None => continue,
                };
                let expired = share.expires_at.is_some_and(|at| at <= Utc::now());
                if expired && share.revoked_at.is_none() {
                    share.revoked_at = share.expires_at;
                    self.store
                        .cloud_put(record::SHARE, &share.share_id, &to_json(&share)?)?;
                }
                let active = share.revoked_at.is_none() && node.removed_at.is_none();
                let wanted: Vec<&VaultItem> = if !active {
                    vec![]
                } else {
                    items
                        .iter()
                        .filter(|item| match &share.scope {
                            ShareScope::Item { item_id } => &item.id == item_id,
                            ShareScope::Project { project_id } => {
                                item.project_id.as_ref() == Some(project_id)
                            }
                        })
                        .filter(|item| !item.extensions.contains_key(SHARE_EXTENSION))
                        .collect()
                };
                let prefix = format!("{}/", share.share_id);
                let published = self.store.cloud_list(record::SHARE_ITEM, &prefix)?;
                for (key, revision) in &published {
                    let item_id = key.trim_start_matches(&prefix);
                    if wanted.iter().any(|item| item.id.0 == item_id) {
                        continue;
                    }
                    if node.removed_at.is_none() {
                        let revision: u64 = revision.parse().unwrap_or(0);
                        self.queue_message(
                            &link,
                            &keys,
                            &node.member_id,
                            &node.box_public_b64,
                            kind::UNSHARE,
                            item_id,
                            revision,
                            &MessagePayload::Unshare {
                                share_id: share.share_id.clone(),
                                item_id: ItemId(item_id.into()),
                            },
                        )?;
                        queued += 1;
                    }
                    self.store.cloud_delete(record::SHARE_ITEM, key)?;
                }
                for item in wanted {
                    let key = format!("{prefix}{}", item.id.0);
                    if self.store.cloud_get(record::SHARE_ITEM, &key)?.as_deref()
                        == Some(item.revision.to_string().as_str())
                    {
                        continue;
                    }
                    self.queue_message(
                        &link,
                        &keys,
                        &node.member_id,
                        &node.box_public_b64,
                        kind::SHARE,
                        &item.id.0,
                        item.revision,
                        &MessagePayload::Share {
                            share_id: share.share_id.clone(),
                            item: Box::new(item.clone()),
                            expires_at: share.expires_at,
                        },
                    )?;
                    self.store
                        .cloud_put(record::SHARE_ITEM, &key, &item.revision.to_string())?;
                    queued += 1;
                }
            }
            Ok(queued)
        })
    }

    /// Applies mailbox messages. Returns the ids to acknowledge: applied ones
    /// and ones rejected for a bad signature or payload (they never will
    /// apply). A message that fails for a passing reason (a locked vault) is
    /// not acknowledged and is retried on the next sync.
    pub fn cloud_apply_inbox(&self, messages: &[RelayEnvelope]) -> Result<InboxOutcome> {
        let link = self.require_link()?;
        let mut outcome = InboxOutcome::default();
        self.with_vault_passive(|vault| {
            let keys = self.load_keys(vault)?;
            for message in messages {
                if self
                    .store
                    .cloud_get(record::APPLIED, &message.message_id)?
                    .is_some()
                {
                    outcome.acknowledged.push(message.message_id.clone());
                    continue;
                }
                match self.apply_message(vault, &link, &keys, message) {
                    Ok(()) => outcome.applied += 1,
                    Err(KeyLeaseError::VaultLocked { .. }) | Err(KeyLeaseError::Storage) => {
                        continue;
                    }
                    Err(error) => outcome.rejected.push(format!(
                        "{} {}: {error:?}",
                        message.kind, message.message_id
                    )),
                }
                self.store.cloud_put(
                    record::APPLIED,
                    &message.message_id,
                    &to_json(&Utc::now())?,
                )?;
                outcome.acknowledged.push(message.message_id.clone());
            }
            // Applied ids older than the cloud's retention are not needed.
            for (id, json) in self.store.cloud_list(record::APPLIED, "")? {
                if from_json::<DateTime<Utc>>(&json)
                    .is_ok_and(|at| at < Utc::now() - Duration::days(30))
                {
                    self.store.cloud_delete(record::APPLIED, &id)?;
                }
            }
            self.expire_received(vault)?;
            Ok(outcome)
        })
    }

    fn apply_message(
        &self,
        vault: &keylease_store::UnlockedVault,
        link: &CloudLink,
        keys: &Keys,
        message: &RelayEnvelope,
    ) -> Result<()> {
        if message.account_id != link.account_id || message.to_member_id != link.member_id {
            return Err(invalid("message is addressed to another member"));
        }
        let sender_sign = match link.role {
            CloudRole::Node => {
                if message.from_member_id != link.owner_member_id {
                    return Err(invalid("a node accepts messages only from the owner"));
                }
                link.owner_sign_public_b64.clone()
            }
            CloudRole::Owner => {
                let node: CloudNode = from_json(
                    &self
                        .store
                        .cloud_get(record::NODE, &message.from_member_id)?
                        .ok_or_else(|| invalid("message from an unverified node"))?,
                )?;
                if node.removed_at.is_some() {
                    return Err(invalid("message from a removed node"));
                }
                node.sign_public_b64
            }
        };
        let label = message.label();
        verify_signature(
            &sender_sign,
            &label.signing_input(&message.sealed_json),
            &message.signature_b64,
        )?;
        let sealed: SealedBox =
            from_json(&message.sealed_json).map_err(|_| KeyLeaseError::Crypto)?;
        let plain = open(&keys.boxed, &sealed, &label.aad())?;
        let payload: MessagePayload =
            serde_json::from_slice(&plain).map_err(|_| invalid("unreadable message payload"))?;
        match (link.role, message.kind.as_str(), payload) {
            (
                CloudRole::Node,
                kind::SHARE,
                MessagePayload::Share {
                    share_id,
                    item,
                    expires_at,
                },
            ) if item.id.0 == message.object_id && item.revision == message.revision => {
                self.receive_shared_item(vault, link, &share_id, *item, expires_at)
            }
            (CloudRole::Node, kind::UNSHARE, MessagePayload::Unshare { share_id, item_id })
                if item_id.0 == message.object_id =>
            {
                self.drop_shared_item(vault, &share_id, &item_id)
            }
            (CloudRole::Node, kind::RESTORE, MessagePayload::Restore { item })
                if item.id.0 == message.object_id =>
            {
                self.import_restored_item(vault, *item)
            }
            (
                CloudRole::Node,
                kind::REQUEST_DECISION,
                MessagePayload::RequestDecision {
                    request_id,
                    approved,
                    share_id,
                },
            ) if request_id == message.object_id => {
                if let Some(json) = self.store.cloud_get(record::REQUEST, &request_id)? {
                    let mut request: CloudShareRequest = from_json(&json)?;
                    request.status = if approved {
                        RequestStatus::Approved
                    } else {
                        RequestStatus::Denied
                    };
                    request.share_id = share_id;
                    self.store
                        .cloud_put(record::REQUEST, &request_id, &to_json(&request)?)?;
                }
                Ok(())
            }
            (
                CloudRole::Owner,
                kind::SHARE_REQUEST,
                MessagePayload::ShareRequest {
                    request_id,
                    agent_id,
                    purpose,
                    hint,
                },
            ) if request_id == message.object_id => {
                validate_purpose(&purpose)?;
                let node: CloudNode = from_json(
                    &self
                        .store
                        .cloud_get(record::NODE, &message.from_member_id)?
                        .ok_or(KeyLeaseError::Storage)?,
                )?;
                let request = CloudShareRequest {
                    request_id,
                    agent_id,
                    purpose,
                    hint,
                    node_member_id: Some(node.member_id),
                    node_name: Some(node.name),
                    created_at: message.created_at,
                    status: RequestStatus::Pending,
                    share_id: None,
                };
                self.store.cloud_insert(
                    record::REQUEST,
                    &request.request_id,
                    &to_json(&request)?,
                )?;
                Ok(())
            }
            _ => Err(invalid("message kind does not match its payload")),
        }
    }

    fn receive_shared_item(
        &self,
        vault: &keylease_store::UnlockedVault,
        link: &CloudLink,
        share_id: &str,
        owner_item: VaultItem,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        let key = format!("{share_id}/{}", owner_item.id.0);
        let existing: Option<ReceivedRecord> = self
            .store
            .cloud_get(record::RECEIVED, &key)?
            .map(|json| from_json(&json))
            .transpose()?;
        if let Some(existing) = &existing
            && existing.owner_revision >= owner_item.revision
        {
            return Ok(());
        }
        let current = match &existing {
            Some(record) => self.store.get_item(vault, &record.local_item_id).ok(),
            None => None,
        };
        let local_id = existing
            .as_ref()
            .map(|r| r.local_item_id.clone())
            .unwrap_or_default();
        let base_revision = current.as_ref().map_or(0, |item| item.revision);
        let mut item = owner_item.clone();
        item.id = local_id.clone();
        item.vault_id = vault.vault_id.clone();
        item.group_id = GroupId(SHARED_GROUP.into());
        item.project_id = None;
        item.revision = base_revision + 1;
        item.updated_at = Utc::now();
        if current.is_none() {
            item.created_at = Utc::now();
        }
        item.extensions.insert(
            SHARE_EXTENSION.into(),
            serde_json::json!({
                "share_id": share_id,
                "owner_member_id": link.owner_member_id,
                "owner_item_id": owner_item.id.0,
                "owner_revision": owner_item.revision,
                "expires_at": expires_at,
                "read_only": true,
            }),
        );
        self.store.put_item(
            vault,
            &item,
            Some(base_revision),
            MutationContext {
                actor: "cloud",
                idempotency_key: &format!("cloud-share-{key}-{}", owner_item.revision),
                request_material: format!("cloud-share:{key}:{}", owner_item.revision).as_bytes(),
                audit_event: Some(&self.vault_audit_event(
                    &self.cloud_actor(),
                    "cloud:receive",
                    &format!("kl://{}/item/{}", vault.vault_id.0, local_id.0),
                    "allow",
                    &format!("shared by the owner ({share_id})"),
                    vec![],
                )),
            },
        )?;
        self.store.cloud_put(
            record::RECEIVED,
            &key,
            &to_json(&ReceivedRecord {
                local_item_id: local_id,
                owner_revision: owner_item.revision,
            })?,
        )
    }

    fn drop_shared_item(
        &self,
        vault: &keylease_store::UnlockedVault,
        share_id: &str,
        owner_item_id: &ItemId,
    ) -> Result<()> {
        let key = format!("{share_id}/{}", owner_item_id.0);
        let Some(json) = self.store.cloud_get(record::RECEIVED, &key)? else {
            return Ok(());
        };
        let record: ReceivedRecord = from_json(&json)?;
        if let Ok(item) = self.store.get_item(vault, &record.local_item_id) {
            self.store.delete_item(
                vault,
                &item.id,
                item.revision,
                MutationContext {
                    actor: "cloud",
                    idempotency_key: &format!("cloud-unshare-{key}-{}", item.revision),
                    request_material: format!("cloud-unshare:{key}:{}", item.revision).as_bytes(),
                    audit_event: Some(&self.vault_audit_event(
                        &self.cloud_actor(),
                        "cloud:unshare",
                        &format!("kl://{}/item/{}", vault.vault_id.0, item.id.0),
                        "allow",
                        &format!("share {share_id} ended"),
                        vec![],
                    )),
                },
            )?;
        }
        self.store.cloud_delete(record::RECEIVED, &key)
    }

    /// Node: drops shared items whose share expired, even if the owner's
    /// revocation has not arrived.
    fn expire_received(&self, vault: &keylease_store::UnlockedVault) -> Result<()> {
        for (key, json) in self.store.cloud_list(record::RECEIVED, "")? {
            let record: ReceivedRecord = from_json(&json)?;
            let Ok(item) = self.store.get_item(vault, &record.local_item_id) else {
                self.store.cloud_delete(record::RECEIVED, &key)?;
                continue;
            };
            let expired = item
                .extensions
                .get(SHARE_EXTENSION)
                .and_then(|share| share.get("expires_at"))
                .and_then(|at| serde_json::from_value::<Option<DateTime<Utc>>>(at.clone()).ok())
                .flatten()
                .is_some_and(|at| at <= Utc::now());
            if expired && let Some((share_id, owner_item)) = key.split_once('/') {
                self.drop_shared_item(vault, share_id, &ItemId(owner_item.into()))?;
            }
        }
        Ok(())
    }

    fn import_restored_item(
        &self,
        vault: &keylease_store::UnlockedVault,
        backup_item: VaultItem,
    ) -> Result<()> {
        let mut item = backup_item;
        let source = item.id.clone();
        if self.store.get_item(vault, &source).is_ok() {
            // Restored once already (the same item id).
            return Ok(());
        }
        item.vault_id = vault.vault_id.clone();
        item.group_id = GroupId(RESTORED_GROUP.into());
        item.project_id = None;
        item.revision = 1;
        item.extensions.remove(SHARE_EXTENSION);
        item.updated_at = Utc::now();
        self.store.put_item(
            vault,
            &item,
            Some(0),
            MutationContext {
                actor: "cloud",
                idempotency_key: &format!("cloud-restore-{}", source.0),
                request_material: format!("cloud-restore:{}", source.0).as_bytes(),
                audit_event: Some(&self.vault_audit_event(
                    &self.cloud_actor(),
                    "cloud:restore",
                    &format!("kl://{}/item/{}", vault.vault_id.0, item.id.0),
                    "allow",
                    "restored from a cloud backup",
                    vec![],
                )),
            },
        )?;
        Ok(())
    }

    // ---- backups -----------------------------------------------------------

    /// This member's backup objects that changed since the last backup, sealed
    /// to the owner: items (not shared-in copies), deletions, and on the owner
    /// its verified nodes and shares.
    pub fn cloud_backup_batch(&self, limit: usize) -> Result<Vec<PendingBackup>> {
        let link = self.require_link()?;
        self.with_vault_passive(|vault| {
            let keys = self.load_keys(vault)?;
            let mut objects: Vec<(String, BackupPayload, Option<u64>)> = Vec::new();
            for item in self.store.list_items(vault)? {
                if item.extensions.contains_key(SHARE_EXTENSION) {
                    continue;
                }
                let revision = item.revision;
                objects.push((
                    item.id.0.clone(),
                    BackupPayload::Item {
                        item: Box::new(item),
                    },
                    Some(revision),
                ));
            }
            if link.role == CloudRole::Owner {
                for node in self.cloud_nodes()? {
                    objects.push((
                        format!("node-{}", node.member_id),
                        BackupPayload::Node { node },
                        None,
                    ));
                }
                for share in self.cloud_shares()? {
                    objects.push((
                        format!("share-{}", share.share_id),
                        BackupPayload::Share { share },
                        None,
                    ));
                }
            }
            let present: std::collections::BTreeSet<String> =
                objects.iter().map(|(id, _, _)| id.clone()).collect();
            let mut out = Vec::new();
            for (object_id, payload, item_revision) in objects {
                if out.len() >= limit {
                    break;
                }
                let plain = Zeroizing::new(
                    serde_json::to_vec(&payload).map_err(|_| KeyLeaseError::Storage)?,
                );
                let digest = relay_digest(&plain);
                let previous: Option<BackupState> = self
                    .store
                    .cloud_get(record::BACKUP, &object_id)?
                    .map(|json| from_json(&json))
                    .transpose()?;
                if previous.as_ref().is_some_and(|p| p.digest == digest) {
                    continue;
                }
                let revision = item_revision
                    .unwrap_or(0)
                    .max(previous.as_ref().map_or(0, |p| p.revision) + 1);
                out.push(PendingBackup {
                    backup: self.seal_backup(&link, &keys, &object_id, revision, Some(&plain))?,
                    digest,
                });
            }
            for (object_id, json) in self.store.cloud_list(record::BACKUP, "")? {
                if out.len() >= limit {
                    break;
                }
                if present.contains(&object_id) {
                    continue;
                }
                let previous: BackupState = from_json(&json)?;
                out.push(PendingBackup {
                    backup: self.seal_backup(
                        &link,
                        &keys,
                        &object_id,
                        previous.revision + 1,
                        None,
                    )?,
                    digest: String::new(),
                });
            }
            Ok(out)
        })
    }

    fn seal_backup(
        &self,
        link: &CloudLink,
        keys: &Keys,
        object_id: &str,
        revision: u64,
        plain: Option<&[u8]>,
    ) -> Result<RelayBackup> {
        let mut backup = RelayBackup {
            member_id: link.member_id.clone(),
            object_id: object_id.into(),
            revision,
            deleted: plain.is_none(),
            sealed_json: String::new(),
            signature_b64: String::new(),
            updated_at: Utc::now(),
        };
        let label_owned = backup.clone();
        let label = label_owned.label(&link.account_id, &link.owner_member_id);
        if let Some(plain) = plain {
            backup.sealed_json = to_json(&seal(
                &unb64_32(&link.owner_box_public_b64)?,
                plain,
                &label.aad(),
            )?)?;
        }
        backup.signature_b64 = b64(&keys
            .sign
            .sign(&label.signing_input(&backup.sealed_json))
            .to_bytes());
        Ok(backup)
    }

    /// Records a backup the cloud accepted.
    pub fn cloud_backup_stored(&self, pending: &PendingBackup) -> Result<()> {
        let backup = &pending.backup;
        if backup.deleted {
            return self.store.cloud_delete(record::BACKUP, &backup.object_id);
        }
        self.store.cloud_put(
            record::BACKUP,
            &backup.object_id,
            &to_json(&BackupState {
                revision: backup.revision,
                digest: pending.digest.clone(),
            })?,
        )
    }

    /// Owner: opens the backups of `from` (a node, or this owner) after
    /// checking each one's signature. Deleted objects are skipped.
    fn open_backups(
        &self,
        link: &CloudLink,
        keys: &Keys,
        from_member_id: &str,
        backups: &[RelayBackup],
    ) -> Result<Vec<BackupPayload>> {
        let sender_sign = if from_member_id == link.member_id {
            link.sign_public_b64.clone()
        } else {
            from_json::<CloudNode>(
                &self
                    .store
                    .cloud_get(record::NODE, from_member_id)?
                    .ok_or_else(|| KeyLeaseError::NotFound {
                        resource: format!("verified node {from_member_id}"),
                    })?,
            )?
            .sign_public_b64
        };
        let mut out = Vec::new();
        for backup in backups.iter().filter(|b| !b.deleted) {
            if backup.member_id != from_member_id {
                return Err(invalid("a backup of another member was returned"));
            }
            let label = backup.label(&link.account_id, &link.owner_member_id);
            verify_signature(
                &sender_sign,
                &label.signing_input(&backup.sealed_json),
                &backup.signature_b64,
            )?;
            let sealed: SealedBox = from_json(&backup.sealed_json)?;
            let plain = open(&keys.boxed, &sealed, &label.aad())?;
            out.push(serde_json::from_slice(&plain).map_err(|_| KeyLeaseError::Crypto)?);
        }
        Ok(out)
    }

    /// Owner: restores the backups of `from` to the node `to` (as restore
    /// messages) or, when `to` is `None`, into this vault. On a recovered
    /// owner, restoring its own backups also brings back its nodes and shares.
    pub fn cloud_restore(
        &self,
        from_member_id: &str,
        to_node: Option<&str>,
        backups: &[RelayBackup],
    ) -> Result<usize> {
        let link = self.require_owner()?;
        let target = to_node.map(|node| self.find_node(node)).transpose()?;
        if let Some(target) = &target
            && target.removed_at.is_some()
        {
            return Err(invalid("cannot restore to a removed node"));
        }
        self.with_vault(|vault| {
            let keys = self.load_keys(vault)?;
            let payloads = self.open_backups(&link, &keys, from_member_id, backups)?;
            let mut restored = 0;
            for payload in payloads {
                match (payload, &target) {
                    (BackupPayload::Item { item }, Some(node)) => {
                        let object = item.id.0.clone();
                        self.queue_message(
                            &link,
                            &keys,
                            &node.member_id,
                            &node.box_public_b64,
                            kind::RESTORE,
                            &object,
                            1,
                            &MessagePayload::Restore { item },
                        )?;
                        restored += 1;
                    }
                    (BackupPayload::Item { item }, None) => {
                        self.import_restored_item(vault, *item)?;
                        restored += 1;
                    }
                    (BackupPayload::Node { node }, None) if from_member_id == link.member_id => {
                        self.store
                            .cloud_insert(record::NODE, &node.member_id, &to_json(&node)?)?;
                    }
                    (BackupPayload::Share { share }, None) if from_member_id == link.member_id => {
                        self.store.cloud_insert(
                            record::SHARE,
                            &share.share_id,
                            &to_json(&share)?,
                        )?;
                    }
                    _ => {}
                }
            }
            self.cloud_audit(
                "cloud:restore",
                &format!("kl://cloud/members/{from_member_id}"),
                &format!(
                    "{restored} items to {}",
                    target
                        .as_ref()
                        .map_or("this vault", |t| t.member_id.as_str())
                ),
            )?;
            Ok(restored)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Writes an item straight to the store (revision bumps on each call).
    fn put_item(service: &KeyLeaseService, id: &ItemId, title: &str) -> VaultItem {
        service
            .with_vault(|vault| {
                let current = service.store.get_item(vault, id).ok();
                let now = Utc::now();
                let item = VaultItem {
                    id: id.clone(),
                    vault_id: vault.vault_id.clone(),
                    group_id: GroupId("group_default".into()),
                    kind: "core.login".into(),
                    title: title.into(),
                    sections: vec![],
                    fields: vec![ItemField {
                        id: FieldId::new(),
                        key: "password".into(),
                        label: "Password".into(),
                        value: FieldValue::Concealed("s3cret".into()),
                        sensitivity: Sensitivity::HighlySensitive,
                        protected: true,
                        semantic_role: Some("password".into()),
                    }],
                    urls: vec![],
                    tags: vec![],
                    favorite: false,
                    attachments: vec![],
                    notes: None,
                    template_version: 1,
                    project_id: None,
                    agent_access: AgentAccess::None,
                    content_metadata: None,
                    schema_version: 1,
                    revision: current.as_ref().map_or(1, |c| c.revision + 1),
                    created_at: now,
                    updated_at: now,
                    secret_changed_at: None,
                    expires_at: None,
                    rotation_interval_days: None,
                    issuer: None,
                    environment: None,
                    owner: None,
                    status: ItemStatus::Active,
                    extensions: Default::default(),
                };
                service.store.put_item(
                    vault,
                    &item,
                    Some(current.map_or(0, |c| c.revision)),
                    MutationContext {
                        actor: "test",
                        idempotency_key: &format!("test-{}-{}", id.0, item.revision),
                        request_material: title.as_bytes(),
                        audit_event: None,
                    },
                )?;
                Ok(item)
            })
            .unwrap()
    }

    fn items(service: &KeyLeaseService) -> Vec<VaultItem> {
        service
            .with_vault(|vault| service.store.list_items(vault))
            .unwrap()
    }

    fn owner_linked(owner: &KeyLeaseService) -> OwnerSetup {
        let setup = owner
            .cloud_owner_prepare("https://cloud.example", "laptop")
            .unwrap();
        owner
            .cloud_owner_commit(&RelayAccountCreated {
                account_id: setup.request.account_id.clone(),
                owner_member_id: "member_owner".into(),
            })
            .unwrap();
        setup
    }

    /// Plays the cloud's part of pairing: hands the invite to the node and the
    /// node's registration back to the owner.
    fn join(owner: &KeyLeaseService, node: &KeyLeaseService, name: &str, member_id: &str) {
        let link = owner.cloud_link().unwrap().unwrap();
        let invite = owner.cloud_create_invite(name).unwrap();
        let join = node
            .cloud_node_prepare(
                "https://cloud.example",
                &invite.code,
                &RelayInvite {
                    account_id: link.account_id.clone(),
                    owner_member_id: link.member_id.clone(),
                    owner: link.keys(),
                    name: name.into(),
                    owner_tag_b64: invite.request.owner_tag_b64.clone(),
                    expires_at: invite.request.expires_at,
                },
            )
            .unwrap();
        node.cloud_node_commit(&RelayJoined {
            account_id: link.account_id.clone(),
            member_id: member_id.into(),
        })
        .unwrap();
        let problems = owner
            .cloud_verify_members(&[RelayMember {
                member_id: member_id.into(),
                role: RelayRole::Node,
                name: name.into(),
                keys: join.keys,
                node_tag_b64: Some(join.node_tag_b64),
                invite_lookup_hash: Some(invite.request.lookup_hash),
                created_at: Utc::now(),
                revoked_at: None,
            }])
            .unwrap();
        assert!(problems.is_empty(), "{problems:?}");
    }

    fn deliver(from: &KeyLeaseService, to: &KeyLeaseService) -> InboxOutcome {
        let outbox = from.cloud_outbox().unwrap();
        for message in &outbox {
            from.cloud_outbox_sent(&message.message_id).unwrap();
        }
        to.cloud_apply_inbox(&outbox).unwrap()
    }

    fn agent() -> ActorContext {
        ActorContext {
            agent_id: AgentId("agent_codex".into()),
            workload_id: None,
            human_principal: None,
            on_behalf_of: None,
            client_session_id: "s".into(),
            purpose: None,
        }
    }

    #[test]
    fn an_altered_owner_key_or_node_key_is_detected_at_pairing() {
        let (_a, owner) = service();
        let (_b, node) = service();
        let setup = owner_linked(&owner);
        let invite = owner.cloud_create_invite("vps").unwrap();
        let forged = RelayInvite {
            account_id: setup.request.account_id.clone(),
            owner_member_id: "member_owner".into(),
            owner: Keys::generate().public(),
            name: "vps".into(),
            owner_tag_b64: invite.request.owner_tag_b64.clone(),
            expires_at: invite.request.expires_at,
        };
        assert!(matches!(
            node.cloud_node_prepare("https://cloud.example", &invite.code, &forged),
            Err(KeyLeaseError::Denied { .. })
        ));
        let problems = owner
            .cloud_verify_members(&[RelayMember {
                member_id: "member_evil".into(),
                role: RelayRole::Node,
                name: "vps".into(),
                keys: Keys::generate().public(),
                node_tag_b64: Some(b64(&[7_u8; 32])),
                invite_lookup_hash: Some(invite.request.lookup_hash.clone()),
                created_at: Utc::now(),
                revoked_at: None,
            }])
            .unwrap();
        assert_eq!(problems.len(), 1);
        assert!(owner.cloud_nodes().unwrap().is_empty());
        assert!(
            owner
                .cloud_share(
                    ShareScope::Item {
                        item_id: ItemId::new()
                    },
                    "member_evil",
                    None,
                    None
                )
                .is_err()
        );
    }

    #[test]
    fn an_item_share_reaches_the_node_updates_and_is_revoked() {
        let (_a, owner) = service();
        let (_b, node) = service();
        owner_linked(&owner);
        join(&owner, &node, "vps-prod", "member_node");
        let id = ItemId::new();
        put_item(&owner, &id, "prod db");
        let share = owner
            .cloud_share(
                ShareScope::Item {
                    item_id: id.clone(),
                },
                "vps-prod",
                None,
                None,
            )
            .unwrap();
        assert_eq!(owner.cloud_publish_shares().unwrap(), 1);
        assert_eq!(owner.cloud_publish_shares().unwrap(), 0, "nothing new");
        assert_eq!(deliver(&owner, &node).applied, 1);
        let received = items(&node);
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].title, "prod db");
        assert_eq!(received[0].group_id.0, SHARED_GROUP);
        assert!(received[0].extensions.contains_key(SHARE_EXTENSION));
        assert!(
            node.cloud_backup_batch(100).unwrap().is_empty(),
            "shared copies are not backed up by the node"
        );

        put_item(&owner, &id, "prod db (rotated)");
        assert_eq!(owner.cloud_publish_shares().unwrap(), 1);
        deliver(&owner, &node);
        assert_eq!(items(&node)[0].title, "prod db (rotated)");
        assert_eq!(items(&node).len(), 1);

        owner.cloud_revoke_share(&share.share_id).unwrap();
        assert_eq!(owner.cloud_publish_shares().unwrap(), 1);
        deliver(&owner, &node);
        assert!(items(&node).is_empty());
    }

    #[test]
    fn a_project_share_follows_items_into_and_out_of_the_project() {
        let (_a, owner) = service();
        let (_b, node) = service();
        owner_linked(&owner);
        join(&owner, &node, "vps-prod", "member_node");
        let project = owner
            .with_vault(|vault| {
                let now = Utc::now();
                let project = VaultProject {
                    id: ProjectId::new(),
                    vault_id: vault.vault_id.clone(),
                    slug: "glow".into(),
                    name: "Glow".into(),
                    revision: 1,
                    created_by: AgentId("test".into()),
                    updated_by: AgentId("test".into()),
                    created_at: now,
                    updated_at: now,
                    archived_at: None,
                };
                owner.store.put_project(
                    vault,
                    &project,
                    Some(0),
                    MutationContext {
                        actor: "test",
                        idempotency_key: "project",
                        request_material: b"project",
                        audit_event: None,
                    },
                )?;
                Ok(project)
            })
            .unwrap();
        assert_eq!(owner.cloud_project_id("glow").unwrap(), project.id);
        let first = ItemId::new();
        put_item(&owner, &first, "api key");
        let set_project = |id: &ItemId, project: Option<ProjectId>| {
            owner
                .with_vault(|vault| {
                    let mut item = owner.store.get_item(vault, id)?;
                    let base = item.revision;
                    item.project_id = project;
                    item.revision += 1;
                    owner.store.put_item(
                        vault,
                        &item,
                        Some(base),
                        MutationContext {
                            actor: "test",
                            idempotency_key: &format!("p-{}-{}", id.0, item.revision),
                            request_material: b"p",
                            audit_event: None,
                        },
                    )
                })
                .unwrap()
        };
        set_project(&first, Some(project.id.clone()));
        owner
            .cloud_share(
                ShareScope::Project {
                    project_id: project.id.clone(),
                },
                "vps-prod",
                None,
                None,
            )
            .unwrap();
        owner.cloud_publish_shares().unwrap();
        deliver(&owner, &node);
        assert_eq!(items(&node).len(), 1);
        let second = ItemId::new();
        put_item(&owner, &second, "db password");
        set_project(&second, Some(project.id.clone()));
        owner.cloud_publish_shares().unwrap();
        deliver(&owner, &node);
        assert_eq!(
            items(&node).len(),
            2,
            "an item added to the project follows"
        );
        set_project(&first, None);
        owner.cloud_publish_shares().unwrap();
        deliver(&owner, &node);
        let left = items(&node);
        assert_eq!(left.len(), 1, "an item that left the project is withdrawn");
        assert_eq!(left[0].title, "db password");
    }

    #[test]
    fn a_node_request_is_decided_by_the_owner_and_replays_are_ignored() {
        let (_a, owner) = service();
        let (_b, node) = service();
        owner_linked(&owner);
        join(&owner, &node, "vps-prod", "member_node");
        let id = ItemId::new();
        put_item(&owner, &id, "deploy key");
        let request = node
            .cloud_request_share_authorized(&agent(), "migrate the prod database", Some("prod db"))
            .unwrap();
        let outbox = node.cloud_outbox().unwrap();
        assert_eq!(owner.cloud_apply_inbox(&outbox).unwrap().applied, 1);
        let replay = owner.cloud_apply_inbox(&outbox).unwrap();
        assert_eq!(replay.applied, 0);
        assert_eq!(replay.acknowledged.len(), 1);
        let pending = owner.cloud_requests().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].purpose, "migrate the prod database");
        assert_eq!(pending[0].node_name.as_deref(), Some("vps-prod"));
        assert!(
            owner
                .cloud_request_share_authorized(&agent(), "x", None)
                .is_err()
        );

        owner
            .cloud_approve_request(&request.request_id, &id, Some(Duration::hours(1)))
            .unwrap();
        assert!(
            owner.cloud_deny_request(&request.request_id).is_err(),
            "decided once"
        );
        owner.cloud_publish_shares().unwrap();
        assert_eq!(
            deliver(&owner, &node).applied,
            2,
            "the decision and the share"
        );
        assert_eq!(items(&node)[0].title, "deploy key");
        let node_view = node.cloud_requests().unwrap();
        assert_eq!(node_view[0].status, RequestStatus::Approved);
    }

    #[test]
    fn a_dead_nodes_backup_is_restored_to_a_new_node() {
        let (_a, owner) = service();
        let (_b, node) = service();
        owner_linked(&owner);
        join(&owner, &node, "vps-prod", "member_node");
        let id = ItemId::new();
        put_item(&node, &id, "node-made db password");
        let pending = node.cloud_backup_batch(100).unwrap();
        assert_eq!(pending.len(), 1);
        for backup in &pending {
            node.cloud_backup_stored(backup).unwrap();
        }
        assert!(
            node.cloud_backup_batch(100).unwrap().is_empty(),
            "unchanged"
        );
        let backups: Vec<RelayBackup> = pending.into_iter().map(|p| p.backup).collect();

        let (_c, replacement) = service();
        join(&owner, &replacement, "vps-new", "member_new");
        assert_eq!(
            owner
                .cloud_restore("member_node", Some("vps-new"), &backups)
                .unwrap(),
            1
        );
        deliver(&owner, &replacement);
        let restored = items(&replacement);
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].title, "node-made db password");
        assert_eq!(restored[0].group_id.0, RESTORED_GROUP);
        assert!(!restored[0].extensions.contains_key(SHARE_EXTENSION));
        // The restored item is the new node's own: it backs it up.
        assert_eq!(replacement.cloud_backup_batch(100).unwrap().len(), 1);

        // A deletion becomes a tombstone.
        node.with_vault(|vault| {
            node.store.delete_item(
                vault,
                &id,
                1,
                MutationContext {
                    actor: "test",
                    idempotency_key: "delete",
                    request_material: b"d",
                    audit_event: None,
                },
            )
        })
        .unwrap();
        let tombstones = node.cloud_backup_batch(100).unwrap();
        assert_eq!(tombstones.len(), 1);
        assert!(tombstones[0].backup.deleted);
        assert_eq!(tombstones[0].backup.revision, 2);
    }

    #[test]
    fn a_recovery_kit_restores_the_owner_keys_items_and_nodes() {
        let (_a, owner) = service();
        let (_n, node) = service();
        let setup = owner_linked(&owner);
        join(&owner, &node, "vps-prod", "member_node");
        put_item(&owner, &ItemId::new(), "personal email");
        let backups: Vec<RelayBackup> = owner
            .cloud_backup_batch(100)
            .unwrap()
            .into_iter()
            .map(|p| p.backup)
            .collect();
        assert!(backups.iter().any(|b| b.object_id == "node-member_node"));

        let (_b, recovered) = service();
        let account = setup.request.account_id.clone();
        assert!(
            recovered
                .cloud_recover(
                    "https://cloud.example",
                    &account,
                    "member_owner",
                    &setup.request.recovery_kit,
                    "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG",
                    "new laptop",
                )
                .is_err()
        );
        let link = recovered
            .cloud_recover(
                "https://cloud.example",
                &account,
                "member_owner",
                &setup.request.recovery_kit,
                &setup.recovery_code.to_lowercase(),
                "new laptop",
            )
            .unwrap();
        assert_eq!(
            link.fingerprint(),
            owner.cloud_link().unwrap().unwrap().fingerprint()
        );
        assert_eq!(
            relay_digest(
                &derive_recovery_keys(&setup.recovery_code, &account)
                    .unwrap()
                    .lookup
            ),
            setup.request.recovery_lookup_hash
        );
        assert_eq!(
            recovered
                .cloud_restore("member_owner", None, &backups)
                .unwrap(),
            1
        );
        assert_eq!(items(&recovered)[0].title, "personal email");
        assert_eq!(
            recovered.cloud_nodes().unwrap().len(),
            1,
            "the verified node is back"
        );
    }

    #[test]
    fn a_tampered_backup_or_message_is_rejected() {
        let (_a, owner) = service();
        let (_b, node) = service();
        owner_linked(&owner);
        join(&owner, &node, "vps-prod", "member_node");
        put_item(&node, &ItemId::new(), "x");
        let mut backups: Vec<RelayBackup> = node
            .cloud_backup_batch(100)
            .unwrap()
            .into_iter()
            .map(|p| p.backup)
            .collect();
        backups[0].revision += 1;
        assert!(owner.cloud_restore("member_node", None, &backups).is_err());

        let id = ItemId::new();
        put_item(&owner, &id, "z");
        owner
            .cloud_share(ShareScope::Item { item_id: id }, "vps-prod", None, None)
            .unwrap();
        owner.cloud_publish_shares().unwrap();
        let mut outbox = owner.cloud_outbox().unwrap();
        outbox[0].object_id = "item_other".into();
        let outcome = node.cloud_apply_inbox(&outbox).unwrap();
        assert_eq!(outcome.applied, 0);
        assert_eq!(outcome.rejected.len(), 1);
        assert_eq!(outcome.acknowledged.len(), 1);
        assert_eq!(items(&node).len(), 1, "only the node's own item");
    }
}
