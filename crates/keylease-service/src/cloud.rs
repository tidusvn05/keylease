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

/// Owner: what one item of a share was last published as. Message
/// revisions follow the clock (and only grow), so they keep growing after the
/// owner recovers on a new device and the node's high-water mark still works.
#[derive(Serialize, Deserialize)]
struct PublishedRecord {
    item_revision: u64,
    message_revision: u64,
}

fn next_message_revision(previous: u64) -> u64 {
    (Utc::now().timestamp_millis().max(0) as u64).max(previous + 1)
}

/// Node: an item received through a share. It outlives an unshare
/// (`closed`), so a replayed or reordered older share cannot bring the item
/// back: only a message revision above `owner_revision` applies.
#[derive(Serialize, Deserialize)]
struct ReceivedRecord {
    local_item_id: ItemId,
    owner_revision: u64,
    #[serde(default)]
    closed: bool,
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
    Item {
        item: Box<VaultItem>,
    },
    Project {
        project: VaultProject,
    },
    Node {
        node: CloudNode,
    },
    Share {
        share: CloudShare,
    },
    /// Every live object and its revision, signed with the rest: a relay that
    /// serves an older revision, drops an object or hides a deletion is
    /// caught on restore.
    Manifest {
        entries: std::collections::BTreeMap<String, u64>,
        as_of: DateTime<Utc>,
    },
}

const MANIFEST_ID: &str = "manifest";

/// What a restore did.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RestoreReport {
    pub restored: usize,
    /// When the backup's manifest was written (None: no manifest found).
    pub as_of: Option<DateTime<Utc>>,
    /// Objects the manifest lists that the cloud did not return at that
    /// revision.
    pub missing: Vec<String>,
    /// Objects the cloud returned that the manifest does not list.
    pub ignored: usize,
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
/// An id from another member: letters, digits, `_` and `-`, at most 128.
fn valid_wire_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
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
        if link.role != CloudRole::Owner
            || link.account_id != created.account_id
            || created.owner_member_id != link.keys().member_id()
        {
            return Err(invalid("the cloud answered for another account or key"));
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
                &link
                    .keys()
                    .tag_material(&link.account_id, name.trim(), RelayRole::Owner),
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
                .tag_material(&invite.account_id, &invite.name, RelayRole::Owner),
        );
        if !tags_match(&expected, &invite.owner_tag_b64)
            || invite.owner_member_id != invite.owner.member_id()
        {
            return Err(KeyLeaseError::Denied {
                reason: "the invite does not match the code: the cloud may have altered the owner's keys".into(),
            });
        }
        self.with_vault(|vault| {
            let keys = Keys::generate();
            let public = keys.public();
            let node_tag = invite_tag(
                secret,
                &public.tag_material(&invite.account_id, &invite.name, RelayRole::Node),
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
        if link.role != CloudRole::Node
            || link.account_id != joined.account_id
            || joined.member_id != link.keys().member_id()
        {
            return Err(invalid("the cloud answered for another account or key"));
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
            let owner_member_id = public.member_id();
            let owner_member_id = owner_member_id.as_str();
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
            received_items: self
                .store
                .cloud_list(record::RECEIVED, "")?
                .into_iter()
                .filter(|(_, json)| from_json::<ReceivedRecord>(json).is_ok_and(|r| !r.closed))
                .count(),
            backed_up_objects: self
                .store
                .cloud_list(record::BACKUP, "")?
                .iter()
                .filter(|(id, _)| id != MANIFEST_ID)
                .count(),
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
                    let node: CloudNode = from_json(&json)?;
                    if node.sign_public_b64 != member.keys.sign_public_b64
                        || node.box_public_b64 != member.keys.box_public_b64
                    {
                        problems.push(format!(
                            "{} ({}) now shows different keys; it is not trusted",
                            node.name, node.member_id
                        ));
                        continue;
                    }
                    // Removal is decided here (cloud_remove_node), never by
                    // what the cloud reports.
                    continue;
                }
                if member.member_id != member.keys.member_id() {
                    problems.push(format!(
                        "{}: its member id does not match its key; it is not trusted",
                        member.member_id
                    ));
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
                // The name comes from this device's invite, not from the
                // cloud, and the tag covers it.
                let expected = invite_tag(
                    &secret,
                    &member
                        .keys
                        .tag_material(&link.account_id, &invite.name, RelayRole::Node),
                );
                if !tags_match(&expected, tag) {
                    // Kept: a bogus entry must not burn the real node's invite.
                    problems.push(format!(
                        "{} registered keys that do not match the invite for {}; it is not trusted",
                        member.member_id, invite.name
                    ));
                    continue;
                }
                self.store.cloud_delete(record::INVITE, lookup_hash)?;
                let node = CloudNode {
                    member_id: member.member_id.clone(),
                    name: invite.name.clone(),
                    sign_public_b64: member.keys.sign_public_b64.clone(),
                    box_public_b64: member.keys.box_public_b64.clone(),
                    fingerprint: member.keys.fingerprint(),
                    verified_at: Utc::now(),
                    removed_at: None,
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
                if from_json::<InviteRecord>(&json)?.expires_at < Utc::now() - Duration::days(7) {
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
        let message_id = new_id("msg");
        let label = RelayPayloadLabel {
            message_id: &message_id,
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
            message_id: message_id.clone(),
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
                for (key, json) in &published {
                    let item_id = key.trim_start_matches(&prefix);
                    if wanted.iter().any(|item| item.id.0 == item_id) {
                        continue;
                    }
                    if node.removed_at.is_none() {
                        let previous: PublishedRecord = from_json(json)?;
                        let revision = next_message_revision(previous.message_revision);
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
                    let previous: Option<PublishedRecord> = self
                        .store
                        .cloud_get(record::SHARE_ITEM, &key)?
                        .map(|json| from_json(&json))
                        .transpose()?;
                    if previous
                        .as_ref()
                        .is_some_and(|p| p.item_revision == item.revision)
                    {
                        continue;
                    }
                    let revision =
                        next_message_revision(previous.map_or(0, |p| p.message_revision));
                    let mut copy = item.clone();
                    // The node decides its own agents' access.
                    copy.agent_access = AgentAccess::default();
                    self.queue_message(
                        &link,
                        &keys,
                        &node.member_id,
                        &node.box_public_b64,
                        kind::SHARE,
                        &item.id.0,
                        revision,
                        &MessagePayload::Share {
                            share_id: share.share_id.clone(),
                            item: Box::new(copy),
                            expires_at: share.expires_at,
                        },
                    )?;
                    self.store.cloud_put(
                        record::SHARE_ITEM,
                        &key,
                        &to_json(&PublishedRecord {
                            item_revision: item.revision,
                            message_revision: revision,
                        })?,
                    )?;
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
                    // Passing conditions (a locked vault, a node not verified
                    // yet): leave the message in the mailbox for a later sync.
                    Err(KeyLeaseError::VaultLocked { .. })
                    | Err(KeyLeaseError::Storage)
                    | Err(KeyLeaseError::NotFound { .. }) => continue,
                    Err(error) => outcome.rejected.push(format!(
                        "{} {}: {error:?}",
                        message.kind, message.message_id
                    )),
                }
                // Applied ids are kept: the message id is signed, so a replay
                // under the same id is recognized however late it comes.
                self.store.cloud_put(
                    record::APPLIED,
                    &message.message_id,
                    &to_json(&Utc::now())?,
                )?;
                outcome.acknowledged.push(message.message_id.clone());
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
                        .ok_or_else(|| KeyLeaseError::NotFound {
                            resource: format!("verified node {}", message.from_member_id),
                        })?,
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
            ) if item.id.0 == message.object_id => self.receive_shared_item(
                vault,
                link,
                &share_id,
                *item,
                message.revision,
                expires_at,
            ),
            (CloudRole::Node, kind::UNSHARE, MessagePayload::Unshare { share_id, item_id })
                if item_id.0 == message.object_id =>
            {
                self.drop_shared_item(vault, &share_id, &item_id, message.revision)
            }
            (CloudRole::Node, kind::RESTORE, MessagePayload::Restore { item })
                if item.id.0 == message.object_id =>
            {
                self.import_restored_item(vault, *item, false)
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
                // Everything here was written by the node: bound and plain.
                validate_purpose(&purpose)?;
                if let Some(hint) = &hint {
                    validate_purpose(hint)?;
                }
                if !valid_wire_id(&agent_id) || !valid_wire_id(&request_id) {
                    return Err(invalid("malformed share request"));
                }
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
        message_revision: u64,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        let key = format!("{share_id}/{}", owner_item.id.0);
        let existing: Option<ReceivedRecord> = self
            .store
            .cloud_get(record::RECEIVED, &key)?
            .map(|json| from_json(&json))
            .transpose()?;
        // Only a newer message applies: an old or reordered share (also one
        // from before an unshare) is ignored.
        if existing
            .as_ref()
            .is_some_and(|e| e.owner_revision >= message_revision)
        {
            return Ok(());
        }
        let current = match &existing {
            Some(record) if !record.closed => {
                self.store.get_item(vault, &record.local_item_id).ok()
            }
            _ => None,
        };
        let local_id = current
            .as_ref()
            .map(|item| item.id.clone())
            .unwrap_or_default();
        let base_revision = current.as_ref().map_or(0, |item| item.revision);
        let mut item = owner_item.clone();
        item.id = local_id.clone();
        item.vault_id = vault.vault_id.clone();
        item.group_id = GroupId(SHARED_GROUP.into());
        item.project_id = None;
        item.agent_access = AgentAccess::default();
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
                "owner_revision": message_revision,
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
                idempotency_key: &format!("cloud-share-{key}-{message_revision}"),
                request_material: format!("cloud-share:{key}:{message_revision}").as_bytes(),
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
                owner_revision: message_revision,
                closed: false,
            })?,
        )
    }

    fn drop_shared_item(
        &self,
        vault: &keylease_store::UnlockedVault,
        share_id: &str,
        owner_item_id: &ItemId,
        message_revision: u64,
    ) -> Result<()> {
        let key = format!("{share_id}/{}", owner_item_id.0);
        let existing: Option<ReceivedRecord> = self
            .store
            .cloud_get(record::RECEIVED, &key)?
            .map(|json| from_json(&json))
            .transpose()?;
        // An unshare older than the copy we hold (reordered by the relay) is
        // stale: the owner shared the item again after it.
        if existing
            .as_ref()
            .is_some_and(|e| e.owner_revision > message_revision)
        {
            return Ok(());
        }
        if let Some(record) = existing.as_ref().filter(|r| !r.closed) {
            self.delete_received_copy(vault, share_id, &key, &record.local_item_id)?;
        }
        // The closed record is the high-water mark against replays.
        self.store.cloud_put(
            record::RECEIVED,
            &key,
            &to_json(&ReceivedRecord {
                local_item_id: existing
                    .map(|r| r.local_item_id)
                    .unwrap_or_else(|| ItemId(String::new())),
                owner_revision: message_revision,
                closed: true,
            })?,
        )
    }

    fn delete_received_copy(
        &self,
        vault: &keylease_store::UnlockedVault,
        share_id: &str,
        key: &str,
        local_item_id: &ItemId,
    ) -> Result<()> {
        if let Ok(item) = self.store.get_item(vault, local_item_id) {
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
        Ok(())
    }

    /// Node: drops shared items whose share expired, even if the owner's
    /// revocation has not arrived.
    fn expire_received(&self, vault: &keylease_store::UnlockedVault) -> Result<()> {
        for (key, json) in self.store.cloud_list(record::RECEIVED, "")? {
            let mut record: ReceivedRecord = from_json(&json)?;
            if record.closed {
                continue;
            }
            let expired = match self.store.get_item(vault, &record.local_item_id) {
                Ok(item) => item
                    .extensions
                    .get(SHARE_EXTENSION)
                    .and_then(|share| share.get("expires_at"))
                    .and_then(|at| serde_json::from_value::<Option<DateTime<Utc>>>(at.clone()).ok())
                    .flatten()
                    .is_some_and(|at| at <= Utc::now()),
                Err(_) => true,
            };
            if expired && let Some((share_id, _)) = key.split_once('/') {
                self.delete_received_copy(vault, share_id, &key, &record.local_item_id)?;
                record.closed = true;
                self.store
                    .cloud_put(record::RECEIVED, &key, &to_json(&record)?)?;
            }
        }
        Ok(())
    }

    /// Imports a backed-up item as this vault's own. `keep_project` (an
    /// owner restoring its own backup, projects included) keeps the item's
    /// project when that project exists here.
    fn import_restored_item(
        &self,
        vault: &keylease_store::UnlockedVault,
        backup_item: VaultItem,
        keep_project: bool,
    ) -> Result<()> {
        let mut item = backup_item;
        let source = item.id.clone();
        if self.store.get_item(vault, &source).is_ok() {
            // Restored once already (the same item id).
            return Ok(());
        }
        item.vault_id = vault.vault_id.clone();
        item.group_id = GroupId(RESTORED_GROUP.into());
        if !(keep_project
            && item
                .project_id
                .as_ref()
                .is_some_and(|id| self.store.get_project(vault, id).is_ok()))
        {
            item.project_id = None;
        }
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
    /// to the owner: items (not shared-in copies), projects, deletions, on the
    /// owner its verified nodes and shares, and, once those are stored, the
    /// manifest. Call it until it returns nothing.
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
            for project in self.store.list_projects(vault)? {
                objects.push((
                    format!("project-{}", project.id.0),
                    BackupPayload::Project { project },
                    None,
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
                if let Some(pending) =
                    self.backup_if_changed(&link, &keys, &object_id, &payload, item_revision)?
                {
                    out.push(pending);
                }
            }
            for (object_id, json) in self.store.cloud_list(record::BACKUP, "")? {
                if out.len() >= limit {
                    break;
                }
                if present.contains(&object_id) || object_id == MANIFEST_ID {
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
            if out.is_empty() {
                // Everything is stored: the manifest lists what the cloud has.
                let entries = self
                    .store
                    .cloud_list(record::BACKUP, "")?
                    .into_iter()
                    .filter(|(id, _)| id != MANIFEST_ID)
                    .map(|(id, json)| Ok((id, from_json::<BackupState>(&json)?.revision)))
                    .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
                let manifest = BackupPayload::Manifest {
                    entries: entries.clone(),
                    as_of: Utc::now(),
                };
                let entries_digest = relay_digest(
                    &serde_json::to_vec(&entries).map_err(|_| KeyLeaseError::Storage)?,
                );
                let previous: Option<BackupState> = self
                    .store
                    .cloud_get(record::BACKUP, MANIFEST_ID)?
                    .map(|json| from_json(&json))
                    .transpose()?;
                if previous.as_ref().is_none_or(|p| p.digest != entries_digest) {
                    let plain = Zeroizing::new(
                        serde_json::to_vec(&manifest).map_err(|_| KeyLeaseError::Storage)?,
                    );
                    let revision = previous.map_or(0, |p| p.revision) + 1;
                    out.push(PendingBackup {
                        backup: self.seal_backup(
                            &link,
                            &keys,
                            MANIFEST_ID,
                            revision,
                            Some(&plain),
                        )?,
                        digest: entries_digest,
                    });
                }
            }
            Ok(out)
        })
    }

    fn backup_if_changed(
        &self,
        link: &CloudLink,
        keys: &Keys,
        object_id: &str,
        payload: &BackupPayload,
        item_revision: Option<u64>,
    ) -> Result<Option<PendingBackup>> {
        let plain =
            Zeroizing::new(serde_json::to_vec(payload).map_err(|_| KeyLeaseError::Storage)?);
        let digest = relay_digest(&plain);
        let previous: Option<BackupState> = self
            .store
            .cloud_get(record::BACKUP, object_id)?
            .map(|json| from_json(&json))
            .transpose()?;
        if previous.as_ref().is_some_and(|p| p.digest == digest) {
            return Ok(None);
        }
        let revision = item_revision
            .unwrap_or(0)
            .max(previous.as_ref().map_or(0, |p| p.revision) + 1);
        Ok(Some(PendingBackup {
            backup: self.seal_backup(link, keys, object_id, revision, Some(&plain))?,
            digest,
        }))
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

    /// The cloud already holds `revision` (or newer) of an object, for
    /// example after a recovery: the next batch continues above it.
    pub fn cloud_backup_rebase(&self, object_id: &str, revision: u64) -> Result<()> {
        self.store.cloud_put(
            record::BACKUP,
            object_id,
            &to_json(&BackupState {
                revision,
                digest: String::new(),
            })?,
        )
    }

    /// Owner: opens the backups of `from` (a node, or this owner), checking
    /// each signature, that each payload is the object it claims to be, and
    /// the set against the signed manifest.
    fn open_backups(
        &self,
        link: &CloudLink,
        keys: &Keys,
        from_member_id: &str,
        backups: &[RelayBackup],
    ) -> Result<(Vec<BackupPayload>, RestoreReport)> {
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
        let mut opened = Vec::new();
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
            let payload: BackupPayload =
                serde_json::from_slice(&plain).map_err(|_| KeyLeaseError::Crypto)?;
            let claimed = match &payload {
                BackupPayload::Item { item } => item.id.0.clone(),
                BackupPayload::Project { project } => format!("project-{}", project.id.0),
                BackupPayload::Node { node } => format!("node-{}", node.member_id),
                BackupPayload::Share { share } => format!("share-{}", share.share_id),
                BackupPayload::Manifest { .. } => MANIFEST_ID.into(),
            };
            if claimed != backup.object_id {
                return Err(invalid("a backup holds another object than it is labelled"));
            }
            opened.push((backup.object_id.clone(), backup.revision, payload));
        }
        let mut report = RestoreReport::default();
        let manifest = opened.iter().find_map(|(_, _, payload)| match payload {
            BackupPayload::Manifest { entries, as_of } => Some((entries.clone(), *as_of)),
            _ => None,
        });
        let mut out = Vec::new();
        match manifest {
            Some((entries, as_of)) => {
                report.as_of = Some(as_of);
                for (object_id, revision) in &entries {
                    if !opened
                        .iter()
                        .any(|(id, rev, _)| id == object_id && rev == revision)
                    {
                        report.missing.push(object_id.clone());
                    }
                }
                for (object_id, revision, payload) in opened {
                    if matches!(payload, BackupPayload::Manifest { .. }) {
                        continue;
                    }
                    if entries.get(&object_id) == Some(&revision) {
                        out.push(payload);
                    } else {
                        report.ignored += 1;
                    }
                }
            }
            None => out.extend(
                opened
                    .into_iter()
                    .map(|(_, _, payload)| payload)
                    .filter(|payload| !matches!(payload, BackupPayload::Manifest { .. })),
            ),
        }
        Ok((out, report))
    }

    /// Owner: restores the backups of `from` to the node `to` (as restore
    /// messages) or, when `to` is `None`, into this vault. On a recovered
    /// owner, restoring its own backups also brings back its projects, nodes
    /// and shares, and later backups continue above the cloud's revisions.
    pub fn cloud_restore(
        &self,
        from_member_id: &str,
        to_node: Option<&str>,
        backups: &[RelayBackup],
    ) -> Result<RestoreReport> {
        let link = self.require_owner()?;
        let target = to_node.map(|node| self.find_node(node)).transpose()?;
        if let Some(target) = &target
            && target.removed_at.is_some()
        {
            return Err(invalid("cannot restore to a removed node"));
        }
        let own = from_member_id == link.member_id;
        self.with_vault(|vault| {
            let keys = self.load_keys(vault)?;
            let (mut payloads, mut report) =
                self.open_backups(&link, &keys, from_member_id, backups)?;
            // Projects first, so restored items can keep theirs.
            payloads.sort_by_key(|payload| !matches!(payload, BackupPayload::Project { .. }));
            for payload in payloads {
                match (payload, &target) {
                    (BackupPayload::Item { item }, Some(node)) => {
                        let object = item.id.0.clone();
                        let mut item = item;
                        item.project_id = None;
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
                        report.restored += 1;
                    }
                    (BackupPayload::Item { item }, None) => {
                        self.import_restored_item(vault, *item, own)?;
                        report.restored += 1;
                    }
                    (BackupPayload::Project { mut project }, None) if own => {
                        if self.store.get_project(vault, &project.id).is_err() {
                            project.vault_id = vault.vault_id.clone();
                            project.revision = 1;
                            self.store.put_project(
                                vault,
                                &project,
                                Some(0),
                                MutationContext {
                                    actor: "cloud",
                                    idempotency_key: &format!("cloud-restore-{}", project.id.0),
                                    request_material: project.id.0.as_bytes(),
                                    audit_event: None,
                                },
                            )?;
                        }
                    }
                    (BackupPayload::Node { node }, None) if own => {
                        self.store
                            .cloud_insert(record::NODE, &node.member_id, &to_json(&node)?)?;
                    }
                    (BackupPayload::Share { share }, None) if own => {
                        self.store.cloud_insert(
                            record::SHARE,
                            &share.share_id,
                            &to_json(&share)?,
                        )?;
                    }
                    _ => {}
                }
            }
            if own {
                for backup in backups {
                    self.cloud_backup_rebase(&backup.object_id, backup.revision)?;
                }
            }
            self.cloud_audit(
                "cloud:restore",
                &format!("kl://cloud/members/{from_member_id}"),
                &format!(
                    "{} items to {}; {} missing",
                    report.restored,
                    target
                        .as_ref()
                        .map_or("this vault", |t| t.member_id.as_str()),
                    report.missing.len()
                ),
            )?;
            Ok(report)
        })
    }

    /// Whether `member_id` is a node this owner removed (its messages can be
    /// dropped when the cloud no longer knows it).
    pub fn cloud_recipient_removed(&self, member_id: &str) -> Result<bool> {
        Ok(self
            .store
            .cloud_get(record::NODE, member_id)?
            .map(|json| from_json::<CloudNode>(&json))
            .transpose()?
            .is_some_and(|node| node.removed_at.is_some()))
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
                    project_id: current.as_ref().and_then(|c| c.project_id.clone()),
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

    fn titles(service: &KeyLeaseService) -> Vec<String> {
        let mut titles: Vec<String> = items(service).into_iter().map(|i| i.title).collect();
        titles.sort();
        titles
    }

    fn owner_linked(owner: &KeyLeaseService) -> OwnerSetup {
        let setup = owner
            .cloud_owner_prepare("https://cloud.example", "laptop")
            .unwrap();
        owner
            .cloud_owner_commit(&RelayAccountCreated {
                account_id: setup.request.account_id.clone(),
                owner_member_id: setup.request.owner.member_id(),
            })
            .unwrap();
        setup
    }

    /// Plays the cloud's part of pairing: hands the invite to the node and the
    /// node's registration back to the owner. Returns the node's member id.
    fn join(owner: &KeyLeaseService, node: &KeyLeaseService, name: &str) -> String {
        let (member, _) = join_member(owner, node, name);
        let problems = owner
            .cloud_verify_members(std::slice::from_ref(&member))
            .unwrap();
        assert!(problems.is_empty(), "{problems:?}");
        member.member_id
    }

    fn join_member(
        owner: &KeyLeaseService,
        node: &KeyLeaseService,
        name: &str,
    ) -> (RelayMember, InviteSetup) {
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
        let member_id = join.keys.member_id();
        node.cloud_node_commit(&RelayJoined {
            account_id: link.account_id.clone(),
            member_id: member_id.clone(),
        })
        .unwrap();
        (
            RelayMember {
                member_id,
                role: RelayRole::Node,
                name: name.into(),
                keys: join.keys,
                node_tag_b64: Some(join.node_tag_b64),
                invite_lookup_hash: Some(invite.request.lookup_hash.clone()),
                created_at: Utc::now(),
                revoked_at: None,
            },
            invite,
        )
    }

    fn take_outbox(from: &KeyLeaseService) -> Vec<RelayEnvelope> {
        let outbox = from.cloud_outbox().unwrap();
        for message in &outbox {
            from.cloud_outbox_sent(&message.message_id).unwrap();
        }
        outbox
    }

    fn deliver(from: &KeyLeaseService, to: &KeyLeaseService) -> InboxOutcome {
        to.cloud_apply_inbox(&take_outbox(from)).unwrap()
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

    fn backups(service: &KeyLeaseService) -> Vec<RelayBackup> {
        let mut all = Vec::new();
        loop {
            let batch = service.cloud_backup_batch(100).unwrap();
            if batch.is_empty() {
                return all;
            }
            for pending in batch {
                service.cloud_backup_stored(&pending).unwrap();
                all.retain(|b: &RelayBackup| b.object_id != pending.backup.object_id);
                all.push(pending.backup);
            }
        }
    }

    #[test]
    fn an_altered_owner_key_node_key_or_member_id_is_detected_at_pairing() {
        let (_a, owner) = service();
        let (_b, node) = service();
        let setup = owner_linked(&owner);
        let invite = owner.cloud_create_invite("vps").unwrap();
        let attacker = Keys::generate().public();
        let forged = RelayInvite {
            account_id: setup.request.account_id.clone(),
            owner_member_id: attacker.member_id(),
            owner: attacker,
            name: "vps".into(),
            owner_tag_b64: invite.request.owner_tag_b64.clone(),
            expires_at: invite.request.expires_at,
        };
        assert!(matches!(
            node.cloud_node_prepare("https://cloud.example", &invite.code, &forged),
            Err(KeyLeaseError::Denied { .. })
        ));
        let bogus_keys = Keys::generate().public();
        let problems = owner
            .cloud_verify_members(&[RelayMember {
                member_id: bogus_keys.member_id(),
                role: RelayRole::Node,
                name: "vps".into(),
                keys: bogus_keys,
                node_tag_b64: Some(b64(&[7_u8; 32])),
                invite_lookup_hash: Some(invite.request.lookup_hash.clone()),
                created_at: Utc::now(),
                revoked_at: None,
            }])
            .unwrap();
        assert_eq!(problems.len(), 1);
        assert!(owner.cloud_nodes().unwrap().is_empty());
        // The bogus entry did not burn the real node's invite.
        let link = owner.cloud_link().unwrap().unwrap();
        let join = node
            .cloud_node_prepare(
                "https://cloud.example",
                &invite.code,
                &RelayInvite {
                    account_id: link.account_id.clone(),
                    owner_member_id: link.member_id.clone(),
                    owner: link.keys(),
                    name: "vps".into(),
                    owner_tag_b64: invite.request.owner_tag_b64.clone(),
                    expires_at: invite.request.expires_at,
                },
            )
            .unwrap();
        let mut member = RelayMember {
            member_id: "member_chosen_by_the_cloud".into(),
            role: RelayRole::Node,
            name: "vps".into(),
            keys: join.keys.clone(),
            node_tag_b64: Some(join.node_tag_b64.clone()),
            invite_lookup_hash: Some(invite.request.lookup_hash.clone()),
            created_at: Utc::now(),
            revoked_at: None,
        };
        assert_eq!(
            owner.cloud_verify_members(&[member.clone()]).unwrap().len(),
            1
        );
        member.member_id = join.keys.member_id();
        assert!(owner.cloud_verify_members(&[member]).unwrap().is_empty());
        assert_eq!(owner.cloud_nodes().unwrap().len(), 1);
    }

    #[test]
    fn a_cloud_that_swaps_node_names_cannot_redirect_a_share() {
        let (_a, owner) = service();
        let (_b, prod) = service();
        let (_c, scratch) = service();
        owner_linked(&owner);
        let (mut prod_member, _) = join_member(&owner, &prod, "prod-db");
        let (mut scratch_member, _) = join_member(&owner, &scratch, "scratch");
        prod_member.name = "scratch".into();
        scratch_member.name = "prod-db".into();
        assert!(
            owner
                .cloud_verify_members(&[prod_member.clone(), scratch_member.clone()])
                .unwrap()
                .is_empty()
        );
        // Names come from this device's invites, not from the cloud.
        let nodes = owner.cloud_nodes().unwrap();
        let named = |name: &str| {
            nodes
                .iter()
                .find(|n| n.name == name)
                .unwrap()
                .member_id
                .clone()
        };
        assert_eq!(named("prod-db"), prod_member.member_id);
        assert_eq!(named("scratch"), scratch_member.member_id);
    }

    #[test]
    fn an_item_share_reaches_the_node_updates_and_is_revoked() {
        let (_a, owner) = service();
        let (_b, node) = service();
        owner_linked(&owner);
        join(&owner, &node, "vps-prod");
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
        assert_eq!(received[0].group_id.0, SHARED_GROUP);
        assert!(received[0].extensions.contains_key(SHARE_EXTENSION));
        assert!(
            backups(&node).iter().all(|b| b.object_id == MANIFEST_ID),
            "shared copies are not backed up by the node"
        );
        // Shared copies are read-only on the node.
        assert!(matches!(
            refuse_shared_copy(&received[0]),
            Err(KeyLeaseError::Denied { .. })
        ));

        put_item(&owner, &id, "prod db (rotated)");
        assert_eq!(owner.cloud_publish_shares().unwrap(), 1);
        deliver(&owner, &node);
        assert_eq!(titles(&node), vec!["prod db (rotated)"]);

        owner.cloud_revoke_share(&share.share_id).unwrap();
        assert_eq!(owner.cloud_publish_shares().unwrap(), 1);
        deliver(&owner, &node);
        assert!(items(&node).is_empty());
    }

    #[test]
    fn replayed_or_reordered_messages_cannot_undo_a_revocation() {
        let (_a, owner) = service();
        let (_b, node) = service();
        owner_linked(&owner);
        join(&owner, &node, "vps-prod");
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
        owner.cloud_publish_shares().unwrap();
        let share_message = take_outbox(&owner);
        node.cloud_apply_inbox(&share_message).unwrap();
        owner.cloud_revoke_share(&share.share_id).unwrap();
        owner.cloud_publish_shares().unwrap();
        let unshare = take_outbox(&owner);
        node.cloud_apply_inbox(&unshare).unwrap();
        assert!(items(&node).is_empty());

        // The cloud re-sends the old share under a new id: the signature
        // covers the id.
        let mut renamed = share_message.clone();
        renamed[0].message_id = "msg_replayed".into();
        let outcome = node.cloud_apply_inbox(&renamed).unwrap();
        assert_eq!(outcome.applied, 0);
        assert_eq!(outcome.rejected.len(), 1);
        // The same id again is recognized.
        assert_eq!(node.cloud_apply_inbox(&share_message).unwrap().applied, 0);
        assert!(items(&node).is_empty());

        // Reordered: the unshare arrives before the share it ends.
        let (_c, other) = service();
        join(&owner, &other, "vps-two");
        let id2 = ItemId::new();
        put_item(&owner, &id2, "api key");
        let share2 = owner
            .cloud_share(ShareScope::Item { item_id: id2 }, "vps-two", None, None)
            .unwrap();
        owner.cloud_publish_shares().unwrap();
        let first = take_outbox(&owner);
        owner.cloud_revoke_share(&share2.share_id).unwrap();
        owner.cloud_publish_shares().unwrap();
        let second = take_outbox(&owner);
        other.cloud_apply_inbox(&second).unwrap();
        other.cloud_apply_inbox(&first).unwrap();
        assert!(
            items(&other).is_empty(),
            "a share older than its unshare is ignored"
        );
    }

    #[test]
    fn a_project_share_follows_items_into_and_out_of_the_project() {
        let (_a, owner) = service();
        let (_b, node) = service();
        owner_linked(&owner);
        join(&owner, &node, "vps-prod");
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
        let first = ItemId::new();
        put_item(&owner, &first, "api key");
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
        assert_eq!(
            titles(&node),
            vec!["db password"],
            "an item that left is withdrawn"
        );
        set_project(&first, Some(project.id.clone()));
        owner.cloud_publish_shares().unwrap();
        deliver(&owner, &node);
        assert_eq!(
            titles(&node),
            vec!["api key", "db password"],
            "and it can come back"
        );
    }

    #[test]
    fn a_node_request_is_decided_by_the_owner_and_replays_are_ignored() {
        let (_a, owner) = service();
        let (_b, node) = service();
        owner_linked(&owner);
        join(&owner, &node, "vps-prod");
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
        assert_eq!(titles(&node), vec!["deploy key"]);
        assert_eq!(
            node.cloud_requests().unwrap()[0].status,
            RequestStatus::Approved
        );
    }

    #[test]
    fn a_request_from_a_node_not_verified_yet_waits_in_the_mailbox() {
        let (_a, owner) = service();
        let (_b, node) = service();
        owner_linked(&owner);
        let (member, _) = join_member(&owner, &node, "vps-prod");
        node.cloud_request_share_authorized(&agent(), "deploy", None)
            .unwrap();
        let outbox = node.cloud_outbox().unwrap();
        let early = owner.cloud_apply_inbox(&outbox).unwrap();
        assert_eq!(early.applied, 0);
        assert!(early.acknowledged.is_empty(), "kept for a later sync");
        owner.cloud_verify_members(&[member]).unwrap();
        assert_eq!(owner.cloud_apply_inbox(&outbox).unwrap().applied, 1);
    }

    #[test]
    fn a_dead_nodes_backup_is_restored_to_a_new_node() {
        let (_a, owner) = service();
        let (_b, node) = service();
        owner_linked(&owner);
        let node_id = join(&owner, &node, "vps-prod");
        let id = ItemId::new();
        put_item(&node, &id, "node-made db password");
        let stored = backups(&node);
        assert_eq!(stored.len(), 2, "the item and the manifest");
        assert!(
            node.cloud_backup_batch(100).unwrap().is_empty(),
            "unchanged"
        );

        let (_c, replacement) = service();
        join(&owner, &replacement, "vps-new");
        let report = owner
            .cloud_restore(&node_id, Some("vps-new"), &stored)
            .unwrap();
        assert_eq!(report.restored, 1);
        assert!(report.as_of.is_some() && report.missing.is_empty());
        deliver(&owner, &replacement);
        let restored = items(&replacement);
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].title, "node-made db password");
        assert_eq!(restored[0].group_id.0, RESTORED_GROUP);
        assert!(!restored[0].extensions.contains_key(SHARE_EXTENSION));
        assert_eq!(backups(&replacement).len(), 2, "it is the new node's own");

        // A deletion becomes a tombstone and a new manifest.
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
        let tombstone = node.cloud_backup_batch(100).unwrap();
        assert_eq!(tombstone.len(), 1);
        assert!(tombstone[0].backup.deleted);
        assert_eq!(tombstone[0].backup.revision, 2);
    }

    #[test]
    fn the_manifest_catches_a_rolled_back_or_hidden_backup() {
        let (_a, owner) = service();
        let (_b, node) = service();
        owner_linked(&owner);
        let node_id = join(&owner, &node, "vps-prod");
        let first = ItemId::new();
        let second = ItemId::new();
        put_item(&node, &first, "one");
        put_item(&node, &second, "two");
        let old = backups(&node);
        let old_first = old.iter().find(|b| b.object_id == first.0).unwrap().clone();
        put_item(&node, &first, "one (rotated)");
        let mut current: Vec<RelayBackup> = old.clone();
        for backup in backups(&node) {
            current.retain(|b| b.object_id != backup.object_id);
            current.push(backup);
        }
        let complete = owner.cloud_restore(&node_id, None, &current).unwrap();
        assert_eq!(complete.restored, 2);
        assert!(complete.missing.is_empty());

        // The cloud serves the pre-rotation copy and hides the other item.
        let (_c, owner2) = service();
        let _ = owner2;
        let tampered: Vec<RelayBackup> = current
            .iter()
            .filter(|b| b.object_id != second.0)
            .map(|b| {
                if b.object_id == first.0 {
                    old_first.clone()
                } else {
                    b.clone()
                }
            })
            .collect();
        let report = owner
            .cloud_restore(&node_id, Some("vps-prod"), &tampered)
            .unwrap();
        assert_eq!(report.restored, 0);
        assert_eq!(report.ignored, 1, "the old revision is not the manifest's");
        assert_eq!(report.missing.len(), 2);
    }

    #[test]
    fn a_recovery_kit_restores_the_owner_keys_items_projects_and_nodes() {
        let (_a, owner) = service();
        let (_n, node) = service();
        let setup = owner_linked(&owner);
        let node_id = join(&owner, &node, "vps-prod");
        put_item(&owner, &ItemId::new(), "personal email");
        let stored = backups(&owner);
        assert!(
            stored
                .iter()
                .any(|b| b.object_id == format!("node-{node_id}"))
        );

        let (_b, recovered) = service();
        let account = setup.request.account_id.clone();
        assert!(
            recovered
                .cloud_recover(
                    "https://cloud.example",
                    &account,
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
                &setup.request.recovery_kit,
                &setup.recovery_code.to_lowercase(),
                "new laptop",
            )
            .unwrap();
        assert_eq!(link.member_id, setup.request.owner.member_id());
        assert_eq!(
            relay_digest(
                &derive_recovery_keys(&setup.recovery_code, &account)
                    .unwrap()
                    .lookup
            ),
            setup.request.recovery_lookup_hash
        );
        let report = recovered
            .cloud_restore(&link.member_id, None, &stored)
            .unwrap();
        assert_eq!(report.restored, 1);
        assert_eq!(titles(&recovered), vec!["personal email"]);
        assert_eq!(
            recovered.cloud_nodes().unwrap().len(),
            1,
            "the verified node is back"
        );
        // Later backups continue above what the cloud holds.
        let next = recovered.cloud_backup_batch(100).unwrap();
        for pending in &next {
            let previous = stored
                .iter()
                .find(|b| b.object_id == pending.backup.object_id);
            if let Some(previous) = previous {
                assert!(pending.backup.revision > previous.revision);
            }
        }
    }

    #[test]
    fn a_tampered_backup_or_message_is_rejected() {
        let (_a, owner) = service();
        let (_b, node) = service();
        owner_linked(&owner);
        let node_id = join(&owner, &node, "vps-prod");
        put_item(&node, &ItemId::new(), "x");
        let mut stored = backups(&node);
        stored[0].revision += 1;
        assert!(owner.cloud_restore(&node_id, None, &stored).is_err());

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
        assert_eq!(titles(&node), vec!["x"], "only the node's own item");
    }
}
