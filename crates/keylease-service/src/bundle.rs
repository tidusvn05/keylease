//! Offline transfer between nodes without a server: signed bundles encrypted
//! with [age](https://age-encryption.org).
//!
//! Every node has a **node ID**, an age X25519 recipient (`age1…`), and an
//! Ed25519 signing key. `export_bundle` encrypts selected items (and their
//! projects) to another node's ID and signs them; the result is ASCII-armored
//! text to paste or copy. `import_bundle` decrypts it with this node's age
//! identity, checks the signature, pins the sender's key on first use and
//! stores the items. Items imported read-only are updated by later bundles
//! from the same sender and cannot be edited locally; editable imports are
//! independent copies.
//!
//! The bundle is a standard age file: `age -d -i KEY` decrypts it, and the
//! plaintext is JSON (`keylease-bundle/v1`).

use super::*;
use age::secrecy::ExposeSecret;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub const BUNDLE_FORMAT: &str = "keylease-bundle/v1";
/// Extension on a read-only imported item: `{sender, origin_id, revision}`.
pub const BUNDLE_EXTENSION: &str = "keylease.bundle_origin";
const SIGNATURE_CONTEXT: &[u8] = b"keylease-bundle-v1\n";
const MAX_BUNDLE_ITEMS: usize = 1000;
const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;

mod record {
    pub const KIND: &str = "bundle";
    pub const IDENTITY: &str = "age_identity";
    pub const SIGNER: &str = "signing_key";
    pub const PEER: &str = "bundle_peer";
    pub const RECEIVED: &str = "bundle_received";
}

/// This node's public identity for bundles.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct NodeIdentity {
    /// The age recipient other nodes export to.
    pub node_id: String,
    /// Base64 Ed25519 public key that signs this node's bundles.
    pub signing_key: String,
    /// Short form of `signing_key` to compare out of band.
    pub fingerprint: String,
}

/// What to export: a whole project, or items by ID.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BundleSelection {
    #[serde(default)]
    pub project_slug: Option<String>,
    #[serde(default)]
    pub item_ids: Vec<ItemId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BundlePreview {
    pub sender_fingerprint: String,
    pub sender_name: Option<String>,
    /// Whether this node already trusts the sender's key.
    pub known_sender: bool,
    pub created_at: DateTime<Utc>,
    pub projects: Vec<String>,
    pub items: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BundleImportReport {
    pub sender_fingerprint: String,
    pub created: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub projects_created: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedBundle {
    format: String,
    /// The signed JSON text of `BundleBody`.
    body: String,
    signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleBody {
    bundle_id: String,
    created_at: DateTime<Utc>,
    sender: BundleSender,
    recipient: String,
    projects: Vec<BundleProject>,
    items: Vec<BundleItem>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleSender {
    node_id: String,
    signing_key: String,
    name: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleProject {
    slug: String,
    name: String,
    #[serde(default)]
    environments: Vec<ProjectEnvironment>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleItem {
    group_name: String,
    project_slug: Option<String>,
    item: VaultItem,
}

#[derive(Serialize, Deserialize)]
struct PeerRecord {
    node_id: String,
    name: Option<String>,
    first_seen: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
struct ReceivedRecord {
    local_id: ItemId,
    revision: u64,
}

fn fingerprint(signing_key: &[u8]) -> String {
    let digest = Sha256::digest(signing_key);
    let hex = hex(&digest[..12]);
    hex.as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect::<Vec<_>>()
        .join(":")
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(text: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "bundle is malformed".into(),
        })
}

fn malformed() -> KeyLeaseError {
    KeyLeaseError::InvalidRequest {
        reason: "not a KeyLease bundle, or not encrypted to this node".into(),
    }
}

impl KeyLeaseService {
    /// This node's bundle identity, created on first use (owner command).
    pub fn node_identity(&self) -> Result<NodeIdentity> {
        self.with_vault(|vault| {
            let (identity, signer) = self.bundle_keys(vault)?;
            let signing_key = signer.verifying_key().to_bytes();
            Ok(NodeIdentity {
                node_id: identity.to_public().to_string(),
                signing_key: b64(&signing_key),
                fingerprint: fingerprint(&signing_key),
            })
        })
    }

    pub(crate) fn bundle_keys(
        &self,
        vault: &UnlockedVault,
    ) -> Result<(age::x25519::Identity, SigningKey)> {
        let identity = match self.store.cloud_get(record::KIND, record::IDENTITY)? {
            Some(sealed) => {
                let secret = self
                    .store
                    .open_local_secret(vault, record::IDENTITY, &sealed)?;
                std::str::from_utf8(&secret)
                    .ok()
                    .and_then(|text| text.parse::<age::x25519::Identity>().ok())
                    .ok_or(KeyLeaseError::Crypto)?
            }
            None => {
                let identity = age::x25519::Identity::generate();
                let secret = identity.to_string();
                let sealed = self.store.seal_local_secret(
                    vault,
                    record::IDENTITY,
                    secret.expose_secret().as_bytes(),
                )?;
                self.store
                    .cloud_put(record::KIND, record::IDENTITY, &sealed)?;
                identity
            }
        };
        let signer = match self.store.cloud_get(record::KIND, record::SIGNER)? {
            Some(sealed) => {
                let secret = self
                    .store
                    .open_local_secret(vault, record::SIGNER, &sealed)?;
                let bytes: [u8; 32] = secret
                    .as_slice()
                    .try_into()
                    .map_err(|_| KeyLeaseError::Crypto)?;
                SigningKey::from_bytes(&bytes)
            }
            None => {
                let mut seed = Zeroizing::new([0_u8; 32]);
                rand::rng().fill_bytes(seed.as_mut());
                let sealed = self
                    .store
                    .seal_local_secret(vault, record::SIGNER, seed.as_ref())?;
                self.store
                    .cloud_put(record::KIND, record::SIGNER, &sealed)?;
                SigningKey::from_bytes(&seed)
            }
        };
        Ok((identity, signer))
    }

    /// Encrypts the selected items to `recipient` (an `age1…` node ID) and
    /// signs them (owner command). Personal items are included only when
    /// selected by ID.
    pub fn export_bundle(
        &self,
        recipient: &str,
        selection: &BundleSelection,
        sender_name: Option<&str>,
    ) -> Result<String> {
        let recipient_key: age::x25519::Recipient =
            recipient
                .trim()
                .parse()
                .map_err(|_| KeyLeaseError::InvalidRequest {
                    reason:
                        "the node ID must be an age recipient (age1…) from `keylease node init`"
                            .into(),
                })?;
        if selection.project_slug.is_none() && selection.item_ids.is_empty() {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "choose a project or at least one item to export".into(),
            });
        }
        self.with_vault(|vault| {
            let (identity, signer) = self.bundle_keys(vault)?;
            let projects = self.store.list_projects(vault)?;
            let groups = self.store.list_groups(vault)?;
            let selected_project = match &selection.project_slug {
                Some(slug) => Some(
                    projects
                        .iter()
                        .find(|project| &project.slug == slug)
                        .ok_or_else(|| KeyLeaseError::NotFound {
                            resource: format!("project {slug}"),
                        })?,
                ),
                None => None,
            };
            let mut items: Vec<VaultItem> = Vec::new();
            for item in self.store.list_items(vault)? {
                let by_id = selection.item_ids.contains(&item.id);
                let by_project = selected_project
                    .is_some_and(|project| item.project_id.as_ref() == Some(&project.id))
                    && !item.personal
                    && item.status == ItemStatus::Active;
                if (by_id || by_project) && !item.extensions.contains_key(cloud::SHARE_EXTENSION) {
                    items.push(item);
                }
            }
            if let Some(missing) = selection
                .item_ids
                .iter()
                .find(|id| !items.iter().any(|item| &item.id == *id))
            {
                return Err(KeyLeaseError::NotFound {
                    resource: missing.0.clone(),
                });
            }
            if items.is_empty() {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "nothing to export".into(),
                });
            }
            if items.len() > MAX_BUNDLE_ITEMS {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: format!("a bundle holds at most {MAX_BUNDLE_ITEMS} items"),
                });
            }
            let mut bundle_projects: Vec<BundleProject> = Vec::new();
            let mut bundle_items = Vec::with_capacity(items.len());
            for item in items {
                let project = item
                    .project_id
                    .as_ref()
                    .and_then(|id| projects.iter().find(|project| &project.id == id));
                if let Some(project) = project
                    && !bundle_projects
                        .iter()
                        .any(|known| known.slug == project.slug)
                {
                    bundle_projects.push(BundleProject {
                        slug: project.slug.clone(),
                        name: project.name.clone(),
                        environments: project.environments.clone(),
                    });
                }
                let group_name = groups
                    .iter()
                    .find(|group| group.id == item.group_id)
                    .map(|group| group.name.clone())
                    .unwrap_or_else(|| "Imported".into());
                bundle_items.push(BundleItem {
                    group_name,
                    project_slug: project.map(|project| project.slug.clone()),
                    item,
                });
            }
            let body = BundleBody {
                bundle_id: uuid::Uuid::now_v7().to_string(),
                created_at: Utc::now(),
                sender: BundleSender {
                    node_id: identity.to_public().to_string(),
                    signing_key: b64(&signer.verifying_key().to_bytes()),
                    name: sender_name.map(str::to_owned),
                },
                recipient: recipient_key.to_string(),
                projects: bundle_projects,
                items: bundle_items,
            };
            let body =
                Zeroizing::new(serde_json::to_string(&body).map_err(|_| KeyLeaseError::Storage)?);
            let mut signed_input = SIGNATURE_CONTEXT.to_vec();
            signed_input.extend_from_slice(body.as_bytes());
            let signature = signer.sign(&signed_input);
            let signed = Zeroizing::new(
                serde_json::to_vec(&SignedBundle {
                    format: BUNDLE_FORMAT.into(),
                    body: body.to_string(),
                    signature: b64(&signature.to_bytes()),
                })
                .map_err(|_| KeyLeaseError::Storage)?,
            );
            age::encrypt_and_armor(&recipient_key, &signed).map_err(|_| KeyLeaseError::Crypto)
        })
    }

    /// Decrypts and verifies a bundle without storing it (owner command).
    pub fn preview_bundle(&self, armored: &str) -> Result<BundlePreview> {
        self.with_vault(|vault| {
            let (body, signing_key) = self.open_bundle(vault, armored)?;
            Ok(BundlePreview {
                sender_fingerprint: fingerprint(&signing_key),
                sender_name: body.sender.name.clone(),
                known_sender: self
                    .store
                    .cloud_get(record::PEER, &body.sender.signing_key)?
                    .is_some(),
                created_at: body.created_at,
                projects: body
                    .projects
                    .iter()
                    .map(|project| project.slug.clone())
                    .collect(),
                items: body
                    .items
                    .iter()
                    .map(|entry| entry.item.title.clone())
                    .collect(),
            })
        })
    }

    fn open_bundle(&self, vault: &UnlockedVault, armored: &str) -> Result<(BundleBody, Vec<u8>)> {
        if armored.len() > MAX_BUNDLE_BYTES {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "bundle is too large".into(),
            });
        }
        let (identity, _) = self.bundle_keys(vault)?;
        let plaintext = Zeroizing::new(
            age::decrypt(&identity, armored.trim().as_bytes()).map_err(|_| malformed())?,
        );
        let signed: SignedBundle = serde_json::from_slice(&plaintext).map_err(|_| malformed())?;
        if signed.format != BUNDLE_FORMAT {
            return Err(KeyLeaseError::InvalidRequest {
                reason: format!("unsupported bundle format {}", signed.format),
            });
        }
        let body: BundleBody = serde_json::from_str(&signed.body).map_err(|_| malformed())?;
        let signing_key = unb64(&body.sender.signing_key)?;
        let key_bytes: [u8; 32] = signing_key.as_slice().try_into().map_err(|_| malformed())?;
        let verifying = VerifyingKey::from_bytes(&key_bytes).map_err(|_| malformed())?;
        let signature_bytes: [u8; 64] = unb64(&signed.signature)?
            .as_slice()
            .try_into()
            .map_err(|_| malformed())?;
        let mut signed_input = SIGNATURE_CONTEXT.to_vec();
        signed_input.extend_from_slice(signed.body.as_bytes());
        verifying
            .verify(&signed_input, &Signature::from_bytes(&signature_bytes))
            .map_err(|_| KeyLeaseError::InvalidRequest {
                reason: "the bundle's signature does not verify".into(),
            })?;
        if body.recipient != identity.to_public().to_string() {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "this bundle was made for another node".into(),
            });
        }
        if body.items.len() > MAX_BUNDLE_ITEMS {
            return Err(KeyLeaseError::InvalidRequest {
                reason: format!("a bundle holds at most {MAX_BUNDLE_ITEMS} items"),
            });
        }
        Ok((body, signing_key))
    }

    /// Stores a bundle's items (owner command).
    ///
    /// A sender seen for the first time must be confirmed: pass its
    /// fingerprint as `trust_sender`, after comparing it with the sending
    /// node's `keylease node init`. Read-only items (the default) are kept in
    /// sync by later bundles from the same sender; `editable` stores
    /// independent copies instead.
    pub fn import_bundle(
        &self,
        armored: &str,
        trust_sender: Option<&str>,
        editable: bool,
    ) -> Result<BundleImportReport> {
        self.with_vault(|vault| {
            let (body, signing_key) = self.open_bundle(vault, armored)?;
            let sender_fingerprint = fingerprint(&signing_key);
            if self
                .store
                .cloud_get(record::PEER, &body.sender.signing_key)?
                .is_none()
            {
                if trust_sender.map(str::trim) != Some(sender_fingerprint.as_str()) {
                    return Err(KeyLeaseError::InvalidRequest {
                        reason: format!(
                            "unknown sender {sender_fingerprint}; compare it with `keylease node \
                             init` on the sending node, then import again with --trust-sender \
                             {sender_fingerprint}"
                        ),
                    });
                }
                self.store.cloud_put(
                    record::PEER,
                    &body.sender.signing_key,
                    &serde_json::to_string(&PeerRecord {
                        node_id: body.sender.node_id.clone(),
                        name: body.sender.name.clone(),
                        first_seen: Utc::now(),
                    })
                    .map_err(|_| KeyLeaseError::Storage)?,
                )?;
            }
            let mut report = BundleImportReport {
                sender_fingerprint: sender_fingerprint.clone(),
                created: 0,
                updated: 0,
                unchanged: 0,
                projects_created: vec![],
            };
            let mut projects = self.store.list_projects(vault)?;
            for incoming in &body.projects {
                if let Some(existing) = projects
                    .iter_mut()
                    .find(|project| project.slug == incoming.slug)
                {
                    let missing: Vec<ProjectEnvironment> = incoming
                        .environments
                        .iter()
                        .filter(|environment| existing.environment(&environment.slug).is_none())
                        .cloned()
                        .collect();
                    if !missing.is_empty() {
                        let expected = existing.revision;
                        existing.environments.extend(missing);
                        existing.revision += 1;
                        existing.updated_at = Utc::now();
                        self.put_owner_project(vault, existing, expected)?;
                    }
                    continue;
                }
                let slug = normalize_project_slug(&incoming.slug)?;
                validate_project_name(&incoming.name)?;
                let now = Utc::now();
                let project = VaultProject {
                    id: ProjectId::new(),
                    vault_id: vault.vault_id.clone(),
                    slug,
                    name: incoming.name.clone(),
                    revision: 1,
                    created_by: AgentId("owner".into()),
                    updated_by: AgentId("owner".into()),
                    created_at: now,
                    updated_at: now,
                    archived_at: None,
                    environments: incoming.environments.clone(),
                };
                self.put_owner_project(vault, &project, 0)?;
                report.projects_created.push(project.slug.clone());
                projects.push(project);
            }
            let mut groups = self.store.list_groups(vault)?;
            for entry in body.items {
                let group_id = match groups.iter().find(|group| group.name == entry.group_name) {
                    Some(group) => group.id.clone(),
                    None => {
                        validate_group(&entry.group_name, None, &groups)?;
                        let now = Utc::now();
                        let group = VaultGroup {
                            id: GroupId::new(),
                            vault_id: vault.vault_id.clone(),
                            parent_id: None,
                            name: entry.group_name.clone(),
                            purpose: GroupPurpose::User,
                            sort_order: None,
                            revision: 1,
                            created_at: now,
                            updated_at: now,
                        };
                        self.store.put_group(vault, &group, Some(0), None)?;
                        let id = group.id.clone();
                        groups.push(group);
                        id
                    }
                };
                let project_id = entry.project_slug.as_ref().and_then(|slug| {
                    projects
                        .iter()
                        .find(|project| &project.slug == slug)
                        .map(|project| project.id.clone())
                });
                let origin_id = entry.item.id.clone();
                let origin_revision = entry.item.revision;
                let received_key = format!("{}/{}", body.sender.signing_key, origin_id.0);
                let previous: Option<ReceivedRecord> = if editable {
                    None
                } else {
                    self.store
                        .cloud_get(record::RECEIVED, &received_key)?
                        .and_then(|json| serde_json::from_str(&json).ok())
                };
                let mut item = entry.item;
                let (expected, existing_id) = match &previous {
                    Some(previous) => {
                        if previous.revision >= origin_revision {
                            report.unchanged += 1;
                            continue;
                        }
                        match self.store.get_item(vault, &previous.local_id) {
                            Ok(local) => (Some(local.revision), Some(local.id)),
                            Err(_) => (None, None),
                        }
                    }
                    None => (None, None),
                };
                item.id = existing_id.clone().unwrap_or_else(ItemId::new);
                item.vault_id = vault.vault_id.clone();
                item.group_id = group_id;
                item.project_id = project_id;
                item.revision = expected.map_or(1, |revision| revision + 1);
                item.updated_at = Utc::now();
                item.extensions.remove(BUNDLE_EXTENSION);
                item.extensions.remove(cloud::SHARE_EXTENSION);
                if !editable {
                    item.extensions.insert(
                        BUNDLE_EXTENSION.into(),
                        serde_json::json!({
                            "sender": sender_fingerprint,
                            "origin_id": origin_id,
                            "revision": origin_revision,
                        }),
                    );
                }
                let idempotency_key = random_token("bundle");
                let request_material = operation_material(&serde_json::json!({
                    "operation":"bundle:import",
                    "bundle":body.bundle_id,
                    "origin":origin_id,
                    "revision":origin_revision,
                }))?;
                self.store.put_item(
                    vault,
                    &item,
                    Some(expected.unwrap_or(0)),
                    MutationContext {
                        actor: "owner",
                        idempotency_key: &idempotency_key,
                        request_material: &request_material,
                        audit_event: None,
                    },
                )?;
                if existing_id.is_some() {
                    report.updated += 1;
                } else {
                    report.created += 1;
                }
                if !editable {
                    self.store.cloud_put(
                        record::RECEIVED,
                        &received_key,
                        &serde_json::to_string(&ReceivedRecord {
                            local_id: item.id.clone(),
                            revision: origin_revision,
                        })
                        .map_err(|_| KeyLeaseError::Storage)?,
                    )?;
                }
            }
            Ok(report)
        })
    }

    fn put_owner_project(
        &self,
        vault: &UnlockedVault,
        project: &VaultProject,
        expected: u64,
    ) -> Result<()> {
        let idempotency_key = random_token("bundle-project");
        let request_material = operation_material(&serde_json::json!({
            "operation":"bundle:project",
            "project":project.id,
            "revision":project.revision,
        }))?;
        self.store.put_project(
            vault,
            project,
            Some(expected),
            MutationContext {
                actor: "owner",
                idempotency_key: &idempotency_key,
                request_material: &request_material,
                audit_event: None,
            },
        )?;
        Ok(())
    }
}
