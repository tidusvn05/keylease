//! Owner: read-only copies of each node's own items, so everything is in one
//! place on the owner device.
//!
//! A node backs up the items it created, sealed to the owner (ADR 0006). On
//! every sync the owner opens those backups and keeps one read-only copy of
//! each item in a group named after the node. Nothing new crosses the relay:
//! the copies come from the backups the node already sends.
//!
//! A copy changes only on the node. `cloud_adopt` turns copies into the
//! owner's own items and shares them back, so from then on they are managed
//! here; the node's originals become the shared copies, keeping their ids.

use super::*;

pub const MIRROR_EXTENSION: &str = keylease_core::CLOUD_MIRROR_EXTENSION;
const GROUP_PREFIX: &str = "group_cloud_node_";

/// Whether `id` is the group holding a node's copies.
pub fn is_mirror_group(id: &GroupId) -> bool {
    id.0.starts_with(GROUP_PREFIX)
}

fn mirror_group_id(member_id: &str) -> GroupId {
    let safe: String = member_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    GroupId(format!("{GROUP_PREFIX}{safe}"))
}

#[derive(Serialize, Deserialize)]
struct MirrorRecord {
    local_item_id: ItemId,
    node_revision: u64,
}

/// The digest of the backup list last mirrored, so an unchanged node costs
/// nothing.
#[derive(Serialize, Deserialize)]
struct MirrorState {
    digest: String,
}

/// What one mirror pass did.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MirrorReport {
    pub node: String,
    pub items: usize,
    pub updated: usize,
    pub removed: usize,
}

/// What `cloud_adopt` did.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AdoptReport {
    pub node: String,
    /// Items now managed on this device.
    pub adopted: Vec<ItemId>,
    /// Projects shared with the node (slugs).
    pub projects: Vec<String>,
    /// Items without a project, shared one by one.
    pub item_shares: usize,
    /// Items left as they were, with the reason.
    pub skipped: Vec<String>,
}

impl KeyLeaseService {
    /// Owner: brings the read-only copies of `node_member_id`'s items in line
    /// with its backups. Devices are skipped (they sync two-way instead).
    pub fn cloud_mirror_node(
        &self,
        node_member_id: &str,
        backups: &[RelayBackup],
    ) -> Result<MirrorReport> {
        let link = self.require_owner()?;
        let node = self.find_node(node_member_id)?;
        let mut report = MirrorReport {
            node: node.name.clone(),
            ..MirrorReport::default()
        };
        if node.role != CloudRole::Node || node.removed_at.is_some() {
            return Ok(report);
        }
        let digest = relay_digest(
            &serde_json::to_vec(
                &backups
                    .iter()
                    .map(|b| (&b.object_id, b.revision, b.deleted))
                    .collect::<Vec<_>>(),
            )
            .map_err(|_| KeyLeaseError::Storage)?,
        );
        let state_key = format!("{}/", node.member_id);
        let unchanged = self
            .store
            .cloud_get(record::MIRROR, &state_key)?
            .and_then(|json| from_json::<MirrorState>(&json).ok())
            .is_some_and(|state| state.digest == digest);
        self.with_vault_passive(|vault| {
            let group_id = self.ensure_mirror_group(vault, &node)?;
            if unchanged {
                report.items = self.mirror_records(&node.member_id)?.len();
                return Ok(());
            }
            let keys = self.load_keys(vault)?;
            // Each object is checked against the node's signature. The
            // manifest is not required: a copy to look at should follow the
            // node's newest backup even while a round is half uploaded.
            let opened = self.open_backup_objects(&link, &keys, &node.member_id, backups)?;
            let projects: std::collections::BTreeMap<String, VaultProject> = opened
                .iter()
                .filter_map(|(_, _, payload)| match payload {
                    BackupPayload::Project { project } => {
                        Some((project.id.0.clone(), project.clone()))
                    }
                    _ => None,
                })
                .collect();
            let mut wanted = std::collections::BTreeSet::new();
            for (_, _, payload) in opened {
                let BackupPayload::Item { item } = payload else {
                    continue;
                };
                let adopted_key = format!("{}/{}", node.member_id, item.id.0);
                if self
                    .store
                    .cloud_get(record::ADOPTED, &adopted_key)?
                    .is_some()
                {
                    continue;
                }
                wanted.insert(item.id.0.clone());
                let project = item
                    .project_id
                    .as_ref()
                    .and_then(|id| projects.get(&id.0))
                    .cloned();
                if self.mirror_item(vault, &node, &group_id, *item, project.as_ref())? {
                    report.updated += 1;
                }
            }
            for (key, json) in self.mirror_records(&node.member_id)? {
                let node_item = key.trim_start_matches(&state_key);
                if wanted.contains(node_item) {
                    continue;
                }
                let record: MirrorRecord = from_json(&json)?;
                self.delete_mirror_copy(vault, &record.local_item_id)?;
                self.store.cloud_delete(record::MIRROR, &key)?;
                report.removed += 1;
            }
            report.items = wanted.len();
            self.store.cloud_put(
                record::MIRROR,
                &state_key,
                &to_json(&MirrorState { digest })?,
            )
        })?;
        Ok(report)
    }

    /// How many read-only copies of `node_member_id`'s items this vault has.
    pub(crate) fn cloud_node_copies(&self, node_member_id: &str) -> Result<usize> {
        Ok(self.mirror_records(node_member_id)?.len())
    }

    /// `NODE/ITEM` mirror records of one node (not its state record).
    fn mirror_records(&self, node_member_id: &str) -> Result<Vec<(String, String)>> {
        let prefix = format!("{node_member_id}/");
        Ok(self
            .store
            .cloud_list(record::MIRROR, &prefix)?
            .into_iter()
            .filter(|(key, _)| key.len() > prefix.len())
            .collect())
    }

    fn ensure_mirror_group(
        &self,
        vault: &keylease_store::UnlockedVault,
        node: &CloudNode,
    ) -> Result<GroupId> {
        let id = mirror_group_id(&node.member_id);
        let now = Utc::now();
        match self.store.get_group(vault, &id) {
            Ok(group) if group.name == node.name => {}
            Ok(mut group) => {
                let expected = group.revision;
                group.name = node.name.clone();
                group.revision += 1;
                group.updated_at = now;
                self.store.put_group(vault, &group, Some(expected), None)?;
            }
            Err(_) => {
                let group = VaultGroup {
                    id: id.clone(),
                    vault_id: vault.vault_id.clone(),
                    parent_id: None,
                    name: node.name.clone(),
                    purpose: GroupPurpose::User,
                    sort_order: None,
                    revision: 1,
                    created_at: now,
                    updated_at: now,
                };
                self.store.put_group(vault, &group, Some(0), None)?;
            }
        }
        Ok(id)
    }

    /// Writes the copy of one node item. Returns whether it changed.
    fn mirror_item(
        &self,
        vault: &keylease_store::UnlockedVault,
        node: &CloudNode,
        group_id: &GroupId,
        node_item: VaultItem,
        project: Option<&VaultProject>,
    ) -> Result<bool> {
        let key = format!("{}/{}", node.member_id, node_item.id.0);
        let record: Option<MirrorRecord> = self
            .store
            .cloud_get(record::MIRROR, &key)?
            .map(|json| from_json(&json))
            .transpose()?;
        let current = record
            .as_ref()
            .and_then(|record| self.store.get_item(vault, &record.local_item_id).ok());
        if let (Some(record), Some(_)) = (&record, &current)
            && record.node_revision == node_item.revision
        {
            return Ok(false);
        }
        let node_revision = node_item.revision;
        let mut item = node_item.clone();
        item.id = current
            .as_ref()
            .map_or_else(ItemId::new, |item| item.id.clone());
        item.vault_id = vault.vault_id.clone();
        item.group_id = group_id.clone();
        item.project_id = None;
        item.personal = false;
        item.agent_access = AgentAccess::default();
        item.revision = current.as_ref().map_or(1, |item| item.revision + 1);
        item.extensions.remove(SHARE_EXTENSION);
        item.extensions.remove(crate::bundle::BUNDLE_EXTENSION);
        item.extensions.insert(
            MIRROR_EXTENSION.into(),
            serde_json::json!({
                "node_member_id": node.member_id,
                "node_name": node.name,
                "node_item_id": node_item.id.0,
                "node_revision": node_revision,
                "node_project": project.map(|p| serde_json::json!({
                    "id": p.id.0,
                    "slug": p.slug,
                    "name": p.name,
                })),
            }),
        );
        let operation = new_id("mirror");
        self.store.put_item(
            vault,
            &item,
            Some(current.as_ref().map_or(0, |item| item.revision)),
            MutationContext {
                actor: "cloud",
                idempotency_key: &operation,
                request_material: operation.as_bytes(),
                audit_event: None,
            },
        )?;
        self.store.cloud_put(
            record::MIRROR,
            &key,
            &to_json(&MirrorRecord {
                local_item_id: item.id,
                node_revision,
            })?,
        )?;
        Ok(true)
    }

    fn delete_mirror_copy(
        &self,
        vault: &keylease_store::UnlockedVault,
        local_item_id: &ItemId,
    ) -> Result<()> {
        if let Ok(item) = self.store.get_item(vault, local_item_id)
            && item.extensions.contains_key(MIRROR_EXTENSION)
        {
            let operation = new_id("unmirror");
            self.store.delete_item(
                vault,
                &item.id,
                item.revision,
                MutationContext {
                    actor: "cloud",
                    idempotency_key: &operation,
                    request_material: operation.as_bytes(),
                    audit_event: None,
                },
            )?;
        }
        Ok(())
    }

    /// Owner: drops every copy of a node's items and its group (the node was
    /// removed).
    pub(super) fn cloud_unmirror_node(&self, node_member_id: &str) -> Result<()> {
        self.with_vault(|vault| {
            for (key, json) in self.mirror_records(node_member_id)? {
                let record: MirrorRecord = from_json(&json)?;
                self.delete_mirror_copy(vault, &record.local_item_id)?;
                self.store.cloud_delete(record::MIRROR, &key)?;
            }
            self.store
                .cloud_delete(record::MIRROR, &format!("{node_member_id}/"))?;
            let group_id = mirror_group_id(node_member_id);
            if let Ok(group) = self.store.get_group(vault, &group_id)
                && !self
                    .store
                    .list_items(vault)?
                    .iter()
                    .any(|item| item.group_id == group_id)
            {
                self.store
                    .delete_group(vault, &group_id, group.revision, None)?;
            }
            Ok(())
        })
    }

    /// Owner: makes the copies of `node`'s items (all, or `item_ids`, which
    /// may be the copies' ids or the node's) this device's own items, and
    /// shares them back: a node project as a project share (the project is
    /// created here with the same id, or matched by slug), other items one by
    /// one. On the node each original becomes the shared copy and keeps its
    /// id, so references to it keep working; it is then read-only there.
    pub fn cloud_adopt(&self, node: &str, item_ids: &[String]) -> Result<AdoptReport> {
        self.require_owner()?;
        let node = self.find_node(node)?;
        if node.role != CloudRole::Node || node.removed_at.is_some() {
            return Err(invalid("only a current node's items can be adopted"));
        }
        let mut report = AdoptReport {
            node: node.name.clone(),
            ..AdoptReport::default()
        };
        // (owner project id, slug) to share, and item ids without a project.
        let mut project_shares: Vec<(ProjectId, String)> = Vec::new();
        let mut item_shares: Vec<ItemId> = Vec::new();
        self.with_vault(|vault| {
            let copies: Vec<(String, VaultItem)> = self
                .mirror_records(&node.member_id)?
                .into_iter()
                .filter_map(|(key, json)| {
                    let record: MirrorRecord = from_json(&json).ok()?;
                    let item = self.store.get_item(vault, &record.local_item_id).ok()?;
                    Some((key, item))
                })
                .collect();
            let user_group = self.default_user_group(vault)?;
            let mut matched = vec![false; item_ids.len()];
            for (key, copy) in copies {
                let mirror = copy.extensions[MIRROR_EXTENSION].clone();
                let node_item_id = mirror["node_item_id"].as_str().unwrap_or_default();
                if !item_ids.is_empty() {
                    let Some(position) = item_ids
                        .iter()
                        .position(|id| id == &copy.id.0 || id == node_item_id)
                    else {
                        continue;
                    };
                    matched[position] = true;
                }
                let adopted_id = ItemId(node_item_id.into());
                if !adopted_id.0.starts_with("item_") {
                    report
                        .skipped
                        .push(format!("{}: not an item id", copy.title));
                    continue;
                }
                if self.store.get_item(vault, &adopted_id).is_ok() {
                    report.skipped.push(format!(
                        "{}: this vault already has an item with its id",
                        copy.title
                    ));
                    continue;
                }
                let project_id = match mirror["node_project"].as_object() {
                    Some(project) => Some(self.adopt_project(vault, project)?),
                    None => None,
                };
                let mut item = copy.clone();
                item.id = adopted_id.clone();
                item.group_id = user_group.clone();
                item.project_id = project_id.as_ref().map(|(id, _)| id.clone());
                item.extensions.remove(MIRROR_EXTENSION);
                item.revision = 1;
                item.updated_at = Utc::now();
                let operation = new_id("adopt");
                self.store.put_item(
                    vault,
                    &item,
                    Some(0),
                    MutationContext {
                        actor: "cloud",
                        idempotency_key: &operation,
                        request_material: operation.as_bytes(),
                        audit_event: Some(&self.vault_audit_event(
                            &self.cloud_actor(),
                            "cloud:adopt",
                            &format!("kl://{}/item/{}", vault.vault_id.0, item.id.0),
                            "allow",
                            &format!("adopted from {}", node.member_id),
                            vec![],
                        )),
                    },
                )?;
                self.store.cloud_put(
                    record::ADOPTED,
                    &format!("{}/{}", node.member_id, adopted_id.0),
                    "{}",
                )?;
                self.delete_mirror_copy(vault, &copy.id)?;
                self.store.cloud_delete(record::MIRROR, &key)?;
                match project_id {
                    Some(project) => {
                        if !project_shares.contains(&project) {
                            project_shares.push(project);
                        }
                    }
                    None => item_shares.push(adopted_id.clone()),
                }
                report.adopted.push(adopted_id);
            }
            for (id, found) in item_ids.iter().zip(matched) {
                if !found {
                    report
                        .skipped
                        .push(format!("{id}: not a copy of an item of {}", node.name));
                }
            }
            Ok(())
        })?;
        let active = self.cloud_shares()?;
        for (project_id, slug) in project_shares {
            let shared = active.iter().any(|share| {
                share.node_member_id == node.member_id
                    && share.revoked_at.is_none()
                    && share.expires_at.is_none()
                    && share.scope
                        == ShareScope::Project {
                            project_id: project_id.clone(),
                        }
            });
            if !shared {
                self.cloud_share(
                    ShareScope::Project { project_id },
                    &node.member_id,
                    None,
                    None,
                )?;
            }
            report.projects.push(slug);
        }
        for item_id in item_shares {
            self.cloud_share(ShareScope::Item { item_id }, &node.member_id, None, None)?;
            report.item_shares += 1;
        }
        Ok(report)
    }

    /// The owner's project for a node project: the same id if this vault has
    /// it, else one with the same slug, else a new one with the node's id.
    fn adopt_project(
        &self,
        vault: &keylease_store::UnlockedVault,
        node_project: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<(ProjectId, String)> {
        let id = ProjectId(
            node_project
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .into(),
        );
        let slug = node_project
            .get("slug")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let projects = self.store.list_projects(vault)?;
        if let Some(found) = projects
            .iter()
            .find(|p| p.id == id)
            .or_else(|| projects.iter().find(|p| p.slug == slug))
        {
            return Ok((found.id.clone(), found.slug.clone()));
        }
        if !id.0.starts_with("project_") || slug.is_empty() {
            return Err(invalid("the node's project has no usable id or slug"));
        }
        let now = Utc::now();
        let project = VaultProject {
            id: id.clone(),
            vault_id: vault.vault_id.clone(),
            slug: slug.clone(),
            name: node_project
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(&slug)
                .into(),
            revision: 1,
            created_by: AgentId("cloud".into()),
            updated_by: AgentId("cloud".into()),
            created_at: now,
            updated_at: now,
            archived_at: None,
            environments: Vec::new(),
        };
        let operation = new_id("adopt-project");
        self.store.put_project(
            vault,
            &project,
            Some(0),
            MutationContext {
                actor: "cloud",
                idempotency_key: &operation,
                request_material: operation.as_bytes(),
                audit_event: None,
            },
        )?;
        Ok((id, slug))
    }

    /// Where adopted items go: the top-level group named Root, else the first
    /// top-level group of the user's own.
    fn default_user_group(&self, vault: &keylease_store::UnlockedVault) -> Result<GroupId> {
        let groups = self.store.list_groups(vault)?;
        let mine = |group: &&VaultGroup| {
            group.parent_id.is_none()
                && group.purpose == GroupPurpose::User
                && !is_mirror_group(&group.id)
                && group.id.0 != SHARED_GROUP
                && group.id.0 != RESTORED_GROUP
        };
        Ok(groups
            .iter()
            .filter(mine)
            .find(|group| group.name.eq_ignore_ascii_case("root"))
            .or_else(|| groups.iter().find(mine))
            .map_or_else(|| GroupId(RESTORED_GROUP.into()), |group| group.id.clone()))
    }
}
