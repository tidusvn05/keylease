//! Two-way sync between the owner device and the owner's other devices
//! (v2 plan, step 10).
//!
//! Every item, group and project change is sent, sealed to the recipient, as
//! a `sync` message: from a device to the owner device, and from the owner
//! device to every device (so devices reach each other through it). The newest
//! `updated_at` wins (ties broken by the larger member id); the store keeps
//! the history of every item revision, so an overwritten version can be
//! recovered. A deleted item is sent as a deletion that wins over older
//! edits.

use super::*;

const SENT: &str = "sync_sent";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(super) enum SyncObject {
    Item(Box<VaultItem>),
    Group(VaultGroup),
    Project(VaultProject),
    DeleteItem {
        item_id: ItemId,
        deleted_at: DateTime<Utc>,
    },
}

#[derive(Serialize, Deserialize)]
struct SentRecord {
    /// Local revision last sent (or received from this peer).
    revision: u64,
    message_revision: u64,
}

fn sent_key(peer: &str, object: &str) -> String {
    format!("{peer}/{object}")
}

/// Whether `incoming` (from `from`) should replace a local copy last changed
/// at `local_updated` by `local_member`.
fn newer(
    incoming: DateTime<Utc>,
    from: &str,
    local_updated: DateTime<Utc>,
    local_member: &str,
) -> bool {
    incoming > local_updated || (incoming == local_updated && from > local_member)
}

impl KeyLeaseService {
    /// Whom this member syncs with: the owner device for a device; every
    /// verified device for the owner.
    fn sync_peers(&self, link: &CloudLink) -> Result<Vec<(String, String)>> {
        Ok(match link.role {
            CloudRole::Device => vec![(
                link.owner_member_id.clone(),
                link.owner_box_public_b64.clone(),
            )],
            CloudRole::Owner => self
                .store
                .cloud_list(record::NODE, "")?
                .into_iter()
                .filter_map(|(_, json)| from_json::<CloudNode>(&json).ok())
                .filter(|node| node.role == CloudRole::Device && node.removed_at.is_none())
                .map(|node| (node.member_id, node.box_public_b64))
                .collect(),
            CloudRole::Node => vec![],
        })
    }

    /// Queues `sync` messages for every change a peer has not seen yet.
    /// Returns how many were queued.
    pub fn cloud_publish_sync(&self) -> Result<usize> {
        let link = self.require_link()?;
        let peers = self.sync_peers(&link)?;
        if peers.is_empty() {
            return Ok(0);
        }
        let mut queued = 0;
        self.with_vault_passive(|vault| {
            let keys = self.load_keys(vault)?;
            let groups = self.store.list_groups(vault)?;
            let projects = self.store.list_projects(vault)?;
            // Shared-in and bundle copies belong to their origin.
            let items: Vec<VaultItem> = self
                .store
                .list_items(vault)?
                .into_iter()
                .filter(|item| {
                    !item.extensions.contains_key(SHARE_EXTENSION)
                        && !item
                            .extensions
                            .contains_key(crate::bundle::BUNDLE_EXTENSION)
                })
                .collect();
            let mut objects: Vec<(String, u64, SyncObject)> = Vec::new();
            for group in groups
                .iter()
                .filter(|group| group.id.0 != SHARED_GROUP && group.id.0 != RESTORED_GROUP)
            {
                objects.push((
                    group.id.0.clone(),
                    group.revision,
                    SyncObject::Group(group.clone()),
                ));
            }
            for project in &projects {
                objects.push((
                    project.id.0.clone(),
                    project.revision,
                    SyncObject::Project(project.clone()),
                ));
            }
            for item in &items {
                objects.push((
                    item.id.0.clone(),
                    item.revision,
                    SyncObject::Item(Box::new(item.clone())),
                ));
            }
            for (peer, peer_box) in &peers {
                for (object_id, revision, object) in &objects {
                    let key = sent_key(peer, object_id);
                    let previous: Option<SentRecord> = self
                        .store
                        .cloud_get(SENT, &key)?
                        .and_then(|json| from_json(&json).ok());
                    if previous
                        .as_ref()
                        .is_some_and(|sent| sent.revision >= *revision)
                    {
                        continue;
                    }
                    let message_revision =
                        next_message_revision(previous.map_or(0, |sent| sent.message_revision));
                    self.queue_message(
                        &link,
                        &keys,
                        peer,
                        peer_box,
                        kind::SYNC,
                        object_id,
                        message_revision,
                        &MessagePayload::Sync {
                            object: Box::new(object.clone()),
                        },
                    )?;
                    self.store.cloud_put(
                        SENT,
                        &key,
                        &to_json(&SentRecord {
                            revision: *revision,
                            message_revision,
                        })?,
                    )?;
                    queued += 1;
                }
                // Items this peer has seen that no longer exist: deletions.
                let prefix = format!("{peer}/");
                for (key, json) in self.store.cloud_list(SENT, &prefix)? {
                    let object_id = key.trim_start_matches(&prefix);
                    if !object_id.starts_with("item_")
                        || items.iter().any(|item| item.id.0 == object_id)
                    {
                        continue;
                    }
                    let previous: SentRecord = from_json(&json)?;
                    if previous.revision == u64::MAX {
                        continue;
                    }
                    let message_revision = next_message_revision(previous.message_revision);
                    self.queue_message(
                        &link,
                        &keys,
                        peer,
                        peer_box,
                        kind::SYNC,
                        object_id,
                        message_revision,
                        &MessagePayload::Sync {
                            object: Box::new(SyncObject::DeleteItem {
                                item_id: ItemId(object_id.into()),
                                deleted_at: Utc::now(),
                            }),
                        },
                    )?;
                    self.store.cloud_put(
                        SENT,
                        &key,
                        &to_json(&SentRecord {
                            revision: u64::MAX,
                            message_revision,
                        })?,
                    )?;
                    queued += 1;
                }
            }
            Ok(queued)
        })
    }

    /// Applies one `sync` message from `from` (already verified).
    pub(super) fn apply_sync(
        &self,
        vault: &keylease_store::UnlockedVault,
        link: &CloudLink,
        from: &str,
        object: SyncObject,
    ) -> Result<()> {
        let context = |operation: &str,
                       object_id: &str,
                       revision: u64|
         -> Result<(String, Zeroizing<Vec<u8>>)> {
            Ok((
                new_id("sync"),
                Zeroizing::new(
                    to_json(&serde_json::json!({
                        "operation": operation,
                        "from": from,
                        "object": object_id,
                        "revision": revision,
                    }))?
                    .into_bytes(),
                ),
            ))
        };
        let me = link.member_id.as_str();
        let (object_id, local_revision) = match object {
            SyncObject::Item(item) => {
                let mut item = *item;
                if !item.id.0.starts_with("item_") {
                    return Err(invalid("sync item id"));
                }
                let local = self.store.get_item(vault, &item.id).ok();
                if let Some(local) = &local
                    && !newer(item.updated_at, from, local.updated_at, me)
                {
                    return Ok(());
                }
                item.vault_id = vault.vault_id.clone();
                item.revision = local.as_ref().map_or(1, |local| local.revision + 1);
                let expected = local.as_ref().map_or(0, |local| local.revision);
                let (key, material) = context("sync:item", &item.id.0, item.revision)?;
                self.store.put_item(
                    vault,
                    &item,
                    Some(expected),
                    MutationContext {
                        actor: "cloud-sync",
                        idempotency_key: &key,
                        request_material: &material,
                        audit_event: None,
                    },
                )?;
                (item.id.0.clone(), item.revision)
            }
            SyncObject::Group(mut group) => {
                if !group.id.0.starts_with("group_")
                    || group.id.0 == SHARED_GROUP
                    || group.id.0 == RESTORED_GROUP
                {
                    return Err(invalid("sync group id"));
                }
                let local = self.store.get_group(vault, &group.id).ok();
                if let Some(local) = &local
                    && !newer(group.updated_at, from, local.updated_at, me)
                {
                    return Ok(());
                }
                group.vault_id = vault.vault_id.clone();
                group.revision = local.as_ref().map_or(1, |local| local.revision + 1);
                let expected = local.as_ref().map_or(0, |local| local.revision);
                self.store.put_group(vault, &group, Some(expected), None)?;
                (group.id.0.clone(), group.revision)
            }
            SyncObject::Project(mut project) => {
                if !project.id.0.starts_with("project_") {
                    return Err(invalid("sync project id"));
                }
                let local = self.store.get_project(vault, &project.id).ok();
                if let Some(local) = &local
                    && !newer(project.updated_at, from, local.updated_at, me)
                {
                    return Ok(());
                }
                project.vault_id = vault.vault_id.clone();
                project.revision = local.as_ref().map_or(1, |local| local.revision + 1);
                let expected = local.as_ref().map_or(0, |local| local.revision);
                let (key, material) = context("sync:project", &project.id.0, project.revision)?;
                self.store.put_project(
                    vault,
                    &project,
                    Some(expected),
                    MutationContext {
                        actor: "cloud-sync",
                        idempotency_key: &key,
                        request_material: &material,
                        audit_event: None,
                    },
                )?;
                (project.id.0.clone(), project.revision)
            }
            SyncObject::DeleteItem {
                item_id,
                deleted_at,
            } => {
                let Ok(local) = self.store.get_item(vault, &item_id) else {
                    return Ok(());
                };
                if local.updated_at > deleted_at {
                    // Edited here after the deletion: the edit wins and is
                    // sent back.
                    return Ok(());
                }
                let (key, material) = context("sync:delete", &item_id.0, local.revision)?;
                self.store.delete_item(
                    vault,
                    &item_id,
                    local.revision,
                    MutationContext {
                        actor: "cloud-sync",
                        idempotency_key: &key,
                        request_material: &material,
                        audit_event: None,
                    },
                )?;
                (item_id.0.clone(), u64::MAX)
            }
        };
        // The sender has this version: do not send it back.
        let key = sent_key(from, &object_id);
        let message_revision = self
            .store
            .cloud_get(SENT, &key)?
            .and_then(|json| from_json::<SentRecord>(&json).ok())
            .map_or(0, |sent| sent.message_revision);
        self.store.cloud_put(
            SENT,
            &key,
            &to_json(&SentRecord {
                revision: local_revision,
                message_revision,
            })?,
        )?;
        self.cloud_audit(
            "cloud:sync",
            &format!("kl://cloud/sync/{object_id}"),
            "applied",
        )?;
        Ok(())
    }
}
