//! KDBX and 1PUX import, exports, native backups and restore.

use super::*;

impl KeyLeaseService {
    pub fn preview_kdbx_import(&self, bytes: &[u8], password: &str) -> Result<ImportPreview> {
        self.with_vault(|vault| {
            let mut source = bytes;
            let mut preview =
                KeepassRsAdapter.preview_import(&mut source, password, &vault.vault_id)?;
            let existing_items = self
                .store
                .list_items(vault)?
                .into_iter()
                .map(|item| item.id)
                .collect::<std::collections::HashSet<_>>();
            let before = preview.items.len();
            preview.items.retain(|item| {
                let duplicate = existing_items.contains(&item.id);
                if duplicate {
                    preview.report.duplicate_decisions.push(format!(
                        "{}: skipped because the stable item ID already exists",
                        item.id.0
                    ));
                }
                !duplicate
            });
            let existing_groups = self
                .store
                .list_groups(vault)?
                .into_iter()
                .map(|group| group.id)
                .collect::<std::collections::HashSet<_>>();
            preview.groups.retain(|group| {
                let duplicate = existing_groups.contains(&group.id);
                if duplicate {
                    preview
                        .report
                        .duplicate_decisions
                        .push(format!("{}: reused existing group", group.id.0));
                }
                !duplicate
            });
            if before != preview.items.len() {
                preview.report.warnings.push(format!(
                    "{} duplicate items will be skipped",
                    before - preview.items.len()
                ));
            }
            preview.report.successful_items = preview.items.len() as u64;
            Ok(preview)
        })
    }
    pub fn commit_kdbx_import(&self, preview: &ImportPreview) -> Result<MigrationReport> {
        self.with_vault(|vault| {
            let checksum = preview
                .report
                .source_checksum_sha256
                .as_deref()
                .ok_or_else(|| KeyLeaseError::InvalidRequest {
                    reason: "import preview has no source checksum".into(),
                })?;
            self.store.import_batch(
                vault,
                &preview.groups,
                &preview.items,
                &format!("kdbx-import-{checksum}"),
            )?;
            Ok(preview.report.clone())
        })
    }
    pub fn preview_onepux_import(&self, bytes: &[u8]) -> Result<OnePuxImportPreview> {
        self.with_vault(|vault| {
            let mut source = bytes;
            let mut preview = ZipOnePuxAdapter.preview_import(&mut source, &vault.vault_id)?;
            let existing_items = self
                .store
                .list_items(vault)?
                .into_iter()
                .map(|item| item.id)
                .collect::<std::collections::HashSet<_>>();
            let item_count = preview.items.len();
            preview.items.retain(|item| {
                let duplicate = existing_items.contains(&item.id);
                if duplicate {
                    preview.report.duplicate_decisions.push(format!(
                        "{}: skipped because the stable item ID already exists",
                        item.id.0
                    ));
                }
                !duplicate
            });
            let existing_groups = self
                .store
                .list_groups(vault)?
                .into_iter()
                .map(|group| group.id)
                .collect::<std::collections::HashSet<_>>();
            preview.groups.retain(|group| {
                let duplicate = existing_groups.contains(&group.id);
                if duplicate {
                    preview
                        .report
                        .duplicate_decisions
                        .push(format!("{}: reused existing group", group.id.0));
                }
                !duplicate
            });
            if item_count != preview.items.len() {
                preview.report.warnings.push(format!(
                    "{} duplicate items will be skipped",
                    item_count - preview.items.len()
                ));
            }
            preview.report.successful_groups = preview.groups.len() as u64;
            preview.report.successful_items = preview.items.len() as u64;
            Ok(preview)
        })
    }
    pub fn commit_onepux_import(
        &self,
        preview: &OnePuxImportPreview,
    ) -> Result<OnePuxMigrationReport> {
        self.with_vault(|vault| {
            self.store.import_batch(
                vault,
                &preview.groups,
                &preview.items,
                &format!("onepux-import-{}", preview.report.source_checksum_sha256),
            )?;
            Ok(preview.report.clone())
        })
    }
    pub fn export_kdbx(
        &self,
        password: &str,
        selected_item_ids: &[ItemId],
    ) -> Result<(Vec<u8>, MigrationReport)> {
        self.with_vault(|vault| {
            let groups = self.store.list_groups(vault)?;
            let selected = selected_item_ids
                .iter()
                .collect::<std::collections::HashSet<_>>();
            let items = self
                .store
                .list_items(vault)?
                .into_iter()
                .filter(|item| !item.tags.iter().any(|tag| tag == "keylease.connection"))
                .filter(|item| selected.is_empty() || selected.contains(&item.id))
                .collect::<Vec<_>>();
            if !selected.is_empty() && items.len() != selected.len() {
                return Err(KeyLeaseError::NotFound {
                    resource: "one or more selected KDBX export items".into(),
                });
            }
            let mut output = vec![];
            let report = KeepassRsAdapter.export(&mut output, password, &groups, &items)?;
            Ok((output, report))
        })
    }
    pub fn export_native_backup(&self) -> Result<Vec<u8>> {
        self.export_native_backup_filtered(true)
    }

    /// Exports a backup, optionally omitting stored connector credentials.
    ///
    /// See [`NativeStore::export_native_backup_filtered`] for why a mobile
    /// export leaves them out.
    pub fn export_native_backup_filtered(&self, include_connections: bool) -> Result<Vec<u8>> {
        self.with_vault(|vault| {
            self.store
                .export_native_backup_filtered(vault, include_connections)
        })
    }

    /// Rotates the master password after verifying the current one.
    ///
    /// Only the password slot is rewritten: the account root key is unchanged,
    /// so item ciphertext is untouched and other devices keep working.
    pub fn change_master_password(&self, current: &[u8], next: &[u8]) -> Result<()> {
        if next.len() < 10 {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "new password must contain at least 10 characters".into(),
            });
        }
        // Unlocking with the current password is the verification step; a wrong
        // one fails here rather than silently rewriting the slot.
        let unlocked = self.store.unlock(current)?;
        self.store.change_password(&unlocked, next)
    }
    pub fn restore_native_backup(
        &self,
        password: &[u8],
        bytes: &[u8],
        session_ttl: Duration,
    ) -> Result<VaultId> {
        validate_session_timeout(session_ttl)?;
        let vault = self.store.restore_native_backup(password, bytes)?;
        let id = vault.vault_id.clone();
        *self.session.lock().map_err(|_| KeyLeaseError::Storage)? = Some(Session {
            vault,
            idle_timeout: session_ttl,
            last_activity: Utc::now(),
        });
        Ok(id)
    }

    pub fn restore_native_backup_filtered(
        &self,
        password: &[u8],
        bytes: &[u8],
        session_ttl: Duration,
        include_connections: bool,
    ) -> Result<VaultId> {
        validate_session_timeout(session_ttl)?;
        let vault =
            self.store
                .restore_native_backup_filtered(password, bytes, include_connections)?;
        let id = vault.vault_id.clone();
        *self.session.lock().map_err(|_| KeyLeaseError::Storage)? = Some(Session {
            vault,
            idle_timeout: session_ttl,
            last_activity: Utc::now(),
        });
        Ok(id)
    }
}
