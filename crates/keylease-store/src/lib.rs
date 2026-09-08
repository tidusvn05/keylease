//! Atomic encrypted SQLite repository. SQLite never receives item plaintext.

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chrono::{DateTime, Utc};
use keylease_core::{
    AccessLease, AccountId, AgentId, ApprovalRecord, ApprovalState, AuditEvent, ConnectionId,
    ConnectionRecord, DataBudget, DataUsage, GroupId, ItemId, KeyLeaseError, PolicyRule, ProjectId,
    Result, VaultGroup, VaultId, VaultItem, VaultProject,
};
use keylease_crypto::{
    EncryptedItem, PasswordSlot, SecretKey, WrappedKey, create_password_slot, decrypt_item,
    encrypt_item, keyed_digest, unlock_password_slot, unwrap_vault_key, wrap_vault_key,
};
use rand::RngCore;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, TransactionBehavior, backup::Backup, params,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Mutex};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub struct UnlockedVault {
    pub account_id: AccountId,
    pub vault_id: VaultId,
    root_key: SecretKey,
    vault_key: SecretKey,
    pub session_id: String,
}

impl std::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("account_id", &self.account_id)
            .field("vault_id", &self.vault_id)
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

pub struct NativeStore {
    connection: Mutex<Connection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationReplay {
    pub item_id: ItemId,
    pub result_revision: u64,
}

pub struct MutationContext<'a> {
    pub actor: &'a str,
    pub idempotency_key: &'a str,
    pub request_material: &'a [u8],
    pub audit_event: Option<&'a AuditEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationRecord {
    pub migration_id: String,
    pub version: u32,
    pub state: String,
    pub preview_digest: String,
    pub item_count: u64,
    pub applied_at: DateTime<Utc>,
    pub rolled_back_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct TaskBudgetContext {
    pub task_id: String,
    pub connection_id: String,
    pub policy_version: u64,
    pub budget: DataBudget,
    pub initial_usage: DataUsage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRecoveryRecord {
    pub idempotency_key: String,
    pub request_digest: String,
    pub error: KeyLeaseError,
    pub reconciliation_required: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackup {
    pub format: String,
    pub format_version: u32,
    pub created_at: DateTime<Utc>,
    pub account_id: String,
    pub vault_id: String,
    pub password_slot: String,
    pub wrapped_vault_key: String,
    pub items: Vec<BackupObject>,
    pub groups: Vec<BackupObject>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub projects: Vec<BackupObject>,
    pub history: Vec<BackupHistory>,
    pub tombstones: Vec<BackupObject>,
    pub connections: Vec<String>,
    pub mac_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupObject {
    pub id: String,
    pub revision: u64,
    pub envelope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupHistory {
    pub id: String,
    pub revision: u64,
    pub envelope: String,
    pub created_at: String,
}

impl NativeStore {
    /// Copies a consistent SQLite snapshot without changing the source file.
    pub fn snapshot_database(source: &Path, destination: &Path) -> Result<()> {
        let source = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| KeyLeaseError::InvalidRequest {
                reason: "cannot open the existing KeyLease database".into(),
            })?;
        let mut destination = Connection::open(destination).map_err(|_| KeyLeaseError::Storage)?;
        let backup = Backup::new(&source, &mut destination).map_err(|_| KeyLeaseError::Storage)?;
        backup
            .run_to_completion(64, std::time::Duration::from_millis(10), None)
            .map_err(|_| KeyLeaseError::Storage)?;
        drop(backup);
        destination
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|_| KeyLeaseError::Storage)?;
        Ok(())
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let connection = Connection::open(path).map_err(|_| KeyLeaseError::Storage)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if path.to_string_lossy() != ":memory:" {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                    .map_err(|_| KeyLeaseError::Storage)?;
            }
        }
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|_| KeyLeaseError::Storage)?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(|_| KeyLeaseError::Storage)?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| KeyLeaseError::Storage)?;
        connection
            .execute_batch(SCHEMA)
            .map_err(|_| KeyLeaseError::Storage)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn initialize(&self, password: &[u8]) -> Result<UnlockedVault> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let exists: bool = connection
            .query_row("SELECT EXISTS(SELECT 1 FROM vault_meta)", [], |r| r.get(0))
            .map_err(|_| KeyLeaseError::Storage)?;
        if exists {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "vault already initialized".into(),
            });
        }
        let account_id = AccountId::new();
        let vault_id = VaultId::new();
        let root_key = SecretKey::random();
        let vault_key = SecretKey::random();
        let slot = create_password_slot(password, &account_id, &root_key)?;
        let wrapped_vault = wrap_vault_key(&account_id, &vault_id, &root_key, &vault_key)?;
        connection.execute("INSERT INTO vault_meta(account_id,vault_id,password_slot,wrapped_vault_key,schema_version) VALUES(?1,?2,?3,?4,1)",
            params![account_id.0, vault_id.0, json(&slot)?, json(&wrapped_vault)?]).map_err(|_| KeyLeaseError::Storage)?;
        Ok(UnlockedVault {
            account_id,
            vault_id,
            root_key,
            vault_key,
            session_id: random_session_id(),
        })
    }

    pub fn unlock(&self, password: &[u8]) -> Result<UnlockedVault> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let row = connection.query_row("SELECT account_id,vault_id,password_slot,wrapped_vault_key FROM vault_meta LIMIT 1", [], |r| {
            Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?, r.get::<_,String>(2)?, r.get::<_,String>(3)?))
        }).optional().map_err(|_| KeyLeaseError::Storage)?.ok_or_else(|| KeyLeaseError::NotFound { resource: "vault".into() })?;
        let account_id = AccountId(row.0);
        let vault_id = VaultId(row.1);
        let slot: PasswordSlot = from_json(&row.2)?;
        let wrapped_vault: WrappedKey = from_json(&row.3)?;
        let root_key = unlock_password_slot(password, &account_id, &slot)?;
        let vault_key = unwrap_vault_key(&account_id, &vault_id, &root_key, &wrapped_vault)?;
        Ok(UnlockedVault {
            account_id,
            vault_id,
            root_key,
            vault_key,
            session_id: random_session_id(),
        })
    }

    pub fn change_password(&self, unlocked: &UnlockedVault, new_password: &[u8]) -> Result<()> {
        let slot = create_password_slot(new_password, &unlocked.account_id, &unlocked.root_key)?;
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        connection
            .execute("UPDATE vault_meta SET password_slot=?1", [json(&slot)?])
            .map_err(|_| KeyLeaseError::Storage)?;
        Ok(())
    }

    pub fn export_native_backup(&self, unlocked: &UnlockedVault) -> Result<Vec<u8>> {
        let _ = self.list_items(unlocked)?;
        let _ = self.list_groups(unlocked)?;
        let _ = self.list_projects(unlocked)?;
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let (account_id, vault_id, password_slot, wrapped_vault_key): (String, String, String, String) = connection
            .query_row("SELECT account_id,vault_id,password_slot,wrapped_vault_key FROM vault_meta LIMIT 1", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
            .map_err(|_| KeyLeaseError::Storage)?;
        let items =
            read_backup_objects(&connection, "SELECT item_id,revision,envelope FROM items")?;
        let groups =
            read_backup_objects(&connection, "SELECT group_id,revision,envelope FROM groups")?;
        let projects = read_backup_objects(
            &connection,
            "SELECT project_id,revision,envelope FROM projects",
        )?;
        let tombstones = read_backup_objects(
            &connection,
            "SELECT item_id,revision,envelope FROM tombstones",
        )?;
        let mut statement = connection
            .prepare("SELECT item_id,revision,envelope,created_at FROM item_history")
            .map_err(|_| KeyLeaseError::Storage)?;
        let history = statement
            .query_map([], |row| {
                Ok(BackupHistory {
                    id: row.get(0)?,
                    revision: row.get(1)?,
                    envelope: row.get(2)?,
                    created_at: row.get(3)?,
                })
            })
            .map_err(|_| KeyLeaseError::Storage)?
            .map(|row| row.map_err(|_| KeyLeaseError::Storage))
            .collect::<Result<Vec<_>>>()?;
        let mut statement = connection
            .prepare("SELECT record_json FROM connections")
            .map_err(|_| KeyLeaseError::Storage)?;
        let connections = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|_| KeyLeaseError::Storage)?
            .map(|row| row.map_err(|_| KeyLeaseError::Storage))
            .collect::<Result<Vec<_>>>()?;
        let mut backup = NativeBackup {
            format: "keylease-native-backup".into(),
            format_version: 3,
            created_at: Utc::now(),
            account_id,
            vault_id,
            password_slot,
            wrapped_vault_key,
            items,
            groups,
            projects,
            history,
            tombstones,
            connections,
            mac_hex: String::new(),
        };
        backup.mac_hex = native_backup_mac(&backup, &unlocked.vault_key)?;
        serde_json::to_vec(&backup).map_err(|_| KeyLeaseError::Storage)
    }

    pub fn restore_native_backup(&self, password: &[u8], bytes: &[u8]) -> Result<UnlockedVault> {
        let backup: NativeBackup =
            serde_json::from_slice(bytes).map_err(|_| KeyLeaseError::InvalidRequest {
                reason: "invalid native backup".into(),
            })?;
        if backup.format != "keylease-native-backup" || !matches!(backup.format_version, 2 | 3) {
            return Err(KeyLeaseError::UnsupportedVersion {
                version: backup.format_version,
            });
        }
        let account_id = AccountId(backup.account_id.clone());
        let vault_id = VaultId(backup.vault_id.clone());
        let slot: PasswordSlot = from_json(&backup.password_slot)?;
        let wrapped: WrappedKey = from_json(&backup.wrapped_vault_key)?;
        let root_key = unlock_password_slot(password, &account_id, &slot)?;
        let vault_key = unwrap_vault_key(&account_id, &vault_id, &root_key, &wrapped)?;
        let expected_mac = native_backup_mac(&backup, &vault_key)?;
        if expected_mac
            .as_bytes()
            .ct_eq(backup.mac_hex.as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "native backup authentication failed".into(),
            });
        }
        for object in &backup.items {
            validate_backup_envelope(object, &vault_key)?;
        }
        for object in &backup.tombstones {
            validate_backup_tombstone(object, &vault_key)?;
        }
        for object in &backup.groups {
            validate_backup_envelope(object, &vault_key)?;
        }
        for object in &backup.projects {
            validate_backup_envelope(object, &vault_key)?;
        }
        for object in &backup.history {
            let envelope: EncryptedItem = from_json(&object.envelope)?;
            let _ = decrypt_item(&envelope, &vault_key)?;
        }
        let restored_at = backup.created_at.to_rfc3339();
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        let exists: bool = tx
            .query_row("SELECT EXISTS(SELECT 1 FROM vault_meta)", [], |row| {
                row.get(0)
            })
            .map_err(|_| KeyLeaseError::Storage)?;
        if exists {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "restore target is already initialized".into(),
            });
        }
        tx.execute("INSERT INTO vault_meta(account_id,vault_id,password_slot,wrapped_vault_key,schema_version) VALUES(?1,?2,?3,?4,1)",params![backup.account_id,backup.vault_id,backup.password_slot,backup.wrapped_vault_key]).map_err(|_|KeyLeaseError::Storage)?;
        for object in backup.items {
            tx.execute(
                "INSERT INTO items(item_id,revision,envelope,updated_at) VALUES(?1,?2,?3,?4)",
                params![object.id, object.revision, object.envelope, restored_at],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        }
        for object in backup.groups {
            tx.execute(
                "INSERT INTO groups(group_id,revision,envelope) VALUES(?1,?2,?3)",
                params![object.id, object.revision, object.envelope],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        }
        for object in backup.projects {
            tx.execute(
                "INSERT INTO projects(project_id,revision,envelope,updated_at) VALUES(?1,?2,?3,?4)",
                params![object.id, object.revision, object.envelope, restored_at],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        }
        for object in backup.tombstones {
            tx.execute(
                "INSERT INTO tombstones(item_id,revision,envelope,deleted_at) VALUES(?1,?2,?3,?4)",
                params![object.id, object.revision, object.envelope, restored_at],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        }
        for object in backup.history {
            tx.execute("INSERT INTO item_history(item_id,revision,envelope,created_at) VALUES(?1,?2,?3,?4)",params![object.id,object.revision,object.envelope,object.created_at]).map_err(|_|KeyLeaseError::Storage)?;
        }
        for raw in backup.connections {
            let mut record: ConnectionRecord = from_json(&raw)?;
            record.health = keylease_core::ConnectionHealth::Disconnected;
            tx.execute(
                "INSERT INTO connections(connection_id,record_json) VALUES(?1,?2)",
                params![record.id.0, json(&record)?],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        }
        tx.commit().map_err(|_| KeyLeaseError::Storage)?;
        Ok(UnlockedVault {
            account_id,
            vault_id,
            root_key,
            vault_key,
            session_id: random_session_id(),
        })
    }

    pub fn put_item(
        &self,
        unlocked: &UnlockedVault,
        item: &VaultItem,
        expected_revision: Option<u64>,
        context: MutationContext<'_>,
    ) -> Result<u64> {
        if item.vault_id != unlocked.vault_id {
            return Err(KeyLeaseError::Denied {
                reason: "item belongs to another vault".into(),
            });
        }
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        let request_digest = hex_digest(&keyed_digest(
            &unlocked.vault_key,
            "keylease-mutation-journal-v1",
            context.request_material,
        ));
        if let Some((previous_digest, revision)) = transaction.query_row(
            "SELECT request_digest,result_revision FROM mutation_journal WHERE idempotency_key=?1", [context.idempotency_key],
            |r| Ok((r.get::<_,String>(0)?, r.get::<_,u64>(1)?))).optional().map_err(|_| KeyLeaseError::Storage)? {
            return if previous_digest == request_digest { Ok(revision) } else { Err(KeyLeaseError::IdempotencyConflict) };
        }
        let current: Option<(u64, String)> = transaction
            .query_row(
                "SELECT revision,envelope FROM items WHERE item_id=?1",
                [&item.id.0],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)?;
        let actual = current.as_ref().map_or(0, |v| v.0);
        if let Some(expected) = expected_revision
            && expected != actual
        {
            return Err(KeyLeaseError::RevisionConflict {
                expected,
                actual,
                retryable: false,
            });
        }
        let next_revision = actual + 1;
        if item.revision != next_revision {
            return Err(KeyLeaseError::InvalidRequest {
                reason: format!("item revision must be {next_revision}"),
            });
        }
        let plaintext =
            Zeroizing::new(serde_json::to_vec(item).map_err(|_| KeyLeaseError::Storage)?);
        let encrypted = encrypt_item(
            &unlocked.account_id,
            &unlocked.vault_id,
            &item.id,
            item.revision,
            item.schema_version,
            &unlocked.vault_key,
            &plaintext,
        )?;
        let envelope = json(&encrypted)?;
        if let Some((revision, old_envelope)) = current {
            transaction.execute("INSERT INTO item_history(item_id,revision,envelope,created_at) VALUES(?1,?2,?3,?4)",
                params![item.id.0, revision, old_envelope, Utc::now().to_rfc3339()]).map_err(|_| KeyLeaseError::Storage)?;
        }
        transaction.execute("INSERT INTO items(item_id,revision,envelope,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(item_id) DO UPDATE SET revision=excluded.revision,envelope=excluded.envelope,updated_at=excluded.updated_at",
            params![item.id.0, item.revision, envelope, Utc::now().to_rfc3339()]).map_err(|_| KeyLeaseError::Storage)?;
        transaction.execute("INSERT INTO mutation_journal(idempotency_key,request_digest,actor,item_id,base_revision,result_revision,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![context.idempotency_key,request_digest,context.actor,item.id.0,actual,item.revision,Utc::now().to_rfc3339()]).map_err(|_| KeyLeaseError::Storage)?;
        if let Some(event) = context.audit_event {
            transaction
                .execute(
                    "INSERT INTO audit_events(timestamp,event_json) VALUES(?1,?2)",
                    params![event.timestamp.to_rfc3339(), json(event)?],
                )
                .map_err(|_| KeyLeaseError::Storage)?;
        }
        transaction.commit().map_err(|_| KeyLeaseError::Storage)?;
        Ok(item.revision)
    }

    pub fn get_item(&self, unlocked: &UnlockedVault, id: &ItemId) -> Result<VaultItem> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let envelope: String = connection
            .query_row(
                "SELECT envelope FROM items WHERE item_id=?1",
                [&id.0],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)?
            .ok_or_else(|| KeyLeaseError::NotFound {
                resource: id.0.clone(),
            })?;
        decrypt_stored_item(&unlocked.vault_key, &envelope)
    }

    pub fn get_item_at_revision(
        &self,
        unlocked: &UnlockedVault,
        id: &ItemId,
        revision: u64,
    ) -> Result<VaultItem> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let current = connection
            .query_row(
                "SELECT envelope FROM items WHERE item_id=?1 AND revision=?2",
                params![id.0, revision],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)?;
        let envelope = match current {
            Some(envelope) => Some(envelope),
            None => {
                let historical = connection
                    .query_row(
                        "SELECT envelope FROM item_history WHERE item_id=?1 AND revision=?2",
                        params![id.0, revision],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .map_err(|_| KeyLeaseError::Storage)?;
                match historical {
                    Some(envelope) => Some(envelope),
                    None => connection
                        .query_row(
                            "SELECT envelope FROM tombstones WHERE item_id=?1",
                            [&id.0],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()
                        .map_err(|_| KeyLeaseError::Storage)?,
                }
            }
        }
        .ok_or_else(|| KeyLeaseError::NotFound {
            resource: format!("{}@{}", id.0, revision),
        })?;
        let item = decrypt_stored_item(&unlocked.vault_key, &envelope)?;
        if item.revision != revision {
            return Err(KeyLeaseError::NotFound {
                resource: format!("{}@{}", id.0, revision),
            });
        }
        Ok(item)
    }

    pub fn mutation_replay(
        &self,
        unlocked: &UnlockedVault,
        idempotency_key: &str,
        request_material: &[u8],
    ) -> Result<Option<MutationReplay>> {
        let expected_digest = hex_digest(&keyed_digest(
            &unlocked.vault_key,
            "keylease-mutation-journal-v1",
            request_material,
        ));
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let replay = connection
            .query_row(
                "SELECT request_digest,item_id,result_revision FROM mutation_journal WHERE idempotency_key=?1",
                [idempotency_key],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        MutationReplay {
                            item_id: ItemId(row.get(1)?),
                            result_revision: row.get(2)?,
                        },
                    ))
                },
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)?;
        match replay {
            Some((digest, replay)) if digest == expected_digest => Ok(Some(replay)),
            Some(_) => Err(KeyLeaseError::IdempotencyConflict),
            None => Ok(None),
        }
    }

    pub fn item_history(&self, unlocked: &UnlockedVault, id: &ItemId) -> Result<Vec<VaultItem>> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let mut statement = connection
            .prepare("SELECT envelope FROM item_history WHERE item_id=?1 ORDER BY revision DESC")
            .map_err(|_| KeyLeaseError::Storage)?;
        let rows = statement
            .query_map([&id.0], |row| row.get::<_, String>(0))
            .map_err(|_| KeyLeaseError::Storage)?;
        rows.map(|row| {
            decrypt_stored_item(
                &unlocked.vault_key,
                &row.map_err(|_| KeyLeaseError::Storage)?,
            )
        })
        .collect()
    }

    pub fn list_items(&self, unlocked: &UnlockedVault) -> Result<Vec<VaultItem>> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let mut statement = connection
            .prepare("SELECT envelope FROM items ORDER BY updated_at DESC")
            .map_err(|_| KeyLeaseError::Storage)?;
        let rows = statement
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|_| KeyLeaseError::Storage)?;
        rows.map(|row| {
            decrypt_stored_item(
                &unlocked.vault_key,
                &row.map_err(|_| KeyLeaseError::Storage)?,
            )
        })
        .collect()
    }

    pub fn list_migration_records(&self) -> Result<Vec<MigrationRecord>> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let mut statement = connection
            .prepare("SELECT migration_id,version,state,preview_digest,item_count,applied_at,rolled_back_at FROM migration_runs ORDER BY applied_at DESC")
            .map_err(|_| KeyLeaseError::Storage)?;
        statement
            .query_map([], |row| {
                let applied_at: String = row.get(5)?;
                let rolled_back_at: Option<String> = row.get(6)?;
                Ok(MigrationRecord {
                    migration_id: row.get(0)?,
                    version: row.get(1)?,
                    state: row.get(2)?,
                    preview_digest: row.get(3)?,
                    item_count: row.get(4)?,
                    applied_at: DateTime::parse_from_rfc3339(&applied_at)
                        .map(|value| value.with_timezone(&Utc))
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    rolled_back_at: rolled_back_at
                        .map(|value| {
                            DateTime::parse_from_rfc3339(&value)
                                .map(|parsed| parsed.with_timezone(&Utc))
                                .map_err(|_| rusqlite::Error::InvalidQuery)
                        })
                        .transpose()?,
                })
            })
            .map_err(|_| KeyLeaseError::Storage)?
            .map(|row| row.map_err(|_| KeyLeaseError::Storage))
            .collect()
    }

    pub fn apply_item_migration(
        &self,
        unlocked: &UnlockedVault,
        migration_id: &str,
        version: u32,
        preview_digest: &str,
        items: &[VaultItem],
        audit_event: &AuditEvent,
    ) -> Result<u64> {
        let mut encrypted = Vec::with_capacity(items.len());
        for item in items {
            if item.vault_id != unlocked.vault_id || item.revision < 2 {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "migration items must belong to the open vault and advance a revision"
                        .into(),
                });
            }
            let plaintext =
                Zeroizing::new(serde_json::to_vec(item).map_err(|_| KeyLeaseError::Storage)?);
            encrypted.push((
                item,
                json(&encrypt_item(
                    &unlocked.account_id,
                    &unlocked.vault_id,
                    &item.id,
                    item.revision,
                    item.schema_version,
                    &unlocked.vault_key,
                    &plaintext,
                )?)?,
            ));
        }
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        let existing: Option<(String, String, u64)> = transaction
            .query_row(
                "SELECT state,preview_digest,item_count FROM migration_runs WHERE migration_id=?1",
                [migration_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)?;
        if let Some((state, digest, count)) = existing {
            return if state == "applied" && digest == preview_digest {
                Ok(count)
            } else {
                Err(KeyLeaseError::IdempotencyConflict)
            };
        }
        for (item, envelope) in encrypted {
            let (actual, old_envelope): (u64, String) = transaction
                .query_row(
                    "SELECT revision,envelope FROM items WHERE item_id=?1",
                    [&item.id.0],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|_| KeyLeaseError::NotFound {
                    resource: item.id.0.clone(),
                })?;
            let expected = item.revision - 1;
            if actual != expected {
                return Err(KeyLeaseError::RevisionConflict {
                    expected,
                    actual,
                    retryable: false,
                });
            }
            transaction
                .execute(
                    "INSERT INTO migration_checkpoints(migration_id,item_id,original_revision,applied_revision,envelope) VALUES(?1,?2,?3,?4,?5)",
                    params![migration_id, item.id.0, actual, item.revision, old_envelope],
                )
                .map_err(|_| KeyLeaseError::Storage)?;
            transaction
                .execute(
                    "INSERT INTO item_history(item_id,revision,envelope,created_at) VALUES(?1,?2,?3,?4)",
                    params![item.id.0, actual, old_envelope, Utc::now().to_rfc3339()],
                )
                .map_err(|_| KeyLeaseError::Storage)?;
            transaction
                .execute(
                    "UPDATE items SET revision=?1,envelope=?2,updated_at=?3 WHERE item_id=?4",
                    params![item.revision, envelope, Utc::now().to_rfc3339(), item.id.0],
                )
                .map_err(|_| KeyLeaseError::Storage)?;
        }
        let now = Utc::now();
        transaction
            .execute(
                "INSERT INTO migration_runs(migration_id,version,state,preview_digest,item_count,applied_at,rolled_back_at) VALUES(?1,?2,'applied',?3,?4,?5,NULL)",
                params![migration_id, version, preview_digest, items.len() as u64, now.to_rfc3339()],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        transaction
            .execute(
                "INSERT INTO audit_events(timestamp,event_json) VALUES(?1,?2)",
                params![audit_event.timestamp.to_rfc3339(), json(audit_event)?],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        transaction.commit().map_err(|_| KeyLeaseError::Storage)?;
        Ok(items.len() as u64)
    }

    pub fn rollback_item_migration(
        &self,
        unlocked: &UnlockedVault,
        migration_id: &str,
        audit_event: &AuditEvent,
    ) -> Result<u64> {
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        let state: String = transaction
            .query_row(
                "SELECT state FROM migration_runs WHERE migration_id=?1",
                [migration_id],
                |row| row.get(0),
            )
            .map_err(|_| KeyLeaseError::NotFound {
                resource: migration_id.into(),
            })?;
        if state != "applied" {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "only an applied migration can be rolled back".into(),
            });
        }
        let checkpoints = {
            let mut statement = transaction
                .prepare("SELECT item_id,original_revision,applied_revision,envelope FROM migration_checkpoints WHERE migration_id=?1 ORDER BY item_id")
                .map_err(|_| KeyLeaseError::Storage)?;
            statement
                .query_map([migration_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .map_err(|_| KeyLeaseError::Storage)?
                .map(|row| row.map_err(|_| KeyLeaseError::Storage))
                .collect::<Result<Vec<_>>>()?
        };
        for (item_id, _original_revision, applied_revision, old_envelope) in &checkpoints {
            let (actual, current_envelope): (u64, String) = transaction
                .query_row(
                    "SELECT revision,envelope FROM items WHERE item_id=?1",
                    [item_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|_| KeyLeaseError::Storage)?;
            if actual != *applied_revision {
                return Err(KeyLeaseError::RevisionConflict {
                    expected: *applied_revision,
                    actual,
                    retryable: false,
                });
            }
            let mut original = decrypt_stored_item(&unlocked.vault_key, old_envelope)?;
            original.revision = actual + 1;
            original.updated_at = Utc::now();
            let plaintext =
                Zeroizing::new(serde_json::to_vec(&original).map_err(|_| KeyLeaseError::Storage)?);
            let restored_envelope = json(&encrypt_item(
                &unlocked.account_id,
                &unlocked.vault_id,
                &original.id,
                original.revision,
                original.schema_version,
                &unlocked.vault_key,
                &plaintext,
            )?)?;
            transaction
                .execute(
                    "INSERT INTO item_history(item_id,revision,envelope,created_at) VALUES(?1,?2,?3,?4)",
                    params![item_id, actual, current_envelope, Utc::now().to_rfc3339()],
                )
                .map_err(|_| KeyLeaseError::Storage)?;
            transaction
                .execute(
                    "UPDATE items SET revision=?1,envelope=?2,updated_at=?3 WHERE item_id=?4",
                    params![
                        original.revision,
                        restored_envelope,
                        original.updated_at.to_rfc3339(),
                        item_id
                    ],
                )
                .map_err(|_| KeyLeaseError::Storage)?;
        }
        transaction
            .execute(
                "UPDATE migration_runs SET state='rolled_back',rolled_back_at=?1 WHERE migration_id=?2",
                params![Utc::now().to_rfc3339(), migration_id],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        transaction
            .execute(
                "INSERT INTO audit_events(timestamp,event_json) VALUES(?1,?2)",
                params![audit_event.timestamp.to_rfc3339(), json(audit_event)?],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        transaction.commit().map_err(|_| KeyLeaseError::Storage)?;
        Ok(checkpoints.len() as u64)
    }

    pub fn put_group(
        &self,
        unlocked: &UnlockedVault,
        group: &VaultGroup,
        expected_revision: Option<u64>,
        context: Option<MutationContext<'_>>,
    ) -> Result<()> {
        if group.vault_id != unlocked.vault_id {
            return Err(KeyLeaseError::Denied {
                reason: "group belongs to another vault".into(),
            });
        }
        let item_id = ItemId(group.id.0.replacen("group_", "groupitem_", 1));
        let plaintext =
            Zeroizing::new(serde_json::to_vec(group).map_err(|_| KeyLeaseError::Storage)?);
        let envelope = encrypt_item(
            &unlocked.account_id,
            &unlocked.vault_id,
            &item_id,
            group.revision,
            1,
            &unlocked.vault_key,
            &plaintext,
        )?;
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        let request_digest = context.as_ref().map(|context| {
            hex_digest(&keyed_digest(
                &unlocked.vault_key,
                "keylease-mutation-journal-v1",
                context.request_material,
            ))
        });
        if let Some(context) = &context
            && let Some((previous_digest, item_id)) = tx
                .query_row(
                    "SELECT request_digest,item_id FROM mutation_journal WHERE idempotency_key=?1",
                    [context.idempotency_key],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(|_| KeyLeaseError::Storage)?
        {
            return if Some(previous_digest) == request_digest && item_id == group.id.0 {
                Ok(())
            } else {
                Err(KeyLeaseError::IdempotencyConflict)
            };
        }
        let actual: Option<u64> = tx
            .query_row(
                "SELECT revision FROM groups WHERE group_id=?1",
                [&group.id.0],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)?;
        let current = actual.unwrap_or(0);
        if expected_revision.is_some_and(|e| e != current) {
            return Err(KeyLeaseError::RevisionConflict {
                expected: expected_revision.unwrap_or(0),
                actual: current,
                retryable: false,
            });
        }
        if group.revision != current + 1 {
            return Err(KeyLeaseError::InvalidRequest {
                reason: format!("group revision must be {}", current + 1),
            });
        }
        tx.execute("INSERT INTO groups(group_id,revision,envelope) VALUES(?1,?2,?3) ON CONFLICT(group_id) DO UPDATE SET revision=excluded.revision,envelope=excluded.envelope",params![group.id.0,group.revision,json(&envelope)?]).map_err(|_|KeyLeaseError::Storage)?;
        if let Some(context) = context {
            let request_digest = request_digest.ok_or(KeyLeaseError::Storage)?;
            tx.execute("INSERT INTO mutation_journal(idempotency_key,request_digest,actor,item_id,base_revision,result_revision,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![context.idempotency_key,request_digest,context.actor,group.id.0,current,group.revision,Utc::now().to_rfc3339()]).map_err(|_|KeyLeaseError::Storage)?;
            if let Some(event) = context.audit_event {
                tx.execute(
                    "INSERT INTO audit_events(timestamp,event_json) VALUES(?1,?2)",
                    params![event.timestamp.to_rfc3339(), json(event)?],
                )
                .map_err(|_| KeyLeaseError::Storage)?;
            }
        }
        tx.commit().map_err(|_| KeyLeaseError::Storage)
    }

    pub fn get_group(&self, unlocked: &UnlockedVault, id: &GroupId) -> Result<VaultGroup> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let envelope: String = connection
            .query_row(
                "SELECT envelope FROM groups WHERE group_id=?1",
                [&id.0],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)?
            .ok_or_else(|| KeyLeaseError::NotFound {
                resource: id.0.clone(),
            })?;
        let envelope: EncryptedItem = from_json(&envelope)?;
        let bytes = Zeroizing::new(decrypt_item(&envelope, &unlocked.vault_key)?);
        serde_json::from_slice(&bytes).map_err(|_| KeyLeaseError::Crypto)
    }

    pub fn list_groups(&self, unlocked: &UnlockedVault) -> Result<Vec<VaultGroup>> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let mut statement = connection
            .prepare("SELECT envelope FROM groups")
            .map_err(|_| KeyLeaseError::Storage)?;
        let rows = statement
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|_| KeyLeaseError::Storage)?;
        rows.map(|row| {
            let envelope: EncryptedItem = from_json(&row.map_err(|_| KeyLeaseError::Storage)?)?;
            let bytes = Zeroizing::new(decrypt_item(&envelope, &unlocked.vault_key)?);
            serde_json::from_slice(&bytes).map_err(|_| KeyLeaseError::Crypto)
        })
        .collect()
    }

    pub fn put_project(
        &self,
        unlocked: &UnlockedVault,
        project: &VaultProject,
        expected_revision: Option<u64>,
        context: MutationContext<'_>,
    ) -> Result<u64> {
        if project.vault_id != unlocked.vault_id {
            return Err(KeyLeaseError::Denied {
                reason: "project belongs to another vault".into(),
            });
        }
        let object_id = ItemId(project.id.0.replacen("project_", "projectitem_", 1));
        let plaintext =
            Zeroizing::new(serde_json::to_vec(project).map_err(|_| KeyLeaseError::Storage)?);
        let envelope = encrypt_item(
            &unlocked.account_id,
            &unlocked.vault_id,
            &object_id,
            project.revision,
            1,
            &unlocked.vault_key,
            &plaintext,
        )?;
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        let request_digest = hex_digest(&keyed_digest(
            &unlocked.vault_key,
            "keylease-mutation-journal-v1",
            context.request_material,
        ));
        if let Some((previous_digest, result_revision)) = tx
            .query_row(
                "SELECT request_digest,result_revision FROM mutation_journal WHERE idempotency_key=?1",
                [context.idempotency_key],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)),
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)?
        {
            return if previous_digest == request_digest {
                Ok(result_revision)
            } else {
                Err(KeyLeaseError::IdempotencyConflict)
            };
        }
        let current: Option<(u64, String)> = tx
            .query_row(
                "SELECT revision,envelope FROM projects WHERE project_id=?1",
                [&project.id.0],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)?;
        let actual = current.as_ref().map_or(0, |value| value.0);
        if expected_revision.is_some_and(|expected| expected != actual) {
            return Err(KeyLeaseError::RevisionConflict {
                expected: expected_revision.unwrap_or(0),
                actual,
                retryable: false,
            });
        }
        if project.revision != actual + 1 {
            return Err(KeyLeaseError::InvalidRequest {
                reason: format!("project revision must be {}", actual + 1),
            });
        }
        if let Some((revision, old_envelope)) = current {
            tx.execute(
                "INSERT INTO project_history(project_id,revision,envelope,created_at) VALUES(?1,?2,?3,?4)",
                params![project.id.0, revision, old_envelope, Utc::now().to_rfc3339()],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        }
        tx.execute(
            "INSERT INTO projects(project_id,revision,envelope,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(project_id) DO UPDATE SET revision=excluded.revision,envelope=excluded.envelope,updated_at=excluded.updated_at",
            params![project.id.0, project.revision, json(&envelope)?, Utc::now().to_rfc3339()],
        )
        .map_err(|_| KeyLeaseError::Storage)?;
        tx.execute(
            "INSERT INTO mutation_journal(idempotency_key,request_digest,actor,item_id,base_revision,result_revision,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![context.idempotency_key, request_digest, context.actor, project.id.0, actual, project.revision, Utc::now().to_rfc3339()],
        )
        .map_err(|_| KeyLeaseError::Storage)?;
        if let Some(event) = context.audit_event {
            tx.execute(
                "INSERT INTO audit_events(timestamp,event_json) VALUES(?1,?2)",
                params![event.timestamp.to_rfc3339(), json(event)?],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        }
        tx.commit().map_err(|_| KeyLeaseError::Storage)?;
        Ok(project.revision)
    }

    pub fn get_project(&self, unlocked: &UnlockedVault, id: &ProjectId) -> Result<VaultProject> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let envelope: String = connection
            .query_row(
                "SELECT envelope FROM projects WHERE project_id=?1",
                [&id.0],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)?
            .ok_or_else(|| KeyLeaseError::NotFound {
                resource: id.0.clone(),
            })?;
        let envelope: EncryptedItem = from_json(&envelope)?;
        let bytes = Zeroizing::new(decrypt_item(&envelope, &unlocked.vault_key)?);
        serde_json::from_slice(&bytes).map_err(|_| KeyLeaseError::Crypto)
    }

    pub fn list_projects(&self, unlocked: &UnlockedVault) -> Result<Vec<VaultProject>> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let mut statement = connection
            .prepare("SELECT envelope FROM projects ORDER BY updated_at DESC")
            .map_err(|_| KeyLeaseError::Storage)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|_| KeyLeaseError::Storage)?;
        rows.map(|row| {
            let envelope: EncryptedItem = from_json(&row.map_err(|_| KeyLeaseError::Storage)?)?;
            let bytes = Zeroizing::new(decrypt_item(&envelope, &unlocked.vault_key)?);
            serde_json::from_slice(&bytes).map_err(|_| KeyLeaseError::Crypto)
        })
        .collect()
    }

    pub fn import_batch(
        &self,
        unlocked: &UnlockedVault,
        groups: &[VaultGroup],
        items: &[VaultItem],
        batch_id: &str,
    ) -> Result<()> {
        let encrypted_groups = groups
            .iter()
            .map(|group| {
                if group.vault_id != unlocked.vault_id || group.revision != 1 {
                    return Err(KeyLeaseError::InvalidRequest {
                        reason: "imported groups must be new revision-1 objects in the open vault"
                            .into(),
                    });
                }
                let item_id = ItemId(group.id.0.replacen("group_", "groupitem_", 1));
                let plaintext =
                    Zeroizing::new(serde_json::to_vec(group).map_err(|_| KeyLeaseError::Storage)?);
                Ok((
                    group.id.0.clone(),
                    json(&encrypt_item(
                        &unlocked.account_id,
                        &unlocked.vault_id,
                        &item_id,
                        1,
                        1,
                        &unlocked.vault_key,
                        &plaintext,
                    )?)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let encrypted_items = items
            .iter()
            .map(|item| {
                if item.vault_id != unlocked.vault_id || item.revision != 1 {
                    return Err(KeyLeaseError::InvalidRequest {
                        reason: "imported items must be new revision-1 objects in the open vault"
                            .into(),
                    });
                }
                let plaintext =
                    Zeroizing::new(serde_json::to_vec(item).map_err(|_| KeyLeaseError::Storage)?);
                let digest = hex_digest(&keyed_digest(
                    &unlocked.vault_key,
                    "keylease-import-journal-v1",
                    &plaintext,
                ));
                Ok((
                    item.id.0.clone(),
                    json(&encrypt_item(
                        &unlocked.account_id,
                        &unlocked.vault_id,
                        &item.id,
                        1,
                        item.schema_version,
                        &unlocked.vault_key,
                        &plaintext,
                    )?)?,
                    digest,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        for (id, envelope) in encrypted_groups {
            transaction
                .execute(
                    "INSERT INTO groups(group_id,revision,envelope) VALUES(?1,1,?2)",
                    params![id, envelope],
                )
                .map_err(|_| KeyLeaseError::InvalidRequest {
                    reason: "import group conflicts with an existing ID".into(),
                })?;
        }
        for (id, envelope, digest) in encrypted_items {
            transaction
                .execute(
                    "INSERT INTO items(item_id,revision,envelope,updated_at) VALUES(?1,1,?2,?3)",
                    params![id, envelope, Utc::now().to_rfc3339()],
                )
                .map_err(|_| KeyLeaseError::InvalidRequest {
                    reason: "import item conflicts with an existing ID".into(),
                })?;
            transaction.execute("INSERT INTO mutation_journal(idempotency_key,request_digest,actor,item_id,base_revision,result_revision,created_at) VALUES(?1,?2,'local-human',?3,0,1,?4)",params![format!("{batch_id}:{id}"),digest,id,Utc::now().to_rfc3339()]).map_err(|_|KeyLeaseError::Storage)?;
        }
        transaction.commit().map_err(|_| KeyLeaseError::Storage)
    }

    pub fn delete_group(
        &self,
        unlocked: &UnlockedVault,
        id: &GroupId,
        expected_revision: u64,
        context: Option<MutationContext<'_>>,
    ) -> Result<()> {
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        let request_digest = context.as_ref().map(|context| {
            hex_digest(&keyed_digest(
                &unlocked.vault_key,
                "keylease-mutation-journal-v1",
                context.request_material,
            ))
        });
        if let Some(context) = &context
            && let Some((previous_digest, item_id)) = tx
                .query_row(
                    "SELECT request_digest,item_id FROM mutation_journal WHERE idempotency_key=?1",
                    [context.idempotency_key],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(|_| KeyLeaseError::Storage)?
        {
            return if Some(previous_digest) == request_digest && item_id == id.0 {
                Ok(())
            } else {
                Err(KeyLeaseError::IdempotencyConflict)
            };
        }
        let changed = tx
            .execute(
                "DELETE FROM groups WHERE group_id=?1 AND revision=?2",
                params![id.0, expected_revision],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        if changed == 0 {
            return Err(KeyLeaseError::RevisionConflict {
                expected: expected_revision,
                actual: 0,
                retryable: false,
            });
        }
        if let Some(context) = context {
            tx.execute("INSERT INTO mutation_journal(idempotency_key,request_digest,actor,item_id,base_revision,result_revision,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![context.idempotency_key,request_digest.ok_or(KeyLeaseError::Storage)?,context.actor,id.0,expected_revision,expected_revision+1,Utc::now().to_rfc3339()]).map_err(|_|KeyLeaseError::Storage)?;
            if let Some(event) = context.audit_event {
                tx.execute(
                    "INSERT INTO audit_events(timestamp,event_json) VALUES(?1,?2)",
                    params![event.timestamp.to_rfc3339(), json(event)?],
                )
                .map_err(|_| KeyLeaseError::Storage)?;
            }
        }
        tx.commit().map_err(|_| KeyLeaseError::Storage)
    }

    pub fn delete_item(
        &self,
        unlocked: &UnlockedVault,
        id: &ItemId,
        expected_revision: u64,
        context: MutationContext<'_>,
    ) -> Result<()> {
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        let request_digest = hex_digest(&keyed_digest(
            &unlocked.vault_key,
            "keylease-mutation-journal-v1",
            context.request_material,
        ));
        if let Some(previous) = tx
            .query_row(
                "SELECT request_digest FROM mutation_journal WHERE idempotency_key=?1",
                [context.idempotency_key],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)?
        {
            return if previous == request_digest {
                Ok(())
            } else {
                Err(KeyLeaseError::IdempotencyConflict)
            };
        }
        let current: Option<(u64, String)> = tx
            .query_row(
                "SELECT revision,envelope FROM items WHERE item_id=?1",
                [&id.0],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)?;
        let (actual, envelope) = current.ok_or_else(|| KeyLeaseError::NotFound {
            resource: id.0.clone(),
        })?;
        if actual != expected_revision {
            return Err(KeyLeaseError::RevisionConflict {
                expected: expected_revision,
                actual,
                retryable: false,
            });
        }
        tx.execute(
            "INSERT INTO tombstones(item_id,revision,envelope,deleted_at) VALUES(?1,?2,?3,?4)",
            params![id.0, actual + 1, envelope, Utc::now().to_rfc3339()],
        )
        .map_err(|_| KeyLeaseError::Storage)?;
        tx.execute("DELETE FROM items WHERE item_id=?1", [&id.0])
            .map_err(|_| KeyLeaseError::Storage)?;
        tx.execute("INSERT INTO mutation_journal(idempotency_key,request_digest,actor,item_id,base_revision,result_revision,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![context.idempotency_key,request_digest,context.actor,id.0,actual,actual+1,Utc::now().to_rfc3339()]).map_err(|_| KeyLeaseError::Storage)?;
        if let Some(event) = context.audit_event {
            tx.execute(
                "INSERT INTO audit_events(timestamp,event_json) VALUES(?1,?2)",
                params![event.timestamp.to_rfc3339(), json(event)?],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        }
        tx.commit().map_err(|_| KeyLeaseError::Storage)
    }

    pub fn append_audit(&self, event: &AuditEvent) -> Result<()> {
        let payload = json(event)?;
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        connection
            .execute(
                "INSERT INTO audit_events(timestamp,event_json) VALUES(?1,?2)",
                params![event.timestamp.to_rfc3339(), payload],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        Ok(())
    }

    pub fn query_audit(&self, limit: u32) -> Result<Vec<AuditEvent>> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let mut statement = connection
            .prepare("SELECT event_json FROM audit_events ORDER BY seq DESC LIMIT ?1")
            .map_err(|_| KeyLeaseError::Storage)?;
        let rows = statement
            .query_map([limit], |r| r.get::<_, String>(0))
            .map_err(|_| KeyLeaseError::Storage)?;
        rows.map(|row| from_json::<AuditEvent>(&row.map_err(|_| KeyLeaseError::Storage)?))
            .collect()
    }

    pub fn save_approval(&self, approval: &ApprovalRecord) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        connection
            .execute(
                "INSERT OR REPLACE INTO approvals(approval_id,record_json) VALUES(?1,?2)",
                params![approval.id.0, json(approval)?],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        Ok(())
    }

    pub fn save_approval_with_audit(
        &self,
        approval: &ApprovalRecord,
        event: &AuditEvent,
    ) -> Result<()> {
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        tx.execute(
            "INSERT INTO approvals(approval_id,record_json) VALUES(?1,?2)",
            params![approval.id.0, json(approval)?],
        )
        .map_err(|_| KeyLeaseError::Storage)?;
        tx.execute(
            "INSERT INTO audit_events(timestamp,event_json) VALUES(?1,?2)",
            params![event.timestamp.to_rfc3339(), json(event)?],
        )
        .map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().map_err(|_| KeyLeaseError::Storage)
    }

    pub fn decide_pending_approval(
        &self,
        id: &str,
        decision: ApprovalState,
        now: DateTime<Utc>,
        audit_event: Option<&AuditEvent>,
    ) -> Result<ApprovalRecord> {
        if !matches!(
            decision,
            ApprovalState::Approved | ApprovalState::Denied | ApprovalState::Revoked
        ) {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "invalid approval decision state".into(),
            });
        }
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        let raw: String = tx
            .query_row(
                "SELECT record_json FROM approvals WHERE approval_id=?1",
                [id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)?
            .ok_or_else(|| KeyLeaseError::NotFound {
                resource: id.into(),
            })?;
        let mut record: ApprovalRecord = from_json(&raw)?;
        if record.expires_at <= now {
            return Err(KeyLeaseError::Denied {
                reason: "approval has expired".into(),
            });
        }
        if record.state != ApprovalState::Pending {
            return Err(KeyLeaseError::Denied {
                reason: "approval is no longer pending".into(),
            });
        }
        record.state = decision;
        tx.execute(
            "UPDATE approvals SET record_json=?1 WHERE approval_id=?2",
            params![json(&record)?, id],
        )
        .map_err(|_| KeyLeaseError::Storage)?;
        if let Some(event) = audit_event {
            tx.execute(
                "INSERT INTO audit_events(timestamp,event_json) VALUES(?1,?2)",
                params![event.timestamp.to_rfc3339(), json(event)?],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        }
        tx.commit().map_err(|_| KeyLeaseError::Storage)?;
        Ok(record)
    }

    pub fn get_approval(&self, id: &str) -> Result<ApprovalRecord> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let raw: String = connection
            .query_row(
                "SELECT record_json FROM approvals WHERE approval_id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)?
            .ok_or_else(|| KeyLeaseError::NotFound {
                resource: id.into(),
            })?;
        from_json(&raw)
    }

    pub fn list_pending_approvals(
        &self,
        limit: u32,
        now: DateTime<Utc>,
    ) -> Result<Vec<ApprovalRecord>> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let mut statement = connection
            .prepare("SELECT record_json FROM approvals ORDER BY rowid DESC LIMIT ?1")
            .map_err(|_| KeyLeaseError::Storage)?;
        let rows = statement
            .query_map([limit.min(1000)], |row| row.get::<_, String>(0))
            .map_err(|_| KeyLeaseError::Storage)?;
        rows.map(|row| from_json::<ApprovalRecord>(&row.map_err(|_| KeyLeaseError::Storage)?))
            .filter_map(|result| match result {
                Ok(record) if record.state == ApprovalState::Pending && record.expires_at > now => {
                    Some(Ok(record))
                }
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }

    pub fn save_lease(&self, lease: &AccessLease) -> Result<()> {
        let token_hash = hex_digest(lease.token.as_bytes());
        let mut persisted = lease.clone();
        persisted.token.zeroize();
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        connection.execute("INSERT INTO leases(lease_id,token_hash,record_json,remaining_uses,revoked,expires_at) VALUES(?1,?2,?3,?4,0,?5)",
            params![lease.id.0,token_hash,json(&persisted)?,lease.remaining_uses,lease.expires_at.to_rfc3339()]).map_err(|_| KeyLeaseError::Storage)?;
        Ok(())
    }

    pub fn save_lease_consuming_approval(
        &self,
        lease: &AccessLease,
        approval_id: &str,
        request_digest_hex: &str,
        policy_version: u64,
        now: DateTime<Utc>,
    ) -> Result<ApprovalRecord> {
        let token_hash = hex_digest(lease.token.as_bytes());
        let mut persisted = lease.clone();
        persisted.token.zeroize();
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        let raw: String = tx
            .query_row(
                "SELECT record_json FROM approvals WHERE approval_id=?1",
                [approval_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)?
            .ok_or_else(|| KeyLeaseError::NotFound {
                resource: approval_id.into(),
            })?;
        let mut approval: ApprovalRecord = from_json(&raw)?;
        if approval.state != ApprovalState::Approved
            || approval.request_digest_hex != request_digest_hex
            || approval.policy_version != policy_version
            || approval.expires_at <= now
        {
            return Err(KeyLeaseError::Denied {
                reason: "approval is invalid, expired, or bound to another request".into(),
            });
        }
        approval.state = ApprovalState::Consumed;
        tx.execute(
            "UPDATE approvals SET record_json=?1 WHERE approval_id=?2",
            params![json(&approval)?, approval_id],
        )
        .map_err(|_| KeyLeaseError::Storage)?;
        tx.execute(
            "INSERT INTO leases(lease_id,token_hash,record_json,remaining_uses,revoked,expires_at) VALUES(?1,?2,?3,?4,0,?5)",
            params![lease.id.0,token_hash,json(&persisted)?,lease.remaining_uses,lease.expires_at.to_rfc3339()],
        )
        .map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().map_err(|_| KeyLeaseError::Storage)?;
        Ok(approval)
    }

    pub fn lookup_lease(&self, token: &str) -> Result<AccessLease> {
        let hash = hex_digest(token.as_bytes());
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let (raw, remaining, revoked): (String, u64, bool) = connection
            .query_row(
                "SELECT record_json,remaining_uses,revoked FROM leases WHERE token_hash=?1",
                [hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)?
            .ok_or_else(|| KeyLeaseError::Denied {
                reason: "invalid lease token".into(),
            })?;
        let mut lease: AccessLease = from_json(&raw)?;
        lease.token = token.into();
        lease.remaining_uses = remaining;
        lease.revoked = revoked;
        Ok(lease)
    }

    pub fn register_client(&self, agent_id: &AgentId) -> Result<String> {
        let mut raw = [0_u8; 32];
        rand::rng().fill_bytes(&mut raw);
        let token = format!("kl_client_{}", STANDARD_NO_PAD.encode(raw));
        let hash = hex_digest(token.as_bytes());
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        connection
            .execute(
                "INSERT INTO clients(agent_id,token_hash,revoked) VALUES(?1,?2,0)",
                params![agent_id.0, hash],
            )
            .map_err(|_| KeyLeaseError::InvalidRequest {
                reason: "client already registered".into(),
            })?;
        Ok(token)
    }
    /// Creates or rotates the private local desktop credential and records its
    /// role separately from session-scoped policy grants.
    pub fn register_desktop_client(&self, agent_id: &AgentId) -> Result<String> {
        let mut raw = [0_u8; 32];
        rand::rng().fill_bytes(&mut raw);
        let token = format!("kl_client_{}", STANDARD_NO_PAD.encode(raw));
        let hash = hex_digest(token.as_bytes());
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        transaction
            .execute(
                "INSERT INTO clients(agent_id,token_hash,revoked) VALUES(?1,?2,0) ON CONFLICT(agent_id) DO UPDATE SET token_hash=excluded.token_hash,revoked=0",
                params![agent_id.0, hash],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        transaction
            .execute(
                "INSERT OR REPLACE INTO local_client_roles(agent_id,role) VALUES(?1,'desktop_owner')",
                [&agent_id.0],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        transaction.commit().map_err(|_| KeyLeaseError::Storage)?;
        Ok(token)
    }

    pub fn is_desktop_client(&self, agent_id: &AgentId) -> Result<bool> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM local_client_roles WHERE agent_id=?1 AND role='desktop_owner')",
                [&agent_id.0],
                |row| row.get(0),
            )
            .map_err(|_| KeyLeaseError::Storage)
    }
    pub fn authenticate_client(&self, agent_id: &AgentId, token: &str) -> Result<()> {
        let hash = hex_digest(token.as_bytes());
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let valid:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM clients WHERE agent_id=?1 AND token_hash=?2 AND revoked=0)",params![agent_id.0,hash],|r|r.get(0)).map_err(|_|KeyLeaseError::Storage)?;
        if !valid {
            return Err(KeyLeaseError::Denied {
                reason: "client authentication failed".into(),
            });
        }
        Ok(())
    }
    pub fn list_clients(&self) -> Result<Vec<AgentId>> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let mut statement = connection
            .prepare("SELECT agent_id FROM clients WHERE revoked=0 ORDER BY agent_id")
            .map_err(|_| KeyLeaseError::Storage)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|_| KeyLeaseError::Storage)?;
        rows.map(|row| row.map(AgentId).map_err(|_| KeyLeaseError::Storage))
            .collect()
    }
    pub fn revoke_client(&self, agent_id: &AgentId) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let changed = connection
            .execute(
                "UPDATE clients SET revoked=1 WHERE agent_id=?1 AND revoked=0",
                [&agent_id.0],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        if changed == 0 {
            return Err(KeyLeaseError::NotFound {
                resource: agent_id.0.clone(),
            });
        }
        Ok(())
    }
    pub fn save_policy_rule(&self, rule: &PolicyRule) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        connection
            .execute(
                "INSERT OR REPLACE INTO policy_rules(rule_id,record_json) VALUES(?1,?2)",
                params![rule.id, json(rule)?],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        Ok(())
    }
    pub fn replace_policy_rules(&self, rules: &[PolicyRule]) -> Result<()> {
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        transaction
            .execute("DELETE FROM policy_rules", [])
            .map_err(|_| KeyLeaseError::Storage)?;
        for rule in rules {
            transaction
                .execute(
                    "INSERT INTO policy_rules(rule_id,record_json) VALUES(?1,?2)",
                    params![rule.id, json(rule)?],
                )
                .map_err(|_| KeyLeaseError::Storage)?;
        }
        // A new policy version invalidates every outstanding local lease.
        transaction
            .execute("UPDATE leases SET revoked=1 WHERE revoked=0", [])
            .map_err(|_| KeyLeaseError::Storage)?;
        transaction.commit().map_err(|_| KeyLeaseError::Storage)
    }
    pub fn load_policy_rules(&self) -> Result<Vec<PolicyRule>> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let mut stmt = connection
            .prepare("SELECT record_json FROM policy_rules ORDER BY rule_id")
            .map_err(|_| KeyLeaseError::Storage)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|_| KeyLeaseError::Storage)?;
        rows.map(|r| from_json(&r.map_err(|_| KeyLeaseError::Storage)?))
            .collect()
    }
    pub fn delete_policy_rule(&self, id: &str) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let changed = connection
            .execute("DELETE FROM policy_rules WHERE rule_id=?1", [id])
            .map_err(|_| KeyLeaseError::Storage)?;
        if changed == 0 {
            return Err(KeyLeaseError::NotFound {
                resource: id.into(),
            });
        }
        Ok(())
    }
    pub fn revoke_session_authority(&self) -> Result<()> {
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        transaction
            .execute("UPDATE leases SET revoked=1 WHERE revoked=0", [])
            .map_err(|_| KeyLeaseError::Storage)?;
        transaction
            .execute("DELETE FROM approvals", [])
            .map_err(|_| KeyLeaseError::Storage)?;
        transaction
            .execute("DELETE FROM policy_rules", [])
            .map_err(|_| KeyLeaseError::Storage)?;
        transaction.commit().map_err(|_| KeyLeaseError::Storage)
    }
    pub fn save_connection(&self, record: &ConnectionRecord) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        connection
            .execute(
                "INSERT OR REPLACE INTO connections(connection_id,record_json) VALUES(?1,?2)",
                params![record.id.0, json(record)?],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        Ok(())
    }
    pub fn get_connection(&self, id: &ConnectionId) -> Result<ConnectionRecord> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let raw: String = connection
            .query_row(
                "SELECT record_json FROM connections WHERE connection_id=?1",
                [&id.0],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)?
            .ok_or_else(|| KeyLeaseError::NotFound {
                resource: id.0.clone(),
            })?;
        from_json(&raw)
    }
    pub fn list_connections(&self) -> Result<Vec<ConnectionRecord>> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let mut stmt = connection
            .prepare("SELECT record_json FROM connections")
            .map_err(|_| KeyLeaseError::Storage)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|_| KeyLeaseError::Storage)?;
        rows.map(|r| from_json(&r.map_err(|_| KeyLeaseError::Storage)?))
            .collect()
    }

    pub fn revoke_lease(&self, id: &str) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let changed = connection
            .execute("UPDATE leases SET revoked=1 WHERE lease_id=?1", [id])
            .map_err(|_| KeyLeaseError::Storage)?;
        if changed == 0 {
            return Err(KeyLeaseError::NotFound {
                resource: id.into(),
            });
        }
        Ok(())
    }

    pub fn set_kill_switch(&self, enabled: bool) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        connection.execute("INSERT INTO runtime_flags(name,value) VALUES('kill_switch',?1) ON CONFLICT(name) DO UPDATE SET value=excluded.value", [enabled as i64]).map_err(|_| KeyLeaseError::Storage)?;
        Ok(())
    }

    pub fn kill_switch_enabled(&self) -> Result<bool> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        connection
            .query_row(
                "SELECT COALESCE((SELECT value FROM runtime_flags WHERE name='kill_switch'),0)",
                [],
                |row| row.get(0),
            )
            .map_err(|_| KeyLeaseError::Storage)
    }

    /// Atomically reserves a lease use and an idempotency key before connector dispatch.
    pub fn consume_lease(
        &self,
        token: &str,
        request_digest_hex: &str,
        idempotency_key: &str,
        now: DateTime<Utc>,
    ) -> Result<LeaseConsume> {
        self.consume_lease_with_budget(token, request_digest_hex, idempotency_key, now, None)
    }

    /// Atomically reserves a lease use, an idempotency key and the predictable
    /// portion of a cumulative task budget before connector dispatch.
    pub fn consume_lease_with_budget(
        &self,
        token: &str,
        request_digest_hex: &str,
        idempotency_key: &str,
        now: DateTime<Utc>,
        task_budget: Option<&TaskBudgetContext>,
    ) -> Result<LeaseConsume> {
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        let killed: bool = tx
            .query_row(
                "SELECT COALESCE((SELECT value FROM runtime_flags WHERE name='kill_switch'),0)",
                [],
                |r| r.get(0),
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        if killed {
            return Err(KeyLeaseError::Denied {
                reason: "global kill switch is active".into(),
            });
        }
        if let Some(raw) = tx
            .query_row(
                "SELECT record_json FROM execution_failures WHERE idempotency_key=?1",
                [idempotency_key],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)?
        {
            let failure: ExecutionRecoveryRecord = from_json(&raw)?;
            return Err(failure.error);
        }
        if let Some((digest,response)) = tx.query_row("SELECT request_digest,response_json FROM execution_journal WHERE idempotency_key=?1", [idempotency_key], |r| Ok((r.get::<_,String>(0)?,r.get::<_,Option<String>>(1)?))).optional().map_err(|_| KeyLeaseError::Storage)? {
            if digest != request_digest_hex { return Err(KeyLeaseError::IdempotencyConflict); }
            return Ok(LeaseConsume::Replay { response_json: response });
        }
        let token_hash = hex_digest(token.as_bytes());
        let row: Option<(String,u64,bool,String)> = tx.query_row("SELECT record_json,remaining_uses,revoked,expires_at FROM leases WHERE token_hash=?1", [&token_hash],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(|_| KeyLeaseError::Storage)?;
        let (record_json, remaining, revoked, expires) = row.ok_or(KeyLeaseError::Denied {
            reason: "invalid lease token".into(),
        })?;
        if revoked {
            return Err(KeyLeaseError::LeaseRevoked);
        }
        let expires_at = DateTime::parse_from_rfc3339(&expires)
            .map_err(|_| KeyLeaseError::Storage)?
            .with_timezone(&Utc);
        if expires_at <= now {
            return Err(KeyLeaseError::LeaseExpired);
        }
        if remaining == 0 {
            return Err(KeyLeaseError::LeaseExhausted);
        }
        let lease: AccessLease = from_json(&record_json)?;
        if lease.request_digest_hex != request_digest_hex {
            return Err(KeyLeaseError::Denied {
                reason: "lease is bound to a different canonical request".into(),
            });
        }
        if let Some(context) = task_budget {
            reserve_task_usage(&tx, context, &context.initial_usage)?;
        }
        tx.execute(
            "UPDATE leases SET remaining_uses=remaining_uses-1 WHERE token_hash=?1",
            [&token_hash],
        )
        .map_err(|_| KeyLeaseError::Storage)?;
        tx.execute("INSERT INTO execution_journal(idempotency_key,request_digest,status,created_at) VALUES(?1,?2,'reserved',?3)", params![idempotency_key,request_digest_hex,now.to_rfc3339()]).map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().map_err(|_| KeyLeaseError::Storage)?;
        Ok(LeaseConsume::Reserved {
            lease: Box::new(lease),
        })
    }

    pub fn complete_execution(
        &self,
        idempotency_key: &str,
        response_json: &str,
        audit_event: Option<&AuditEvent>,
    ) -> Result<()> {
        self.complete_execution_with_usage(
            idempotency_key,
            response_json,
            audit_event,
            None,
            &DataUsage::default(),
            false,
        )
    }

    pub fn complete_execution_with_usage(
        &self,
        idempotency_key: &str,
        response_json: &str,
        audit_event: Option<&AuditEvent>,
        task_budget: Option<&TaskBudgetContext>,
        completion_usage: &DataUsage,
        reconciliation_required_on_budget_failure: bool,
    ) -> Result<()> {
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        if let Some(context) = task_budget
            && let Err(error) = reserve_task_usage(&transaction, context, completion_usage)
        {
            let request_digest: String = transaction
                .query_row(
                    "SELECT request_digest FROM execution_journal WHERE idempotency_key=?1",
                    [idempotency_key],
                    |row| row.get(0),
                )
                .map_err(|_| KeyLeaseError::Storage)?;
            let failure = ExecutionRecoveryRecord {
                idempotency_key: idempotency_key.into(),
                request_digest,
                error: error.clone(),
                reconciliation_required: reconciliation_required_on_budget_failure,
                created_at: Utc::now(),
            };
            transaction
                .execute(
                    "INSERT OR REPLACE INTO execution_failures(idempotency_key,record_json,reconciliation_required,created_at) VALUES(?1,?2,?3,?4)",
                    params![idempotency_key, json(&failure)?, reconciliation_required_on_budget_failure, failure.created_at.to_rfc3339()],
                )
                .map_err(|_| KeyLeaseError::Storage)?;
            transaction
                .execute(
                    "UPDATE execution_journal SET status='budget_denied' WHERE idempotency_key=?1 AND status='reserved'",
                    [idempotency_key],
                )
                .map_err(|_| KeyLeaseError::Storage)?;
            transaction.commit().map_err(|_| KeyLeaseError::Storage)?;
            return Err(error);
        }
        let changed = transaction.execute("UPDATE execution_journal SET status='complete',response_json=?1 WHERE idempotency_key=?2 AND status='reserved'", params![response_json,idempotency_key]).map_err(|_| KeyLeaseError::Storage)?;
        if changed != 1 {
            return Err(KeyLeaseError::Storage);
        }
        if let Some(event) = audit_event {
            transaction
                .execute(
                    "INSERT INTO audit_events(timestamp,event_json) VALUES(?1,?2)",
                    params![event.timestamp.to_rfc3339(), json(event)?],
                )
                .map_err(|_| KeyLeaseError::Storage)?;
        }
        transaction.commit().map_err(|_| KeyLeaseError::Storage)
    }

    pub fn mark_execution_failed(
        &self,
        idempotency_key: &str,
        error: &KeyLeaseError,
        reconciliation_required: bool,
    ) -> Result<ExecutionRecoveryRecord> {
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        let request_digest: String = tx
            .query_row(
                "SELECT request_digest FROM execution_journal WHERE idempotency_key=?1 AND status='reserved'",
                [idempotency_key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)?
            .ok_or_else(|| KeyLeaseError::NotFound {
                resource: idempotency_key.into(),
            })?;
        let record = ExecutionRecoveryRecord {
            idempotency_key: idempotency_key.into(),
            request_digest,
            error: error.clone(),
            reconciliation_required,
            created_at: Utc::now(),
        };
        tx.execute(
            "UPDATE execution_journal SET status=?1 WHERE idempotency_key=?2 AND status='reserved'",
            params![
                if reconciliation_required {
                    "failed_uncertain"
                } else {
                    "failed_safe"
                },
                idempotency_key
            ],
        )
        .map_err(|_| KeyLeaseError::Storage)?;
        tx.execute(
            "INSERT OR REPLACE INTO execution_failures(idempotency_key,record_json,reconciliation_required,created_at) VALUES(?1,?2,?3,?4)",
            params![idempotency_key, json(&record)?, reconciliation_required, record.created_at.to_rfc3339()],
        )
        .map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().map_err(|_| KeyLeaseError::Storage)?;
        Ok(record)
    }

    pub fn list_execution_recovery(&self, limit: u32) -> Result<Vec<ExecutionRecoveryRecord>> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let mut statement = connection
            .prepare(
                "SELECT record_json FROM execution_failures WHERE reconciliation_required=1 ORDER BY created_at DESC LIMIT ?1",
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        let rows = statement
            .query_map([limit.min(1000)], |row| row.get::<_, String>(0))
            .map_err(|_| KeyLeaseError::Storage)?;
        rows.map(|row| from_json(&row.map_err(|_| KeyLeaseError::Storage)?))
            .collect()
    }

    pub fn task_usage(&self, task_id: &str, connection_id: &str) -> Result<DataUsage> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        connection
            .query_row(
                "SELECT requests,items,cells,response_bytes,rows_changed FROM task_budget_usage WHERE task_id=?1 AND connection_id=?2",
                params![task_id, connection_id],
                |row| {
                    Ok(DataUsage {
                        requests: row.get(0)?,
                        items: row.get(1)?,
                        cells: row.get(2)?,
                        response_bytes: row.get(3)?,
                        rows_changed: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)
            .map(|value| value.unwrap_or_default())
    }

    pub fn raw_item_ciphertext(&self, id: &ItemId) -> Result<String> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        connection
            .query_row(
                "SELECT envelope FROM items WHERE item_id=?1",
                [&id.0],
                |r| r.get(0),
            )
            .map_err(|_| KeyLeaseError::Storage)
    }
    #[cfg(test)]
    fn open_in_memory_for_test() -> Self {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(SCHEMA).unwrap();
        Self {
            connection: Mutex::new(connection),
        }
    }
}

#[derive(Debug)]
pub enum LeaseConsume {
    Reserved { lease: Box<AccessLease> },
    Replay { response_json: Option<String> },
}

fn decrypt_stored_item(vault_key: &SecretKey, raw: &str) -> Result<VaultItem> {
    let envelope: EncryptedItem = from_json(raw)?;
    let plaintext = Zeroizing::new(decrypt_item(&envelope, vault_key)?);
    serde_json::from_slice(&plaintext).map_err(|_| KeyLeaseError::Crypto)
}
fn read_backup_objects(connection: &Connection, sql: &str) -> Result<Vec<BackupObject>> {
    let mut statement = connection
        .prepare(sql)
        .map_err(|_| KeyLeaseError::Storage)?;
    let rows = statement
        .query_map([], |row| {
            Ok(BackupObject {
                id: row.get(0)?,
                revision: row.get(1)?,
                envelope: row.get(2)?,
            })
        })
        .map_err(|_| KeyLeaseError::Storage)?;
    rows.map(|row| row.map_err(|_| KeyLeaseError::Storage))
        .collect()
}
fn validate_backup_envelope(object: &BackupObject, vault_key: &SecretKey) -> Result<()> {
    let envelope: EncryptedItem = from_json(&object.envelope)?;
    if envelope.revision != object.revision {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "backup object revision mismatch".into(),
        });
    }
    let _ = decrypt_item(&envelope, vault_key)?;
    Ok(())
}
fn validate_backup_tombstone(object: &BackupObject, vault_key: &SecretKey) -> Result<()> {
    let envelope: EncryptedItem = from_json(&object.envelope)?;
    if envelope.revision.saturating_add(1) != object.revision {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "backup tombstone revision mismatch".into(),
        });
    }
    let _ = decrypt_item(&envelope, vault_key)?;
    Ok(())
}
fn native_backup_mac(backup: &NativeBackup, vault_key: &SecretKey) -> Result<String> {
    let mut authenticated = backup.clone();
    authenticated.mac_hex.clear();
    let material = serde_json::to_vec(&authenticated).map_err(|_| KeyLeaseError::Storage)?;
    Ok(hex_digest(&keyed_digest(
        vault_key,
        if backup.format_version == 2 {
            "keylease-native-backup-v2"
        } else {
            "keylease-native-backup-v3"
        },
        &material,
    )))
}
fn json<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|_| KeyLeaseError::Storage)
}
fn from_json<T: serde::de::DeserializeOwned>(value: &str) -> Result<T> {
    serde_json::from_str(value).map_err(|_| KeyLeaseError::Storage)
}
fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn random_session_id() -> String {
    let mut b = [0_u8; 24];
    rand::rng().fill_bytes(&mut b);
    format!("session_{}", STANDARD_NO_PAD.encode(b))
}

fn reserve_task_usage(
    transaction: &rusqlite::Transaction<'_>,
    context: &TaskBudgetContext,
    addition: &DataUsage,
) -> Result<()> {
    let current = transaction
        .query_row(
            "SELECT requests,items,cells,response_bytes,rows_changed FROM task_budget_usage WHERE task_id=?1 AND connection_id=?2",
            params![context.task_id, context.connection_id],
            |row| {
                Ok(DataUsage {
                    requests: row.get(0)?,
                    items: row.get(1)?,
                    cells: row.get(2)?,
                    response_bytes: row.get(3)?,
                    rows_changed: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|_| KeyLeaseError::Storage)?
        .unwrap_or_default();
    let next = current
        .checked_add(addition)
        .ok_or_else(|| KeyLeaseError::Denied {
            reason: "task data budget counter overflow".into(),
        })?;
    if !next.fits_task_budget(&context.budget) {
        return Err(KeyLeaseError::Denied {
            reason: "cumulative task data budget exceeded".into(),
        });
    }
    transaction
        .execute(
            "INSERT INTO task_budget_usage(task_id,connection_id,policy_version,requests,items,cells,response_bytes,rows_changed) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(task_id,connection_id) DO UPDATE SET policy_version=excluded.policy_version,requests=excluded.requests,items=excluded.items,cells=excluded.cells,response_bytes=excluded.response_bytes,rows_changed=excluded.rows_changed",
            params![
                context.task_id,
                context.connection_id,
                context.policy_version,
                next.requests,
                next.items,
                next.cells,
                next.response_bytes,
                next.rows_changed,
            ],
        )
        .map_err(|_| KeyLeaseError::Storage)?;
    Ok(())
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS vault_meta(account_id TEXT PRIMARY KEY,vault_id TEXT NOT NULL,password_slot TEXT NOT NULL,wrapped_vault_key TEXT NOT NULL,schema_version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS items(item_id TEXT PRIMARY KEY,revision INTEGER NOT NULL,envelope TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS groups(group_id TEXT PRIMARY KEY,revision INTEGER NOT NULL,envelope TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS projects(project_id TEXT PRIMARY KEY,revision INTEGER NOT NULL,envelope TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS project_history(project_id TEXT NOT NULL,revision INTEGER NOT NULL,envelope TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(project_id,revision));
CREATE TABLE IF NOT EXISTS item_history(item_id TEXT NOT NULL,revision INTEGER NOT NULL,envelope TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(item_id,revision));
CREATE TABLE IF NOT EXISTS tombstones(item_id TEXT PRIMARY KEY,revision INTEGER NOT NULL,envelope TEXT NOT NULL,deleted_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS mutation_journal(idempotency_key TEXT PRIMARY KEY,request_digest TEXT NOT NULL,actor TEXT NOT NULL,item_id TEXT NOT NULL,base_revision INTEGER NOT NULL,result_revision INTEGER NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,timestamp TEXT NOT NULL,event_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS approvals(approval_id TEXT PRIMARY KEY,record_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS leases(lease_id TEXT PRIMARY KEY,token_hash TEXT UNIQUE NOT NULL,record_json TEXT NOT NULL,remaining_uses INTEGER NOT NULL,revoked INTEGER NOT NULL,expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS execution_journal(idempotency_key TEXT PRIMARY KEY,request_digest TEXT NOT NULL,status TEXT NOT NULL,response_json TEXT,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS execution_failures(idempotency_key TEXT PRIMARY KEY,record_json TEXT NOT NULL,reconciliation_required INTEGER NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS task_budget_usage(task_id TEXT NOT NULL,connection_id TEXT NOT NULL,policy_version INTEGER NOT NULL,requests INTEGER NOT NULL,items INTEGER NOT NULL,cells INTEGER NOT NULL,response_bytes INTEGER NOT NULL,rows_changed INTEGER NOT NULL,PRIMARY KEY(task_id,connection_id));
CREATE TABLE IF NOT EXISTS runtime_flags(name TEXT PRIMARY KEY,value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS migration_runs(migration_id TEXT PRIMARY KEY,version INTEGER NOT NULL,state TEXT NOT NULL,preview_digest TEXT NOT NULL,item_count INTEGER NOT NULL,applied_at TEXT NOT NULL,rolled_back_at TEXT);
CREATE TABLE IF NOT EXISTS migration_checkpoints(migration_id TEXT NOT NULL,item_id TEXT NOT NULL,original_revision INTEGER NOT NULL,applied_revision INTEGER NOT NULL,envelope TEXT NOT NULL,PRIMARY KEY(migration_id,item_id));
CREATE TABLE IF NOT EXISTS clients(agent_id TEXT PRIMARY KEY,token_hash TEXT NOT NULL,revoked INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS local_client_roles(agent_id TEXT PRIMARY KEY,role TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS policy_rules(rule_id TEXT PRIMARY KEY,record_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS connections(connection_id TEXT PRIMARY KEY,record_json TEXT NOT NULL);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use keylease_core::{GroupId, ItemStatus};

    fn item(vault: &VaultId) -> VaultItem {
        let now = Utc::now();
        VaultItem {
            id: ItemId::new(),
            vault_id: vault.clone(),
            group_id: GroupId::new(),
            kind: "core.login".into(),
            title: "Example".into(),
            sections: vec![],
            fields: vec![],
            urls: vec![],
            tags: vec![],
            favorite: false,
            attachments: vec![],
            notes: Some("plaintext marker".into()),
            template_version: 1,
            project_id: None,
            agent_access: keylease_core::AgentAccess::None,
            content_metadata: None,
            schema_version: 1,
            revision: 1,
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
        }
    }

    #[test]
    fn ciphertext_only_revision_and_password_rewrap() {
        let dir = tempfile::tempdir().unwrap();
        let store = NativeStore::open(dir.path().join("v.sqlite")).unwrap();
        let unlocked = store.initialize(b"old password").unwrap();
        let value = item(&unlocked.vault_id);
        store
            .put_item(
                &unlocked,
                &value,
                Some(0),
                MutationContext {
                    actor: "human",
                    idempotency_key: "create-1",
                    request_material: b"digest-1",
                    audit_event: None,
                },
            )
            .unwrap();
        let before = store.raw_item_ciphertext(&value.id).unwrap();
        assert!(!before.contains("plaintext marker"));
        store.change_password(&unlocked, b"new password").unwrap();
        let after = store.raw_item_ciphertext(&value.id).unwrap();
        assert_eq!(before, after);
        assert!(store.unlock(b"old password").is_err());
        let reopened = store.unlock(b"new password").unwrap();
        assert_eq!(
            store.get_item(&reopened, &value.id).unwrap().title,
            "Example"
        );
    }

    #[test]
    fn optimistic_revision_and_idempotency() {
        let store = NativeStore::open_in_memory_for_test();
        let unlocked = store.initialize(b"password").unwrap();
        let mut value = item(&unlocked.vault_id);
        assert_eq!(
            store
                .put_item(
                    &unlocked,
                    &value,
                    Some(0),
                    MutationContext {
                        actor: "agent",
                        idempotency_key: "same",
                        request_material: b"digest-a",
                        audit_event: None,
                    },
                )
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .put_item(
                    &unlocked,
                    &value,
                    Some(0),
                    MutationContext {
                        actor: "agent",
                        idempotency_key: "same",
                        request_material: b"digest-a",
                        audit_event: None,
                    },
                )
                .unwrap(),
            1
        );
        value.revision = 2;
        value.title = "changed".into();
        assert!(matches!(
            store.put_item(
                &unlocked,
                &value,
                Some(0),
                MutationContext {
                    actor: "agent",
                    idempotency_key: "other",
                    request_material: b"digest-b",
                    audit_event: None,
                },
            ),
            Err(KeyLeaseError::RevisionConflict { .. })
        ));
    }

    #[test]
    fn concurrent_lease_consumption_cannot_exceed_max_uses() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(NativeStore::open(dir.path().join("leases.sqlite")).unwrap());
        let lease = AccessLease {
            id: keylease_core::LeaseId::new(),
            token: "kl_live_fixture".into(),
            request_digest_hex: "digest".into(),
            policy_version: 1,
            action: "fake.write".into(),
            resource: "fake:resource/1".into(),
            audience: "fake".into(),
            expires_at: Utc::now() + chrono::Duration::minutes(1),
            max_uses: 3,
            remaining_uses: 3,
            budget: Default::default(),
            approval_id: None,
            session_id: "s".into(),
            revoked: false,
        };
        store.save_lease(&lease).unwrap();
        let handles: Vec<_> = (0..12)
            .map(|i| {
                let store = store.clone();
                std::thread::spawn(move || {
                    store.consume_lease(
                        "kl_live_fixture",
                        "digest",
                        &format!("attempt-{i}"),
                        Utc::now(),
                    )
                })
            })
            .collect();
        let reserved = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|result| matches!(result, Ok(LeaseConsume::Reserved { .. })))
            .count();
        assert_eq!(reserved, 3);
    }

    #[test]
    fn cumulative_task_budget_is_reserved_atomically_and_survives_replay() {
        let store = NativeStore::open_in_memory_for_test();
        let lease = AccessLease {
            id: keylease_core::LeaseId::new(),
            token: "kl_live_task_budget".into(),
            request_digest_hex: "task-digest".into(),
            policy_version: 3,
            action: "fake.resource.read".into(),
            resource: "fake:resource/1".into(),
            audience: "fake".into(),
            expires_at: Utc::now() + chrono::Duration::minutes(1),
            max_uses: 3,
            remaining_uses: 3,
            budget: DataBudget {
                max_task_requests: Some(1),
                max_task_response_bytes: Some(4),
                ..Default::default()
            },
            approval_id: None,
            session_id: "s".into(),
            revoked: false,
        };
        store.save_lease(&lease).unwrap();
        let context = TaskBudgetContext {
            task_id: "task-one".into(),
            connection_id: "conn-one".into(),
            policy_version: 3,
            budget: lease.budget.clone(),
            initial_usage: DataUsage {
                requests: 1,
                ..Default::default()
            },
        };
        assert!(matches!(
            store
                .consume_lease_with_budget(
                    &lease.token,
                    "task-digest",
                    "task-operation-one",
                    Utc::now(),
                    Some(&context),
                )
                .unwrap(),
            LeaseConsume::Reserved { .. }
        ));
        assert!(matches!(
            store.consume_lease_with_budget(
                &lease.token,
                "task-digest",
                "task-operation-two",
                Utc::now(),
                Some(&context),
            ),
            Err(KeyLeaseError::Denied { reason }) if reason.contains("cumulative task")
        ));
        assert_eq!(
            store.task_usage("task-one", "conn-one").unwrap().requests,
            1
        );

        let completion = store.complete_execution_with_usage(
            "task-operation-one",
            "{}",
            None,
            Some(&context),
            &DataUsage {
                response_bytes: 5,
                ..Default::default()
            },
            true,
        );
        assert!(matches!(completion, Err(KeyLeaseError::Denied { .. })));
        let recovery = store.list_execution_recovery(10).unwrap();
        assert_eq!(recovery.len(), 1);
        assert!(recovery[0].reconciliation_required);
        assert!(matches!(
            store.consume_lease(
                &lease.token,
                "task-digest",
                "task-operation-one",
                Utc::now()
            ),
            Err(KeyLeaseError::Denied { .. })
        ));
    }

    #[test]
    fn approval_consumption_and_lease_issue_are_atomic_and_single_use() {
        let store = std::sync::Arc::new(NativeStore::open_in_memory_for_test());
        let approval = ApprovalRecord {
            id: keylease_core::ApprovalId::new(),
            request_digest_hex: "exact-digest".into(),
            policy_version: 7,
            state: ApprovalState::Pending,
            expires_at: Utc::now() + chrono::Duration::minutes(1),
            request_id: None,
            agent_id: None,
            connection_id: None,
            action: None,
            resource: None,
            created_at: None,
            task_id: None,
            risk: None,
            semantic_summary: None,
        };
        store.save_approval(&approval).unwrap();
        store
            .decide_pending_approval(&approval.id.0, ApprovalState::Approved, Utc::now(), None)
            .unwrap();
        let handles = (0..8)
            .map(|index| {
                let store = store.clone();
                let id = approval.id.0.clone();
                std::thread::spawn(move || {
                    let lease = AccessLease {
                        id: keylease_core::LeaseId::new(),
                        token: format!("kl_live_approval_{index}"),
                        request_digest_hex: "exact-digest".into(),
                        policy_version: 7,
                        action: "fake.write".into(),
                        resource: "fake:resource/1".into(),
                        audience: "fake".into(),
                        expires_at: Utc::now() + chrono::Duration::minutes(1),
                        max_uses: 1,
                        remaining_uses: 1,
                        budget: Default::default(),
                        approval_id: Some(keylease_core::ApprovalId(id.clone())),
                        session_id: "s".into(),
                        revoked: false,
                    };
                    store.save_lease_consuming_approval(&lease, &id, "exact-digest", 7, Utc::now())
                })
            })
            .collect::<Vec<_>>();
        let consumed = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(Result::is_ok)
            .count();
        assert_eq!(consumed, 1);
        assert_eq!(
            store
                .connection
                .lock()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM leases", [], |row| row
                    .get::<_, u64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn native_backup_is_ciphertext_only_and_excludes_active_authorization() {
        let source = NativeStore::open_in_memory_for_test();
        let unlocked = source.initialize(b"backup password").unwrap();
        let value = item(&unlocked.vault_id);
        source
            .put_item(
                &unlocked,
                &value,
                Some(0),
                MutationContext {
                    actor: "human",
                    idempotency_key: "backup-item",
                    request_material: b"backup-digest",
                    audit_event: None,
                },
            )
            .unwrap();
        let deleted = item(&unlocked.vault_id);
        source
            .put_item(
                &unlocked,
                &deleted,
                Some(0),
                MutationContext {
                    actor: "human",
                    idempotency_key: "deleted-item",
                    request_material: b"deleted-item-create",
                    audit_event: None,
                },
            )
            .unwrap();
        source
            .delete_item(
                &unlocked,
                &deleted.id,
                1,
                MutationContext {
                    actor: "human",
                    idempotency_key: "deleted-item-remove",
                    request_material: b"deleted-item-remove",
                    audit_event: None,
                },
            )
            .unwrap();
        let now = Utc::now();
        let project = VaultProject {
            id: ProjectId::new(),
            vault_id: unlocked.vault_id.clone(),
            slug: "backup-project".into(),
            name: "Backup Project".into(),
            revision: 1,
            created_by: AgentId("agent_backup".into()),
            updated_by: AgentId("agent_backup".into()),
            created_at: now,
            updated_at: now,
            archived_at: None,
        };
        source
            .put_project(
                &unlocked,
                &project,
                Some(0),
                MutationContext {
                    actor: "agent_backup",
                    idempotency_key: "backup-project",
                    request_material: b"backup-project-digest",
                    audit_event: None,
                },
            )
            .unwrap();
        let agent = AgentId("agent_backup".into());
        let token = source.register_client(&agent).unwrap();
        source
            .save_policy_rule(&PolicyRule {
                id: "sensitive-grant".into(),
                version: 1,
                effect: keylease_core::PolicyEffect::Allow,
                agent_id: Some(agent),
                connection_id: None,
                resource_prefix: "kl://".into(),
                actions: vec!["entry:read_secret".into()],
                argument_equals: Default::default(),
                not_before: None,
                expires_at: None,
                max_lease_ttl_seconds: 60,
                max_uses: 1,
                budget: Default::default(),
            })
            .unwrap();
        let bytes = source.export_native_backup(&unlocked).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(!text.contains("plaintext marker"));
        assert!(!text.contains(&token));
        assert!(!text.contains("sensitive-grant"));
        let restored = NativeStore::open_in_memory_for_test();
        let session = restored
            .restore_native_backup(b"backup password", &bytes)
            .unwrap();
        assert_eq!(
            restored
                .get_item(&session, &value.id)
                .unwrap()
                .notes
                .as_deref(),
            Some("plaintext marker")
        );
        assert_eq!(
            restored.get_project(&session, &project.id).unwrap(),
            project
        );
        assert_eq!(
            restored
                .get_item_at_revision(&session, &deleted.id, 1)
                .unwrap()
                .id,
            deleted.id
        );
        assert!(restored.load_policy_rules().unwrap().is_empty());

        let mut tampered: NativeBackup = serde_json::from_slice(&bytes).unwrap();
        tampered.created_at += chrono::Duration::seconds(1);
        let tampered_bytes = serde_json::to_vec(&tampered).unwrap();
        let tampered_target = NativeStore::open_in_memory_for_test();
        assert!(matches!(
            tampered_target.restore_native_backup(b"backup password", &tampered_bytes),
            Err(KeyLeaseError::InvalidRequest { reason })
                if reason == "native backup authentication failed"
        ));
    }
    #[test]
    fn completed_execution_replay_survives_daemon_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.sqlite");
        let store = NativeStore::open(&path).unwrap();
        let lease = AccessLease {
            id: keylease_core::LeaseId::new(),
            token: "kl_live_restart".into(),
            request_digest_hex: "digest".into(),
            policy_version: 1,
            action: "fake.write".into(),
            resource: "fake:resource/1".into(),
            audience: "fake".into(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            max_uses: 1,
            remaining_uses: 1,
            budget: Default::default(),
            approval_id: None,
            session_id: "vault-session".into(),
            revoked: false,
        };
        store.save_lease(&lease).unwrap();
        assert!(matches!(
            store
                .consume_lease(&lease.token, "digest", "idem", Utc::now())
                .unwrap(),
            LeaseConsume::Reserved { .. }
        ));
        store
            .complete_execution("idem", r#"{"written":true}"#, None)
            .unwrap();
        drop(store);
        let reopened = NativeStore::open(&path).unwrap();
        assert!(matches!(
            reopened
                .consume_lease(&lease.token, "digest", "idem", Utc::now())
                .unwrap(),
            LeaseConsume::Replay {
                response_json: Some(_)
            }
        ));
    }
    #[test]
    fn interrupted_transaction_exposes_neither_ciphertext_nor_revision() {
        let store = NativeStore::open_in_memory_for_test();
        {
            let mut connection = store.connection.lock().unwrap();
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            transaction.execute("INSERT INTO items(item_id,revision,envelope,updated_at) VALUES('partial',9,'partial-ciphertext','now')",[]).unwrap();
        }
        let connection = store.connection.lock().unwrap();
        let count: u64 = connection
            .query_row(
                "SELECT COUNT(*) FROM items WHERE item_id='partial'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mutations: u64 = connection
            .query_row(
                "SELECT COUNT(*) FROM mutation_journal WHERE item_id='partial'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((count, mutations), (0, 0));
    }
    #[test]
    fn import_batch_rolls_back_every_object_on_conflict() {
        let store = NativeStore::open_in_memory_for_test();
        let unlocked = store.initialize(b"password").unwrap();
        let now = Utc::now();
        let group = VaultGroup {
            id: GroupId::new(),
            vault_id: unlocked.vault_id.clone(),
            parent_id: None,
            name: "one".into(),
            purpose: keylease_core::GroupPurpose::User,
            sort_order: None,
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        assert!(
            store
                .import_batch(&unlocked, &[group.clone(), group], &[], "batch")
                .is_err()
        );
        assert!(store.list_groups(&unlocked).unwrap().is_empty());
    }
}
