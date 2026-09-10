//! Vault provisioning: the operations that exist before there is a client.
//!
//! Initialising a vault, restoring a backup and registering the first owner
//! credential cannot be authenticated, because until they have run there is no
//! credential to authenticate with. On desktop that is why they are CLI
//! subcommands that open SQLite directly rather than daemon commands: putting
//! them on the Unix socket would let any process running as the same user mint
//! itself an owner token, which is exactly what the "Local IPC spoofing"
//! control in the threat model exists to prevent.
//!
//! A phone still needs them, so they live here — in a **separate enum with a
//! separate dispatcher**. That separation, not the `provisioning` cargo
//! feature, is the actual guarantee: no string in [`crate::RpcRequest`] routes
//! here, so the socket transport cannot reach these operations however it is
//! built. `tests/parity.rs` asserts that.
//!
//! The cargo feature is a second, weaker layer that keeps the code out of a
//! binary that does not need it. It cannot be relied on inside a workspace
//! build, where cargo unifies features across crates.

use chrono::Duration;
use keylease_core::{KeyLeaseError, LocalOwnerRole, Result};
use keylease_service::KeyLeaseService;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::encode_response;

/// A vault lifecycle operation.
///
/// Deliberately not part of [`crate::RpcRequest`].
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "provision", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProvisionRequest {
    /// Reports whether this database already holds a vault, and who owns it.
    Inspect,

    /// Adopts an existing vault from an encrypted desktop backup.
    ///
    /// This is the path a phone should normally take. See [`Self::Create`].
    RestoreBackup {
        /// A file the caller has already copied into app-private storage.
        source_path: String,
        password: String,
        session_ttl_seconds: i64,
    },

    /// Creates a brand new, standalone vault.
    ///
    /// `NativeStore::initialize` mints a random account root key, so a vault
    /// created here shares no key material with any other device and can never
    /// be merged with one. The caller must pass `acknowledge_standalone` to
    /// confirm the user was told that, because it is not recoverable later.
    Create {
        password: String,
        session_ttl_seconds: i64,
        acknowledge_standalone: bool,
    },

    /// Unlocks the vault and (re)issues this device's owner credential.
    UnlockOwner {
        password: String,
        session_ttl_seconds: i64,
    },

    /// Changes the master password. Item ciphertext is not rewritten.
    ChangePassword { current: String, next: String },

    /// Writes an encrypted backup to `destination_path`.
    ExportBackup {
        destination_path: String,
        /// Whether to include stored connector credentials.
        ///
        /// A native backup carries the `connections` table, so exporting one
        /// and restoring it elsewhere copies live OAuth credentials onto that
        /// device. ADR 0002 confines those to the local service that owns them,
        /// so a mobile export defaults this off.
        #[serde(default)]
        include_connections: bool,
    },
}

/// Which owner credential this client provisions for itself.
#[derive(Debug, Clone, Copy)]
pub struct ProvisionContext {
    pub role: LocalOwnerRole,
}

impl ProvisionContext {
    pub const MOBILE: Self = Self {
        role: LocalOwnerRole::MobileOwner,
    };
}

fn ttl(seconds: i64) -> Duration {
    Duration::seconds(seconds)
}

/// Registers this device's owner credential and re-establishes the session as
/// that client.
///
/// The second step is not optional. `initialize` and `restore_native_backup`
/// leave the vault unlocked but load no owner policy rule — only
/// `unlock_for_client` rebuilds it — so without this a freshly provisioned
/// vault answers "default deny: no matching policy rule" to everything.
fn adopt_owner(
    service: &KeyLeaseService,
    context: ProvisionContext,
    password: &str,
    session_ttl_seconds: i64,
) -> Result<(keylease_core::AgentId, String, keylease_core::VaultId)> {
    let (agent_id, token) = service.register_local_owner_client(context.role)?;
    let vault_id =
        service.unlock_for_client(&agent_id, password.as_bytes(), ttl(session_ttl_seconds))?;
    Ok((agent_id, token, vault_id))
}

/// Reads a caller-supplied file, bounded so a wrong path cannot exhaust memory.
fn read_bounded(path: &str) -> Result<Zeroizing<Vec<u8>>> {
    let metadata = std::fs::metadata(path).map_err(|_| KeyLeaseError::NotFound {
        resource: "backup file".into(),
    })?;
    if !metadata.is_file() {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "the backup source must be a regular file".into(),
        });
    }
    if metadata.len() > crate::MAX_LOCAL_JSON_BYTES as u64 {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "the backup file exceeds the size limit".into(),
        });
    }
    Ok(Zeroizing::new(
        std::fs::read(path).map_err(|_| KeyLeaseError::Storage)?,
    ))
}

pub async fn handle_provision(
    service: &KeyLeaseService,
    context: ProvisionContext,
    request: ProvisionRequest,
) -> Result<Value> {
    match request {
        ProvisionRequest::Inspect => {
            let status = service.status()?;
            let initialised = service.list_clients().is_ok() && status.get("locked").is_some();
            Ok(json!({
                "initialized": initialised,
                "status": status,
            }))
        }

        ProvisionRequest::Create {
            password,
            session_ttl_seconds,
            acknowledge_standalone,
        } => {
            if !acknowledge_standalone {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "a standalone vault cannot be merged with another device later; \
                             acknowledgement is required"
                        .into(),
                });
            }
            service.initialize(password.as_bytes(), ttl(session_ttl_seconds))?;
            if service.list_groups()?.is_empty() {
                service.create_group("Personal", None)?;
            }
            let (agent_id, token, vault_id) =
                adopt_owner(service, context, &password, session_ttl_seconds)?;
            let (device_id, provenance) = service.device_identity("created_locally")?;
            Ok(json!({
                "vault_id": vault_id,
                "agent_id": agent_id,
                "token": token,
                "device_id": device_id,
                "provenance": provenance,
            }))
        }

        ProvisionRequest::RestoreBackup {
            source_path,
            password,
            session_ttl_seconds,
        } => {
            let bytes = read_bounded(&source_path)?;
            service.restore_native_backup(password.as_bytes(), &bytes, ttl(session_ttl_seconds))?;
            let (agent_id, token, vault_id) =
                adopt_owner(service, context, &password, session_ttl_seconds)?;
            let (device_id, provenance) = service.device_identity("restored")?;
            Ok(json!({
                "vault_id": vault_id,
                "agent_id": agent_id,
                "token": token,
                "device_id": device_id,
                "provenance": provenance,
            }))
        }

        ProvisionRequest::UnlockOwner {
            password,
            session_ttl_seconds,
        } => {
            let (agent_id, token, vault_id) =
                adopt_owner(service, context, &password, session_ttl_seconds)?;
            // Unlock does not decide provenance; if the row already exists this
            // returns it unchanged.
            let (device_id, provenance) = service.device_identity("restored")?;
            Ok(json!({
                "vault_id": vault_id,
                "agent_id": agent_id,
                "token": token,
                "device_id": device_id,
                "provenance": provenance,
            }))
        }

        ProvisionRequest::ChangePassword { current, next } => {
            service.change_master_password(current.as_bytes(), next.as_bytes())?;
            Ok(json!({"changed": true}))
        }

        ProvisionRequest::ExportBackup {
            destination_path,
            include_connections,
        } => {
            let bytes = service.export_native_backup_filtered(include_connections)?;
            std::fs::write(&destination_path, &bytes).map_err(|_| KeyLeaseError::Storage)?;
            Ok(json!({
                "written": true,
                "bytes": bytes.len(),
                "includes_connections": include_connections,
            }))
        }
    }
}

/// Dispatches one provisioning request encoded as JSON text.
pub async fn dispatch_provision_line(
    service: &KeyLeaseService,
    context: ProvisionContext,
    line: &str,
) -> Zeroizing<String> {
    if line.len() > crate::MAX_LOCAL_JSON_BYTES {
        return Zeroizing::new(
            encode_response(Err(KeyLeaseError::InvalidRequest {
                reason: "the provisioning request exceeds the size limit".into(),
            }))
            .to_string(),
        );
    }
    let parsed =
        serde_json::from_str::<ProvisionRequest>(line).map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid provisioning request".into(),
        });
    let response = match parsed {
        Ok(request) => encode_response(handle_provision(service, context, request).await),
        Err(error) => encode_response(Err(error)),
    };
    Zeroizing::new(response.to_string())
}
