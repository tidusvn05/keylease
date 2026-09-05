use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Error, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum KeyLeaseError {
    #[error("vault is locked")]
    VaultLocked { requires_user_action: bool },
    #[error("access denied")]
    Denied { reason: String },
    #[error("approval required")]
    ApprovalRequired { approval_id: String },
    #[error("revision conflict")]
    RevisionConflict {
        expected: u64,
        actual: u64,
        retryable: bool,
    },
    #[error("invalid request")]
    InvalidRequest { reason: String },
    #[error("unsupported schema version")]
    UnsupportedVersion { version: u32 },
    #[error("not found")]
    NotFound { resource: String },
    #[error("lease expired")]
    LeaseExpired,
    #[error("lease revoked")]
    LeaseRevoked,
    #[error("lease exhausted")]
    LeaseExhausted,
    #[error("idempotency key reused with a different request")]
    IdempotencyConflict,
    #[error("connector unavailable")]
    ConnectorUnavailable { retryable: bool },
    #[error("storage failure")]
    Storage,
    #[error("cryptographic operation failed")]
    Crypto,
}

pub type Result<T> = std::result::Result<T, KeyLeaseError>;
