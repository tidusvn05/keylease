//! Self-hosted dynamic credential broker contracts and local provider backends.
//!
//! Credential material is returned once by the local Gateway and is never
//! persisted by the control plane. Repository implementations persist only
//! redacted lease metadata and an encrypted backend revocation handle.

mod backends;

pub use backends::{
    AwsStsWebIdentityBackend, AwsStsWebIdentityConfig, OAuthTokenExchangeBackend,
    OAuthTokenExchangeConfig, PostgresRoleBackend, PostgresRoleConfig, SshCertificateBackend,
    SshCertificateConfig,
};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use keylease_core::{ActorContext, ConnectionId, CredentialLeaseId, KeyLeaseError, Result, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};
use zeroize::Zeroize;

pub const CREDENTIAL_CONTRACT_VERSION: u32 = 1;
pub const HARD_MAX_CREDENTIAL_TTL_SECONDS: u64 = 3_600;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentMode {
    SelfHosted,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    LocalGateway,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    AwsSts,
    SshCertificate,
    PostgresqlRole,
    #[serde(rename = "oauth_token_exchange")]
    OAuthTokenExchange,
}

impl CredentialKind {
    pub fn policy_action(&self) -> &'static str {
        match self {
            Self::AwsSts => "credential.aws.issue",
            Self::SshCertificate => "credential.ssh.issue",
            Self::PostgresqlRole => "credential.postgresql.issue",
            Self::OAuthTokenExchange => "credential.oauth.exchange",
        }
    }

    pub fn resource_segment(&self) -> &'static str {
        match self {
            Self::AwsSts => "aws",
            Self::SshCertificate => "ssh",
            Self::PostgresqlRole => "postgresql",
            Self::OAuthTokenExchange => "oauth",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SenderConstraint {
    /// Use only when the upstream credential is already short-lived and does
    /// not support cryptographic sender binding.
    None,
    /// SSH certificates are bound to possession of the matching private key.
    SshPublicKeySha256 { thumbprint: String },
    /// Reserved for a backend that creates and verifies RFC 9449 proofs.
    Dpop { jkt: String },
    /// Reserved for an upstream service that validates RFC 8705 binding.
    Mtls { certificate_sha256: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialLeaseRequest {
    pub schema_version: u32,
    pub connection_id: ConnectionId,
    pub backend_id: String,
    pub kind: CredentialKind,
    /// Provider-specific target name, not a secret. Examples are an AWS role,
    /// SSH host group, or database service label.
    pub target: String,
    pub requested_ttl_seconds: u64,
    pub idempotency_key: String,
    pub task_id: Option<TaskId>,
    pub approval_id: Option<String>,
    #[serde(default)]
    pub claims: BTreeMap<String, String>,
}

impl CredentialLeaseRequest {
    pub fn canonical_resource(&self) -> String {
        format!(
            "credential:{}/{}/{}",
            self.kind.resource_segment(),
            self.backend_id,
            self.target
        )
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CREDENTIAL_CONTRACT_VERSION {
            return Err(KeyLeaseError::UnsupportedVersion {
                version: self.schema_version,
            });
        }
        for value in [&self.connection_id.0, &self.backend_id, &self.target] {
            validate_text(value, 512)?;
        }
        validate_text(&self.idempotency_key, 256)?;
        if self.requested_ttl_seconds == 0
            || self.requested_ttl_seconds > HARD_MAX_CREDENTIAL_TTL_SECONDS
            || self.claims.len() > 32
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "credential TTL or claims exceed the local Gateway ceiling".into(),
            });
        }
        for (key, value) in &self.claims {
            validate_claim_key(key)?;
            validate_text(value, 16_384)?;
        }
        Ok(())
    }

    pub fn digest(&self, actor: &ActorContext, policy_version: u64) -> String {
        let value = serde_json::json!({
            "schema_version": self.schema_version,
            "agent_id": actor.agent_id,
            "workload_id": actor.workload_id,
            "task_id": self.task_id,
            "connection_id": self.connection_id,
            "backend_id": self.backend_id,
            "kind": self.kind,
            "target": self.target,
            "requested_ttl_seconds": self.requested_ttl_seconds,
            "claims": self.claims,
            "policy_version": policy_version,
        });
        hex(&Sha256::digest(
            serde_json::to_vec(&value).expect("serializing credential request cannot fail"),
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialLeaseState {
    Pending,
    Active,
    Revoking,
    Revoked,
    Expired,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionPostureStatus {
    Healthy,
    Expiring,
    RotationDue,
    Stale,
    Misconfigured,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectionPosture {
    pub schema_version: u32,
    pub connection_id: ConnectionId,
    pub status: ConnectionPostureStatus,
    pub checked_at: DateTime<Utc>,
    pub secret_expires_at: Option<DateTime<Utc>>,
    pub rotation_due_at: Option<DateTime<Utc>>,
    pub last_rotated_at: Option<DateTime<Utc>>,
    /// Stable reason codes only; never provider responses or secret values.
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RotationState {
    Pending,
    Rotating,
    Verifying,
    Activated,
    Failed,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RotationRecord {
    pub schema_version: u32,
    pub rotation_id: keylease_core::RotationId,
    pub connection_id: ConnectionId,
    pub state: RotationState,
    pub requested_by: String,
    pub reason: String,
    pub expected_connection_updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub failure_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialLeaseRecord {
    pub schema_version: u32,
    pub lease_id: CredentialLeaseId,
    pub agent_id: keylease_core::AgentId,
    pub workload_id: Option<String>,
    pub task_id: Option<TaskId>,
    pub connection_id: ConnectionId,
    pub backend_id: String,
    pub kind: CredentialKind,
    pub target: String,
    pub policy_version: u64,
    pub request_digest_sha256: String,
    pub sender_constraint: SenderConstraint,
    pub state: CredentialLeaseState,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub renewable: bool,
    pub failure_code: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "format", rename_all = "snake_case")]
pub enum CredentialMaterial {
    Aws {
        access_key_id: String,
        secret_access_key: String,
        session_token: String,
    },
    SshCertificate {
        certificate: String,
    },
    Postgresql {
        username: String,
        password: String,
        host: String,
        port: u16,
        database: String,
        tls_required: bool,
    },
    OAuth {
        access_token: String,
        token_type: String,
        issued_token_type: Option<String>,
        scope: Option<String>,
    },
}

impl std::fmt::Debug for CredentialMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let format = match self {
            Self::Aws { .. } => "aws",
            Self::SshCertificate { .. } => "ssh_certificate",
            Self::Postgresql { .. } => "postgresql",
            Self::OAuth { .. } => "oauth",
        };
        formatter
            .debug_struct("CredentialMaterial")
            .field("format", &format)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl Drop for CredentialMaterial {
    fn drop(&mut self) {
        match self {
            Self::Aws {
                access_key_id,
                secret_access_key,
                session_token,
            } => {
                access_key_id.zeroize();
                secret_access_key.zeroize();
                session_token.zeroize();
            }
            Self::SshCertificate { certificate } => certificate.zeroize(),
            Self::Postgresql {
                username,
                password,
                host,
                database,
                ..
            } => {
                username.zeroize();
                password.zeroize();
                host.zeroize();
                database.zeroize();
            }
            Self::OAuth {
                access_token,
                token_type,
                issued_token_type,
                scope,
            } => {
                access_token.zeroize();
                token_type.zeroize();
                issued_token_type.zeroize();
                scope.zeroize();
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssuedCredential {
    pub lease: CredentialLeaseRecord,
    /// Returned once from the local Gateway. Never report this field to the
    /// Control Plane, logs, metrics, or audit events.
    pub credential: CredentialMaterial,
}

impl std::fmt::Debug for IssuedCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuedCredential")
            .field("lease", &self.lease)
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

pub struct BackendIssue {
    pub credential: CredentialMaterial,
    /// Opaque provider handle stored only in encrypted local state.
    pub revocation_handle: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub sender_constraint: SenderConstraint,
    pub renewable: bool,
}

impl std::fmt::Debug for BackendIssue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BackendIssue")
            .field("credential", &"[REDACTED]")
            .field("revocation_handle", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("sender_constraint", &self.sender_constraint)
            .field("renewable", &self.renewable)
            .finish()
    }
}

impl Drop for BackendIssue {
    fn drop(&mut self) {
        self.revocation_handle.zeroize();
    }
}

#[async_trait]
pub trait CredentialBackend: Send + Sync {
    fn id(&self) -> &str;
    fn connection_id(&self) -> &ConnectionId;
    fn kind(&self) -> CredentialKind;
    async fn issue(
        &self,
        lease_id: &CredentialLeaseId,
        request: &CredentialLeaseRequest,
        effective_ttl_seconds: u64,
        now: DateTime<Utc>,
    ) -> Result<BackendIssue>;
    async fn revoke(&self, revocation_handle: Option<&str>) -> Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialAuthorization {
    pub policy_version: u64,
    pub maximum_ttl_seconds: u64,
}

#[async_trait]
pub trait CredentialAuthorizer: Send + Sync {
    async fn authorize(
        &self,
        actor: &ActorContext,
        request: &CredentialLeaseRequest,
        now: DateTime<Utc>,
    ) -> Result<CredentialAuthorization>;
}

pub trait CredentialLeaseRepository: Send + Sync {
    fn find_idempotent(
        &self,
        agent_id: &keylease_core::AgentId,
        idempotency_key: &str,
    ) -> Result<Option<CredentialLeaseRecord>>;
    fn begin(&self, record: &CredentialLeaseRecord, idempotency_key: &str) -> Result<()>;
    fn activate(
        &self,
        record: &CredentialLeaseRecord,
        revocation_handle: Option<&str>,
    ) -> Result<()>;
    fn fail(&self, lease_id: &CredentialLeaseId, failure_code: &str) -> Result<()>;
    fn get_with_handle(
        &self,
        lease_id: &CredentialLeaseId,
    ) -> Result<Option<(CredentialLeaseRecord, Option<String>)>>;
    fn list_for_agent(
        &self,
        agent_id: &keylease_core::AgentId,
    ) -> Result<Vec<CredentialLeaseRecord>>;
    fn list_reapable(&self, now: DateTime<Utc>) -> Result<Vec<CredentialLeaseRecord>>;
    fn mark_revoking(&self, lease_id: &CredentialLeaseId) -> Result<()>;
    fn mark_terminal(
        &self,
        lease_id: &CredentialLeaseId,
        state: CredentialLeaseState,
        now: DateTime<Utc>,
    ) -> Result<()>;
}

pub struct LocalCredentialGateway {
    deployment_mode: DeploymentMode,
    execution_mode: ExecutionMode,
    repository: Arc<dyn CredentialLeaseRepository>,
    authorizer: Arc<dyn CredentialAuthorizer>,
    backends: BTreeMap<String, Arc<dyn CredentialBackend>>,
}

impl std::fmt::Debug for LocalCredentialGateway {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalCredentialGateway")
            .field("deployment_mode", &self.deployment_mode)
            .field("execution_mode", &self.execution_mode)
            .field("backend_ids", &self.backends.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl LocalCredentialGateway {
    pub fn new(
        repository: Arc<dyn CredentialLeaseRepository>,
        authorizer: Arc<dyn CredentialAuthorizer>,
        backends: Vec<Arc<dyn CredentialBackend>>,
    ) -> Result<Self> {
        let mut by_id = BTreeMap::new();
        for backend in backends {
            validate_text(backend.id(), 200)?;
            if by_id.insert(backend.id().to_owned(), backend).is_some() {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "duplicate local credential backend ID".into(),
                });
            }
        }
        Ok(Self {
            deployment_mode: DeploymentMode::SelfHosted,
            execution_mode: ExecutionMode::LocalGateway,
            repository,
            authorizer,
            backends: by_id,
        })
    }

    pub fn backend_ids(&self) -> Vec<String> {
        self.backends.keys().cloned().collect()
    }

    pub fn backend_bindings(&self) -> Vec<(String, ConnectionId, CredentialKind)> {
        self.backends
            .values()
            .map(|backend| {
                (
                    backend.id().to_owned(),
                    backend.connection_id().clone(),
                    backend.kind(),
                )
            })
            .collect()
    }

    pub async fn issue(
        &self,
        actor: &ActorContext,
        request: CredentialLeaseRequest,
        now: DateTime<Utc>,
    ) -> Result<IssuedCredential> {
        request.validate()?;
        let backend =
            self.backends
                .get(&request.backend_id)
                .ok_or_else(|| KeyLeaseError::NotFound {
                    resource: "local credential backend".into(),
                })?;
        if backend.kind() != request.kind {
            return Err(KeyLeaseError::Denied {
                reason: "credential backend kind cannot be rebound by the request".into(),
            });
        }
        if backend.connection_id() != &request.connection_id {
            return Err(KeyLeaseError::Denied {
                reason: "credential backend connection cannot be rebound by the request".into(),
            });
        }
        if self
            .repository
            .find_idempotent(&actor.agent_id, &request.idempotency_key)?
            .is_some()
        {
            // Credential material is returned once and is never recoverable
            // from metadata. A replay must not mint a second credential.
            return Err(KeyLeaseError::IdempotencyConflict);
        }
        let authorization = self.authorizer.authorize(actor, &request, now).await?;
        let ttl = request
            .requested_ttl_seconds
            .min(authorization.maximum_ttl_seconds)
            .min(HARD_MAX_CREDENTIAL_TTL_SECONDS);
        if ttl == 0 {
            return Err(KeyLeaseError::Denied {
                reason: "policy grants no usable credential lifetime".into(),
            });
        }
        let lease_id = CredentialLeaseId::new();
        let digest = request.digest(actor, authorization.policy_version);
        let mut record = CredentialLeaseRecord {
            schema_version: CREDENTIAL_CONTRACT_VERSION,
            lease_id: lease_id.clone(),
            agent_id: actor.agent_id.clone(),
            workload_id: actor.workload_id.as_ref().map(|id| id.0.clone()),
            task_id: request.task_id.clone(),
            connection_id: request.connection_id.clone(),
            backend_id: request.backend_id.clone(),
            kind: request.kind.clone(),
            target: request.target.clone(),
            policy_version: authorization.policy_version,
            request_digest_sha256: digest,
            sender_constraint: SenderConstraint::None,
            state: CredentialLeaseState::Pending,
            issued_at: now,
            expires_at: now + Duration::seconds(ttl as i64),
            revoked_at: None,
            renewable: false,
            failure_code: None,
        };
        self.repository.begin(&record, &request.idempotency_key)?;
        let issue = match backend.issue(&lease_id, &request, ttl, now).await {
            Ok(issue) => issue,
            Err(error) => {
                self.repository
                    .fail(&lease_id, backend_error_code(&error))?;
                return Err(error);
            }
        };
        if issue.expires_at <= now || issue.expires_at > now + Duration::seconds(ttl as i64 + 5) {
            self.repository
                .fail(&lease_id, "backend_expiry_outside_policy")?;
            let _ = backend.revoke(issue.revocation_handle.as_deref()).await;
            return Err(KeyLeaseError::Denied {
                reason: "backend issued a credential outside the policy TTL".into(),
            });
        }
        record.state = CredentialLeaseState::Active;
        record.expires_at = issue.expires_at;
        record.sender_constraint = issue.sender_constraint.clone();
        record.renewable = issue.renewable;
        self.repository
            .activate(&record, issue.revocation_handle.as_deref())?;
        Ok(IssuedCredential {
            lease: record,
            credential: issue.credential.clone(),
        })
    }

    pub fn list_for_agent(
        &self,
        agent_id: &keylease_core::AgentId,
    ) -> Result<Vec<CredentialLeaseRecord>> {
        self.repository.list_for_agent(agent_id)
    }

    pub async fn revoke(
        &self,
        actor: &ActorContext,
        lease_id: &CredentialLeaseId,
        now: DateTime<Utc>,
    ) -> Result<CredentialLeaseRecord> {
        let (record, handle) =
            self.repository
                .get_with_handle(lease_id)?
                .ok_or_else(|| KeyLeaseError::NotFound {
                    resource: lease_id.0.clone(),
                })?;
        if record.agent_id != actor.agent_id {
            return Err(KeyLeaseError::Denied {
                reason: "credential lease belongs to another agent".into(),
            });
        }
        self.revoke_record(record, handle, now).await
    }

    pub async fn reap(&self, now: DateTime<Utc>) -> Result<Vec<CredentialLeaseRecord>> {
        let records = self.repository.list_reapable(now)?;
        let mut reaped = Vec::new();
        for record in records {
            let Some((current, handle)) = self.repository.get_with_handle(&record.lease_id)? else {
                continue;
            };
            if let Ok(record) = self.revoke_record(current, handle, now).await {
                reaped.push(record);
            }
        }
        Ok(reaped)
    }

    async fn revoke_record(
        &self,
        record: CredentialLeaseRecord,
        handle: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<CredentialLeaseRecord> {
        if matches!(
            record.state,
            CredentialLeaseState::Revoked | CredentialLeaseState::Expired
        ) {
            return Ok(record);
        }
        let backend =
            self.backends
                .get(&record.backend_id)
                .ok_or_else(|| KeyLeaseError::NotFound {
                    resource: "local credential backend".into(),
                })?;
        self.repository.mark_revoking(&record.lease_id)?;
        backend.revoke(handle.as_deref()).await?;
        let state = if record.expires_at <= now {
            CredentialLeaseState::Expired
        } else {
            CredentialLeaseState::Revoked
        };
        self.repository
            .mark_terminal(&record.lease_id, state.clone(), now)?;
        let mut result = record;
        result.state = state;
        result.revoked_at = Some(now);
        Ok(result)
    }
}

fn backend_error_code(error: &KeyLeaseError) -> &'static str {
    match error {
        KeyLeaseError::Denied { .. } => "backend_denied",
        KeyLeaseError::InvalidRequest { .. } => "backend_invalid_request",
        KeyLeaseError::ConnectorUnavailable { .. } => "backend_unavailable",
        KeyLeaseError::Storage => "backend_storage",
        KeyLeaseError::Crypto => "backend_crypto",
        _ => "backend_failure",
    }
}

pub(crate) fn validate_text(value: &str, maximum: usize) -> Result<()> {
    if value.trim().is_empty()
        || value.len() > maximum
        || value
            .chars()
            .any(|character| character == '\0' || character == '\r')
    {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "credential field is empty, too long, or contains control data".into(),
        });
    }
    Ok(())
}

fn validate_claim_key(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "credential claim key is invalid".into(),
        });
    }
    Ok(())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

#[cfg(test)]
mod tests;
