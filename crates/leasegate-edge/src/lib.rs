//! LeaseGate Edge durable control state, bounded-offline enforcement, and an
//! encrypted/replay-safe audit spool.

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use chrono::{DateTime, Duration, Utc};
use keylease_core::{
    AgentId, AuditEvent, CONTRACT_VERSION, ConnectionId, EdgeId, KeyLeaseError, OrganizationId,
    ProjectId, Result, RiskTier,
};
use leasegate_control::{
    ApprovalRequest, AuditBatch, CONTROL_CONTRACT_VERSION, ControlEvent, ControlEventKind,
    EdgeEventBatch, EdgeHeartbeat, Revocation, RevocationScope, SignedApprovalReceipt,
    SignedPolicyBundle,
};
use leasegate_mcp::{CanonicalActionExecutor, GateToolInput, GateToolOutput};
use leasegate_policy_bundle::{
    BundleAcceptanceState, verify_approval_receipt, verify_policy_bundle,
};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    future::Future,
    path::Path,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, Mutex},
};
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SERVICE_NAME: &str = "leasegate-edge";
pub const EDGE_SCHEMA_VERSION: u32 = 1;
pub const HARD_MAX_OFFLINE_SECONDS: u64 = 15 * 60;

#[derive(Debug, Clone)]
pub struct EdgeConfig {
    pub edge_id: EdgeId,
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub software_version: String,
    pub control_verifying_key_base64: String,
    pub maximum_offline_seconds: u64,
    pub maximum_revocation_staleness_seconds: u64,
    pub maximum_audit_spool_bytes: u64,
}

impl EdgeConfig {
    pub fn validate(&self) -> Result<()> {
        if self.software_version.is_empty()
            || parse_version(&self.software_version).is_none()
            || self.control_verifying_key_base64.is_empty()
            || self.maximum_offline_seconds == 0
            || self.maximum_offline_seconds > HARD_MAX_OFFLINE_SECONDS
            || self.maximum_revocation_staleness_seconds == 0
            || self.maximum_audit_spool_bytes < 64 * 1024
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "invalid Edge security limits or identity".into(),
            });
        }
        Ok(())
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct EdgeStorageKey([u8; 32]);

impl std::fmt::Debug for EdgeStorageKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EdgeStorageKey([REDACTED])")
    }
}

#[derive(Debug, Clone)]
pub struct EdgeExecutionContext {
    pub agent_id: AgentId,
    pub workload_id: Option<String>,
    pub task_id: Option<String>,
    pub connection_id: ConnectionId,
    pub approval_id: Option<String>,
    pub lease_id: Option<String>,
    pub risk: RiskTier,
    pub side_effecting: bool,
    pub cloud_connected: bool,
    pub now: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeAuthorization {
    pub policy_version: u64,
    pub offline: bool,
    pub revocation_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditSpoolStatus {
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    pub pending_events: u64,
    pub encrypted_bytes: u64,
    pub maximum_bytes: u64,
}

/// HTTPS control-plane client authenticated with a one-Edge credential. Plain
/// HTTP is accepted only on loopback for a same-host Compose deployment.
pub struct CloudControlClient {
    http: reqwest::Client,
    base_url: Url,
    edge_id: EdgeId,
    organization_id: OrganizationId,
    project_id: ProjectId,
    credential: zeroize::Zeroizing<String>,
}

impl std::fmt::Debug for CloudControlClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CloudControlClient")
            .field("base_url", &self.base_url)
            .field("edge_id", &self.edge_id)
            .field("credential", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl CloudControlClient {
    pub fn new(
        base_url: &str,
        edge_id: EdgeId,
        organization_id: OrganizationId,
        project_id: ProjectId,
        credential: String,
    ) -> Result<Self> {
        let mut base_url = Url::parse(base_url).map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid Cloud URL".into(),
        })?;
        let secure = base_url.scheme() == "https";
        let loopback = base_url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if (!secure && !loopback)
            || !matches!(base_url.scheme(), "http" | "https")
            || credential.len() < 32
            || credential.len() > 1024
        {
            return Err(KeyLeaseError::Denied {
                reason:
                    "Cloud control requires HTTPS (except loopback) and a valid Edge credential"
                        .into(),
            });
        }
        if !base_url.path().ends_with('/') {
            base_url.set_path(&format!("{}/", base_url.path()));
        }
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .https_only(secure)
            .build()
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: false })?;
        Ok(Self {
            http,
            base_url,
            edge_id,
            organization_id,
            project_id,
            credential: zeroize::Zeroizing::new(credential),
        })
    }

    pub async fn poll_control(
        &self,
        store: &EdgeControlStore,
        service: &Arc<keylease_service::KeyLeaseService>,
        limit: u32,
        now: DateTime<Utc>,
    ) -> Result<u64> {
        let cursor = store.heartbeat(BTreeMap::new(), now)?.control_cursor;
        let response = self
            .http
            .get(self.endpoint(&format!(
                "v1/edges/{}/events?after={cursor}&limit={}",
                self.edge_id.0,
                limit.clamp(1, 500)
            ))?)
            .bearer_auth(self.credential.as_str())
            .send()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        if !response.status().is_success() {
            return Err(KeyLeaseError::Denied {
                reason: "Cloud rejected Edge control poll".into(),
            });
        }
        let batch: EdgeEventBatch = response
            .json()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: false })?;
        if batch.schema_version != CONTROL_CONTRACT_VERSION || batch.cursor < cursor {
            return Err(KeyLeaseError::Denied {
                reason: "Cloud control batch version or cursor rollback".into(),
            });
        }
        for event in &batch.events {
            if let ControlEventKind::PolicyBundle(bundle) = &event.kind {
                // Enter deny-by-default first; partial activation cannot retain
                // authority from the prior policy version.
                service.replace_policy_rules(Vec::new())?;
                store.apply_control_event(event, now)?;
                service.replace_policy_rules(bundle.payload.rules.clone())?;
            } else {
                store.apply_control_event(event, now)?;
                if let ControlEventKind::ApprovalReceipt(receipt) = &event.kind {
                    match service.accept_remote_approval(
                        &receipt.payload.approval_id.0,
                        &receipt.payload.request_digest_hex,
                        receipt.payload.policy_version,
                    ) {
                        Ok(()) | Err(KeyLeaseError::NotFound { .. }) => {}
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        store.record_control_contact(now)?;
        if !batch.events.is_empty() {
            let response = self
                .http
                .post(self.endpoint(&format!("v1/edges/{}/events/ack", self.edge_id.0))?)
                .bearer_auth(self.credential.as_str())
                .json(&serde_json::json!({"cursor":batch.cursor}))
                .send()
                .await
                .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
            if !response.status().is_success() {
                return Err(KeyLeaseError::ConnectorUnavailable { retryable: true });
            }
        }
        Ok(batch.cursor)
    }

    pub async fn submit_approval(&self, approval: &ApprovalRequest) -> Result<()> {
        if approval.organization_id != self.organization_id
            || approval.project_id != self.project_id
        {
            return Err(KeyLeaseError::Denied {
                reason: "approval request is outside this Edge project".into(),
            });
        }
        let response = self
            .http
            .post(self.endpoint(&format!("v1/edges/{}/approvals", self.edge_id.0))?)
            .bearer_auth(self.credential.as_str())
            .json(approval)
            .send()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        if !response.status().is_success() {
            return Err(KeyLeaseError::Denied {
                reason: "Cloud rejected remote approval request".into(),
            });
        }
        Ok(())
    }

    pub async fn send_heartbeat(&self, heartbeat: &EdgeHeartbeat) -> Result<()> {
        if heartbeat.edge_id != self.edge_id {
            return Err(KeyLeaseError::Denied {
                reason: "heartbeat Edge identity mismatch".into(),
            });
        }
        let response = self
            .http
            .post(self.endpoint(&format!("v1/edges/{}/heartbeat", self.edge_id.0))?)
            .bearer_auth(self.credential.as_str())
            .json(heartbeat)
            .send()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        if !response.status().is_success() {
            return Err(KeyLeaseError::ConnectorUnavailable { retryable: true });
        }
        Ok(())
    }

    pub async fn flush_audit(&self, store: &EdgeControlStore, limit: u32) -> Result<u64> {
        let Some(batch) = store.pending_audit_batch(limit)? else {
            return Ok(0);
        };
        let expected = batch
            .first_sequence
            .saturating_add(batch.events.len().saturating_sub(1) as u64);
        let response = self
            .http
            .post(self.endpoint(&format!(
                "v1/organizations/{}/projects/{}/audit",
                self.organization_id.0, self.project_id.0
            ))?)
            .bearer_auth(self.credential.as_str())
            .json(&batch)
            .send()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        if !response.status().is_success() {
            return Err(KeyLeaseError::ConnectorUnavailable { retryable: true });
        }
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: false })?;
        if body
            .get("acknowledged_through")
            .and_then(serde_json::Value::as_u64)
            != Some(expected)
        {
            return Err(KeyLeaseError::Denied {
                reason: "Cloud audit acknowledgement boundary mismatch".into(),
            });
        }
        store.acknowledge_audit_through(expected)?;
        Ok(expected)
    }

    fn endpoint(&self, relative: &str) -> Result<Url> {
        self.base_url
            .join(relative)
            .map_err(|_| KeyLeaseError::InvalidRequest {
                reason: "invalid Cloud endpoint path".into(),
            })
    }
}

/// Composes Edge freshness/revocation/audit requirements around the canonical
/// service executor. It can only reduce authority; provider policy decisions
/// remain inside `KeyLeaseService` for CLI/MCP parity.
pub struct EdgeEnforcedExecutor {
    inner: Arc<dyn CanonicalActionExecutor>,
    store: Arc<EdgeControlStore>,
    cloud: Arc<CloudControlClient>,
    cloud_connected: Arc<AtomicBool>,
    organization_id: OrganizationId,
    project_id: ProjectId,
}

impl EdgeEnforcedExecutor {
    pub fn new(
        inner: Arc<dyn CanonicalActionExecutor>,
        store: Arc<EdgeControlStore>,
        cloud: Arc<CloudControlClient>,
        cloud_connected: Arc<AtomicBool>,
        organization_id: OrganizationId,
        project_id: ProjectId,
    ) -> Self {
        Self {
            inner,
            store,
            cloud,
            cloud_connected,
            organization_id,
            project_id,
        }
    }

    pub fn set_cloud_connected(&self, connected: bool) {
        self.cloud_connected.store(connected, Ordering::Release);
    }
}

impl CanonicalActionExecutor for EdgeEnforcedExecutor {
    fn execute<'a>(
        &'a self,
        actor: keylease_core::ActorContext,
        input: GateToolInput,
    ) -> Pin<Box<dyn Future<Output = Result<GateToolOutput>> + Send + 'a>> {
        Box::pin(async move {
            let now = Utc::now();
            let side_effecting = is_side_effecting_action(&input.action);
            let risk = if side_effecting {
                RiskTier::R2
            } else {
                RiskTier::R1
            };
            self.store.authorize(&EdgeExecutionContext {
                agent_id: actor.agent_id.clone(),
                workload_id: actor.workload_id.as_ref().map(|value| value.0.clone()),
                task_id: input.task_id.clone(),
                connection_id: ConnectionId(input.connection_id.clone()),
                approval_id: input.approval_id.clone(),
                lease_id: None,
                risk,
                side_effecting,
                cloud_connected: self.cloud_connected.load(Ordering::Acquire),
                now,
            })?;
            let action = input.action.clone();
            let resource = input.resource.clone();
            let task_id = input.task_id.clone();
            let outcome = self.inner.execute(actor.clone(), input).await?;
            match &outcome {
                GateToolOutput::ApprovalRequired { approval } => {
                    let created_at = approval.created_at.unwrap_or(now);
                    let request = ApprovalRequest {
                        schema_version: CONTROL_CONTRACT_VERSION,
                        approval_id: approval.id.clone(),
                        organization_id: self.organization_id.clone(),
                        project_id: self.project_id.clone(),
                        agent_id: actor.agent_id.clone(),
                        workload_id: actor.workload_id.as_ref().map(|value| value.0.clone()),
                        on_behalf_of: actor.on_behalf_of.clone(),
                        task_id,
                        connection_id: approval
                            .connection_id
                            .clone()
                            .ok_or(KeyLeaseError::Storage)?,
                        action: approval.action.clone().unwrap_or(action),
                        resource: approval.resource.clone().unwrap_or(resource),
                        request_digest_hex: approval.request_digest_hex.clone(),
                        policy_version: approval.policy_version,
                        risk: approval.risk.clone().ok_or(KeyLeaseError::Storage)?,
                        summary: approval
                            .semantic_summary
                            .clone()
                            .ok_or(KeyLeaseError::Storage)?,
                        created_at,
                        expires_at: approval.expires_at.min(now + Duration::minutes(5)),
                    };
                    self.cloud.submit_approval(&request).await?;
                }
                GateToolOutput::Executed { response } => {
                    let event = AuditEvent {
                        schema_version: CONTRACT_VERSION,
                        timestamp: Utc::now(),
                        request_id: keylease_core::RequestId::new(),
                        agent_id: actor.agent_id,
                        workload_id: actor.workload_id.map(|value| value.0),
                        on_behalf_of: actor.on_behalf_of,
                        action,
                        resource: response.canonical_resource.clone(),
                        connection_id: Some(response.connection_id.clone()),
                        policy_version: self
                            .store
                            .active_policy()?
                            .map(|bundle| bundle.payload.version),
                        decision: "allow".into(),
                        connector: Some(response.provider.clone()),
                        outcome: "success".into(),
                        item_count: response.item_count,
                        cell_count: response.cell_count,
                        byte_count: serde_json::to_vec(&response.body)
                            .ok()
                            .map(|bytes| bytes.len() as u64),
                        changed_fields: if side_effecting {
                            vec!["provider_resource".into()]
                        } else {
                            vec![]
                        },
                    };
                    // Return success only after durable local append.
                    self.store.append_audit(&event)?;
                }
            }
            Ok(outcome)
        })
    }
}

fn is_side_effecting_action(action: &str) -> bool {
    ![".get", ".read", ".list", ".search", ".metadata"]
        .iter()
        .any(|marker| action.contains(marker))
}

/// SQLite remains a single-writer boundary. All sensitive control artifacts
/// and audit event bodies are sealed with XChaCha20-Poly1305 before insertion.
pub struct EdgeControlStore {
    connection: Mutex<Connection>,
    key: EdgeStorageKey,
    config: EdgeConfig,
}

impl std::fmt::Debug for EdgeControlStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EdgeControlStore")
            .field("config", &self.config)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl EdgeControlStore {
    pub fn open(path: impl AsRef<Path>, storage_key: [u8; 32], config: EdgeConfig) -> Result<Self> {
        config.validate()?;
        let connection = Connection::open(path).map_err(|_| KeyLeaseError::Storage)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|_| KeyLeaseError::Storage)?;
        connection
            .pragma_update(None, "foreign_keys", true)
            .map_err(|_| KeyLeaseError::Storage)?;
        connection
            .execute_batch(SCHEMA)
            .map_err(|_| KeyLeaseError::Storage)?;
        let store = Self {
            connection: Mutex::new(connection),
            key: EdgeStorageKey(storage_key),
            config,
        };
        store.bind_identity()?;
        Ok(store)
    }

    fn bind_identity(&self) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        for (name, expected) in [
            ("edge_id", self.config.edge_id.0.as_str()),
            ("organization_id", self.config.organization_id.0.as_str()),
            ("project_id", self.config.project_id.0.as_str()),
        ] {
            let actual: Option<String> = connection
                .query_row("SELECT value FROM edge_meta WHERE key=?1", [name], |row| {
                    row.get(0)
                })
                .optional()
                .map_err(|_| KeyLeaseError::Storage)?;
            if let Some(actual) = actual {
                if actual != expected {
                    return Err(KeyLeaseError::Denied {
                        reason: "Edge state belongs to another enrolled identity".into(),
                    });
                }
            } else {
                connection
                    .execute(
                        "INSERT INTO edge_meta(key,value) VALUES(?1,?2)",
                        params![name, expected],
                    )
                    .map_err(|_| KeyLeaseError::Storage)?;
            }
        }
        Ok(())
    }

    pub fn active_policy(&self) -> Result<Option<SignedPolicyBundle>> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        load_sealed(&connection, &self.key, "policy", "active")
    }

    pub fn accept_policy(&self, bundle: &SignedPolicyBundle, now: DateTime<Utc>) -> Result<()> {
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        accept_policy_tx(&tx, &self.key, &self.config, bundle, now)?;
        tx.commit().map_err(|_| KeyLeaseError::Storage)
    }

    /// Applies a strictly ordered control event. Cursor gaps are rejected so
    /// callers reconcile instead of silently skipping a revocation.
    pub fn apply_control_event(&self, event: &ControlEvent, now: DateTime<Utc>) -> Result<()> {
        if event.schema_version != CONTROL_CONTRACT_VERSION {
            return Err(KeyLeaseError::UnsupportedVersion {
                version: event.schema_version,
            });
        }
        if event.organization_id != self.config.organization_id
            || event
                .project_id
                .as_ref()
                .is_some_and(|id| id != &self.config.project_id)
        {
            return Err(KeyLeaseError::Denied {
                reason: "control event identity or validity mismatch".into(),
            });
        }
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        let cursor = meta_u64(&tx, "control_cursor")?.unwrap_or(0);
        // The organization sequence can contain events for sibling projects,
        // which are intentionally not disclosed by this Edge's feed. Relevant
        // events must still be strictly monotonic and replay-free.
        if event.sequence <= cursor {
            return Err(KeyLeaseError::Denied {
                reason: "control event cursor replay or rollback detected".into(),
            });
        }
        match &event.kind {
            ControlEventKind::PolicyBundle(bundle) => {
                if event.expires_at.is_some_and(|expires| expires <= now) {
                    return Err(KeyLeaseError::Denied {
                        reason: "expired policy event requires full reconciliation".into(),
                    });
                }
                accept_policy_tx(&tx, &self.key, &self.config, bundle, now)?;
            }
            ControlEventKind::ApprovalReceipt(receipt) => {
                if event.expires_at.is_some_and(|expires| expires <= now) {
                    set_meta_u64(&tx, "control_cursor", event.sequence)?;
                    set_meta(&tx, "last_control_at", &now.to_rfc3339())?;
                    tx.commit().map_err(|_| KeyLeaseError::Storage)?;
                    return Ok(());
                }
                let payload = &receipt.payload;
                verify_approval_receipt(
                    receipt,
                    &self.config.control_verifying_key_base64,
                    now,
                    &payload.request_digest_hex,
                    payload.policy_version,
                    &self.config.organization_id,
                    &self.config.project_id,
                )?;
                save_sealed(&tx, &self.key, "approval", &payload.approval_id.0, receipt)?;
                tx.execute(
                    "INSERT INTO approval_usage(approval_id,uses) VALUES(?1,0) ON CONFLICT(approval_id) DO NOTHING",
                    [&payload.approval_id.0],
                )
                .map_err(|_| KeyLeaseError::Storage)?;
            }
            ControlEventKind::Revocation(revocation) => {
                apply_revocation_tx(&tx, &self.key, &self.config, revocation)?;
            }
            ControlEventKind::ConnectionHealth {
                connection_id,
                healthy,
                reason,
            } => save_sealed(
                &tx,
                &self.key,
                "connection_health",
                &connection_id.0,
                &serde_json::json!({"healthy":healthy,"reason":reason,"observed_at":now}),
            )?,
            ControlEventKind::ReconcileRequired { .. } => {
                return Err(KeyLeaseError::Denied {
                    reason: "cloud requires full Edge reconciliation".into(),
                });
            }
        }
        set_meta_u64(&tx, "control_cursor", event.sequence)?;
        set_meta(&tx, "last_control_at", &now.to_rfc3339())?;
        tx.commit().map_err(|_| KeyLeaseError::Storage)
    }

    pub fn record_control_contact(&self, now: DateTime<Utc>) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        set_meta(&connection, "last_control_at", &now.to_rfc3339())
    }

    pub fn authorize(&self, context: &EdgeExecutionContext) -> Result<EdgeAuthorization> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let policy: SignedPolicyBundle = load_sealed(&connection, &self.key, "policy", "active")?
            .ok_or_else(|| KeyLeaseError::Denied {
            reason: "no verified policy is active on this Edge".into(),
        })?;
        if policy.payload.expires_at <= context.now {
            return Err(KeyLeaseError::Denied {
                reason: "cached policy is expired".into(),
            });
        }
        let last_control =
            meta_time(&connection, "last_control_at")?.ok_or_else(|| KeyLeaseError::Denied {
                reason: "Edge has never synchronized control state".into(),
            })?;
        let control_age = (context.now - last_control).num_seconds().max(0) as u64;
        if context.side_effecting && control_age > self.config.maximum_revocation_staleness_seconds
        {
            return Err(KeyLeaseError::Denied {
                reason: "revocation state is stale for a side-effecting action".into(),
            });
        }
        if is_revoked(&connection, &self.key, &self.config, context)? {
            return Err(KeyLeaseError::Denied {
                reason: "action identity or authority has been revoked".into(),
            });
        }
        let offline = !context.cloud_connected;
        if offline {
            let window = policy
                .payload
                .offline
                .max_seconds
                .min(self.config.maximum_offline_seconds)
                .min(HARD_MAX_OFFLINE_SECONDS);
            if !policy.payload.offline.allow_r0_r1
                || !matches!(context.risk, RiskTier::R0 | RiskTier::R1)
                || window == 0
                || control_age > window
            {
                return Err(KeyLeaseError::Denied {
                    reason: "signed policy does not permit this bounded offline action".into(),
                });
            }
        }
        if context.side_effecting
            && spool_status(&connection, self.config.maximum_audit_spool_bytes)?.encrypted_bytes
                >= self.config.maximum_audit_spool_bytes
        {
            return Err(KeyLeaseError::Denied {
                reason: "encrypted audit spool is full".into(),
            });
        }
        Ok(EdgeAuthorization {
            policy_version: policy.payload.version,
            offline,
            revocation_epoch: meta_u64(&connection, "revocation_epoch")?.unwrap_or(0),
        })
    }

    /// Verifies and atomically consumes one exact-request approval use.
    pub fn consume_approval(
        &self,
        approval_id: &str,
        request_digest: &str,
        policy_version: u64,
        now: DateTime<Utc>,
    ) -> Result<SignedApprovalReceipt> {
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        let receipt: SignedApprovalReceipt = load_sealed(&tx, &self.key, "approval", approval_id)?
            .ok_or_else(|| KeyLeaseError::NotFound {
                resource: approval_id.into(),
            })?;
        verify_approval_receipt(
            &receipt,
            &self.config.control_verifying_key_base64,
            now,
            request_digest,
            policy_version,
            &self.config.organization_id,
            &self.config.project_id,
        )?;
        let uses: u64 = tx
            .query_row(
                "SELECT uses FROM approval_usage WHERE approval_id=?1",
                [approval_id],
                |row| row.get(0),
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        if uses >= receipt.payload.max_uses {
            return Err(KeyLeaseError::LeaseExhausted);
        }
        tx.execute(
            "UPDATE approval_usage SET uses=uses+1 WHERE approval_id=?1",
            [approval_id],
        )
        .map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().map_err(|_| KeyLeaseError::Storage)?;
        Ok(receipt)
    }

    pub fn append_audit(&self, event: &AuditEvent) -> Result<u64> {
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        let status = spool_status(&tx, self.config.maximum_audit_spool_bytes)?;
        let next = status
            .last_sequence
            .unwrap_or(meta_u64(&tx, "audit_ack_sequence")?.unwrap_or(0))
            .saturating_add(1);
        let sealed = seal(&self.key, &format!("audit:{next}"), event)?;
        if status.encrypted_bytes.saturating_add(sealed.len() as u64)
            > self.config.maximum_audit_spool_bytes
        {
            return Err(KeyLeaseError::Denied {
                reason: "encrypted audit spool capacity would be exceeded".into(),
            });
        }
        let previous = status
            .last_sequence
            .and_then(|sequence| {
                tx.query_row(
                    "SELECT chain_digest FROM audit_spool WHERE sequence=?1",
                    [sequence],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .ok()
                .flatten()
            })
            .or_else(|| meta(&tx, "audit_anchor_digest").ok().flatten())
            .unwrap_or_else(|| "genesis".into());
        let chain = audit_chain_digest(&previous, next, &sealed);
        tx.execute(
            "INSERT INTO audit_spool(sequence,sealed_event,chain_digest,created_at) VALUES(?1,?2,?3,?4)",
            params![next, sealed, chain, event.timestamp.to_rfc3339()],
        )
        .map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().map_err(|_| KeyLeaseError::Storage)?;
        Ok(next)
    }

    pub fn pending_audit_batch(&self, limit: u32) -> Result<Option<AuditBatch>> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let mut statement = connection
            .prepare("SELECT sequence,sealed_event,chain_digest FROM audit_spool ORDER BY sequence LIMIT ?1")
            .map_err(|_| KeyLeaseError::Storage)?;
        let mut rows = statement
            .query([limit.clamp(1, 500)])
            .map_err(|_| KeyLeaseError::Storage)?;
        let mut events = Vec::new();
        let mut first = None;
        let mut previous =
            meta(&connection, "audit_anchor_digest")?.unwrap_or_else(|| "genesis".into());
        while let Some(row) = rows.next().map_err(|_| KeyLeaseError::Storage)? {
            let sequence: u64 = row.get(0).map_err(|_| KeyLeaseError::Storage)?;
            let sealed: Vec<u8> = row.get(1).map_err(|_| KeyLeaseError::Storage)?;
            let claimed: String = row.get(2).map_err(|_| KeyLeaseError::Storage)?;
            let expected = audit_chain_digest(&previous, sequence, &sealed);
            if claimed != expected {
                return Err(KeyLeaseError::Denied {
                    reason: "audit spool integrity chain is corrupt".into(),
                });
            }
            previous = claimed;
            first.get_or_insert(sequence);
            events.push(open_sealed(
                &self.key,
                &format!("audit:{sequence}"),
                &sealed,
            )?);
        }
        Ok(first.map(|first_sequence| AuditBatch {
            schema_version: CONTROL_CONTRACT_VERSION,
            edge_id: self.config.edge_id.clone(),
            first_sequence,
            events,
        }))
    }

    pub fn acknowledge_audit_through(&self, sequence: u64) -> Result<()> {
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        let digest: Option<String> = tx
            .query_row(
                "SELECT chain_digest FROM audit_spool WHERE sequence=?1",
                [sequence],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)?;
        let digest = digest.ok_or_else(|| KeyLeaseError::InvalidRequest {
            reason: "audit acknowledgement is not an existing spool boundary".into(),
        })?;
        tx.execute("DELETE FROM audit_spool WHERE sequence<=?1", [sequence])
            .map_err(|_| KeyLeaseError::Storage)?;
        set_meta(&tx, "audit_anchor_digest", &digest)?;
        set_meta_u64(&tx, "audit_ack_sequence", sequence)?;
        tx.commit().map_err(|_| KeyLeaseError::Storage)
    }

    pub fn audit_spool_status(&self) -> Result<AuditSpoolStatus> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        spool_status(&connection, self.config.maximum_audit_spool_bytes)
    }

    pub fn heartbeat(
        &self,
        connector_health: BTreeMap<String, String>,
        now: DateTime<Utc>,
    ) -> Result<EdgeHeartbeat> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let policy: Option<SignedPolicyBundle> =
            load_sealed(&connection, &self.key, "policy", "active")?;
        Ok(EdgeHeartbeat {
            schema_version: CONTROL_CONTRACT_VERSION,
            edge_id: self.config.edge_id.clone(),
            software_version: self.config.software_version.clone(),
            policy_version: policy.map(|bundle| bundle.payload.version),
            revocation_epoch: meta_u64(&connection, "revocation_epoch")?.unwrap_or(0),
            control_cursor: meta_u64(&connection, "control_cursor")?.unwrap_or(0),
            audit_spool_bytes: spool_status(&connection, self.config.maximum_audit_spool_bytes)?
                .encrypted_bytes,
            connector_health,
            observed_at: now,
        })
    }
}

fn accept_policy_tx(
    connection: &Connection,
    key: &EdgeStorageKey,
    config: &EdgeConfig,
    bundle: &SignedPolicyBundle,
    now: DateTime<Utc>,
) -> Result<()> {
    let previous_bundle: Option<SignedPolicyBundle> =
        load_sealed(connection, key, "policy", "active")?;
    let previous = previous_bundle
        .as_ref()
        .map(|bundle| BundleAcceptanceState {
            organization_id: bundle.payload.organization_id.clone(),
            project_id: bundle.payload.project_id.clone(),
            version: bundle.payload.version,
            payload_digest_sha256: bundle.payload_digest_sha256.clone(),
            revocation_epoch: bundle.payload.revocation_epoch,
        });
    let state = verify_policy_bundle(
        bundle,
        &config.control_verifying_key_base64,
        now,
        previous.as_ref(),
    )?;
    if state.organization_id != config.organization_id
        || state.project_id != config.project_id
        || version_less(
            &config.software_version,
            &bundle.payload.minimum_edge_version,
        )?
    {
        return Err(KeyLeaseError::Denied {
            reason: "policy tenant mismatch or Edge version below minimum".into(),
        });
    }
    let observed_epoch = meta_u64(connection, "revocation_epoch")?.unwrap_or(0);
    if bundle.payload.revocation_epoch < observed_epoch {
        return Err(KeyLeaseError::Denied {
            reason: "policy revocation epoch is older than Edge state".into(),
        });
    }
    save_sealed(connection, key, "policy", "active", bundle)
}

fn apply_revocation_tx(
    connection: &Connection,
    key: &EdgeStorageKey,
    config: &EdgeConfig,
    revocation: &Revocation,
) -> Result<()> {
    let current = meta_u64(connection, "revocation_epoch")?.unwrap_or(0);
    if revocation.organization_id != config.organization_id
        || revocation
            .project_id
            .as_ref()
            .is_some_and(|project| project != &config.project_id)
        || revocation.epoch != current.saturating_add(1)
    {
        return Err(KeyLeaseError::Denied {
            reason: "revocation tenant mismatch, replay, or epoch gap".into(),
        });
    }
    save_sealed(
        connection,
        key,
        "revocation",
        &revocation.epoch.to_string(),
        revocation,
    )?;
    set_meta_u64(connection, "revocation_epoch", revocation.epoch)
}

fn is_revoked(
    connection: &Connection,
    key: &EdgeStorageKey,
    config: &EdgeConfig,
    context: &EdgeExecutionContext,
) -> Result<bool> {
    let mut statement = connection
        .prepare("SELECT item_key,sealed_value FROM sealed_control WHERE namespace='revocation' ORDER BY CAST(item_key AS INTEGER)")
        .map_err(|_| KeyLeaseError::Storage)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(|_| KeyLeaseError::Storage)?;
    for row in rows {
        let (item_key, sealed) = row.map_err(|_| KeyLeaseError::Storage)?;
        let revocation: Revocation = open_sealed(key, &format!("revocation:{item_key}"), &sealed)?;
        if revocation.organization_id != config.organization_id
            || revocation
                .project_id
                .as_ref()
                .is_some_and(|project| project != &config.project_id)
        {
            continue;
        }
        let matches = match revocation.scope {
            RevocationScope::Organization => true,
            RevocationScope::GlobalSideEffects => context.side_effecting,
            RevocationScope::Project => revocation.target_id == config.project_id.0,
            RevocationScope::Agent => revocation.target_id == context.agent_id.0,
            RevocationScope::Workload => {
                context.workload_id.as_deref() == Some(&revocation.target_id)
            }
            RevocationScope::Task => context.task_id.as_deref() == Some(&revocation.target_id),
            RevocationScope::Connection => revocation.target_id == context.connection_id.0,
            RevocationScope::Approval => {
                context.approval_id.as_deref() == Some(&revocation.target_id)
            }
            RevocationScope::Lease => context.lease_id.as_deref() == Some(&revocation.target_id),
        };
        if matches {
            return Ok(true);
        }
    }
    Ok(false)
}

fn save_sealed<T: Serialize>(
    connection: &Connection,
    key: &EdgeStorageKey,
    namespace: &str,
    item_key: &str,
    value: &T,
) -> Result<()> {
    let aad = format!("{namespace}:{item_key}");
    let sealed = seal(key, &aad, value)?;
    connection
        .execute(
            "INSERT INTO sealed_control(namespace,item_key,sealed_value) VALUES(?1,?2,?3) ON CONFLICT(namespace,item_key) DO UPDATE SET sealed_value=excluded.sealed_value",
            params![namespace, item_key, sealed],
        )
        .map_err(|_| KeyLeaseError::Storage)?;
    Ok(())
}

fn load_sealed<T: DeserializeOwned>(
    connection: &Connection,
    key: &EdgeStorageKey,
    namespace: &str,
    item_key: &str,
) -> Result<Option<T>> {
    let sealed: Option<Vec<u8>> = connection
        .query_row(
            "SELECT sealed_value FROM sealed_control WHERE namespace=?1 AND item_key=?2",
            params![namespace, item_key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| KeyLeaseError::Storage)?;
    sealed
        .map(|sealed| open_sealed(key, &format!("{namespace}:{item_key}"), &sealed))
        .transpose()
}

fn seal<T: Serialize>(key: &EdgeStorageKey, aad: &str, value: &T) -> Result<Vec<u8>> {
    let mut plaintext = serde_json::to_vec(value).map_err(|_| KeyLeaseError::Storage)?;
    let mut nonce = [0_u8; 24];
    rand::rng().fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| KeyLeaseError::Crypto)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| KeyLeaseError::Crypto)?;
    plaintext.zeroize();
    let mut output = Vec::with_capacity(24 + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    nonce.zeroize();
    Ok(output)
}

fn open_sealed<T: DeserializeOwned>(key: &EdgeStorageKey, aad: &str, sealed: &[u8]) -> Result<T> {
    if sealed.len() < 24 + 16 {
        return Err(KeyLeaseError::Crypto);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| KeyLeaseError::Crypto)?;
    let mut plaintext = cipher
        .decrypt(
            XNonce::from_slice(&sealed[..24]),
            Payload {
                msg: &sealed[24..],
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| KeyLeaseError::Crypto)?;
    let result = serde_json::from_slice(&plaintext).map_err(|_| KeyLeaseError::Storage);
    plaintext.zeroize();
    result
}

fn spool_status(connection: &Connection, maximum_bytes: u64) -> Result<AuditSpoolStatus> {
    connection
        .query_row(
            "SELECT MIN(sequence),MAX(sequence),COUNT(*),COALESCE(SUM(LENGTH(sealed_event)),0) FROM audit_spool",
            [],
            |row| {
                Ok(AuditSpoolStatus {
                    first_sequence: row.get(0)?,
                    last_sequence: row.get(1)?,
                    pending_events: row.get(2)?,
                    encrypted_bytes: row.get(3)?,
                    maximum_bytes,
                })
            },
        )
        .map_err(|_| KeyLeaseError::Storage)
}

fn audit_chain_digest(previous: &str, sequence: u64, sealed: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"keylease-edge-audit-chain-v1\0");
    digest.update(previous.as_bytes());
    digest.update(sequence.to_be_bytes());
    digest.update(sealed);
    STANDARD_NO_PAD.encode(digest.finalize())
}

fn meta(connection: &Connection, key: &str) -> Result<Option<String>> {
    connection
        .query_row("SELECT value FROM edge_meta WHERE key=?1", [key], |row| {
            row.get(0)
        })
        .optional()
        .map_err(|_| KeyLeaseError::Storage)
}

fn set_meta(connection: &Connection, key: &str, value: &str) -> Result<()> {
    connection
        .execute(
            "INSERT INTO edge_meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )
        .map_err(|_| KeyLeaseError::Storage)?;
    Ok(())
}

fn meta_u64(connection: &Connection, key: &str) -> Result<Option<u64>> {
    meta(connection, key)?
        .map(|value| value.parse().map_err(|_| KeyLeaseError::Storage))
        .transpose()
}

fn set_meta_u64(connection: &Connection, key: &str, value: u64) -> Result<()> {
    set_meta(connection, key, &value.to_string())
}

fn meta_time(connection: &Connection, key: &str) -> Result<Option<DateTime<Utc>>> {
    meta(connection, key)?
        .map(|value| {
            DateTime::parse_from_rfc3339(&value)
                .map(|value| value.with_timezone(&Utc))
                .map_err(|_| KeyLeaseError::Storage)
        })
        .transpose()
}

fn parse_version(value: &str) -> Option<[u64; 3]> {
    let core = value.split_once('-').map_or(value, |(core, _)| core);
    let mut parts = core.split('.');
    let parsed = [
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ];
    parts.next().is_none().then_some(parsed)
}

fn version_less(current: &str, required: &str) -> Result<bool> {
    let current = parse_version(current).ok_or_else(|| KeyLeaseError::InvalidRequest {
        reason: "invalid Edge software version".into(),
    })?;
    let required = parse_version(required).ok_or_else(|| KeyLeaseError::InvalidRequest {
        reason: "invalid policy minimum Edge version".into(),
    })?;
    Ok(current < required)
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS edge_meta(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sealed_control(
    namespace TEXT NOT NULL,
    item_key TEXT NOT NULL,
    sealed_value BLOB NOT NULL,
    PRIMARY KEY(namespace,item_key)
);
CREATE TABLE IF NOT EXISTS approval_usage(
    approval_id TEXT PRIMARY KEY,
    uses INTEGER NOT NULL CHECK(uses >= 0)
);
CREATE TABLE IF NOT EXISTS audit_spool(
    sequence INTEGER PRIMARY KEY,
    sealed_event BLOB NOT NULL,
    chain_digest TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use keylease_core::{ApprovalId, ConnectionId, HumanId, PolicyBundleId, RequestId};
    use leasegate_control::{ApprovalReceiptPayload, OfflineAuthorization, PolicyBundlePayload};
    use leasegate_policy_bundle::ControlSigner;
    use tempfile::tempdir;

    fn config(signer: &ControlSigner) -> EdgeConfig {
        EdgeConfig {
            edge_id: EdgeId("edge_test".into()),
            organization_id: OrganizationId("org_test".into()),
            project_id: ProjectId("project_test".into()),
            software_version: "0.1.0".into(),
            control_verifying_key_base64: signer.verifying_key_base64(),
            maximum_offline_seconds: 900,
            maximum_revocation_staleness_seconds: 300,
            maximum_audit_spool_bytes: 64 * 1024,
        }
    }

    fn policy(signer: &ControlSigner, now: DateTime<Utc>) -> SignedPolicyBundle {
        signer
            .sign_policy(PolicyBundlePayload {
                schema_version: CONTROL_CONTRACT_VERSION,
                bundle_id: PolicyBundleId::new(),
                organization_id: OrganizationId("org_test".into()),
                project_id: ProjectId("project_test".into()),
                version: 1,
                previous_bundle_digest: None,
                issued_at: now,
                not_before: now - Duration::seconds(1),
                expires_at: now + Duration::minutes(30),
                revocation_epoch: 0,
                minimum_edge_version: "0.1.0".into(),
                offline: OfflineAuthorization {
                    allow_r0_r1: true,
                    max_seconds: 600,
                },
                rules: vec![],
            })
            .unwrap()
    }

    fn context(now: DateTime<Utc>) -> EdgeExecutionContext {
        EdgeExecutionContext {
            agent_id: AgentId("agent_test".into()),
            workload_id: Some("workload_test".into()),
            task_id: Some("task_test".into()),
            connection_id: ConnectionId("conn_test".into()),
            approval_id: None,
            lease_id: None,
            risk: RiskTier::R1,
            side_effecting: true,
            cloud_connected: false,
            now,
        }
    }

    #[test]
    fn bounded_offline_and_revocation_fail_closed_across_restart() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("edge.sqlite3");
        let signer = ControlSigner::generate("control-test").unwrap();
        let now = Utc::now();
        let key = [7_u8; 32];
        {
            let store = EdgeControlStore::open(&path, key, config(&signer)).unwrap();
            store.accept_policy(&policy(&signer, now), now).unwrap();
            store.record_control_contact(now).unwrap();
            assert!(
                store
                    .authorize(&context(now + Duration::minutes(5)))
                    .is_ok()
            );
            assert!(
                store
                    .authorize(&context(now + Duration::minutes(11)))
                    .is_err()
            );
            let event = ControlEvent {
                schema_version: CONTROL_CONTRACT_VERSION,
                id: keylease_core::ControlEventId::new(),
                organization_id: OrganizationId("org_test".into()),
                project_id: Some(ProjectId("project_test".into())),
                sequence: 1,
                created_at: now,
                expires_at: None,
                kind: ControlEventKind::Revocation(Revocation {
                    organization_id: OrganizationId("org_test".into()),
                    project_id: Some(ProjectId("project_test".into())),
                    epoch: 1,
                    scope: RevocationScope::Agent,
                    target_id: "agent_test".into(),
                    reason: "operator revoke".into(),
                    created_at: now,
                }),
            };
            store.apply_control_event(&event, now).unwrap();
        }
        let store = EdgeControlStore::open(&path, key, config(&signer)).unwrap();
        assert!(
            store
                .authorize(&context(now + Duration::seconds(1)))
                .is_err()
        );
    }

    #[test]
    fn approval_uses_are_atomic_and_exact_request_bound() {
        let signer = ControlSigner::generate("control-test").unwrap();
        let now = Utc::now();
        let store = EdgeControlStore::open(":memory:", [3; 32], config(&signer)).unwrap();
        let receipt = signer
            .sign_approval(ApprovalReceiptPayload {
                schema_version: CONTROL_CONTRACT_VERSION,
                approval_id: ApprovalId("approval_test".into()),
                organization_id: OrganizationId("org_test".into()),
                project_id: ProjectId("project_test".into()),
                agent_id: AgentId("agent_test".into()),
                workload_id: None,
                on_behalf_of: None,
                task_id: Some("task_test".into()),
                connection_id: ConnectionId("conn_test".into()),
                action: "github.issue.create".into(),
                resource: "github://owner/repo".into(),
                request_digest_hex: "exact".into(),
                policy_version: 1,
                approver_id: HumanId("human_test".into()),
                issued_at: now,
                expires_at: now + Duration::minutes(2),
                max_uses: 1,
            })
            .unwrap();
        store
            .apply_control_event(
                &ControlEvent {
                    schema_version: CONTROL_CONTRACT_VERSION,
                    id: keylease_core::ControlEventId::new(),
                    organization_id: OrganizationId("org_test".into()),
                    project_id: Some(ProjectId("project_test".into())),
                    sequence: 1,
                    created_at: now,
                    expires_at: Some(now + Duration::minutes(2)),
                    kind: ControlEventKind::ApprovalReceipt(receipt),
                },
                now,
            )
            .unwrap();
        assert!(
            store
                .consume_approval("approval_test", "changed", 1, now)
                .is_err()
        );
        store
            .consume_approval("approval_test", "exact", 1, now)
            .unwrap();
        assert!(
            store
                .consume_approval("approval_test", "exact", 1, now)
                .is_err()
        );
    }

    #[test]
    fn encrypted_audit_spool_is_chained_and_acknowledged() {
        let signer = ControlSigner::generate("control-test").unwrap();
        let store = EdgeControlStore::open(":memory:", [11; 32], config(&signer)).unwrap();
        let now = Utc::now();
        let event = AuditEvent {
            schema_version: 1,
            timestamp: now,
            request_id: RequestId::new(),
            agent_id: AgentId("agent_test".into()),
            workload_id: None,
            on_behalf_of: None,
            action: "github.issue.create".into(),
            resource: "github://owner/repo".into(),
            connection_id: Some(ConnectionId("conn_test".into())),
            policy_version: Some(1),
            decision: "allow".into(),
            connector: Some("github".into()),
            outcome: "success".into(),
            item_count: Some(1),
            cell_count: None,
            byte_count: Some(12),
            changed_fields: vec!["title".into()],
        };
        assert_eq!(store.append_audit(&event).unwrap(), 1);
        assert_eq!(store.append_audit(&event).unwrap(), 2);
        let batch = store.pending_audit_batch(50).unwrap().unwrap();
        assert_eq!(batch.first_sequence, 1);
        assert_eq!(batch.events.len(), 2);
        store.acknowledge_audit_through(1).unwrap();
        assert_eq!(
            store
                .pending_audit_batch(50)
                .unwrap()
                .unwrap()
                .first_sequence,
            2
        );
    }
}
