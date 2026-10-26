use super::{
    CloudControlClient, EdgeControlStore, EdgeExecutionContext, is_revoked, load_sealed,
    save_sealed,
};
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{Path, Request, State},
    http::{StatusCode, header},
    middleware::{Next, from_fn_with_state},
    response::{IntoResponse, Response},
    routing::{delete, get},
};
use chrono::{DateTime, Duration, Utc};
use keylease_core::{
    ActionRequest, ActorContext, ApprovalId, ApprovalSemanticSummary, ArgumentFingerprint,
    AuditEvent, CONTRACT_VERSION, ConnectionId, CredentialLeaseId, KeyLeaseError, PolicyDecision,
    PolicyEngine, RequestId, Result, RiskTier,
};
use leasegate_control::{ApprovalRequest, CONTROL_CONTRACT_VERSION};
use leasegate_credentials::{
    AwsStsWebIdentityBackend, AwsStsWebIdentityConfig, ConnectionPosture, ConnectionPostureStatus,
    CredentialAuthorization, CredentialAuthorizer, CredentialBackend, CredentialLeaseRecord,
    CredentialLeaseRepository, CredentialLeaseRequest, CredentialLeaseState,
    LocalCredentialGateway, OAuthTokenExchangeBackend, OAuthTokenExchangeConfig,
    PostgresRoleBackend, PostgresRoleConfig, SshCertificateBackend, SshCertificateConfig,
};
use leasegate_mcp::{AgentEndpointIdentity, EndpointSecurity};
use leasegate_policy::RulePolicyEngine;
use rusqlite::{ErrorCode, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path as FilePath, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use url::Url;

pub struct EdgeCredentialAuthorizer {
    store: Arc<EdgeControlStore>,
    cloud: Arc<CloudControlClient>,
    cloud_connected: Arc<AtomicBool>,
}

impl EdgeCredentialAuthorizer {
    pub fn new(
        store: Arc<EdgeControlStore>,
        cloud: Arc<CloudControlClient>,
        cloud_connected: Arc<AtomicBool>,
    ) -> Self {
        Self {
            store,
            cloud,
            cloud_connected,
        }
    }
}

#[async_trait]
impl CredentialAuthorizer for EdgeCredentialAuthorizer {
    async fn authorize(
        &self,
        actor: &ActorContext,
        request: &CredentialLeaseRequest,
        now: DateTime<Utc>,
    ) -> Result<CredentialAuthorization> {
        if self.store.connection_is_healthy(&request.connection_id)? != Some(true) {
            return Err(KeyLeaseError::Denied {
                reason: "credential connection is not healthy on this local Gateway".into(),
            });
        }
        let bundle = self
            .store
            .active_policy()?
            .filter(|bundle| bundle.payload.not_before <= now && bundle.payload.expires_at > now)
            .ok_or_else(|| KeyLeaseError::Denied {
                reason: "no valid signed policy is active for credential issuance".into(),
            })?;
        let action_request = credential_action_request(actor, request);
        let decision = RulePolicyEngine::new(bundle.payload.rules.clone()).evaluate(
            &action_request,
            RiskTier::R3,
            now,
        );
        self.store.authorize(&EdgeExecutionContext {
            agent_id: actor.agent_id.clone(),
            workload_id: actor.workload_id.as_ref().map(|id| id.0.clone()),
            task_id: request.task_id.as_ref().map(|id| id.0.clone()),
            connection_id: request.connection_id.clone(),
            approval_id: request.approval_id.clone(),
            lease_id: None,
            risk: RiskTier::R3,
            side_effecting: true,
            cloud_connected: self.cloud_connected.load(Ordering::Acquire),
            now,
        })?;
        match decision {
            PolicyDecision::Deny { reason, .. } => Err(KeyLeaseError::Denied { reason }),
            PolicyDecision::Allow {
                policy_version,
                max_ttl_seconds,
                ..
            } => Ok(CredentialAuthorization {
                policy_version,
                maximum_ttl_seconds: max_ttl_seconds,
            }),
            PolicyDecision::RequireApproval {
                policy_version,
                request_digest_hex,
                max_ttl_seconds,
                ..
            } => {
                if let Some(approval_id) = request.approval_id.as_deref() {
                    let receipt = self.store.consume_approval(
                        approval_id,
                        &request_digest_hex,
                        policy_version,
                        now,
                    )?;
                    if receipt.payload.agent_id != actor.agent_id
                        || receipt.payload.connection_id != request.connection_id
                        || receipt.payload.action != request.kind.policy_action()
                        || receipt.payload.resource != request.canonical_resource()
                    {
                        return Err(KeyLeaseError::Denied {
                            reason: "approval identity or credential target mismatch".into(),
                        });
                    }
                    return Ok(CredentialAuthorization {
                        policy_version,
                        maximum_ttl_seconds: max_ttl_seconds,
                    });
                }
                let approval_id = ApprovalId::new();
                let approval = ApprovalRequest {
                    schema_version: CONTROL_CONTRACT_VERSION,
                    approval_id: approval_id.clone(),
                    organization_id: self.store.config.organization_id.clone(),
                    project_id: self.store.config.project_id.clone(),
                    agent_id: actor.agent_id.clone(),
                    workload_id: actor.workload_id.as_ref().map(|id| id.0.clone()),
                    on_behalf_of: actor.on_behalf_of.clone(),
                    task_id: request.task_id.as_ref().map(|id| id.0.clone()),
                    connection_id: request.connection_id.clone(),
                    action: request.kind.policy_action().into(),
                    resource: request.canonical_resource(),
                    request_digest_hex,
                    policy_version,
                    risk: RiskTier::R3,
                    summary: credential_summary(request),
                    created_at: now,
                    expires_at: now + Duration::minutes(5),
                };
                self.cloud.submit_approval(&approval).await?;
                Err(KeyLeaseError::ApprovalRequired {
                    approval_id: approval_id.0,
                })
            }
        }
    }
}

fn credential_action_request(
    actor: &ActorContext,
    request: &CredentialLeaseRequest,
) -> ActionRequest {
    ActionRequest {
        schema_version: CONTRACT_VERSION,
        request_id: RequestId::new(),
        subject: actor.clone(),
        task_id: request.task_id.clone(),
        connection_id: request.connection_id.clone(),
        resource: request.canonical_resource(),
        action: request.kind.policy_action().into(),
        arguments: serde_json::json!({
            "backend_id": request.backend_id,
            "target": request.target,
            "requested_ttl_seconds": request.requested_ttl_seconds,
            "claims": request.claims,
        }),
        idempotency_key: request.idempotency_key.clone(),
    }
}

fn credential_summary(request: &CredentialLeaseRequest) -> ApprovalSemanticSummary {
    let mut changed_fields = request.claims.keys().cloned().collect::<Vec<_>>();
    changed_fields.sort();
    let argument_fingerprints = request
        .claims
        .iter()
        .map(|(field, value)| ArgumentFingerprint {
            field: field.clone(),
            value_type: "string".into(),
            length: Some(value.len() as u64),
            sha256: digest(value.as_bytes()),
        })
        .collect();
    ApprovalSemanticSummary {
        operation: request.kind.policy_action().into(),
        target: request.canonical_resource(),
        changed_fields,
        argument_fingerprints,
        blast_radius: format!(
            "one credential, maximum {} seconds",
            request.requested_ttl_seconds
        ),
    }
}

impl CredentialLeaseRepository for EdgeControlStore {
    fn find_idempotent(
        &self,
        agent_id: &keylease_core::AgentId,
        idempotency_key: &str,
    ) -> Result<Option<CredentialLeaseRecord>> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let value: Option<String> = connection
            .query_row(
                "SELECT record_json FROM credential_leases WHERE agent_id=?1 AND idempotency_key=?2",
                params![agent_id.0, idempotency_key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)?;
        value
            .map(|json| serde_json::from_str(&json).map_err(|_| KeyLeaseError::Storage))
            .transpose()
    }

    fn begin(&self, record: &CredentialLeaseRecord, idempotency_key: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let json = serde_json::to_string(record).map_err(|_| KeyLeaseError::Storage)?;
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        match connection.execute(
            "INSERT INTO credential_leases(lease_id,agent_id,idempotency_key,record_json,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?5)",
            params![record.lease_id.0, record.agent_id.0, idempotency_key, json, now],
        ) {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == ErrorCode::ConstraintViolation =>
            {
                Err(KeyLeaseError::IdempotencyConflict)
            }
            Err(_) => Err(KeyLeaseError::Storage),
        }
    }

    fn activate(
        &self,
        record: &CredentialLeaseRecord,
        revocation_handle: Option<&str>,
    ) -> Result<()> {
        let mut connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyLeaseError::Storage)?;
        let changed = tx
            .execute(
                "UPDATE credential_leases SET record_json=?1,updated_at=?2 WHERE lease_id=?3",
                params![
                    serde_json::to_string(record).map_err(|_| KeyLeaseError::Storage)?,
                    Utc::now().to_rfc3339(),
                    record.lease_id.0
                ],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        if changed != 1 {
            return Err(KeyLeaseError::Storage);
        }
        if let Some(handle) = revocation_handle {
            save_sealed(
                &tx,
                &self.key,
                "credential_handle",
                &record.lease_id.0,
                &handle,
            )?;
        }
        tx.commit().map_err(|_| KeyLeaseError::Storage)
    }

    fn fail(&self, lease_id: &CredentialLeaseId, failure_code: &str) -> Result<()> {
        update_credential_record(self, lease_id, |record| {
            record.state = CredentialLeaseState::Failed;
            record.failure_code = Some(failure_code.into());
        })
    }

    fn get_with_handle(
        &self,
        lease_id: &CredentialLeaseId,
    ) -> Result<Option<(CredentialLeaseRecord, Option<String>)>> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let value: Option<String> = connection
            .query_row(
                "SELECT record_json FROM credential_leases WHERE lease_id=?1",
                [&lease_id.0],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)?;
        let Some(json) = value else {
            return Ok(None);
        };
        let record = serde_json::from_str(&json).map_err(|_| KeyLeaseError::Storage)?;
        let handle = load_sealed(&connection, &self.key, "credential_handle", &lease_id.0)?;
        Ok(Some((record, handle)))
    }

    fn list_for_agent(
        &self,
        agent_id: &keylease_core::AgentId,
    ) -> Result<Vec<CredentialLeaseRecord>> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let mut statement = connection
            .prepare("SELECT record_json FROM credential_leases WHERE agent_id=?1 ORDER BY created_at DESC LIMIT 500")
            .map_err(|_| KeyLeaseError::Storage)?;
        let rows = statement
            .query_map([&agent_id.0], |row| row.get::<_, String>(0))
            .map_err(|_| KeyLeaseError::Storage)?;
        rows.map(|row| {
            serde_json::from_str(&row.map_err(|_| KeyLeaseError::Storage)?)
                .map_err(|_| KeyLeaseError::Storage)
        })
        .collect()
    }

    fn list_reapable(&self, now: DateTime<Utc>) -> Result<Vec<CredentialLeaseRecord>> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let mut statement = connection
            .prepare("SELECT record_json FROM credential_leases ORDER BY created_at LIMIT 1000")
            .map_err(|_| KeyLeaseError::Storage)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|_| KeyLeaseError::Storage)?;
        let mut records = Vec::new();
        for row in rows {
            let record: CredentialLeaseRecord =
                serde_json::from_str(&row.map_err(|_| KeyLeaseError::Storage)?)
                    .map_err(|_| KeyLeaseError::Storage)?;
            let provider_revoked = record.state == CredentialLeaseState::Active
                && is_revoked(
                    &connection,
                    &self.key,
                    &self.config,
                    &EdgeExecutionContext {
                        agent_id: record.agent_id.clone(),
                        workload_id: record.workload_id.clone(),
                        task_id: record.task_id.as_ref().map(|id| id.0.clone()),
                        connection_id: record.connection_id.clone(),
                        approval_id: None,
                        lease_id: Some(record.lease_id.0.clone()),
                        risk: RiskTier::R3,
                        side_effecting: true,
                        cloud_connected: true,
                        now,
                    },
                )?;
            if record.state == CredentialLeaseState::Revoking
                || (record.state == CredentialLeaseState::Pending
                    && record.issued_at <= now - Duration::minutes(5))
                || (record.state == CredentialLeaseState::Active
                    && (record.expires_at <= now || provider_revoked))
            {
                records.push(record);
            }
        }
        Ok(records)
    }

    fn mark_revoking(&self, lease_id: &CredentialLeaseId) -> Result<()> {
        update_credential_record(self, lease_id, |record| {
            record.state = CredentialLeaseState::Revoking;
        })
    }

    fn mark_terminal(
        &self,
        lease_id: &CredentialLeaseId,
        state: CredentialLeaseState,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if !matches!(
            state,
            CredentialLeaseState::Revoked | CredentialLeaseState::Expired
        ) {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "credential terminal state is invalid".into(),
            });
        }
        update_credential_record(self, lease_id, |record| {
            record.state = state;
            record.revoked_at = Some(now);
        })?;
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        connection
            .execute(
                "DELETE FROM sealed_control WHERE namespace='credential_handle' AND item_key=?1",
                [&lease_id.0],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        Ok(())
    }
}

fn update_credential_record(
    store: &EdgeControlStore,
    lease_id: &CredentialLeaseId,
    update: impl FnOnce(&mut CredentialLeaseRecord),
) -> Result<()> {
    let mut connection = store
        .connection
        .lock()
        .map_err(|_| KeyLeaseError::Storage)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| KeyLeaseError::Storage)?;
    let json: String = tx
        .query_row(
            "SELECT record_json FROM credential_leases WHERE lease_id=?1",
            [&lease_id.0],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| KeyLeaseError::Storage)?
        .ok_or_else(|| KeyLeaseError::NotFound {
            resource: lease_id.0.clone(),
        })?;
    let mut record: CredentialLeaseRecord =
        serde_json::from_str(&json).map_err(|_| KeyLeaseError::Storage)?;
    update(&mut record);
    tx.execute(
        "UPDATE credential_leases SET record_json=?1,updated_at=?2 WHERE lease_id=?3",
        params![
            serde_json::to_string(&record).map_err(|_| KeyLeaseError::Storage)?,
            Utc::now().to_rfc3339(),
            lease_id.0
        ],
    )
    .map_err(|_| KeyLeaseError::Storage)?;
    tx.commit().map_err(|_| KeyLeaseError::Storage)
}

#[derive(Clone)]
struct CredentialApiState {
    gateway: Arc<LocalCredentialGateway>,
    identity: AgentEndpointIdentity,
    store: Arc<EdgeControlStore>,
    cloud: Arc<CloudControlClient>,
}

pub fn credential_api_router(
    gateway: Arc<LocalCredentialGateway>,
    identity: AgentEndpointIdentity,
    store: Arc<EdgeControlStore>,
    cloud: Arc<CloudControlClient>,
    security: EndpointSecurity,
) -> Router {
    let state = CredentialApiState {
        gateway,
        identity,
        store,
        cloud,
    };
    Router::new()
        .route("/v1/credential-backends", get(list_backends))
        .route(
            "/v1/credential-leases",
            get(list_leases).post(issue_credential),
        )
        .route("/v1/credential-leases/{lease}", delete(revoke_credential))
        .with_state(state)
        .layer(from_fn_with_state(security, enforce_agent_security))
}

async fn enforce_agent_security(
    State(security): State<EndpointSecurity>,
    request: Request,
    next: Next,
) -> std::result::Result<Response, StatusCode> {
    if !security.authorize_headers(request.headers()) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(request).await)
}

async fn list_backends(State(state): State<CredentialApiState>) -> impl IntoResponse {
    let bindings = state
        .gateway
        .backend_bindings()
        .into_iter()
        .map(|(id, connection_id, kind)| {
            serde_json::json!({"id":id,"connection_id":connection_id,"kind":kind})
        })
        .collect::<Vec<_>>();
    no_store(Json(serde_json::json!({
        "deployment_mode": "self_hosted",
        "execution_mode": "local_gateway",
        "backends": bindings,
    })))
}

async fn list_leases(
    State(state): State<CredentialApiState>,
) -> std::result::Result<Response, CredentialApiError> {
    let leases = state
        .gateway
        .list_for_agent(&state.identity.agent_id)
        .map_err(CredentialApiError)?;
    Ok(no_store(Json(serde_json::json!({"leases": leases}))))
}

async fn issue_credential(
    State(state): State<CredentialApiState>,
    Json(request): Json<CredentialLeaseRequest>,
) -> std::result::Result<Response, CredentialApiError> {
    let actor = actor(&state.identity);
    let action = request.kind.policy_action().to_owned();
    let resource = request.canonical_resource();
    let connection_id = request.connection_id.clone();
    let issued = state
        .gateway
        .issue(&actor, request, Utc::now())
        .await
        .map_err(CredentialApiError)?;
    state
        .store
        .append_audit(&credential_audit(
            &actor,
            action,
            resource,
            connection_id,
            issued.lease.policy_version,
            "issued",
        ))
        .map_err(CredentialApiError)?;
    if let Err(error) = state.cloud.report_credential_lease(&issued.lease).await {
        tracing::warn!(error = %error, lease_id = %issued.lease.lease_id, "credential metadata report deferred");
    }
    let posture = ConnectionPosture {
        schema_version: leasegate_credentials::CREDENTIAL_CONTRACT_VERSION,
        connection_id: issued.lease.connection_id.clone(),
        status: ConnectionPostureStatus::Healthy,
        checked_at: Utc::now(),
        secret_expires_at: None,
        rotation_due_at: None,
        last_rotated_at: None,
        reason_codes: vec!["local_gateway_issuance_succeeded".into()],
    };
    if let Err(error) = state.cloud.report_connection_posture(&posture).await {
        tracing::warn!(error = %error, connection_id = %posture.connection_id, "connection posture report deferred");
    }
    Ok(no_store(Json(issued)))
}

async fn revoke_credential(
    State(state): State<CredentialApiState>,
    Path(lease): Path<String>,
) -> std::result::Result<Response, CredentialApiError> {
    let actor = actor(&state.identity);
    let record = state
        .gateway
        .revoke(&actor, &CredentialLeaseId(lease), Utc::now())
        .await
        .map_err(CredentialApiError)?;
    state
        .store
        .append_audit(&credential_audit(
            &actor,
            "credential.revoke".into(),
            record.lease_id.0.clone(),
            record.connection_id.clone(),
            record.policy_version,
            "revoked",
        ))
        .map_err(CredentialApiError)?;
    if let Err(error) = state.cloud.report_credential_lease(&record).await {
        tracing::warn!(error = %error, lease_id = %record.lease_id, "credential revocation metadata report deferred");
    }
    Ok(no_store(Json(serde_json::json!({"lease":record}))))
}

fn actor(identity: &AgentEndpointIdentity) -> ActorContext {
    ActorContext {
        agent_id: identity.agent_id.clone(),
        workload_id: identity.workload_id.clone(),
        human_principal: None,
        on_behalf_of: identity.on_behalf_of.clone(),
        client_session_id: identity.client_session_id.clone(),
        purpose: None,
    }
}

fn credential_audit(
    actor: &ActorContext,
    action: String,
    resource: String,
    connection_id: ConnectionId,
    policy_version: u64,
    outcome: &str,
) -> AuditEvent {
    AuditEvent {
        schema_version: CONTRACT_VERSION,
        timestamp: Utc::now(),
        request_id: RequestId::new(),
        agent_id: actor.agent_id.clone(),
        workload_id: actor.workload_id.as_ref().map(|id| id.0.clone()),
        on_behalf_of: actor.on_behalf_of.clone(),
        action,
        resource,
        connection_id: Some(connection_id),
        policy_version: Some(policy_version),
        decision: "allow".into(),
        connector: Some("local_credential_gateway".into()),
        outcome: outcome.into(),
        item_count: None,
        cell_count: None,
        byte_count: None,
        changed_fields: Vec::new(),
        trust_id: None,
    }
}

fn no_store<T: Serialize>(body: Json<T>) -> Response {
    let mut response = body.into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store, max-age=0".parse().expect("static header"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, "no-cache".parse().expect("static header"));
    response
}

struct CredentialApiError(KeyLeaseError);

impl IntoResponse for CredentialApiError {
    fn into_response(self) -> Response {
        let (status, code, retryable) = match self.0 {
            KeyLeaseError::ApprovalRequired { approval_id } => {
                return (
                    StatusCode::ACCEPTED,
                    no_store(Json(serde_json::json!({
                        "status":"approval_required",
                        "approval_id":approval_id,
                        "retryable":false
                    }))),
                )
                    .into_response();
            }
            KeyLeaseError::Denied { .. }
            | KeyLeaseError::LeaseExpired
            | KeyLeaseError::LeaseRevoked
            | KeyLeaseError::LeaseExhausted => (StatusCode::FORBIDDEN, "denied", false),
            KeyLeaseError::NotFound { .. } => (StatusCode::NOT_FOUND, "not_found", false),
            KeyLeaseError::IdempotencyConflict => {
                (StatusCode::CONFLICT, "idempotency_conflict", false)
            }
            KeyLeaseError::InvalidRequest { .. }
            | KeyLeaseError::UnsupportedVersion { .. }
            | KeyLeaseError::RevisionConflict { .. } => {
                (StatusCode::BAD_REQUEST, "invalid_request", false)
            }
            KeyLeaseError::ConnectorUnavailable { retryable } => {
                (StatusCode::BAD_GATEWAY, "backend_unavailable", retryable)
            }
            KeyLeaseError::VaultLocked { .. } => {
                (StatusCode::SERVICE_UNAVAILABLE, "gateway_locked", false)
            }
            KeyLeaseError::Storage | KeyLeaseError::Crypto => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", true)
            }
        };
        (
            status,
            no_store(Json(serde_json::json!({
                "status":code,
                "retryable":retryable
            }))),
        )
            .into_response()
    }
}

impl From<KeyLeaseError> for CredentialApiError {
    fn from(value: KeyLeaseError) -> Self {
        Self(value)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalGatewayConfigFile {
    schema_version: u32,
    deployment_mode: String,
    execution_mode: String,
    backends: Vec<LocalBackendConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum LocalBackendConfig {
    #[serde(rename = "aws_sts_web_identity")]
    AwsStsWebIdentity {
        id: String,
        connection_id: ConnectionId,
        endpoint: String,
        role_arn: String,
        web_identity_token_file: PathBuf,
        #[serde(default = "aws_minimum_ttl")]
        minimum_ttl_seconds: u64,
        #[serde(default = "default_maximum_ttl")]
        maximum_ttl_seconds: u64,
    },
    SshCertificate {
        id: String,
        connection_id: ConnectionId,
        ca_private_key_file: PathBuf,
        revoked_keys_file: PathBuf,
        allowed_principals: BTreeSet<String>,
        #[serde(default = "default_maximum_ttl")]
        maximum_ttl_seconds: u64,
    },
    PostgresqlRole {
        id: String,
        connection_id: ConnectionId,
        database_url_file: PathBuf,
        advertised_host: String,
        #[serde(default = "postgres_port")]
        advertised_port: u16,
        advertised_database: String,
        grant_role: String,
        role_prefix: String,
        #[serde(default = "default_maximum_ttl")]
        maximum_ttl_seconds: u64,
        #[serde(default = "default_true")]
        tls_required: bool,
    },
    #[serde(rename = "oauth_token_exchange")]
    OAuthTokenExchange {
        id: String,
        connection_id: ConnectionId,
        token_endpoint: String,
        subject_token_file: PathBuf,
        subject_token_type: String,
        client_id: String,
        client_secret_file: Option<PathBuf>,
        allowed_audiences: BTreeSet<String>,
        allowed_scopes: BTreeSet<String>,
        #[serde(default = "default_maximum_ttl")]
        maximum_ttl_seconds: u64,
    },
}

pub async fn credential_gateway_from_config(
    path: &FilePath,
    store: Arc<EdgeControlStore>,
    authorizer: Arc<EdgeCredentialAuthorizer>,
) -> Result<Arc<LocalCredentialGateway>> {
    validate_config_file(path)?;
    let bytes = fs::read(path).map_err(|_| KeyLeaseError::Storage)?;
    if bytes.len() > 1024 * 1024 {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "local Gateway configuration exceeds 1 MiB".into(),
        });
    }
    let config: LocalGatewayConfigFile =
        serde_json::from_slice(&bytes).map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid local Gateway configuration".into(),
        })?;
    validate_deployment(&config)?;
    let mut backends: Vec<Arc<dyn CredentialBackend>> = Vec::new();
    for backend in config.backends {
        match backend {
            LocalBackendConfig::AwsStsWebIdentity {
                id,
                connection_id,
                endpoint,
                role_arn,
                web_identity_token_file,
                minimum_ttl_seconds,
                maximum_ttl_seconds,
            } => backends.push(Arc::new(AwsStsWebIdentityBackend::new(
                AwsStsWebIdentityConfig {
                    backend_id: id,
                    connection_id,
                    endpoint: Url::parse(&endpoint).map_err(|_| KeyLeaseError::InvalidRequest {
                        reason: "invalid AWS STS endpoint".into(),
                    })?,
                    role_arn,
                    web_identity_token_file,
                    minimum_ttl_seconds,
                    maximum_ttl_seconds,
                },
            )?)),
            LocalBackendConfig::SshCertificate {
                id,
                connection_id,
                ca_private_key_file,
                revoked_keys_file,
                allowed_principals,
                maximum_ttl_seconds,
            } => backends.push(Arc::new(SshCertificateBackend::new(
                SshCertificateConfig {
                    backend_id: id,
                    connection_id,
                    ca_private_key_file,
                    revoked_keys_file,
                    allowed_principals,
                    maximum_ttl_seconds,
                },
            )?)),
            LocalBackendConfig::PostgresqlRole {
                id,
                connection_id,
                database_url_file,
                advertised_host,
                advertised_port,
                advertised_database,
                grant_role,
                role_prefix,
                maximum_ttl_seconds,
                tls_required,
            } => {
                backends.push(Arc::new(
                    PostgresRoleBackend::connect(PostgresRoleConfig {
                        backend_id: id,
                        connection_id,
                        database_url_file,
                        advertised_host,
                        advertised_port,
                        advertised_database,
                        grant_role,
                        role_prefix,
                        maximum_ttl_seconds,
                        tls_required,
                    })
                    .await?,
                ));
            }
            LocalBackendConfig::OAuthTokenExchange {
                id,
                connection_id,
                token_endpoint,
                subject_token_file,
                subject_token_type,
                client_id,
                client_secret_file,
                allowed_audiences,
                allowed_scopes,
                maximum_ttl_seconds,
            } => backends.push(Arc::new(OAuthTokenExchangeBackend::new(
                OAuthTokenExchangeConfig {
                    backend_id: id,
                    connection_id,
                    token_endpoint: Url::parse(&token_endpoint).map_err(|_| {
                        KeyLeaseError::InvalidRequest {
                            reason: "invalid OAuth token endpoint".into(),
                        }
                    })?,
                    subject_token_file,
                    subject_token_type,
                    client_id,
                    client_secret_file,
                    allowed_audiences,
                    allowed_scopes,
                    maximum_ttl_seconds,
                },
            )?)),
        }
    }
    Ok(Arc::new(LocalCredentialGateway::new(
        store, authorizer, backends,
    )?))
}

fn validate_config_file(path: &FilePath) -> Result<()> {
    let metadata = fs::metadata(path).map_err(|_| KeyLeaseError::InvalidRequest {
        reason: "local Gateway configuration is unavailable".into(),
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(KeyLeaseError::Denied {
                reason: "local Gateway configuration must have mode 0600".into(),
            });
        }
    }
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 1024 * 1024 {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "local Gateway configuration must be a bounded regular file".into(),
        });
    }
    Ok(())
}

fn validate_deployment(config: &LocalGatewayConfigFile) -> Result<()> {
    if config.schema_version != 1
        || config.deployment_mode != "self_hosted"
        || config.execution_mode != "local_gateway"
        || config.backends.len() > 64
    {
        return Err(KeyLeaseError::Denied {
            reason: "Gateway only supports self_hosted/local_gateway mode".into(),
        });
    }
    Ok(())
}

fn aws_minimum_ttl() -> u64 {
    900
}

fn default_maximum_ttl() -> u64 {
    3_600
}

fn postgres_port() -> u16 {
    5432
}

fn default_true() -> bool {
    true
}

fn digest(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keylease_core::{AgentId, ControlEventId, EdgeId, OrganizationId, ProjectId};
    use leasegate_control::{ControlEvent, ControlEventKind, Revocation, RevocationScope};
    use leasegate_credentials::{CredentialKind, SenderConstraint};
    use leasegate_policy_bundle::ControlSigner;

    fn store(signer: &ControlSigner) -> EdgeControlStore {
        EdgeControlStore::open(
            ":memory:",
            [31_u8; 32],
            super::super::EdgeConfig {
                edge_id: EdgeId("edge_credentials".into()),
                organization_id: OrganizationId("org_credentials".into()),
                project_id: ProjectId("project_credentials".into()),
                software_version: "0.1.0".into(),
                control_verifying_key_base64: signer.verifying_key_base64(),
                maximum_offline_seconds: 900,
                maximum_revocation_staleness_seconds: 300,
                maximum_audit_spool_bytes: 64 * 1024,
            },
        )
        .unwrap()
    }

    fn record(now: DateTime<Utc>) -> CredentialLeaseRecord {
        CredentialLeaseRecord {
            schema_version: leasegate_credentials::CREDENTIAL_CONTRACT_VERSION,
            lease_id: CredentialLeaseId("credential_lease_test".into()),
            agent_id: AgentId("agent_credentials".into()),
            workload_id: None,
            task_id: None,
            connection_id: ConnectionId("conn_credentials".into()),
            backend_id: "ssh-test".into(),
            kind: CredentialKind::SshCertificate,
            target: "deploy".into(),
            policy_version: 1,
            request_digest_sha256: "a".repeat(64),
            sender_constraint: SenderConstraint::SshPublicKeySha256 {
                thumbprint: "b".repeat(64),
            },
            state: CredentialLeaseState::Active,
            issued_at: now,
            expires_at: now + Duration::minutes(5),
            revoked_at: None,
            renewable: false,
            failure_code: None,
        }
    }

    #[test]
    fn local_repository_seals_handles_and_reaps_signed_revocations() {
        let signer = ControlSigner::generate("credential-test").unwrap();
        let store = store(&signer);
        let now = Utc::now();
        let record = record(now);
        store.begin(&record, "idempotent").unwrap();
        store
            .activate(&record, Some("provider-revocation-secret"))
            .unwrap();
        let raw: Vec<u8> = store
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT sealed_value FROM sealed_control WHERE namespace='credential_handle'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("provider-revocation-secret"));
        assert_eq!(
            store
                .get_with_handle(&record.lease_id)
                .unwrap()
                .unwrap()
                .1
                .as_deref(),
            Some("provider-revocation-secret")
        );

        store
            .apply_control_event(
                &ControlEvent {
                    schema_version: CONTROL_CONTRACT_VERSION,
                    id: ControlEventId::new(),
                    organization_id: OrganizationId("org_credentials".into()),
                    project_id: Some(ProjectId("project_credentials".into())),
                    sequence: 1,
                    created_at: now,
                    expires_at: None,
                    kind: ControlEventKind::Revocation(Revocation {
                        organization_id: OrganizationId("org_credentials".into()),
                        project_id: Some(ProjectId("project_credentials".into())),
                        epoch: 1,
                        scope: RevocationScope::Lease,
                        target_id: record.lease_id.0.clone(),
                        reason: "operator revoke".into(),
                        created_at: now,
                    }),
                },
                now,
            )
            .unwrap();
        assert_eq!(store.list_reapable(now).unwrap(), vec![record]);
    }

    #[test]
    fn deployment_config_rejects_managed_gateway_mode() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.json");
        fs::write(
            &path,
            r#"{"schema_version":1,"deployment_mode":"managed","execution_mode":"managed_gateway","backends":[]}"#,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let bytes = fs::read(&path).unwrap();
        let config: LocalGatewayConfigFile = serde_json::from_slice(&bytes).unwrap();
        assert!(validate_deployment(&config).is_err());
    }
}
