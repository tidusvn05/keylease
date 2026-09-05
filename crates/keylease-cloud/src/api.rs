use crate::{ApprovalDecisionBinding, CloudRepository};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use chrono::{Duration, Utc};
use keylease_core::{
    AccountId, AgentId, DeviceId, EdgeId, KeyLeaseError, OrganizationId, ProjectId, Result, VaultId,
};
use leasegate_control::{
    ApprovalDecision, ApprovalDecisionRequest, ApprovalReceiptPayload, ApprovalRequest, AuditBatch,
    CONTROL_CONTRACT_VERSION, EdgeHeartbeat, Revocation, SyncPushRequest,
};
use leasegate_policy_bundle::{ControlSigner, verify_policy_bundle};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use subtle::ConstantTimeEq;

#[derive(Clone)]
pub struct CloudApiConfig {
    /// Bootstrap/admin credential for the self-hosted beta. Production
    /// deployments place an OIDC-aware identity proxy in front and rotate this
    /// credential out of ordinary operator workflows.
    pub admin_token: String,
    pub maximum_body_bytes: usize,
}

impl std::fmt::Debug for CloudApiConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CloudApiConfig")
            .field("admin_token", &"[REDACTED]")
            .field("maximum_body_bytes", &self.maximum_body_bytes)
            .finish()
    }
}

impl Default for CloudApiConfig {
    fn default() -> Self {
        Self {
            admin_token: String::new(),
            maximum_body_bytes: 4 * 1024 * 1024,
        }
    }
}

#[derive(Clone)]
pub struct CloudApiState {
    pub repository: CloudRepository,
    pub signer: Arc<ControlSigner>,
    admin_token_digest: [u8; 32],
    maximum_body_bytes: usize,
}

impl std::fmt::Debug for CloudApiState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CloudApiState")
            .field("repository", &self.repository)
            .field("signer", &self.signer)
            .field("admin_token", &"[REDACTED]")
            .finish()
    }
}

impl CloudApiState {
    pub fn new(
        repository: CloudRepository,
        signer: ControlSigner,
        config: CloudApiConfig,
    ) -> Result<Self> {
        if config.admin_token.len() < 32 || config.admin_token.len() > 1024 {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "cloud admin token must contain 32..=1024 bytes".into(),
            });
        }
        Ok(Self {
            repository,
            signer: Arc::new(signer),
            admin_token_digest: Sha256::digest(config.admin_token.as_bytes()).into(),
            maximum_body_bytes: config.maximum_body_bytes.clamp(1024, 16 * 1024 * 1024),
        })
    }
}

pub fn router(state: CloudApiState) -> Router {
    let maximum = state.maximum_body_bytes;
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/bootstrap", post(bootstrap))
        .route("/v1/devices", post(register_device))
        .route("/v1/vaults", post(create_vault))
        .route(
            "/v1/organizations/{organization}/projects/{project}/agents",
            post(register_agent),
        )
        .route(
            "/v1/organizations/{organization}/projects/{project}/agents/{agent}",
            delete(revoke_agent),
        )
        .route("/v1/edges/enrollments", post(create_edge_enrollment))
        .route("/v1/edges/enroll", post(enroll_edge))
        .route(
            "/v1/accounts/{account}/vaults/{vault}/sync/push",
            post(sync_push),
        )
        .route(
            "/v1/accounts/{account}/vaults/{vault}/sync/pull",
            get(sync_pull),
        )
        .route("/v1/policies/activate", post(activate_policy))
        .route("/v1/approvals", post(create_approval))
        .route("/v1/edges/{edge}/approvals", post(create_edge_approval))
        .route(
            "/v1/organizations/{organization}/projects/{project}/approvals",
            get(list_approvals),
        )
        .route(
            "/v1/organizations/{organization}/approvals/{approval}/decision",
            post(decide_approval),
        )
        .route("/v1/revocations", post(revoke))
        .route("/v1/edges/{edge}/events", get(edge_events))
        .route("/v1/edges/{edge}/events/ack", post(ack_edge_events))
        .route("/v1/edges/{edge}/heartbeat", post(heartbeat))
        .route(
            "/v1/organizations/{organization}/projects/{project}/edges",
            get(list_edges),
        )
        .route(
            "/v1/organizations/{organization}/projects/{project}/audit",
            post(ingest_audit),
        )
        .layer(DefaultBodyLimit::max(maximum))
        .with_state(state)
}

async fn health() -> Json<Value> {
    Json(
        json!({"ok":true,"service":crate::SERVICE_NAME,"contract_version":CONTROL_CONTRACT_VERSION}),
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapRequest {
    account_id: AccountId,
    organization_name: String,
    project_name: String,
    oidc_issuer: String,
    oidc_subject: String,
    human_name: String,
}

async fn bootstrap(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Json(body): Json<BootstrapRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let (organization, project, membership) = state
        .repository
        .bootstrap_tenant(
            body.account_id,
            &body.organization_name,
            &body.project_name,
            &body.oidc_issuer,
            &body.oidc_subject,
            &body.human_name,
        )
        .await?;
    Ok(Json(
        json!({"organization":organization,"project":project,"membership":membership}),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterDeviceRequest {
    account_id: AccountId,
    device_id: DeviceId,
    verifying_key_base64: String,
}

async fn register_device(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Json(body): Json<RegisterDeviceRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    state
        .repository
        .register_device_key(
            &body.account_id,
            &body.device_id,
            &body.verifying_key_base64,
        )
        .await?;
    Ok(Json(json!({"registered":true,"device_id":body.device_id})))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateVaultRequest {
    account_id: AccountId,
    organization_id: Option<OrganizationId>,
    vault_id: VaultId,
    encrypted_header: String,
}

async fn create_vault(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Json(body): Json<CreateVaultRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    state
        .repository
        .create_vault(
            &body.account_id,
            body.organization_id.as_ref(),
            &body.vault_id,
            &body.encrypted_header,
        )
        .await?;
    Ok(Json(json!({"created":true,"vault_id":body.vault_id})))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterAgentRequest {
    display_name: String,
}

async fn register_agent(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
    Json(body): Json<RegisterAgentRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let created = state
        .repository
        .register_agent(
            &OrganizationId(organization),
            &ProjectId(project),
            &body.display_name,
        )
        .await?;
    Ok(Json(json!({
        "agent": created.registration,
        "credential": created.credential,
        "warning": "shown once; store in a mode-0600 secret file"
    })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeAgentQuery {
    reason: String,
}

async fn revoke_agent(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project, agent)): Path<(String, String, String)>,
    Query(query): Query<RevokeAgentQuery>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let event = state
        .repository
        .revoke_agent(
            &OrganizationId(organization),
            &ProjectId(project),
            &AgentId(agent),
            &query.reason,
        )
        .await?;
    Ok(Json(json!({"revoked":true,"control_event":event})))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateEnrollmentRequest {
    organization_id: OrganizationId,
    project_id: ProjectId,
    name: String,
    #[serde(default = "default_enrollment_ttl")]
    ttl_seconds: i64,
}

fn default_enrollment_ttl() -> i64 {
    600
}

async fn create_edge_enrollment(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Json(body): Json<CreateEnrollmentRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let enrollment = state
        .repository
        .create_edge_enrollment(
            &body.organization_id,
            &body.project_id,
            &body.name,
            Duration::seconds(body.ttl_seconds),
        )
        .await?;
    Ok(Json(
        json!({"enrollment_secret":enrollment.secret,"expires_at":enrollment.expires_at,"warning":"shown once"}),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollEdgeRequest {
    enrollment_secret: String,
    device_id: DeviceId,
    public_key_base64: String,
    software_version: String,
}

async fn enroll_edge(
    State(state): State<CloudApiState>,
    Json(body): Json<EnrollEdgeRequest>,
) -> ApiResult<Json<Value>> {
    let enrolled = state
        .repository
        .enroll_edge(
            &body.enrollment_secret,
            body.device_id,
            &body.public_key_base64,
            &body.software_version,
        )
        .await?;
    Ok(Json(json!({
        "edge":enrolled.edge,
        "edge_credential":enrolled.credential,
        "control_verifying_key":state.signer.verifying_key_base64(),
        "warning":"edge credential is shown once"
    })))
}

async fn sync_push(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((account, vault)): Path<(String, String)>,
    Json(body): Json<SyncPushRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    if body.schema_version != CONTROL_CONTRACT_VERSION {
        return Err(ApiError(KeyLeaseError::UnsupportedVersion {
            version: body.schema_version,
        }));
    }
    Ok(Json(
        serde_json::to_value(
            state
                .repository
                .push_sync(&AccountId(account), &VaultId(vault), body.mutations)
                .await?,
        )
        .map_err(|_| ApiError(KeyLeaseError::Storage))?,
    ))
}

#[derive(Debug, Deserialize)]
struct CursorQuery {
    #[serde(default)]
    after: u64,
    #[serde(default = "default_limit")]
    limit: u32,
}
fn default_limit() -> u32 {
    100
}

async fn sync_pull(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((account, vault)): Path<(String, String)>,
    Query(query): Query<CursorQuery>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    Ok(Json(
        serde_json::to_value(
            state
                .repository
                .pull_sync(
                    &AccountId(account),
                    &VaultId(vault),
                    query.after,
                    query.limit,
                )
                .await?,
        )
        .map_err(|_| ApiError(KeyLeaseError::Storage))?,
    ))
}

async fn activate_policy(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Json(payload): Json<leasegate_control::PolicyBundlePayload>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let previous = state
        .repository
        .latest_policy_state(&payload.organization_id, &payload.project_id)
        .await?;
    let bundle = state.signer.sign_policy(payload)?;
    verify_policy_bundle(
        &bundle,
        &state.signer.verifying_key_base64(),
        Utc::now(),
        previous.as_ref(),
    )?;
    let event = state.repository.activate_policy(&bundle).await?;
    Ok(Json(json!({"bundle":bundle,"control_event":event})))
}

async fn create_approval(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Json(body): Json<ApprovalRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    state.repository.create_approval(&body).await?;
    Ok(Json(json!({"created":true,"approval_id":body.approval_id})))
}

async fn create_edge_approval(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(edge): Path<String>,
    Json(body): Json<ApprovalRequest>,
) -> ApiResult<Json<Value>> {
    let edge = state
        .repository
        .authenticate_edge(&EdgeId(edge), bearer(&headers)?)
        .await?;
    if body.organization_id != edge.organization_id || body.project_id != edge.project_id {
        return Err(ApiError(KeyLeaseError::Denied {
            reason: "approval request is outside the authenticated Edge project".into(),
        }));
    }
    state.repository.create_approval(&body).await?;
    Ok(Json(json!({"created":true,"approval_id":body.approval_id})))
}

async fn list_approvals(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
    Query(query): Query<CursorQuery>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let approvals = state
        .repository
        .pending_approvals(
            &OrganizationId(organization),
            &ProjectId(project),
            query.limit,
        )
        .await?;
    Ok(Json(json!({"approvals":approvals})))
}

async fn decide_approval(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, approval)): Path<(String, String)>,
    Json(body): Json<ApprovalDecisionRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    if body.schema_version != CONTROL_CONTRACT_VERSION {
        return Err(ApiError(KeyLeaseError::UnsupportedVersion {
            version: body.schema_version,
        }));
    }
    let organization_id = OrganizationId(organization);
    let request = state
        .repository
        .approval_request(&organization_id, &approval)
        .await?;
    let receipt = if body.decision == ApprovalDecision::Approved {
        Some(state.signer.sign_approval(ApprovalReceiptPayload {
            schema_version: CONTROL_CONTRACT_VERSION,
            approval_id: request.approval_id.clone(),
            organization_id: request.organization_id.clone(),
            project_id: request.project_id.clone(),
            agent_id: request.agent_id.clone(),
            workload_id: request.workload_id.clone(),
            on_behalf_of: request.on_behalf_of.clone(),
            task_id: request.task_id.clone(),
            connection_id: request.connection_id.clone(),
            action: request.action.clone(),
            resource: request.resource.clone(),
            request_digest_hex: request.request_digest_hex.clone(),
            policy_version: request.policy_version,
            approver_id: body.approver_id.clone(),
            issued_at: Utc::now(),
            expires_at: request.expires_at.min(Utc::now() + Duration::minutes(5)),
            max_uses: 1,
        })?)
    } else {
        None
    };
    let event = state
        .repository
        .decide_approval(
            &organization_id,
            &approval,
            body.decision,
            ApprovalDecisionBinding {
                approver_id: &body.approver_id,
                expected_digest: &body.expected_request_digest_hex,
                expected_policy_version: body.expected_policy_version,
            },
            receipt.as_ref(),
        )
        .await?;
    Ok(Json(
        json!({"decision_recorded":true,"receipt":receipt,"control_event":event}),
    ))
}

async fn revoke(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Json(body): Json<Revocation>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let event = state.repository.append_revocation(&body).await?;
    Ok(Json(json!({"revoked":true,"control_event":event})))
}

async fn edge_events(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(edge): Path<String>,
    Query(query): Query<CursorQuery>,
) -> ApiResult<Json<Value>> {
    let edge_id = EdgeId(edge);
    authorize_edge(&state, &headers, &edge_id).await?;
    Ok(Json(
        serde_json::to_value(
            state
                .repository
                .edge_events(&edge_id, query.after, query.limit)
                .await?,
        )
        .map_err(|_| ApiError(KeyLeaseError::Storage))?,
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AckRequest {
    cursor: u64,
}

async fn ack_edge_events(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(edge): Path<String>,
    Json(body): Json<AckRequest>,
) -> ApiResult<Json<Value>> {
    let edge_id = EdgeId(edge);
    authorize_edge(&state, &headers, &edge_id).await?;
    state
        .repository
        .acknowledge_edge_events(&edge_id, body.cursor)
        .await?;
    Ok(Json(json!({"acknowledged":body.cursor})))
}

async fn heartbeat(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(edge): Path<String>,
    Json(body): Json<EdgeHeartbeat>,
) -> ApiResult<Json<Value>> {
    let edge_id = EdgeId(edge.clone());
    authorize_edge(&state, &headers, &edge_id).await?;
    if body.edge_id.0 != edge {
        return Err(ApiError(KeyLeaseError::Denied {
            reason: "heartbeat edge path/body mismatch".into(),
        }));
    }
    state.repository.record_heartbeat(&body).await?;
    Ok(Json(json!({"recorded":true})))
}

async fn list_edges(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let edges = state
        .repository
        .project_edges(&OrganizationId(organization), &ProjectId(project))
        .await?;
    Ok(Json(json!({"edges":edges})))
}

async fn ingest_audit(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
    Json(body): Json<AuditBatch>,
) -> ApiResult<Json<Value>> {
    authorize_edge(&state, &headers, &body.edge_id).await?;
    let next = state
        .repository
        .ingest_audit(&OrganizationId(organization), &ProjectId(project), &body)
        .await?;
    Ok(Json(json!({"acknowledged_through":next})))
}

fn authorize(state: &CloudApiState, headers: &HeaderMap) -> ApiResult<()> {
    let presented = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| {
            ApiError(KeyLeaseError::Denied {
                reason: "missing bearer credential".into(),
            })
        })?;
    let digest: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
    if !bool::from(digest.ct_eq(&state.admin_token_digest)) {
        return Err(ApiError(KeyLeaseError::Denied {
            reason: "invalid bearer credential".into(),
        }));
    }
    Ok(())
}

async fn authorize_edge(
    state: &CloudApiState,
    headers: &HeaderMap,
    edge_id: &EdgeId,
) -> ApiResult<()> {
    let presented = bearer(headers)?;
    state
        .repository
        .authenticate_edge(edge_id, presented)
        .await
        .map(|_| ())
        .map_err(ApiError)
}

fn bearer(headers: &HeaderMap) -> ApiResult<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| {
            ApiError(KeyLeaseError::Denied {
                reason: "missing bearer credential".into(),
            })
        })
}

type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Debug)]
struct ApiError(KeyLeaseError);

impl From<KeyLeaseError> for ApiError {
    fn from(value: KeyLeaseError) -> Self {
        Self(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            KeyLeaseError::Denied { .. }
            | KeyLeaseError::LeaseExpired
            | KeyLeaseError::LeaseRevoked
            | KeyLeaseError::LeaseExhausted => StatusCode::FORBIDDEN,
            KeyLeaseError::NotFound { .. } => StatusCode::NOT_FOUND,
            KeyLeaseError::Storage | KeyLeaseError::Crypto => StatusCode::INTERNAL_SERVER_ERROR,
            KeyLeaseError::ConnectorUnavailable { .. } => StatusCode::BAD_GATEWAY,
            _ => StatusCode::BAD_REQUEST,
        };
        let code = match &self.0 {
            KeyLeaseError::Denied { .. } => "denied",
            KeyLeaseError::NotFound { .. } => "not_found",
            KeyLeaseError::UnsupportedVersion { .. } => "unsupported_version",
            KeyLeaseError::Storage => "storage",
            _ => "invalid_request",
        };
        (status, Json(json!({"error":code}))).into_response()
    }
}

#[derive(Debug, Serialize)]
struct _SchemaAnchor;
