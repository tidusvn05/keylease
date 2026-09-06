use crate::{ApprovalDecisionBinding, AuditQueryFilter, CloudRepository, CredentialLeaseFilter};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use chrono::{DateTime, Duration, Utc};
use keylease_core::{
    AccountId, ActionRequest, AgentId, ConnectionHealth, ConnectionId, ConnectorPublisherId,
    CredentialLeaseId, DeviceId, EdgeId, KeyLeaseError, OrganizationId, PolicyBundleId,
    PolicyDecision, PolicyProposalId, PolicyRule, ProjectId, Result, RotationId, VaultId,
};
use leasegate_connector_sdk::{SignedConnectorPackage, conformance_report, validate_manifest};
use leasegate_connectors::{
    ConnectorManifest, github_manifest, google_manifest, jira_manifest, linear_manifest,
    normalized_permissions, notion_manifest, slack_manifest, validate_and_canonicalize,
};
use leasegate_control::{
    ApprovalDecision, ApprovalDecisionRequest, ApprovalReceiptPayload, ApprovalRequest, AuditBatch,
    CONTROL_CONTRACT_VERSION, ConnectionDescriptor, EdgeHeartbeat, OfflineAuthorization,
    PolicyBundlePayload, PolicyProposal, PolicyProposalReviewRequest, PolicyProposalStatus,
    Revocation, SyncPushRequest,
};
use leasegate_credentials::{
    CREDENTIAL_CONTRACT_VERSION, ConnectionPosture, CredentialLeaseRecord, CredentialLeaseState,
    RotationRecord, RotationState,
};
use leasegate_policy::RulePolicyEngine;
use leasegate_policy_bundle::{ControlSigner, verify_policy_bundle};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, sync::Arc};
use subtle::ConstantTimeEq;
use url::Url;

#[derive(Clone)]
pub struct CloudApiConfig {
    /// Bootstrap/admin credential for the self-hosted beta. Production
    /// deployments place an OIDC-aware identity proxy in front and rotate this
    /// credential out of ordinary operator workflows.
    pub admin_token: String,
    pub maximum_body_bytes: usize,
    /// Optional host-generated, redacted operations snapshot. The Control
    /// Plane receives this file read-only and never receives the Docker socket.
    pub operations_status_file: Option<PathBuf>,
}

impl std::fmt::Debug for CloudApiConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CloudApiConfig")
            .field("admin_token", &"[REDACTED]")
            .field("maximum_body_bytes", &self.maximum_body_bytes)
            .field("operations_status_file", &self.operations_status_file)
            .finish()
    }
}

impl Default for CloudApiConfig {
    fn default() -> Self {
        Self {
            admin_token: String::new(),
            maximum_body_bytes: 4 * 1024 * 1024,
            operations_status_file: None,
        }
    }
}

#[derive(Clone)]
pub struct CloudApiState {
    pub repository: CloudRepository,
    pub signer: Arc<ControlSigner>,
    admin_token_digest: [u8; 32],
    maximum_body_bytes: usize,
    operations_status_file: Option<PathBuf>,
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
            operations_status_file: config.operations_status_file,
        })
    }
}

pub fn router(state: CloudApiState) -> Router {
    let maximum = state.maximum_body_bytes;
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/metrics", get(metrics))
        .route("/v1/system/status", get(system_status))
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
        .route("/v1/connectors/validate", post(validate_connector))
        .route(
            "/v1/organizations/{organization}/projects/{project}/connector-publishers",
            post(register_connector_publisher),
        )
        .route(
            "/v1/organizations/{organization}/projects/{project}/connectors",
            get(list_connectors).post(publish_connector),
        )
        .route(
            "/v1/organizations/{organization}/projects/{project}/connections",
            get(list_connections).post(upsert_connection),
        )
        .route(
            "/v1/organizations/{organization}/projects/{project}/connections/onboarding",
            post(begin_connection_onboarding),
        )
        .route(
            "/v1/organizations/{organization}/projects/{project}/policy/simulate",
            post(simulate_policy),
        )
        .route(
            "/v1/organizations/{organization}/projects/{project}/agents/{agent}/permissions",
            get(effective_permissions),
        )
        .route(
            "/v1/organizations/{organization}/projects/{project}/agents/{agent}/policy/proposals",
            post(create_policy_proposal),
        )
        .route(
            "/v1/organizations/{organization}/projects/{project}/policy/proposals",
            get(list_policy_proposals),
        )
        .route(
            "/v1/organizations/{organization}/projects/{project}/policy/proposals/{proposal}/review",
            post(review_policy_proposal),
        )
        .route(
            "/v1/organizations/{organization}/projects/{project}/policy/proposals/{proposal}/activate",
            post(activate_policy_proposal),
        )
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
            "/v1/edges/{edge}/credential-leases",
            post(report_credential_lease),
        )
        .route(
            "/v1/edges/{edge}/connection-posture",
            post(report_connection_posture),
        )
        .route(
            "/v1/organizations/{organization}/projects/{project}/edges",
            get(list_edges),
        )
        .route(
            "/v1/organizations/{organization}/projects/{project}/audit",
            get(query_audit).post(ingest_audit),
        )
        .route(
            "/v1/organizations/{organization}/projects/{project}/audit/integrity",
            get(audit_integrity),
        )
        .route(
            "/v1/organizations/{organization}/projects/{project}/credential-leases",
            get(list_credential_leases),
        )
        .route(
            "/v1/organizations/{organization}/projects/{project}/credential-leases/{lease}/revoke",
            post(revoke_credential_lease),
        )
        .route(
            "/v1/organizations/{organization}/projects/{project}/connection-posture",
            get(list_connection_posture),
        )
        .route(
            "/v1/organizations/{organization}/projects/{project}/credential-rotations",
            get(list_rotations).post(create_rotation),
        )
        .route(
            "/v1/organizations/{organization}/projects/{project}/credential-rotations/{rotation}/transition",
            post(transition_rotation),
        )
        .merge(crate::enterprise_api::router())
        .layer(DefaultBodyLimit::max(maximum))
        .with_state(state)
}

async fn health() -> Json<Value> {
    Json(
        json!({"ok":true,"service":crate::SERVICE_NAME,"contract_version":CONTROL_CONTRACT_VERSION}),
    )
}

async fn readiness(State(state): State<CloudApiState>) -> Response {
    match state.repository.readiness().await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "service": crate::SERVICE_NAME,
                "database": "ready",
                "contract_version": CONTROL_CONTRACT_VERSION
            })),
        )
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ok": false,
                "service": crate::SERVICE_NAME,
                "database": "unavailable"
            })),
        )
            .into_response(),
    }
}

async fn metrics(State(state): State<CloudApiState>) -> Response {
    let database_ready = u8::from(state.repository.readiness().await.is_ok());
    let body = format!(
        concat!(
            "# HELP leasegate_service_up Whether the service process is serving requests.\n",
            "# TYPE leasegate_service_up gauge\n",
            "leasegate_service_up{{service=\"keylease-cloud\"}} 1\n",
            "# HELP leasegate_database_ready Whether PostgreSQL passed a minimal readiness query.\n",
            "# TYPE leasegate_database_ready gauge\n",
            "leasegate_database_ready{{service=\"keylease-cloud\"}} {}\n",
            "# HELP leasegate_contract_version Active Control Plane contract version.\n",
            "# TYPE leasegate_contract_version gauge\n",
            "leasegate_contract_version{{service=\"keylease-cloud\"}} {}\n"
        ),
        database_ready, CONTROL_CONTRACT_VERSION
    );
    ([(CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response()
}

async fn system_status(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let Some(path) = state.operations_status_file.as_ref() else {
        return Ok(Json(json!({
            "schema_version": 1,
            "available": false,
            "profile": "single_vps",
            "reason": "host_snapshot_not_configured"
        })));
    };
    load_operations_status(path).map(Json).map_err(ApiError)
}

fn load_operations_status(path: &std::path::Path) -> Result<Value> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => {
            return Ok(json!({
                "schema_version": 1,
                "available": false,
                "profile": "single_vps",
                "reason": "host_snapshot_not_published"
            }));
        }
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > 64 * 1024
    {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "operations status snapshot must be a bounded regular file".into(),
        });
    }
    let raw = fs::read(path).map_err(|_| KeyLeaseError::Storage)?;
    let mut snapshot: OperationsSnapshot =
        serde_json::from_slice(&raw).map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "operations status snapshot is invalid JSON".into(),
        })?;
    if snapshot.schema_version != 1
        || !snapshot.available
        || snapshot.profile != "single_vps"
        || snapshot.release_id.is_empty()
        || snapshot.release_id.len() > 128
        || snapshot
            .release_id
            .chars()
            .any(|value| !(value.is_ascii_alphanumeric() || "._-".contains(value)))
        || snapshot.issues.len() > 32
        || snapshot.issues.iter().any(|issue| {
            issue.is_empty()
                || issue.len() > 64
                || issue
                    .chars()
                    .any(|value| !(value.is_ascii_alphanumeric() || value == '_'))
        })
        || snapshot.services.expected != 6
        || snapshot.services.running > snapshot.services.expected
        || snapshot.disk.used_percent > 100
    {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "operations status snapshot contains unsupported values".into(),
        });
    }
    let age = Utc::now().signed_duration_since(snapshot.generated_at);
    let stale = age > Duration::minutes(10) || age < Duration::minutes(-1);
    snapshot.stale = stale;
    if stale {
        snapshot.healthy = false;
        if !snapshot
            .issues
            .iter()
            .any(|value| value == "status_snapshot_stale")
        {
            snapshot.issues.push("status_snapshot_stale".into());
        }
    }
    serde_json::to_value(snapshot).map_err(|_| KeyLeaseError::Storage)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OperationsSnapshot {
    schema_version: u32,
    available: bool,
    profile: String,
    generated_at: DateTime<Utc>,
    release_id: String,
    healthy: bool,
    issues: Vec<String>,
    services: OperationsServices,
    disk: OperationsDisk,
    backup: OperationsAge,
    tls: OperationsExpiry,
    soak: OperationsSoak,
    #[serde(default)]
    stale: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OperationsServices {
    expected: u64,
    running: u64,
    control_plane_ready: bool,
    gateway_ready: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OperationsDisk {
    used_percent: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OperationsAge {
    age_seconds: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OperationsExpiry {
    expiry_seconds: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OperationsSoak {
    consecutive_seconds: u64,
    failures: u64,
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

async fn validate_connector(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Json(manifest): Json<ConnectorManifest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    Ok(Json(
        serde_json::to_value(conformance_report(&manifest))
            .map_err(|_| ApiError(KeyLeaseError::Storage))?,
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterConnectorPublisherRequest {
    display_name: String,
    verifying_key_base64: String,
}

async fn register_connector_publisher(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
    Json(body): Json<RegisterConnectorPublisherRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let publisher = state
        .repository
        .register_connector_publisher(
            &OrganizationId(organization),
            &ProjectId(project),
            &body.display_name,
            &body.verifying_key_base64,
        )
        .await?;
    Ok(Json(json!({"publisher":publisher})))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishConnectorRequest {
    publisher_id: ConnectorPublisherId,
    package: SignedConnectorPackage,
}

async fn publish_connector(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
    Json(body): Json<PublishConnectorRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let entry = state
        .repository
        .publish_connector(
            &OrganizationId(organization),
            &ProjectId(project),
            &body.publisher_id,
            &body.package,
        )
        .await?;
    Ok(Json(json!({"connector":entry})))
}

async fn list_connectors(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let custom = state
        .repository
        .connector_versions(&OrganizationId(organization), &ProjectId(project))
        .await?;
    let built_in = built_in_manifests();
    Ok(Json(json!({"built_in":built_in,"registered":custom})))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateConnectionRequest {
    schema_version: u32,
    connection_id: ConnectionId,
    provider: String,
    connector_version: String,
    display_name: String,
    auth_method: String,
    health: ConnectionHealth,
    health_reason: Option<String>,
    reauthorization_required: bool,
    #[serde(default)]
    reported_scopes: Vec<String>,
    #[serde(default)]
    authorized_resources: Vec<String>,
}

async fn upsert_connection(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
    Json(body): Json<UpdateConnectionRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    if body.schema_version != CONTROL_CONTRACT_VERSION {
        return Err(ApiError(KeyLeaseError::UnsupportedVersion {
            version: body.schema_version,
        }));
    }
    let manifest = find_manifest(
        &state,
        &organization,
        &project,
        &body.provider,
        &body.connector_version,
    )
    .await?;
    if !manifest.authentication_methods.contains(&body.auth_method) {
        return Err(ApiError(KeyLeaseError::Denied {
            reason: "connection authentication method is not in the connector manifest".into(),
        }));
    }
    let now = Utc::now();
    let descriptor = ConnectionDescriptor {
        schema_version: CONTROL_CONTRACT_VERSION,
        connection_id: body.connection_id,
        organization_id: OrganizationId(organization),
        project_id: ProjectId(project),
        provider: body.provider,
        connector_version: body.connector_version,
        display_name: body.display_name,
        auth_method: body.auth_method,
        health: body.health,
        health_reason: body.health_reason,
        reauthorization_required: body.reauthorization_required,
        granted_permissions: normalized_permissions(&manifest.provider, &body.reported_scopes),
        authorized_resources: body.authorized_resources,
        created_at: now,
        updated_at: now,
    };
    state
        .repository
        .upsert_connection_descriptor(&descriptor)
        .await?;
    Ok(Json(json!({"connection":descriptor})))
}

async fn list_connections(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let connections = state
        .repository
        .project_connections(&OrganizationId(organization), &ProjectId(project))
        .await?;
    Ok(Json(json!({"connections":connections})))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionOnboardingRequest {
    schema_version: u32,
    provider: String,
    connector_version: String,
    display_name: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    code_challenge: Option<String>,
    #[serde(default)]
    requested_scopes: Vec<String>,
}

async fn begin_connection_onboarding(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
    Json(body): Json<ConnectionOnboardingRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    if body.schema_version != CONTROL_CONTRACT_VERSION
        || body.client_id.is_empty()
        || body.client_id.len() > 500
        || body.state.len() < 32
        || body.state.len() > 512
        || body.state.chars().any(char::is_control)
    {
        return Err(ApiError(KeyLeaseError::InvalidRequest {
            reason: "invalid connection onboarding request".into(),
        }));
    }
    let redirect = Url::parse(&body.redirect_uri).map_err(|_| {
        ApiError(KeyLeaseError::InvalidRequest {
            reason: "invalid OAuth redirect URI".into(),
        })
    })?;
    if redirect.scheme() != "https"
        || redirect.host_str().is_none()
        || redirect.fragment().is_some()
        || !redirect.username().is_empty()
        || redirect.password().is_some()
    {
        return Err(ApiError(KeyLeaseError::Denied {
            reason: "OAuth redirect URI must be an HTTPS origin-bound URL".into(),
        }));
    }
    let manifest = find_manifest(
        &state,
        &organization,
        &project,
        &body.provider,
        &body.connector_version,
    )
    .await?;
    let oauth = manifest.oauth.as_ref().ok_or_else(|| {
        ApiError(KeyLeaseError::Denied {
            reason: "connector does not declare public OAuth onboarding".into(),
        })
    })?;
    if oauth.pkce_required
        && body.code_challenge.as_ref().is_none_or(|value| {
            value.len() < 43
                || value.len() > 128
                || !value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '~' | '.'))
        })
    {
        return Err(ApiError(KeyLeaseError::Denied {
            reason: "connector requires a valid S256 PKCE challenge".into(),
        }));
    }
    if !body
        .requested_scopes
        .iter()
        .all(|scope| oauth.supported_scopes.contains(scope))
    {
        return Err(ApiError(KeyLeaseError::Denied {
            reason: "requested OAuth scope is not declared by the connector".into(),
        }));
    }
    let mut authorization_url = Url::parse(&oauth.authorization_endpoint).map_err(|_| {
        ApiError(KeyLeaseError::InvalidRequest {
            reason: "invalid connector OAuth endpoint".into(),
        })
    })?;
    {
        let mut query = authorization_url.query_pairs_mut();
        query.append_pair("client_id", &body.client_id);
        query.append_pair("redirect_uri", &body.redirect_uri);
        query.append_pair("response_type", "code");
        query.append_pair("state", &body.state);
        if manifest.provider == "notion" {
            query.append_pair("owner", "user");
        }
        if !body.requested_scopes.is_empty() {
            let separator = if manifest.provider == "slack" {
                ","
            } else {
                " "
            };
            query.append_pair("scope", &body.requested_scopes.join(separator));
        }
        if manifest.provider == "jira" {
            query.append_pair("audience", "api.atlassian.com");
            query.append_pair("prompt", "consent");
        }
        if let Some(challenge) = &body.code_challenge {
            query.append_pair("code_challenge", challenge);
            query.append_pair("code_challenge_method", "S256");
        }
    }
    let now = Utc::now();
    let connection = ConnectionDescriptor {
        schema_version: CONTROL_CONTRACT_VERSION,
        connection_id: ConnectionId::new(),
        organization_id: OrganizationId(organization),
        project_id: ProjectId(project),
        provider: manifest.provider.clone(),
        connector_version: manifest.version.clone(),
        display_name: body.display_name,
        auth_method: manifest
            .authentication_methods
            .first()
            .cloned()
            .ok_or_else(|| {
                ApiError(KeyLeaseError::InvalidRequest {
                    reason: "connector has no authentication method".into(),
                })
            })?,
        health: ConnectionHealth::Disconnected,
        health_reason: Some("oauth_authorization_pending".into()),
        reauthorization_required: true,
        granted_permissions: Vec::new(),
        authorized_resources: Vec::new(),
        created_at: now,
        updated_at: now,
    };
    state
        .repository
        .upsert_connection_descriptor(&connection)
        .await?;
    Ok(Json(json!({
        "connection":connection,
        "authorization_url":authorization_url,
        "token_exchange_location":"edge",
        "token_endpoint":oauth.token_endpoint,
        "pkce_required":oauth.pkce_required
    })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SimulatePolicyRequest {
    schema_version: u32,
    request: ActionRequest,
}

async fn simulate_policy(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
    Json(body): Json<SimulatePolicyRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    if body.schema_version != CONTROL_CONTRACT_VERSION {
        return Err(ApiError(KeyLeaseError::UnsupportedVersion {
            version: body.schema_version,
        }));
    }
    let organization_id = OrganizationId(organization);
    let project_id = ProjectId(project);
    let connection = state
        .repository
        .connection_descriptor(&organization_id, &project_id, &body.request.connection_id)
        .await?;
    let manifest = find_manifest(
        &state,
        &organization_id.0,
        &project_id.0,
        &connection.provider,
        &connection.connector_version,
    )
    .await?;
    let canonical = validate_and_canonicalize(&manifest, &body.request)?;
    let bundle = state
        .repository
        .latest_policy_bundle(&organization_id, &project_id)
        .await?;
    let rules = bundle
        .as_ref()
        .map_or_else(Vec::new, |bundle| bundle.payload.rules.clone());
    let action = manifest
        .actions
        .iter()
        .find(|action| action.name == canonical.request.action)
        .ok_or_else(|| {
            ApiError(KeyLeaseError::Denied {
                reason: "action is absent from connector manifest".into(),
            })
        })?;
    let engine = RulePolicyEngine::new(rules);
    let mut simulation = engine.simulate(&canonical.request, action.risk.clone(), Utc::now())?;
    let resource_allowed = connection.authorized_resources.iter().any(|resource| {
        resource == &canonical.request.resource
            || canonical
                .request
                .resource
                .strip_prefix(resource)
                .is_some_and(|tail| tail.starts_with('/') || tail.starts_with(':'))
    });
    let permissions_allowed = action
        .required_permissions
        .iter()
        .all(|permission| connection.granted_permissions.contains(permission));
    if connection.health != ConnectionHealth::Connected || connection.reauthorization_required {
        simulation.decision = PolicyDecision::Deny {
            reason: "connection is not healthy and authorized".into(),
            matched_rule: None,
        };
        simulation
            .warnings
            .push("connection_requires_user_action".into());
    } else if !resource_allowed {
        simulation.decision = PolicyDecision::Deny {
            reason: "resource is not enrolled on the connection".into(),
            matched_rule: None,
        };
        simulation
            .warnings
            .push("connection_resource_mismatch".into());
    } else if !permissions_allowed {
        simulation.decision = PolicyDecision::Deny {
            reason: "provider permission is insufficient".into(),
            matched_rule: None,
        };
        simulation
            .warnings
            .push("incremental_reauthorization_required".into());
    }
    Ok(Json(
        json!({"simulation":simulation,"side_effects_executed":false}),
    ))
}

async fn effective_permissions(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project, agent)): Path<(String, String, String)>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let bundle = state
        .repository
        .latest_policy_bundle(
            &OrganizationId(organization.clone()),
            &ProjectId(project.clone()),
        )
        .await?;
    let engine = RulePolicyEngine::new(
        bundle
            .as_ref()
            .map_or_else(Vec::new, |bundle| bundle.payload.rules.clone()),
    );
    let permissions = engine.effective_permissions(&AgentId(agent), Utc::now());
    let connections = state
        .repository
        .project_connections(&OrganizationId(organization), &ProjectId(project))
        .await?;
    Ok(Json(json!({
        "policy_version":bundle.map(|bundle| bundle.payload.version),
        "permissions":permissions,
        "connections":connections
    })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreatePolicyProposalRequest {
    schema_version: u32,
    base_policy_version: u64,
    title: String,
    reason: String,
    rules: Vec<PolicyRule>,
    #[serde(default = "default_proposal_ttl")]
    ttl_seconds: i64,
}

fn default_proposal_ttl() -> i64 {
    86_400
}

async fn create_policy_proposal(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project, agent)): Path<(String, String, String)>,
    Json(body): Json<CreatePolicyProposalRequest>,
) -> ApiResult<Json<Value>> {
    if body.schema_version != CONTROL_CONTRACT_VERSION
        || !(60..=604_800).contains(&body.ttl_seconds)
    {
        return Err(ApiError(KeyLeaseError::InvalidRequest {
            reason: "invalid policy proposal version or TTL".into(),
        }));
    }
    let organization_id = OrganizationId(organization);
    let project_id = ProjectId(project);
    let agent_id = AgentId(agent);
    state
        .repository
        .authenticate_agent(&organization_id, &project_id, &agent_id, bearer(&headers)?)
        .await?;
    let now = Utc::now();
    let mut proposal = PolicyProposal {
        schema_version: CONTROL_CONTRACT_VERSION,
        proposal_id: PolicyProposalId::new(),
        organization_id,
        project_id,
        proposed_by_agent_id: agent_id,
        base_policy_version: body.base_policy_version,
        title: body.title,
        reason: body.reason,
        rules: body.rules,
        proposal_digest_sha256: String::new(),
        status: PolicyProposalStatus::Pending,
        created_at: now,
        expires_at: now + Duration::seconds(body.ttl_seconds),
    };
    proposal.proposal_digest_sha256 = proposal.calculate_digest();
    state.repository.create_policy_proposal(&proposal).await?;
    Ok(Json(json!({"proposal":proposal})))
}

async fn list_policy_proposals(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
    Query(query): Query<CursorQuery>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let proposals = state
        .repository
        .policy_proposals(
            &OrganizationId(organization),
            &ProjectId(project),
            query.limit,
        )
        .await?;
    Ok(Json(json!({"proposals":proposals})))
}

async fn review_policy_proposal(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project, proposal)): Path<(String, String, String)>,
    Json(body): Json<PolicyProposalReviewRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let (proposal, review) = state
        .repository
        .review_policy_proposal(
            &OrganizationId(organization),
            &ProjectId(project),
            &PolicyProposalId(proposal),
            &body,
        )
        .await?;
    Ok(Json(json!({"proposal":proposal,"review":review})))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivateProposalRequest {
    schema_version: u32,
    expected_proposal_digest_sha256: String,
    #[serde(default = "default_policy_validity")]
    validity_seconds: i64,
    #[serde(default)]
    offline: OfflineAuthorization,
    #[serde(default = "default_minimum_edge_version")]
    minimum_edge_version: String,
}

fn default_policy_validity() -> i64 {
    86_400
}
fn default_minimum_edge_version() -> String {
    env!("CARGO_PKG_VERSION").into()
}

async fn activate_policy_proposal(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project, proposal)): Path<(String, String, String)>,
    Json(body): Json<ActivateProposalRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    if body.schema_version != CONTROL_CONTRACT_VERSION
        || !(300..=604_800).contains(&body.validity_seconds)
    {
        return Err(ApiError(KeyLeaseError::InvalidRequest {
            reason: "invalid proposal activation request".into(),
        }));
    }
    let organization_id = OrganizationId(organization);
    let project_id = ProjectId(project);
    let proposal_id = PolicyProposalId(proposal);
    let proposal = state
        .repository
        .policy_proposal(&organization_id, &project_id, &proposal_id)
        .await?;
    if proposal.status != PolicyProposalStatus::Approved
        || proposal.proposal_digest_sha256 != body.expected_proposal_digest_sha256
    {
        return Err(ApiError(KeyLeaseError::Denied {
            reason: "proposal is not approved or digest changed".into(),
        }));
    }
    let previous = state
        .repository
        .latest_policy_state(&organization_id, &project_id)
        .await?;
    let now = Utc::now();
    let bundle = state.signer.sign_policy(PolicyBundlePayload {
        schema_version: CONTROL_CONTRACT_VERSION,
        bundle_id: PolicyBundleId::new(),
        organization_id: organization_id.clone(),
        project_id: project_id.clone(),
        version: proposal.base_policy_version + 1,
        previous_bundle_digest: previous
            .as_ref()
            .map(|state| state.payload_digest_sha256.clone()),
        issued_at: now,
        not_before: now,
        expires_at: now + Duration::seconds(body.validity_seconds),
        revocation_epoch: previous.as_ref().map_or(0, |state| state.revocation_epoch),
        minimum_edge_version: body.minimum_edge_version,
        offline: body.offline,
        rules: proposal.rules.clone(),
    })?;
    verify_policy_bundle(
        &bundle,
        &state.signer.verifying_key_base64(),
        now,
        previous.as_ref(),
    )?;
    let event = state
        .repository
        .activate_reviewed_proposal(&proposal_id, &bundle)
        .await?;
    Ok(Json(
        json!({"bundle":bundle,"control_event":event,"proposal_id":proposal_id}),
    ))
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

async fn report_credential_lease(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(edge): Path<String>,
    Json(body): Json<CredentialLeaseRecord>,
) -> ApiResult<Json<Value>> {
    let edge_id = EdgeId(edge);
    authorize_edge(&state, &headers, &edge_id).await?;
    state
        .repository
        .report_credential_lease(&edge_id, &body)
        .await?;
    Ok(Json(json!({"recorded":true})))
}

async fn report_connection_posture(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(edge): Path<String>,
    Json(body): Json<ConnectionPosture>,
) -> ApiResult<Json<Value>> {
    let edge_id = EdgeId(edge);
    authorize_edge(&state, &headers, &edge_id).await?;
    state
        .repository
        .report_connection_posture(&edge_id, &body)
        .await?;
    Ok(Json(json!({"recorded":true})))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialLeaseQuery {
    agent_id: Option<String>,
    state: Option<CredentialLeaseState>,
    #[serde(default = "default_limit")]
    limit: u32,
}

async fn list_credential_leases(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
    Query(query): Query<CredentialLeaseQuery>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let leases = state
        .repository
        .credential_leases(
            &OrganizationId(organization),
            &ProjectId(project),
            &CredentialLeaseFilter {
                agent_id: query.agent_id,
                state: query.state,
                limit: query.limit,
            },
        )
        .await?;
    Ok(Json(json!({"leases":leases})))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialRevokeRequest {
    schema_version: u32,
    reason: String,
}

async fn revoke_credential_lease(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project, lease)): Path<(String, String, String)>,
    Json(body): Json<CredentialRevokeRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    if body.schema_version != CREDENTIAL_CONTRACT_VERSION {
        return Err(ApiError(KeyLeaseError::UnsupportedVersion {
            version: body.schema_version,
        }));
    }
    let event = state
        .repository
        .revoke_credential_lease(
            &OrganizationId(organization),
            &ProjectId(project),
            &CredentialLeaseId(lease),
            &body.reason,
        )
        .await?;
    Ok(Json(json!({"revoking":true,"control_event":event})))
}

async fn list_connection_posture(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let postures = state
        .repository
        .connection_postures(&OrganizationId(organization), &ProjectId(project))
        .await?;
    Ok(Json(json!({"postures":postures})))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRotationRequest {
    schema_version: u32,
    connection_id: ConnectionId,
    requested_by: String,
    reason: String,
    expected_connection_updated_at: DateTime<Utc>,
}

async fn create_rotation(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
    Json(body): Json<CreateRotationRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    if body.schema_version != CREDENTIAL_CONTRACT_VERSION {
        return Err(ApiError(KeyLeaseError::UnsupportedVersion {
            version: body.schema_version,
        }));
    }
    let now = Utc::now();
    let record = RotationRecord {
        schema_version: CREDENTIAL_CONTRACT_VERSION,
        rotation_id: RotationId::new(),
        connection_id: body.connection_id,
        state: RotationState::Pending,
        requested_by: body.requested_by,
        reason: body.reason,
        expected_connection_updated_at: body.expected_connection_updated_at,
        created_at: now,
        updated_at: now,
        completed_at: None,
        failure_code: None,
    };
    state
        .repository
        .create_rotation(&OrganizationId(organization), &ProjectId(project), &record)
        .await?;
    Ok(Json(json!({"rotation":record})))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransitionRotationRequest {
    schema_version: u32,
    expected_state: RotationState,
    next_state: RotationState,
    failure_code: Option<String>,
}

async fn transition_rotation(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project, rotation)): Path<(String, String, String)>,
    Json(body): Json<TransitionRotationRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    if body.schema_version != CREDENTIAL_CONTRACT_VERSION {
        return Err(ApiError(KeyLeaseError::UnsupportedVersion {
            version: body.schema_version,
        }));
    }
    let record = state
        .repository
        .transition_rotation(
            &OrganizationId(organization),
            &ProjectId(project),
            &RotationId(rotation),
            body.expected_state,
            body.next_state,
            body.failure_code,
        )
        .await?;
    Ok(Json(json!({"rotation":record})))
}

async fn list_rotations(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let rotations = state
        .repository
        .rotations(&OrganizationId(organization), &ProjectId(project))
        .await?;
    Ok(Json(json!({"rotations":rotations})))
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditQuery {
    #[serde(default)]
    after: u64,
    #[serde(default = "default_limit")]
    limit: u32,
    agent_id: Option<String>,
    connection_id: Option<String>,
    action: Option<String>,
    resource_prefix: Option<String>,
    decision: Option<String>,
    outcome: Option<String>,
    policy_version: Option<u64>,
    from: Option<chrono::DateTime<Utc>>,
    until: Option<chrono::DateTime<Utc>>,
}

async fn query_audit(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let page = state
        .repository
        .query_audit(
            &OrganizationId(organization),
            &ProjectId(project),
            &AuditQueryFilter {
                after: query.after,
                limit: query.limit,
                agent_id: query.agent_id,
                connection_id: query.connection_id,
                action: query.action,
                resource_prefix: query.resource_prefix,
                decision: query.decision,
                outcome: query.outcome,
                policy_version: query.policy_version,
                from: query.from,
                until: query.until,
            },
        )
        .await?;
    Ok(Json(
        serde_json::to_value(page).map_err(|_| ApiError(KeyLeaseError::Storage))?,
    ))
}

async fn audit_integrity(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let report = state
        .repository
        .verify_audit_integrity(&OrganizationId(organization), &ProjectId(project))
        .await?;
    Ok(Json(
        serde_json::to_value(report).map_err(|_| ApiError(KeyLeaseError::Storage))?,
    ))
}

fn built_in_manifests() -> Vec<ConnectorManifest> {
    vec![
        google_manifest(),
        github_manifest(),
        linear_manifest(),
        notion_manifest(),
        slack_manifest(),
        jira_manifest(),
    ]
}

async fn find_manifest(
    state: &CloudApiState,
    organization: &str,
    project: &str,
    provider: &str,
    version: &str,
) -> ApiResult<ConnectorManifest> {
    if let Some(manifest) = built_in_manifests()
        .into_iter()
        .find(|manifest| manifest.provider == provider && manifest.version == version)
    {
        validate_manifest(&manifest)?;
        return Ok(manifest);
    }
    let entries = state
        .repository
        .connector_versions(
            &OrganizationId(organization.into()),
            &ProjectId(project.into()),
        )
        .await?;
    let entry = entries
        .into_iter()
        .find(|entry| {
            entry.provider == provider
                && entry.connector_version == version
                && matches!(
                    entry.status,
                    leasegate_connector_sdk::ConnectorRegistryStatus::Published
                )
        })
        .ok_or_else(|| {
            ApiError(KeyLeaseError::NotFound {
                resource: format!("connector:{provider}:{version}"),
            })
        })?;
    validate_manifest(&entry.package.payload.manifest)?;
    Ok(entry.package.payload.manifest)
}

pub(crate) fn authorize(state: &CloudApiState, headers: &HeaderMap) -> ApiResult<()> {
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

pub(crate) fn bearer(headers: &HeaderMap) -> ApiResult<&str> {
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

pub(crate) type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Debug)]
pub(crate) struct ApiError(pub(crate) KeyLeaseError);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operations_snapshot_fails_closed_when_stale() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("operations-status.json");
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "schema_version": 1,
                "available": true,
                "profile": "single_vps",
                "generated_at": "2020-01-01T00:00:00Z",
                "release_id": "phase9-test",
                "healthy": true,
                "issues": [],
                "services": {"expected":6,"running":6,"control_plane_ready":true,"gateway_ready":true},
                "disk": {"used_percent":20},
                "backup": {"age_seconds":60},
                "tls": {"expiry_seconds":86400},
                "soak": {"consecutive_seconds":100,"failures":0}
            }))
            .unwrap(),
        )
        .unwrap();
        let status = load_operations_status(&path).unwrap();
        assert_eq!(status["stale"], true);
        assert_eq!(status["healthy"], false);
        assert!(
            status["issues"]
                .as_array()
                .unwrap()
                .contains(&json!("status_snapshot_stale"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn operations_snapshot_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.json");
        let link = directory.path().join("operations-status.json");
        fs::write(&target, b"{}").unwrap();
        symlink(target, &link).unwrap();
        assert!(matches!(
            load_operations_status(&link),
            Err(KeyLeaseError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn operations_snapshot_rejects_unrecognized_fields() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("operations-status.json");
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "schema_version": 1,
                "available": true,
                "profile": "single_vps",
                "generated_at": Utc::now(),
                "release_id": "phase9-test",
                "healthy": true,
                "issues": [],
                "services": {"expected":6,"running":6,"control_plane_ready":true,"gateway_ready":true},
                "disk": {"used_percent":20},
                "backup": {"age_seconds":60},
                "tls": {"expiry_seconds":86400},
                "soak": {"consecutive_seconds":100,"failures":0},
                "credential": "must-not-pass-through"
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            load_operations_status(&path),
            Err(KeyLeaseError::InvalidRequest { .. })
        ));
    }
}
