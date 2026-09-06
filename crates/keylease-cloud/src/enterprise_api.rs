use crate::{
    ApprovalDecisionBinding,
    api::{ApiError, ApiResult, CloudApiState, authorize, bearer},
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{
        HeaderMap,
        header::{CACHE_CONTROL, PRAGMA},
    },
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use keylease_core::{
    AccessReviewId, DeviceChallengeId, DeviceId, HumanId, KeyLeaseError, MembershipId,
    OrganizationId, PolicyBundleId, PolicyReleaseId, PolicyRule, ProjectId, SecurityAlertId,
};
use leasegate_control::{
    AccessReview, AccessReviewDecision, AccessReviewState, ApprovalDecision,
    ApprovalDecisionRequest, ApprovalReceiptPayload, CONTROL_CONTRACT_VERSION,
    EnterprisePermission, KeyProvider, MembershipRole, MobilePlatform, OfflineAuthorization,
    OidcProvider, OperatorDevice, OperatorSessionClaims, PolicyBundlePayload, PolicyRelease,
    PolicyReleaseState, RetentionPolicy, SiemDestination, SignedOperatorSession,
    WorkloadIdentityBinding,
};
use leasegate_policy_bundle::{verify_operator_session, verify_policy_bundle};
use serde::Deserialize;
use serde_json::{Value, json};

pub(crate) fn router() -> Router<CloudApiState> {
    Router::new()
        .route("/v1/organizations/{organization}/identity/oidc", get(get_oidc).post(upsert_oidc))
        .route("/v1/organizations/{organization}/identity/scim-tokens", post(create_scim_token))
        .route("/v1/scim/{organization}/Users", post(scim_upsert_user))
        .route("/v1/scim/{organization}/Users/{subject}", delete(scim_deactivate_user))
        .route("/v1/organizations/{organization}/memberships", get(list_memberships))
        .route("/v1/organizations/{organization}/access-reviews", get(list_access_reviews).post(create_access_review))
        .route("/v1/organizations/{organization}/access-reviews/{review}/entries/{membership}/decision", post(decide_access_review))
        .route("/v1/organizations/{organization}/access-reviews/{review}/complete", post(complete_access_review))
        .route("/v1/organizations/{organization}/operator-devices", post(register_operator_device))
        .route("/v1/organizations/{organization}/operator-devices/{device}/challenge", post(create_device_challenge))
        .route("/v1/organizations/{organization}/operator-devices/challenges/{challenge}/verify", post(verify_device))
        .route("/v1/organizations/{organization}/projects/{project}/policy/releases", get(list_policy_releases).post(create_policy_release))
        .route("/v1/organizations/{organization}/projects/{project}/policy/releases/{release}/transition", post(transition_policy_release))
        .route("/v1/organizations/{organization}/projects/{project}/retention", post(upsert_retention))
        .route("/v1/organizations/{organization}/projects/{project}/compliance-evidence", get(compliance_evidence))
        .route("/v1/organizations/{organization}/projects/{project}/siem-destinations", get(list_siem).post(upsert_siem))
        .route("/v1/organizations/{organization}/projects/{project}/workload-identities", get(list_workloads).post(upsert_workload))
        .route("/v1/organizations/{organization}/key-providers", get(list_key_providers).post(upsert_key_provider))
        .route("/v1/mobile/organizations/{organization}/projects/{project}/approvals", get(mobile_approvals))
        .route("/v1/mobile/organizations/{organization}/approvals/{approval}/decision", post(mobile_decide_approval))
        .route("/v1/mobile/organizations/{organization}/projects/{project}/security-alerts", get(mobile_security_alerts))
        .route("/v1/mobile/organizations/{organization}/projects/{project}/security-alerts/{alert}/acknowledge", post(mobile_acknowledge_alert))
}

async fn get_oidc(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(organization): Path<String>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let provider = state
        .repository
        .oidc_provider(&OrganizationId(organization))
        .await?;
    Ok(Json(json!({"provider":provider})))
}

async fn upsert_oidc(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(organization): Path<String>,
    Json(provider): Json<OidcProvider>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    if provider.organization_id.0 != organization {
        return Err(ApiError(denied("OIDC tenant mismatch")));
    }
    state.repository.upsert_oidc_provider(&provider).await?;
    Ok(Json(json!({"provider":provider})))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScimTokenRequest {
    display_name: String,
    ttl_seconds: i64,
}

async fn create_scim_token(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(organization): Path<String>,
    Json(body): Json<ScimTokenRequest>,
) -> ApiResult<Response> {
    authorize(&state, &headers)?;
    let secret = state
        .repository
        .create_scim_token(
            &OrganizationId(organization),
            &body.display_name,
            Duration::seconds(body.ttl_seconds),
        )
        .await?;
    Ok(no_store(Json(
        json!({"token_id":secret.token_id,"token":secret.token,"expires_at":secret.expires_at,"warning":"shown once"}),
    )))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScimUserRequest {
    schemas: Vec<String>,
    user_name: String,
    display_name: String,
    external_id: Option<String>,
    #[serde(default = "default_true")]
    active: bool,
    #[serde(default)]
    roles: Vec<ScimRole>,
}

#[derive(Debug, Deserialize)]
struct ScimRole {
    value: MembershipRole,
}

async fn scim_upsert_user(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(organization): Path<String>,
    Json(body): Json<ScimUserRequest>,
) -> ApiResult<Json<Value>> {
    let organization = OrganizationId(organization);
    state
        .repository
        .authenticate_scim_token(&organization, bearer(&headers)?)
        .await?;
    if !body.active
        || !body
            .schemas
            .iter()
            .any(|schema| schema == "urn:ietf:params:scim:schemas:core:2.0:User")
    {
        return Err(ApiError(KeyLeaseError::InvalidRequest {
            reason: "SCIM core User schema and active=true are required".into(),
        }));
    }
    let provider = state
        .repository
        .oidc_provider(&organization)
        .await?
        .filter(|provider| provider.enabled)
        .ok_or_else(|| ApiError(denied("SCIM requires an enabled OIDC provider")))?;
    let role = body
        .roles
        .first()
        .map(|role| role.value.clone())
        .unwrap_or(MembershipRole::Member);
    let subject = body.external_id.as_deref().unwrap_or(&body.user_name);
    let membership = state
        .repository
        .provision_scim_membership(
            &organization,
            &provider.issuer,
            subject,
            &body.display_name,
            role.clone(),
        )
        .await?;
    Ok(Json(json!({
        "schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id":membership.human_id,
        "externalId":subject,
        "userName":body.user_name,
        "displayName":body.display_name,
        "active":true,
        "roles":[{"value":role}],
        "meta":{"resourceType":"User"}
    })))
}

async fn scim_deactivate_user(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, subject)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let organization = OrganizationId(organization);
    state
        .repository
        .authenticate_scim_token(&organization, bearer(&headers)?)
        .await?;
    let provider = state
        .repository
        .oidc_provider(&organization)
        .await?
        .filter(|provider| provider.enabled)
        .ok_or_else(|| ApiError(denied("SCIM requires an enabled OIDC provider")))?;
    state
        .repository
        .deprovision_scim_membership(&organization, &provider.issuer, &subject)
        .await?;
    Ok(Json(
        json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"active":false}),
    ))
}

fn default_true() -> bool {
    true
}

async fn list_memberships(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(organization): Path<String>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    Ok(Json(
        json!({"memberships":state.repository.organization_memberships(&OrganizationId(organization)).await?}),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateAccessReviewRequest {
    created_by: HumanId,
    due_at: DateTime<Utc>,
}

async fn create_access_review(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(organization): Path<String>,
    Json(body): Json<CreateAccessReviewRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let now = Utc::now();
    let review = AccessReview {
        schema_version: CONTROL_CONTRACT_VERSION,
        review_id: AccessReviewId::new(),
        organization_id: OrganizationId(organization),
        state: AccessReviewState::Open,
        created_by: body.created_by,
        due_at: body.due_at,
        created_at: now,
        completed_at: None,
    };
    state.repository.create_access_review(&review).await?;
    Ok(Json(json!({"review":review})))
}

async fn list_access_reviews(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(organization): Path<String>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let reviews = state
        .repository
        .access_reviews(&OrganizationId(organization))
        .await?;
    let reviews = reviews
        .into_iter()
        .map(|(review, entries)| json!({"review":review,"entries":entries}))
        .collect::<Vec<_>>();
    Ok(Json(json!({"reviews":reviews})))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessReviewDecisionRequest {
    actor: HumanId,
    decision: AccessReviewDecision,
}

async fn decide_access_review(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, review, membership)): Path<(String, String, String)>,
    Json(body): Json<AccessReviewDecisionRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    state
        .repository
        .decide_access_review_entry(
            &OrganizationId(organization),
            &AccessReviewId(review),
            &MembershipId(membership),
            body.decision,
            &body.actor,
        )
        .await?;
    Ok(Json(json!({"decided":true})))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActorRequest {
    actor: HumanId,
}

async fn complete_access_review(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, review)): Path<(String, String)>,
    Json(body): Json<ActorRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    state
        .repository
        .complete_access_review(
            &OrganizationId(organization),
            &AccessReviewId(review),
            &body.actor,
        )
        .await?;
    Ok(Json(json!({"completed":true})))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterDeviceRequest {
    device_id: DeviceId,
    human_id: HumanId,
    platform: MobilePlatform,
    display_name: String,
    verifying_key_base64: String,
    push_token: Option<String>,
}

async fn register_operator_device(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(organization): Path<String>,
    Json(body): Json<RegisterDeviceRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let now = Utc::now();
    let device = OperatorDevice {
        schema_version: CONTROL_CONTRACT_VERSION,
        device_id: body.device_id,
        organization_id: OrganizationId(organization),
        human_id: body.human_id,
        platform: body.platform,
        display_name: body.display_name,
        verifying_key_base64: body.verifying_key_base64,
        push_token_digest_sha256: body.push_token.map(|token| sha256(token.as_bytes())),
        created_at: now,
        last_seen_at: None,
        revoked_at: None,
    };
    state.repository.register_operator_device(&device).await?;
    Ok(Json(json!({"device":device})))
}

async fn create_device_challenge(
    State(state): State<CloudApiState>,
    Path((organization, device)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let challenge = state
        .repository
        .create_device_challenge(&OrganizationId(organization), &DeviceId(device))
        .await?;
    let signing_payload_base64 = URL_SAFE_NO_PAD.encode(
        serde_json_canonicalizer::to_vec(&challenge.signing_payload())
            .map_err(|_| ApiError(KeyLeaseError::Storage))?,
    );
    Ok(Json(
        json!({"challenge":challenge,"signing_payload_base64":signing_payload_base64}),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyDeviceRequest {
    signature_base64: String,
    id_token: Option<String>,
}

async fn verify_device(
    State(state): State<CloudApiState>,
    Path((organization, challenge)): Path<(String, String)>,
    Json(body): Json<VerifyDeviceRequest>,
) -> ApiResult<Response> {
    let organization_id = OrganizationId(organization);
    let claims = state
        .repository
        .verify_device_challenge(
            &organization_id,
            &DeviceChallengeId(challenge),
            &body.signature_base64,
        )
        .await?;
    let mut oidc_email = None;
    if let Some(provider) = state
        .repository
        .oidc_provider(&organization_id)
        .await?
        .filter(|provider| provider.enabled)
    {
        let token = body
            .id_token
            .as_deref()
            .ok_or_else(|| ApiError(denied("OIDC ID token is required for this organization")))?;
        let identity = crate::oidc::verify_id_token(&provider, token, Utc::now()).await?;
        let (issuer, subject) = state
            .repository
            .human_oidc_identity(&organization_id, &claims.human_id)
            .await?;
        if issuer != provider.issuer || subject != identity.subject {
            return Err(ApiError(denied(
                "OIDC identity does not match the registered device owner",
            )));
        }
        if claims.role != MembershipRole::Owner && !provider.group_role_mapping.is_empty() {
            let mapped = identity
                .groups
                .iter()
                .filter_map(|group| provider.group_role_mapping.get(group))
                .any(|role| role == &claims.role);
            if !mapped {
                return Err(ApiError(denied(
                    "OIDC groups do not grant the current membership role",
                )));
            }
        }
        oidc_email = identity.email;
    }
    let signed = state.signer.sign_operator_session(claims)?;
    let encoded = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&signed).map_err(|_| ApiError(KeyLeaseError::Storage))?);
    Ok(no_store(Json(
        json!({"access_token":format!("klop_{encoded}"),"token_type":"Bearer","expires_at":signed.claims.expires_at,"role":signed.claims.role,"oidc_email":oidc_email}),
    )))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreatePolicyReleaseRequest {
    source_revision: String,
    source_digest_sha256: String,
    canary_percent: u8,
    created_by: HumanId,
    rules: Vec<PolicyRule>,
    #[serde(default)]
    offline: OfflineAuthorization,
    validity_seconds: i64,
    minimum_edge_version: String,
    rollback_of: Option<PolicyReleaseId>,
}

async fn create_policy_release(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
    Json(body): Json<CreatePolicyReleaseRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let organization_id = OrganizationId(organization);
    let project_id = ProjectId(project);
    let previous = state
        .repository
        .latest_policy_state(&organization_id, &project_id)
        .await?;
    let now = Utc::now();
    if body.rules.len() > 500 || !(300..=604_800).contains(&body.validity_seconds) {
        return Err(ApiError(KeyLeaseError::InvalidRequest {
            reason: "invalid policy release rules or validity".into(),
        }));
    }
    let bundle = state.signer.sign_policy(PolicyBundlePayload {
        schema_version: CONTROL_CONTRACT_VERSION,
        bundle_id: PolicyBundleId::new(),
        organization_id: organization_id.clone(),
        project_id: project_id.clone(),
        version: previous.as_ref().map_or(1, |value| value.version + 1),
        previous_bundle_digest: previous
            .as_ref()
            .map(|value| value.payload_digest_sha256.clone()),
        issued_at: now,
        not_before: now,
        expires_at: now + Duration::seconds(body.validity_seconds),
        revocation_epoch: previous.as_ref().map_or(0, |value| value.revocation_epoch),
        minimum_edge_version: body.minimum_edge_version,
        offline: body.offline,
        rules: body.rules,
    })?;
    verify_policy_bundle(
        &bundle,
        &state.signer.verifying_key_base64(),
        now,
        previous.as_ref(),
    )?;
    let release = PolicyRelease {
        schema_version: CONTROL_CONTRACT_VERSION,
        release_id: PolicyReleaseId::new(),
        organization_id,
        project_id,
        source_revision: body.source_revision,
        source_digest_sha256: body.source_digest_sha256,
        state: PolicyReleaseState::Staged,
        canary_percent: body.canary_percent,
        bundle,
        created_by: body.created_by,
        created_at: now,
        updated_at: now,
        rollback_of: body.rollback_of,
    };
    state.repository.create_policy_release(&release).await?;
    Ok(Json(json!({"release":release})))
}

async fn list_policy_releases(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    Ok(Json(
        json!({"releases":state.repository.policy_releases(&OrganizationId(organization), &ProjectId(project)).await?}),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransitionPolicyReleaseRequest {
    expected_state: PolicyReleaseState,
    next_state: PolicyReleaseState,
}

async fn transition_policy_release(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project, release)): Path<(String, String, String)>,
    Json(body): Json<TransitionPolicyReleaseRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let organization_id = OrganizationId(organization);
    let project_id = ProjectId(project);
    let release_id = PolicyReleaseId(release);
    let releases = state
        .repository
        .policy_releases(&organization_id, &project_id)
        .await?;
    let target = releases
        .into_iter()
        .find(|item| item.release_id == release_id)
        .ok_or_else(|| {
            ApiError(KeyLeaseError::NotFound {
                resource: release_id.0.clone(),
            })
        })?;
    let control_event = if body.next_state == PolicyReleaseState::Active {
        Some(state.repository.activate_policy(&target.bundle).await?)
    } else {
        None
    };
    let release = state
        .repository
        .transition_policy_release(
            &organization_id,
            &project_id,
            &release_id,
            body.expected_state,
            body.next_state,
        )
        .await?;
    Ok(Json(
        json!({"release":release,"control_event":control_event}),
    ))
}

async fn upsert_retention(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
    Json(mut policy): Json<RetentionPolicy>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    if policy.organization_id.0 != organization || policy.project_id.0 != project {
        return Err(ApiError(denied("retention tenant mismatch")));
    }
    policy.updated_at = Utc::now();
    state.repository.upsert_retention_policy(&policy).await?;
    Ok(Json(json!({"policy":policy})))
}

#[derive(Debug, Deserialize)]
struct EvidenceQuery {
    from: DateTime<Utc>,
    until: DateTime<Utc>,
}

async fn compliance_evidence(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
    Query(query): Query<EvidenceQuery>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    let evidence = state
        .repository
        .compliance_evidence(
            &OrganizationId(organization),
            &ProjectId(project),
            query.from,
            query.until,
        )
        .await?;
    let signed = state.signer.sign_compliance_evidence(evidence)?;
    Ok(Json(json!({"artifact":signed})))
}

async fn upsert_siem(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
    Json(destination): Json<SiemDestination>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    if destination.organization_id.0 != organization || destination.project_id.0 != project {
        return Err(ApiError(denied("SIEM tenant mismatch")));
    }
    state
        .repository
        .upsert_siem_destination(&destination)
        .await?;
    Ok(Json(json!({"destination":destination})))
}

async fn list_siem(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    Ok(Json(
        json!({"destinations":state.repository.siem_destinations(&OrganizationId(organization), &ProjectId(project)).await?}),
    ))
}

async fn upsert_workload(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
    Json(binding): Json<WorkloadIdentityBinding>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    if binding.organization_id.0 != organization || binding.project_id.0 != project {
        return Err(ApiError(denied("workload tenant mismatch")));
    }
    state.repository.upsert_workload_identity(&binding).await?;
    Ok(Json(json!({"binding":binding})))
}

async fn list_workloads(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    Ok(Json(
        json!({"workload_identities":state.repository.workload_identities(&OrganizationId(organization), &ProjectId(project)).await?}),
    ))
}

async fn upsert_key_provider(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(organization): Path<String>,
    Json(provider): Json<KeyProvider>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    if provider.organization_id.0 != organization {
        return Err(ApiError(denied("key provider tenant mismatch")));
    }
    state.repository.upsert_key_provider(&provider).await?;
    Ok(Json(json!({"provider":provider})))
}

async fn list_key_providers(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(organization): Path<String>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers)?;
    Ok(Json(
        json!({"key_providers":state.repository.key_providers(&OrganizationId(organization)).await?}),
    ))
}

#[derive(Debug, Deserialize)]
struct MobileCursor {
    limit: Option<u32>,
}

async fn mobile_approvals(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
    Query(query): Query<MobileCursor>,
) -> ApiResult<Json<Value>> {
    let claims = authorize_operator(
        &state,
        &headers,
        &OrganizationId(organization.clone()),
        EnterprisePermission::Approve,
    )?;
    let approvals = state
        .repository
        .pending_approvals(
            &OrganizationId(organization),
            &ProjectId(project),
            query.limit.unwrap_or(100),
        )
        .await?;
    Ok(Json(json!({"approvals":approvals,"session":claims})))
}

async fn mobile_decide_approval(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, approval)): Path<(String, String)>,
    Json(body): Json<ApprovalDecisionRequest>,
) -> ApiResult<Json<Value>> {
    let organization_id = OrganizationId(organization);
    let claims = authorize_operator(
        &state,
        &headers,
        &organization_id,
        EnterprisePermission::Approve,
    )?;
    if body.schema_version != CONTROL_CONTRACT_VERSION || body.approver_id != claims.human_id {
        return Err(ApiError(denied(
            "mobile approver must match device session",
        )));
    }
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
            approver_id: claims.human_id.clone(),
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
                approver_id: &claims.human_id,
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

async fn mobile_security_alerts(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project)): Path<(String, String)>,
    Query(query): Query<MobileCursor>,
) -> ApiResult<Json<Value>> {
    let organization_id = OrganizationId(organization);
    authorize_operator(
        &state,
        &headers,
        &organization_id,
        EnterprisePermission::AuditRead,
    )?;
    let alerts = state
        .repository
        .security_alerts(
            &organization_id,
            &ProjectId(project),
            query.limit.unwrap_or(100),
        )
        .await?;
    Ok(Json(json!({"alerts":alerts})))
}

async fn mobile_acknowledge_alert(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((organization, project, alert)): Path<(String, String, String)>,
) -> ApiResult<Json<Value>> {
    let organization_id = OrganizationId(organization);
    let claims = authorize_operator(
        &state,
        &headers,
        &organization_id,
        EnterprisePermission::AuditRead,
    )?;
    state
        .repository
        .acknowledge_security_alert(
            &organization_id,
            &ProjectId(project),
            &SecurityAlertId(alert),
            &claims.human_id,
        )
        .await?;
    Ok(Json(json!({"acknowledged":true})))
}

fn authorize_operator(
    state: &CloudApiState,
    headers: &HeaderMap,
    organization_id: &OrganizationId,
    permission: EnterprisePermission,
) -> ApiResult<OperatorSessionClaims> {
    let token = bearer(headers)?;
    let encoded = token
        .strip_prefix("klop_")
        .ok_or_else(|| ApiError(denied("device-bound operator session required")))?;
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ApiError(denied("invalid operator session encoding")))?;
    let signed: SignedOperatorSession =
        serde_json::from_slice(&raw).map_err(|_| ApiError(denied("invalid operator session")))?;
    verify_operator_session(&signed, &state.signer.verifying_key_base64(), Utc::now())?;
    if &signed.claims.organization_id != organization_id || !signed.claims.role.allows(permission) {
        return Err(ApiError(denied(
            "operator session lacks required tenant permission",
        )));
    }
    Ok(signed.claims)
}

fn no_store<T: IntoResponse>(value: T) -> Response {
    let mut response = value.into_response();
    response.headers_mut().insert(
        CACHE_CONTROL,
        "no-store, max-age=0".parse().expect("static header"),
    );
    response
        .headers_mut()
        .insert(PRAGMA, "no-cache".parse().expect("static header"));
    response
}

fn sha256(value: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn denied(reason: &str) -> KeyLeaseError {
    KeyLeaseError::Denied {
        reason: reason.into(),
    }
}
