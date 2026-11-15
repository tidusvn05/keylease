//! Managed nodes (ADR 0012). An organization's owners and admins create a
//! one-time enrollment code; a node (`keylease cloud org join`) redeems it
//! with a request signed by its relay key and pins the server's signing key.
//! The organization's node policy (deny and require-approval rules) is
//! signed by the server; nodes fetch it every minute, check the signature and
//! the version, apply it and report the version they run.

use crate::api::{ApiError, ApiResult, CloudApiState};
use crate::console::{require_csrf, session};
use crate::relay::{denied, invalid, parse, storage, verify};
use crate::teams::{OrgRole, org_role};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, Method},
    routing::{delete, get, post, put},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use keylease_core::{
    AgentId, DataBudget, KeyLeaseError, PolicyEffect, PolicyRule,
    managed::{
        AppliedPolicy, MAX_MANAGED_RULES, ManagedPolicy, OrgNodeJoin, OrgNodeJoined,
        OrgPolicyAnswer, SignedManagedPolicy, managed_policy_signing_input,
    },
};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;

/// How long an enrollment code works.
const ENROLLMENT_HOURS: i64 = 24;
/// How long a signed policy stays valid on a node.
const POLICY_DAYS: i64 = 30;
/// A policy is signed again when less than this is left.
const RESIGN_DAYS: i64 = 23;

pub(crate) fn router() -> Router<CloudApiState> {
    Router::new()
        .route("/v1/orgs/{org}/nodes", get(list_nodes))
        .route("/v1/orgs/{org}/nodes/enrollments", post(create_enrollment))
        .route("/v1/orgs/{org}/nodes/{member}", delete(remove_node))
        .route("/v1/orgs/{org}/node-policy", put(set_policy))
        .route("/v1/relay/org-nodes/join", post(join))
        .route("/v1/relay/org-policy", get(fetch_policy))
        .route("/v1/relay/org-policy/applied", put(applied))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn require_admin(state: &CloudApiState, headers: &HeaderMap, org: &str) -> ApiResult<String> {
    let account = session(state, headers).await?;
    if org_role(state, org, &account).await? < OrgRole::Admin {
        return Err(denied(
            "only an owner or admin manages the organization's nodes",
        ));
    }
    Ok(account)
}

async fn create_enrollment(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(org): Path<String>,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = require_admin(&state, &headers, &org).await?;
    let mut bytes = [0_u8; 24];
    rand::rng().fill_bytes(&mut bytes);
    let code = format!("klnode_{}", URL_SAFE_NO_PAD.encode(bytes));
    let expires_at = Utc::now() + Duration::hours(ENROLLMENT_HOURS);
    sqlx::query(
        "INSERT INTO org_node_enrollments(code_hash,org_id,created_by,created_at,expires_at) VALUES($1,$2,$3,now(),$4)",
    )
    .bind(sha256_hex(code.as_bytes()))
    .bind(&org)
    .bind(&account)
    .bind(expires_at)
    .execute(state.repository.pool())
    .await
    .map_err(storage)?;
    Ok(Json(json!({
        "code": code,
        "expires_at": expires_at,
        "command": format!("keylease cloud org join --code {code}"),
    })))
}

async fn list_nodes(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(org): Path<String>,
) -> ApiResult<Json<Value>> {
    require_admin(&state, &headers, &org).await?;
    let pool = state.repository.pool();
    let nodes = sqlx::query(
        "SELECT n.member_id, m.name, m.revoked_at, n.joined_at, n.applied_version, n.last_seen_at \
         FROM org_nodes n JOIN relay_members m ON m.member_id=n.member_id WHERE n.org_id=$1 ORDER BY m.name",
    )
    .bind(&org)
    .fetch_all(pool)
    .await
    .map_err(storage)?;
    let policy = latest_policy(&state, &org).await?;
    let (version, rules) = match &policy {
        Some((signed, _)) => {
            let payload: ManagedPolicy = serde_json::from_str(&signed.payload)
                .map_err(|_| ApiError(KeyLeaseError::Storage))?;
            (
                payload.version,
                serde_json::to_value(&payload.rules).unwrap_or_default(),
            )
        }
        None => (0, json!([])),
    };
    Ok(Json(json!({
        "policy": {"version": version, "rules": rules},
        "nodes": nodes.iter().map(|row| json!({
            "member_id": row.get::<String, _>("member_id"),
            "name": row.get::<String, _>("name"),
            "revoked": row.get::<Option<DateTime<Utc>>, _>("revoked_at").is_some(),
            "joined_at": row.get::<DateTime<Utc>, _>("joined_at"),
            "applied_version": row.get::<Option<i64>, _>("applied_version"),
            "last_seen_at": row.get::<Option<DateTime<Utc>>, _>("last_seen_at"),
        })).collect::<Vec<_>>(),
    })))
}

async fn remove_node(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, member)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    require_admin(&state, &headers, &org).await?;
    let removed = sqlx::query("DELETE FROM org_nodes WHERE member_id=$1 AND org_id=$2")
        .bind(&member)
        .bind(&org)
        .execute(state.repository.pool())
        .await
        .map_err(storage)?
        .rows_affected();
    Ok(Json(json!({"removed": removed})))
}

/// A rule as an admin writes it; the server fills in the rest.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleInput {
    id: String,
    /// `deny` or `require_approval`.
    effect: PolicyEffect,
    actions: Vec<String>,
    #[serde(default)]
    resource_prefix: String,
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    connection_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetPolicy {
    rules: Vec<RuleInput>,
}

fn valid_rule_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Signs and stores a new version of the organization's node policy.
async fn sign_policy(
    state: &CloudApiState,
    org: &str,
    rules: Vec<PolicyRule>,
    account: Option<&str>,
) -> ApiResult<SignedManagedPolicy> {
    let pool = state.repository.pool();
    let version: i64 = sqlx::query(
        "SELECT COALESCE(MAX(version), 0) + 1 AS v FROM org_node_policies WHERE org_id=$1",
    )
    .bind(org)
    .fetch_one(pool)
    .await
    .map_err(storage)?
    .get("v");
    let now = Utc::now();
    let policy = ManagedPolicy {
        v: 1,
        org_id: org.to_owned(),
        version: u64::try_from(version).unwrap_or(1),
        issued_at: now,
        expires_at: now + Duration::days(POLICY_DAYS),
        rules,
    };
    let payload = serde_json::to_string(&policy).map_err(|_| ApiError(KeyLeaseError::Storage))?;
    let signed = SignedManagedPolicy {
        signature: state
            .signer
            .sign_bytes(&managed_policy_signing_input(&payload)),
        key_id: state.signer.key_id().to_owned(),
        payload,
    };
    sqlx::query(
        "INSERT INTO org_node_policies(org_id,version,payload,signature,key_id,expires_at,created_by,created_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,now())",
    )
    .bind(org)
    .bind(version)
    .bind(&signed.payload)
    .bind(&signed.signature)
    .bind(&signed.key_id)
    .bind(policy.expires_at)
    .bind(account)
    .execute(pool)
    .await
    .map_err(|_| invalid("the policy changed at the same time; try again"))?;
    Ok(signed)
}

async fn latest_policy(
    state: &CloudApiState,
    org: &str,
) -> ApiResult<Option<(SignedManagedPolicy, DateTime<Utc>)>> {
    Ok(sqlx::query(
        "SELECT payload,signature,key_id,expires_at FROM org_node_policies WHERE org_id=$1 ORDER BY version DESC LIMIT 1",
    )
    .bind(org)
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .map(|row| {
        (
            SignedManagedPolicy {
                payload: row.get("payload"),
                key_id: row.get("key_id"),
                signature: row.get("signature"),
            },
            row.get("expires_at"),
        )
    }))
}

async fn set_policy(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(org): Path<String>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = require_admin(&state, &headers, &org).await?;
    let request: SetPolicy = parse(&body)?;
    if request.rules.len() > MAX_MANAGED_RULES {
        return Err(invalid("too many rules"));
    }
    let mut rules = Vec::with_capacity(request.rules.len());
    for rule in request.rules {
        if !valid_rule_id(&rule.id) {
            return Err(invalid("a rule id is a-z, A-Z, 0-9, - and _"));
        }
        if !matches!(
            rule.effect,
            PolicyEffect::Deny | PolicyEffect::RequireApproval
        ) {
            return Err(invalid(
                "managed rules only tighten: their effect is deny or require_approval",
            ));
        }
        if rule.actions.is_empty() || rule.actions.len() > 50 || rule.resource_prefix.len() > 1024 {
            return Err(invalid(format!("rule {} needs 1-50 actions", rule.id)));
        }
        rules.push(PolicyRule {
            id: rule.id,
            version: 0,
            effect: rule.effect,
            agent_id: rule.agent_id.map(AgentId),
            connection_id: rule.connection_id,
            resource_prefix: rule.resource_prefix,
            actions: rule.actions,
            argument_equals: Default::default(),
            not_before: None,
            expires_at: None,
            max_lease_ttl_seconds: 300,
            max_uses: 1,
            budget: DataBudget::default(),
        });
    }
    let signed = sign_policy(&state, &org, rules, Some(&account)).await?;
    let version = serde_json::from_str::<ManagedPolicy>(&signed.payload)
        .map(|policy| policy.version)
        .unwrap_or_default();
    crate::managed::audit_event(&state, &org, "-", None, None, "node_policy_set", &account).await?;
    Ok(Json(json!({"version": version})))
}

// ---------------------------------------------------------------------------
// Node side (signed with the relay member key)
// ---------------------------------------------------------------------------

async fn join(
    State(state): State<CloudApiState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<OrgNodeJoined>> {
    let caller = verify(&state, &method, &uri, &headers, &body).await?;
    let request: OrgNodeJoin = parse(&body)?;
    let pool = state.repository.pool();
    let mut transaction = pool.begin().await.map_err(storage)?;
    let row = sqlx::query(
        "UPDATE org_node_enrollments SET used_by=$2, used_at=now() \
         WHERE code_hash=$1 AND used_by IS NULL AND expires_at > now() RETURNING org_id",
    )
    .bind(sha256_hex(request.code.trim().as_bytes()))
    .bind(&caller.member_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(storage)?
    .ok_or_else(|| denied("the enrollment code is unknown, used or expired"))?;
    let org: String = row.get("org_id");
    sqlx::query(
        "INSERT INTO org_nodes(member_id,org_id,joined_at) VALUES($1,$2,now()) \
         ON CONFLICT (member_id) DO UPDATE SET org_id=excluded.org_id, joined_at=now(), applied_version=NULL",
    )
    .bind(&caller.member_id)
    .bind(&org)
    .execute(&mut *transaction)
    .await
    .map_err(storage)?;
    let name: String = sqlx::query("SELECT name FROM team_orgs WHERE org_id=$1")
        .bind(&org)
        .fetch_one(&mut *transaction)
        .await
        .map_err(storage)?
        .get("name");
    transaction.commit().await.map_err(storage)?;
    Ok(Json(OrgNodeJoined {
        org_id: org,
        org_name: name,
        key_id: state.signer.key_id().to_owned(),
        verifying_key: state.signer.verifying_key_base64(),
    }))
}

async fn node_org(state: &CloudApiState, member: &str) -> ApiResult<String> {
    Ok(
        sqlx::query("SELECT org_id FROM org_nodes WHERE member_id=$1")
            .bind(member)
            .fetch_optional(state.repository.pool())
            .await
            .map_err(storage)?
            .ok_or_else(|| {
                ApiError(KeyLeaseError::NotFound {
                    resource: "organization membership".into(),
                })
            })?
            .get("org_id"),
    )
}

/// The organization's current signed policy, signed again when it is close
/// to expiring.
async fn fetch_policy(
    State(state): State<CloudApiState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<OrgPolicyAnswer>> {
    let caller = verify(&state, &method, &uri, &headers, &body).await?;
    let org = node_org(&state, &caller.member_id).await?;
    sqlx::query("UPDATE org_nodes SET last_seen_at=now() WHERE member_id=$1")
        .bind(&caller.member_id)
        .execute(state.repository.pool())
        .await
        .map_err(storage)?;
    let policy = match latest_policy(&state, &org).await? {
        Some((signed, expires_at)) if expires_at - Utc::now() < Duration::days(RESIGN_DAYS) => {
            let rules = serde_json::from_str::<ManagedPolicy>(&signed.payload)
                .map_err(|_| ApiError(KeyLeaseError::Storage))?
                .rules;
            Some(sign_policy(&state, &org, rules, None).await?)
        }
        other => other.map(|(signed, _)| signed),
    };
    Ok(Json(OrgPolicyAnswer { policy }))
}

async fn applied(
    State(state): State<CloudApiState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let caller = verify(&state, &method, &uri, &headers, &body).await?;
    let request: AppliedPolicy = parse(&body)?;
    sqlx::query("UPDATE org_nodes SET applied_version=$2, last_seen_at=now() WHERE member_id=$1")
        .bind(&caller.member_id)
        .bind(i64::try_from(request.version).unwrap_or(i64::MAX))
        .execute(state.repository.pool())
        .await
        .map_err(storage)?;
    Ok(Json(json!({"ok": true})))
}
