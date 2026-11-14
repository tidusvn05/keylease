//! Managed projects (v2 plan, step 13): an organization project's secrets,
//! stored on the server and encrypted with a per-project data key. The data
//! key is wrapped by the KMS root key (`KEYLEASE_KMS_ROOT_KEY_FILE`) and
//! versioned, so it can be rotated; every secret change is a new version, so
//! history and restore come for free.
//!
//! Unlike Private projects, the server can decrypt these: that is what lets
//! CI/CD and the MCP Gateway use them. Access follows the project role: `read`
//! lists and reveals (each reveal audited), `write` sets, deletes and restores.

use crate::api::{ApiError, ApiResult, CloudApiState};
use crate::console::{require_csrf, session};
use crate::relay::{denied, invalid, parse, storage};
use crate::teams::{ProjectRole, project_role};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use keylease_core::{KeyLeaseError, ProjectEnvironment};
use keylease_crypto::{
    SecretKey,
    sealed::{SymmetricBox, open_symmetric, seal_symmetric},
};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use zeroize::Zeroizing;

const MAX_VALUE_BYTES: usize = 64 * 1024;

pub(crate) fn router() -> Router<CloudApiState> {
    Router::new()
        .route("/v1/orgs/{org}/projects/{slug}/secrets", get(list_secrets))
        .route(
            "/v1/orgs/{org}/projects/{slug}/secrets/{environment}/{name}",
            get(reveal_secret).put(set_secret).delete(delete_secret),
        )
        .route(
            "/v1/orgs/{org}/projects/{slug}/secrets/{environment}/{name}/versions",
            get(versions),
        )
        .route(
            "/v1/orgs/{org}/projects/{slug}/secrets/{environment}/{name}/restore",
            post(restore),
        )
        .route("/v1/orgs/{org}/projects/{slug}/export", get(export))
        .route(
            "/v1/orgs/{org}/projects/{slug}/rotate-key",
            post(rotate_key),
        )
        .route("/v1/orgs/{org}/projects/{slug}/audit", get(audit))
        .route(
            "/v1/orgs/{org}/projects/{slug}/change-requests",
            get(list_change_requests),
        )
        .route(
            "/v1/orgs/{org}/projects/{slug}/change-requests/{request}/{decision}",
            post(decide_change_request),
        )
}

fn root(state: &CloudApiState) -> ApiResult<&SecretKey> {
    state
        .kms
        .as_deref()
        .ok_or_else(|| invalid("Managed projects need KEYLEASE_KMS_ROOT_KEY_FILE on the server"))
}

fn key_aad(org: &str, slug: &str, version: i32) -> Vec<u8> {
    format!("keylease-managed-key-v1\n{org}\n{slug}\n{version}").into_bytes()
}

fn secret_aad(org: &str, slug: &str, environment: &str, name: &str, version: i32) -> Vec<u8> {
    format!("keylease-managed-secret-v1\n{org}\n{slug}\n{environment}\n{name}\n{version}")
        .into_bytes()
}

fn crypto(_: KeyLeaseError) -> ApiError {
    ApiError(KeyLeaseError::Crypto)
}

/// The project's current data key (created on first use).
async fn data_key(state: &CloudApiState, org: &str, slug: &str) -> ApiResult<(i32, SecretKey)> {
    let root = root(state)?;
    let row = sqlx::query(
        "SELECT key_version,wrapped_json FROM managed_keys WHERE org_id=$1 AND slug=$2 ORDER BY key_version DESC LIMIT 1",
    )
    .bind(org)
    .bind(slug)
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?;
    if let Some(row) = row {
        let version: i32 = row.get("key_version");
        return Ok((
            version,
            unwrap_key(
                root,
                org,
                slug,
                version,
                &row.get::<String, _>("wrapped_json"),
            )?,
        ));
    }
    new_key_version(state, org, slug, 1).await
}

async fn new_key_version(
    state: &CloudApiState,
    org: &str,
    slug: &str,
    version: i32,
) -> ApiResult<(i32, SecretKey)> {
    let root = root(state)?;
    let mut bytes = Zeroizing::new([0_u8; 32]);
    rand::rng().fill_bytes(bytes.as_mut());
    let wrapped =
        seal_symmetric(root, bytes.as_ref(), &key_aad(org, slug, version)).map_err(crypto)?;
    sqlx::query(
        "INSERT INTO managed_keys(org_id,slug,key_version,wrapped_json,created_at) VALUES($1,$2,$3,$4,now()) ON CONFLICT DO NOTHING",
    )
    .bind(org)
    .bind(slug)
    .bind(version)
    .bind(serde_json::to_string(&wrapped).map_err(|_| ApiError(KeyLeaseError::Storage))?)
    .execute(state.repository.pool())
    .await
    .map_err(storage)?;
    // Another request may have created this version first: use the stored one.
    let stored: String = sqlx::query(
        "SELECT wrapped_json FROM managed_keys WHERE org_id=$1 AND slug=$2 AND key_version=$3",
    )
    .bind(org)
    .bind(slug)
    .bind(version)
    .fetch_one(state.repository.pool())
    .await
    .map_err(storage)?
    .get("wrapped_json");
    Ok((version, unwrap_key(root, org, slug, version, &stored)?))
}

fn unwrap_key(
    root: &SecretKey,
    org: &str,
    slug: &str,
    version: i32,
    wrapped: &str,
) -> ApiResult<SecretKey> {
    let sealed: SymmetricBox =
        serde_json::from_str(wrapped).map_err(|_| ApiError(KeyLeaseError::Crypto))?;
    let bytes = open_symmetric(root, &sealed, &key_aad(org, slug, version)).map_err(crypto)?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ApiError(KeyLeaseError::Crypto))?;
    Ok(SecretKey::from_bytes(array))
}

async fn key_version(
    state: &CloudApiState,
    org: &str,
    slug: &str,
    version: i32,
) -> ApiResult<SecretKey> {
    let wrapped: String = sqlx::query(
        "SELECT wrapped_json FROM managed_keys WHERE org_id=$1 AND slug=$2 AND key_version=$3",
    )
    .bind(org)
    .bind(slug)
    .bind(version)
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .ok_or(ApiError(KeyLeaseError::Crypto))?
    .get("wrapped_json");
    unwrap_key(root(state)?, org, slug, version, &wrapped)
}

/// Checks the caller's project role and that the environment exists.
pub(crate) async fn authorize(
    state: &CloudApiState,
    headers: &HeaderMap,
    org: &str,
    slug: &str,
    environment: Option<&str>,
    needed: ProjectRole,
) -> ApiResult<String> {
    let account = session(state, headers).await?;
    let role = project_role(state, org, slug, &account)
        .await?
        .ok_or_else(|| {
            ApiError(KeyLeaseError::NotFound {
                resource: "project".into(),
            })
        })?;
    if role < needed {
        return Err(denied(format!(
            "this needs the {} role on the project",
            needed.name()
        )));
    }
    if let Some(environment) = environment {
        let environments: Value =
            sqlx::query("SELECT environments FROM team_projects WHERE org_id=$1 AND slug=$2")
                .bind(org)
                .bind(slug)
                .fetch_one(state.repository.pool())
                .await
                .map_err(storage)?
                .get("environments");
        let environments: Vec<ProjectEnvironment> =
            serde_json::from_value(environments).map_err(|_| ApiError(KeyLeaseError::Storage))?;
        if !environments.iter().any(|known| known.slug == environment) {
            return Err(invalid(format!(
                "the project has no environment {environment}"
            )));
        }
    }
    Ok(account)
}

pub(crate) async fn audit_event(
    state: &CloudApiState,
    org: &str,
    slug: &str,
    environment: Option<&str>,
    name: Option<&str>,
    action: &str,
    account: &str,
) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO managed_audit(org_id,slug,environment,name,action,account_id,at) VALUES($1,$2,$3,$4,$5,$6,now())",
    )
    .bind(org)
    .bind(slug)
    .bind(environment)
    .bind(name)
    .bind(action)
    .bind(account)
    .execute(state.repository.pool())
    .await
    .map_err(storage)?;
    Ok(())
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The latest version of every live secret in an environment.
pub(crate) async fn current(
    state: &CloudApiState,
    org: &str,
    slug: &str,
    environment: &str,
) -> ApiResult<Vec<sqlx::postgres::PgRow>> {
    sqlx::query(
        "SELECT DISTINCT ON (name) name,version,deleted,ciphertext_json,key_version,created_by,created_at \
         FROM managed_secrets WHERE org_id=$1 AND slug=$2 AND environment=$3 ORDER BY name, version DESC",
    )
    .bind(org)
    .bind(slug)
    .bind(environment)
    .fetch_all(state.repository.pool())
    .await
    .map_err(storage)
    .map(|rows| rows.into_iter().filter(|row| !row.get::<bool, _>("deleted")).collect())
}

pub(crate) async fn decrypt(
    state: &CloudApiState,
    org: &str,
    slug: &str,
    environment: &str,
    name: &str,
    row: &sqlx::postgres::PgRow,
) -> ApiResult<Zeroizing<Vec<u8>>> {
    let key = key_version(state, org, slug, row.get("key_version")).await?;
    let sealed: SymmetricBox = serde_json::from_str(
        &row.get::<Option<String>, _>("ciphertext_json")
            .unwrap_or_default(),
    )
    .map_err(|_| ApiError(KeyLeaseError::Crypto))?;
    open_symmetric(
        &key,
        &sealed,
        &secret_aad(org, slug, environment, name, row.get("version")),
    )
    .map_err(crypto)
}

#[derive(Deserialize)]
struct EnvironmentQuery {
    environment: String,
}

async fn list_secrets(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug)): Path<(String, String)>,
    Query(query): Query<EnvironmentQuery>,
) -> ApiResult<Json<Value>> {
    authorize(
        &state,
        &headers,
        &org,
        &slug,
        Some(&query.environment),
        ProjectRole::Read,
    )
    .await?;
    let rows = current(&state, &org, &slug, &query.environment).await?;
    Ok(Json(json!({
        "environment": query.environment,
        "secrets": rows.iter().map(|row| json!({
            "name": row.get::<String, _>("name"),
            "version": row.get::<i32, _>("version"),
            "updated_by": row.get::<String, _>("created_by"),
            "updated_at": row.get::<DateTime<Utc>, _>("created_at"),
        })).collect::<Vec<_>>()
    })))
}

async fn latest(
    state: &CloudApiState,
    org: &str,
    slug: &str,
    environment: &str,
    name: &str,
) -> ApiResult<Option<sqlx::postgres::PgRow>> {
    sqlx::query(
        "SELECT name,version,deleted,ciphertext_json,key_version FROM managed_secrets \
         WHERE org_id=$1 AND slug=$2 AND environment=$3 AND name=$4 ORDER BY version DESC LIMIT 1",
    )
    .bind(org)
    .bind(slug)
    .bind(environment)
    .bind(name)
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)
}

async fn reveal_secret(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug, environment, name)): Path<(String, String, String, String)>,
) -> ApiResult<Response> {
    let account = authorize(
        &state,
        &headers,
        &org,
        &slug,
        Some(&environment),
        ProjectRole::Read,
    )
    .await?;
    let row = latest(&state, &org, &slug, &environment, &name)
        .await?
        .filter(|row| !row.get::<bool, _>("deleted"))
        .ok_or_else(|| {
            ApiError(KeyLeaseError::NotFound {
                resource: name.clone(),
            })
        })?;
    let value = decrypt(&state, &org, &slug, &environment, &name, &row).await?;
    audit_event(
        &state,
        &org,
        &slug,
        Some(&environment),
        Some(&name),
        "reveal",
        &account,
    )
    .await?;
    let mut response = Json(json!({
        "name": name,
        "version": row.get::<i32, _>("version"),
        "value": String::from_utf8_lossy(&value),
    }))
    .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetSecret {
    value: String,
}

async fn write_version(
    state: &CloudApiState,
    org: &str,
    slug: &str,
    environment: &str,
    name: &str,
    value: Option<&[u8]>,
    account: &str,
) -> ApiResult<i32> {
    let previous = latest(state, org, slug, environment, name).await?;
    let version = previous
        .as_ref()
        .map_or(1, |row| row.get::<i32, _>("version") + 1);
    let (ciphertext, key_version) = match value {
        Some(value) => {
            let (key_version, key) = data_key(state, org, slug).await?;
            let sealed = seal_symmetric(
                &key,
                value,
                &secret_aad(org, slug, environment, name, version),
            )
            .map_err(crypto)?;
            (
                Some(serde_json::to_string(&sealed).map_err(|_| ApiError(KeyLeaseError::Storage))?),
                Some(key_version),
            )
        }
        None => (None, None),
    };
    sqlx::query(
        "INSERT INTO managed_secrets(org_id,slug,environment,name,version,deleted,ciphertext_json,key_version,created_by,created_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,now())",
    )
    .bind(org)
    .bind(slug)
    .bind(environment)
    .bind(name)
    .bind(version)
    .bind(value.is_none())
    .bind(ciphertext)
    .bind(key_version)
    .bind(account)
    .execute(state.repository.pool())
    .await
    .map_err(|_| invalid("the secret changed at the same time; try again"))?;
    Ok(version)
}

async fn set_secret(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug, environment, name)): Path<(String, String, String, String)>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = authorize(
        &state,
        &headers,
        &org,
        &slug,
        Some(&environment),
        ProjectRole::Write,
    )
    .await?;
    if !valid_name(&name) {
        return Err(invalid(
            "a secret name is a shell variable name (A-Z, 0-9, _)",
        ));
    }
    let request: SetSecret = parse(&body)?;
    if request.value.len() > MAX_VALUE_BYTES {
        return Err(invalid("a secret value is at most 64 KiB"));
    }
    if needs_review(&state, &org, &slug, &environment, &account).await? {
        return propose(
            &state,
            Proposal {
                org: &org,
                slug: &slug,
                environment: &environment,
                name: &name,
                action: "set",
                value: Some(request.value.as_bytes()),
                restore_version: None,
                account: &account,
            },
        )
        .await;
    }
    let version = write_version(
        &state,
        &org,
        &slug,
        &environment,
        &name,
        Some(request.value.as_bytes()),
        &account,
    )
    .await?;
    audit_event(
        &state,
        &org,
        &slug,
        Some(&environment),
        Some(&name),
        "set",
        &account,
    )
    .await?;
    Ok(Json(json!({"name": name, "version": version})))
}

async fn delete_secret(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug, environment, name)): Path<(String, String, String, String)>,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = authorize(
        &state,
        &headers,
        &org,
        &slug,
        Some(&environment),
        ProjectRole::Write,
    )
    .await?;
    if latest(&state, &org, &slug, &environment, &name)
        .await?
        .is_none_or(|row| row.get::<bool, _>("deleted"))
    {
        return Err(ApiError(KeyLeaseError::NotFound { resource: name }));
    }
    if needs_review(&state, &org, &slug, &environment, &account).await? {
        return propose(
            &state,
            Proposal {
                org: &org,
                slug: &slug,
                environment: &environment,
                name: &name,
                action: "delete",
                value: None,
                restore_version: None,
                account: &account,
            },
        )
        .await;
    }
    let version = write_version(&state, &org, &slug, &environment, &name, None, &account).await?;
    audit_event(
        &state,
        &org,
        &slug,
        Some(&environment),
        Some(&name),
        "delete",
        &account,
    )
    .await?;
    Ok(Json(
        json!({"name": name, "version": version, "deleted": true}),
    ))
}

async fn versions(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug, environment, name)): Path<(String, String, String, String)>,
) -> ApiResult<Json<Value>> {
    authorize(
        &state,
        &headers,
        &org,
        &slug,
        Some(&environment),
        ProjectRole::Read,
    )
    .await?;
    let rows = sqlx::query(
        "SELECT version,deleted,created_by,created_at FROM managed_secrets \
         WHERE org_id=$1 AND slug=$2 AND environment=$3 AND name=$4 ORDER BY version DESC",
    )
    .bind(&org)
    .bind(&slug)
    .bind(&environment)
    .bind(&name)
    .fetch_all(state.repository.pool())
    .await
    .map_err(storage)?;
    Ok(Json(json!({
        "versions": rows.iter().map(|row| json!({
            "version": row.get::<i32, _>("version"),
            "deleted": row.get::<bool, _>("deleted"),
            "created_by": row.get::<String, _>("created_by"),
            "created_at": row.get::<DateTime<Utc>, _>("created_at"),
        })).collect::<Vec<_>>()
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Restore {
    version: i32,
}

/// Makes an old version current again (as a new version).
async fn restore(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug, environment, name)): Path<(String, String, String, String)>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = authorize(
        &state,
        &headers,
        &org,
        &slug,
        Some(&environment),
        ProjectRole::Write,
    )
    .await?;
    let request: Restore = parse(&body)?;
    let row = sqlx::query(
        "SELECT name,version,deleted,ciphertext_json,key_version FROM managed_secrets \
         WHERE org_id=$1 AND slug=$2 AND environment=$3 AND name=$4 AND version=$5",
    )
    .bind(&org)
    .bind(&slug)
    .bind(&environment)
    .bind(&name)
    .bind(request.version)
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .filter(|row| !row.get::<bool, _>("deleted"))
    .ok_or_else(|| {
        ApiError(KeyLeaseError::NotFound {
            resource: format!("{name} version {}", request.version),
        })
    })?;
    if needs_review(&state, &org, &slug, &environment, &account).await? {
        return propose(
            &state,
            Proposal {
                org: &org,
                slug: &slug,
                environment: &environment,
                name: &name,
                action: "restore",
                value: None,
                restore_version: Some(request.version),
                account: &account,
            },
        )
        .await;
    }
    let value = decrypt(&state, &org, &slug, &environment, &name, &row).await?;
    let version = write_version(
        &state,
        &org,
        &slug,
        &environment,
        &name,
        Some(&value),
        &account,
    )
    .await?;
    audit_event(
        &state,
        &org,
        &slug,
        Some(&environment),
        Some(&name),
        "restore",
        &account,
    )
    .await?;
    Ok(Json(
        json!({"name": name, "version": version, "restored_from": request.version}),
    ))
}

/// `.env` text of an environment (for members' tools; CI uses machine
/// identities in a later step).
async fn export(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug)): Path<(String, String)>,
    Query(query): Query<EnvironmentQuery>,
) -> ApiResult<Response> {
    let account = authorize(
        &state,
        &headers,
        &org,
        &slug,
        Some(&query.environment),
        ProjectRole::Read,
    )
    .await?;
    let mut text = Zeroizing::new(String::new());
    for row in current(&state, &org, &slug, &query.environment).await? {
        let name: String = row.get("name");
        let value = decrypt(&state, &org, &slug, &query.environment, &name, &row).await?;
        let value = String::from_utf8_lossy(&value);
        let escaped = value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n");
        text.push_str(&format!("{name}=\"{escaped}\"\n"));
    }
    audit_event(
        &state,
        &org,
        &slug,
        Some(&query.environment),
        None,
        "export",
        &account,
    )
    .await?;
    let mut response = text.to_string().into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

/// Starts a new data key version: new secret versions use it; old versions
/// stay readable with their own key version.
async fn rotate_key(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = authorize(&state, &headers, &org, &slug, None, ProjectRole::Admin).await?;
    let (current, _) = data_key(&state, &org, &slug).await?;
    let (version, _) = new_key_version(&state, &org, &slug, current + 1).await?;
    audit_event(&state, &org, &slug, None, None, "rotate_key", &account).await?;
    Ok(Json(json!({"key_version": version})))
}

async fn audit(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers, &org, &slug, None, ProjectRole::Admin).await?;
    let rows = sqlx::query(
        "SELECT environment,name,action,account_id,at FROM managed_audit WHERE org_id=$1 AND slug=$2 ORDER BY at DESC LIMIT 200",
    )
    .bind(&org)
    .bind(&slug)
    .fetch_all(state.repository.pool())
    .await
    .map_err(storage)?;
    Ok(Json(json!({
        "events": rows.iter().map(|row| json!({
            "environment": row.get::<Option<String>, _>("environment"),
            "name": row.get::<Option<String>, _>("name"),
            "action": row.get::<String, _>("action"),
            "account_id": row.get::<String, _>("account_id"),
            "at": row.get::<DateTime<Utc>, _>("at"),
        })).collect::<Vec<_>>()
    })))
}

// ---------------------------------------------------------------- change requests

fn change_aad(request: &str) -> Vec<u8> {
    format!("keylease-managed-change-v1\n{request}").into_bytes()
}

/// Whether a change by `account` must wait for an admin: it is in a protected
/// environment and the account is not a project admin.
async fn needs_review(
    state: &CloudApiState,
    org: &str,
    slug: &str,
    environment: &str,
    account: &str,
) -> ApiResult<bool> {
    if project_role(state, org, slug, account).await? == Some(ProjectRole::Admin) {
        return Ok(false);
    }
    let environments: Value =
        sqlx::query("SELECT environments FROM team_projects WHERE org_id=$1 AND slug=$2")
            .bind(org)
            .bind(slug)
            .fetch_one(state.repository.pool())
            .await
            .map_err(storage)?
            .get("environments");
    let environments: Vec<ProjectEnvironment> =
        serde_json::from_value(environments).map_err(|_| ApiError(KeyLeaseError::Storage))?;
    Ok(environments
        .iter()
        .any(|known| known.slug == environment && known.protected))
}

struct Proposal<'a> {
    org: &'a str,
    slug: &'a str,
    environment: &'a str,
    name: &'a str,
    action: &'a str,
    value: Option<&'a [u8]>,
    restore_version: Option<i32>,
    account: &'a str,
}

/// Records a change for an admin to approve instead of applying it.
async fn propose(state: &CloudApiState, proposal: Proposal<'_>) -> ApiResult<Json<Value>> {
    let request_id = format!("change_{}", uuid::Uuid::now_v7().simple());
    let (sealed, key_version) = match proposal.value {
        Some(value) => {
            let (key_version, key) = data_key(state, proposal.org, proposal.slug).await?;
            let sealed = seal_symmetric(&key, value, &change_aad(&request_id)).map_err(crypto)?;
            (
                Some(serde_json::to_string(&sealed).map_err(|_| ApiError(KeyLeaseError::Storage))?),
                Some(key_version),
            )
        }
        None => (None, None),
    };
    sqlx::query(
        "INSERT INTO managed_change_requests(request_id,org_id,slug,environment,name,action,sealed_json,key_version,restore_version,requested_by,requested_at,status) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now(),'pending')",
    )
    .bind(&request_id)
    .bind(proposal.org)
    .bind(proposal.slug)
    .bind(proposal.environment)
    .bind(proposal.name)
    .bind(proposal.action)
    .bind(sealed)
    .bind(key_version)
    .bind(proposal.restore_version)
    .bind(proposal.account)
    .execute(state.repository.pool())
    .await
    .map_err(storage)?;
    audit_event(
        state,
        proposal.org,
        proposal.slug,
        Some(proposal.environment),
        Some(proposal.name),
        &format!("propose_{}", proposal.action),
        proposal.account,
    )
    .await?;
    Ok(Json(json!({
        "status": "pending",
        "change_request_id": request_id,
        "message": "This environment is protected: a project admin must approve the change.",
    })))
}

async fn list_change_requests(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers, &org, &slug, None, ProjectRole::Write).await?;
    let rows = sqlx::query(
        "SELECT request_id,environment,name,action,restore_version,requested_by,requested_at FROM managed_change_requests \
         WHERE org_id=$1 AND slug=$2 AND status='pending' ORDER BY requested_at",
    )
    .bind(&org)
    .bind(&slug)
    .fetch_all(state.repository.pool())
    .await
    .map_err(storage)?;
    Ok(Json(json!({
        "change_requests": rows.iter().map(|row| json!({
            "change_request_id": row.get::<String, _>("request_id"),
            "environment": row.get::<String, _>("environment"),
            "name": row.get::<String, _>("name"),
            "action": row.get::<String, _>("action"),
            "restore_version": row.get::<Option<i32>, _>("restore_version"),
            "requested_by": row.get::<String, _>("requested_by"),
            "requested_at": row.get::<DateTime<Utc>, _>("requested_at"),
        })).collect::<Vec<_>>()
    })))
}

/// A project admin other than the requester approves (applies) or rejects.
async fn decide_change_request(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug, request_id, decision)): Path<(String, String, String, String)>,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = authorize(&state, &headers, &org, &slug, None, ProjectRole::Admin).await?;
    let approve = match decision.as_str() {
        "approve" => true,
        "reject" => false,
        _ => return Err(invalid("decide with approve or reject")),
    };
    let row = sqlx::query(
        "SELECT environment,name,action,sealed_json,key_version,restore_version,requested_by FROM managed_change_requests \
         WHERE request_id=$1 AND org_id=$2 AND slug=$3 AND status='pending'",
    )
    .bind(&request_id)
    .bind(&org)
    .bind(&slug)
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .ok_or_else(|| ApiError(KeyLeaseError::NotFound { resource: format!("change request {request_id}") }))?;
    let requester: String = row.get("requested_by");
    if requester == account {
        return Err(denied("another admin must decide on your own change"));
    }
    let environment: String = row.get("environment");
    let name: String = row.get("name");
    let claimed = sqlx::query(
        "UPDATE managed_change_requests SET status=$2, decided_by=$3, decided_at=now() WHERE request_id=$1 AND status='pending'",
    )
    .bind(&request_id)
    .bind(if approve { "approved" } else { "rejected" })
    .bind(&account)
    .execute(state.repository.pool())
    .await
    .map_err(storage)?
    .rows_affected();
    if claimed != 1 {
        return Err(invalid("this change request was already decided"));
    }
    if !approve {
        audit_event(
            &state,
            &org,
            &slug,
            Some(&environment),
            Some(&name),
            "reject_change",
            &account,
        )
        .await?;
        return Ok(Json(
            json!({"change_request_id": request_id, "status": "rejected"}),
        ));
    }
    let action: String = row.get("action");
    let value: Option<Zeroizing<Vec<u8>>> = match action.as_str() {
        "set" => {
            let key = key_version(
                &state,
                &org,
                &slug,
                row.get::<Option<i32>, _>("key_version").unwrap_or(1),
            )
            .await?;
            let sealed: SymmetricBox = serde_json::from_str(
                &row.get::<Option<String>, _>("sealed_json")
                    .unwrap_or_default(),
            )
            .map_err(|_| ApiError(KeyLeaseError::Crypto))?;
            Some(open_symmetric(&key, &sealed, &change_aad(&request_id)).map_err(crypto)?)
        }
        "restore" => {
            let version: i32 = row
                .get::<Option<i32>, _>("restore_version")
                .unwrap_or_default();
            let old = sqlx::query(
                "SELECT name,version,deleted,ciphertext_json,key_version FROM managed_secrets \
                 WHERE org_id=$1 AND slug=$2 AND environment=$3 AND name=$4 AND version=$5",
            )
            .bind(&org)
            .bind(&slug)
            .bind(&environment)
            .bind(&name)
            .bind(version)
            .fetch_optional(state.repository.pool())
            .await
            .map_err(storage)?
            .filter(|old| !old.get::<bool, _>("deleted"))
            .ok_or_else(|| {
                ApiError(KeyLeaseError::NotFound {
                    resource: format!("{name} version {version}"),
                })
            })?;
            Some(decrypt(&state, &org, &slug, &environment, &name, &old).await?)
        }
        _ => None,
    };
    let version = write_version(
        &state,
        &org,
        &slug,
        &environment,
        &name,
        value.as_deref().map(|v| v.as_slice()),
        &requester,
    )
    .await?;
    audit_event(
        &state,
        &org,
        &slug,
        Some(&environment),
        Some(&name),
        &action,
        &requester,
    )
    .await?;
    audit_event(
        &state,
        &org,
        &slug,
        Some(&environment),
        Some(&name),
        "approve_change",
        &account,
    )
    .await?;
    Ok(Json(
        json!({"change_request_id": request_id, "status": "approved", "version": version}),
    ))
}
