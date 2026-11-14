//! Enterprise features (v2 plan, step 19):
//!
//! - **KMS API:** per-project keys for `encrypt` (XChaCha20-Poly1305),
//!   `sign` (Ed25519) and `mac` (HMAC-SHA256), wrapped by the KMS root key
//!   and versioned; ciphertexts and signatures name their key version, so
//!   rotation needs no re-encryption. Used by project members (console
//!   session) and by the project's machine identities.
//! - **Audit export for SIEM:** the organization's audit as JSON Lines or
//!   RFC 5424 syslog, paged by a cursor.
//! - **SCIM 2.0 (deprovisioning):** list an organization's members and
//!   deactivate or delete them from an identity provider.

use crate::api::{ApiError, ApiResult, CloudApiState};
use crate::console::{require_csrf, session};
use crate::machine::machine_caller;
use crate::relay::{denied, invalid, parse, storage};
use crate::teams::{OrgRole, ProjectRole, org_role};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey, Verifier};
use hmac::{Hmac, Mac};
use keylease_core::KeyLeaseError;
use keylease_crypto::{
    SecretKey,
    sealed::{SymmetricBox, open_symmetric, seal_symmetric},
};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use zeroize::Zeroizing;

const MAX_PLAINTEXT: usize = 64 * 1024;

pub(crate) fn router() -> Router<CloudApiState> {
    Router::new()
        .route(
            "/v1/orgs/{org}/projects/{slug}/kms/keys",
            get(list_keys).post(create_key),
        )
        .route(
            "/v1/orgs/{org}/projects/{slug}/kms/keys/{name}/rotate",
            post(rotate_key),
        )
        .route(
            "/v1/orgs/{org}/projects/{slug}/kms/keys/{name}/{operation}",
            post(operate),
        )
        .route("/v1/machine/kms/{name}/{operation}", post(machine_operate))
        .route("/v1/orgs/{org}/audit/export", get(export_audit))
        .route("/v1/orgs/{org}/scim-tokens", post(create_scim_token))
        .route("/scim/v2/orgs/{org}/Users", get(scim_list))
        .route(
            "/scim/v2/orgs/{org}/Users/{id}",
            get(scim_get).patch(scim_patch).delete(scim_delete),
        )
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn root(state: &CloudApiState) -> ApiResult<&SecretKey> {
    state
        .kms
        .as_deref()
        .ok_or_else(|| invalid("the KMS API needs KEYLEASE_KMS_ROOT_KEY_FILE on the server"))
}

fn key_aad(key_id: &str, version: i32) -> Vec<u8> {
    format!("keylease-kms-key-v1\n{key_id}\n{version}").into_bytes()
}

// ------------------------------------------------------------------- keys

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateKey {
    name: String,
    purpose: String,
}

async fn add_version(state: &CloudApiState, key_id: &str, version: i32) -> ApiResult<()> {
    let mut material = Zeroizing::new([0_u8; 32]);
    rand::rng().fill_bytes(material.as_mut());
    let wrapped = seal_symmetric(root(state)?, material.as_ref(), &key_aad(key_id, version))
        .map_err(|_| ApiError(KeyLeaseError::Crypto))?;
    sqlx::query("INSERT INTO kms_key_versions(key_id,version,wrapped_json,created_at) VALUES($1,$2,$3,now())")
        .bind(key_id)
        .bind(version)
        .bind(serde_json::to_string(&wrapped).map_err(|_| ApiError(KeyLeaseError::Storage))?)
        .execute(state.repository.pool())
        .await
        .map_err(|_| invalid("the key changed at the same time; try again"))?;
    Ok(())
}

async fn create_key(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug)): Path<(String, String)>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account =
        crate::managed::authorize(&state, &headers, &org, &slug, None, ProjectRole::Admin).await?;
    root(&state)?;
    let request: CreateKey = parse(&body)?;
    if !matches!(request.purpose.as_str(), "encrypt" | "sign" | "mac") {
        return Err(invalid("purpose is encrypt, sign or mac"));
    }
    let key_id = format!("kms_{}", uuid::Uuid::now_v7().simple());
    sqlx::query("INSERT INTO kms_keys(key_id,org_id,slug,name,purpose,created_by,created_at) VALUES($1,$2,$3,$4,$5,$6,now())")
        .bind(&key_id)
        .bind(&org)
        .bind(&slug)
        .bind(&request.name)
        .bind(&request.purpose)
        .bind(&account)
        .execute(state.repository.pool())
        .await
        .map_err(|_| invalid("the name is a-z, 0-9 and -, unique in the project"))?;
    add_version(&state, &key_id, 1).await?;
    crate::managed::audit_event(
        &state,
        &org,
        &slug,
        None,
        Some(&request.name),
        "kms_key_create",
        &account,
    )
    .await?;
    Ok(Json(
        json!({"key_id": key_id, "name": request.name, "purpose": request.purpose, "version": 1}),
    ))
}

async fn list_keys(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    crate::managed::authorize(&state, &headers, &org, &slug, None, ProjectRole::Read).await?;
    let rows = sqlx::query(
        "SELECT k.name,k.purpose,max(v.version) AS version FROM kms_keys k JOIN kms_key_versions v ON v.key_id=k.key_id \
         WHERE k.org_id=$1 AND k.slug=$2 GROUP BY k.name,k.purpose ORDER BY k.name",
    )
    .bind(&org)
    .bind(&slug)
    .fetch_all(state.repository.pool())
    .await
    .map_err(storage)?;
    Ok(Json(json!({"keys": rows.iter().map(|row| json!({
        "name": row.get::<String, _>("name"),
        "purpose": row.get::<String, _>("purpose"),
        "version": row.get::<i32, _>("version"),
    })).collect::<Vec<_>>()})))
}

async fn rotate_key(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug, name)): Path<(String, String, String)>,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account =
        crate::managed::authorize(&state, &headers, &org, &slug, None, ProjectRole::Admin).await?;
    let (key_id, _, version) = lookup(&state, &org, &slug, &name).await?;
    add_version(&state, &key_id, version + 1).await?;
    crate::managed::audit_event(
        &state,
        &org,
        &slug,
        None,
        Some(&name),
        "kms_key_rotate",
        &account,
    )
    .await?;
    Ok(Json(json!({"name": name, "version": version + 1})))
}

/// (key id, purpose, latest version)
async fn lookup(
    state: &CloudApiState,
    org: &str,
    slug: &str,
    name: &str,
) -> ApiResult<(String, String, i32)> {
    let row = sqlx::query(
        "SELECT k.key_id,k.purpose,max(v.version) AS version FROM kms_keys k JOIN kms_key_versions v ON v.key_id=k.key_id \
         WHERE k.org_id=$1 AND k.slug=$2 AND k.name=$3 GROUP BY k.key_id,k.purpose",
    )
    .bind(org)
    .bind(slug)
    .bind(name)
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .ok_or_else(|| ApiError(KeyLeaseError::NotFound { resource: format!("key {name}") }))?;
    Ok((row.get("key_id"), row.get("purpose"), row.get("version")))
}

async fn material(
    state: &CloudApiState,
    key_id: &str,
    version: i32,
) -> ApiResult<Zeroizing<[u8; 32]>> {
    let wrapped: String =
        sqlx::query("SELECT wrapped_json FROM kms_key_versions WHERE key_id=$1 AND version=$2")
            .bind(key_id)
            .bind(version)
            .fetch_optional(state.repository.pool())
            .await
            .map_err(storage)?
            .ok_or_else(|| invalid(format!("key version {version} does not exist")))?
            .get("wrapped_json");
    let sealed: SymmetricBox =
        serde_json::from_str(&wrapped).map_err(|_| ApiError(KeyLeaseError::Crypto))?;
    let bytes = open_symmetric(root(state)?, &sealed, &key_aad(key_id, version))
        .map_err(|_| ApiError(KeyLeaseError::Crypto))?;
    let mut array = Zeroizing::new([0_u8; 32]);
    array.copy_from_slice(&bytes);
    Ok(array)
}

/// `kl:v<version>:<base64>`: the version travels with the output.
fn wrap_output(version: i32, bytes: &[u8]) -> String {
    format!("kl:v{version}:{}", STANDARD.encode(bytes))
}

fn unwrap_output(text: &str) -> ApiResult<(i32, Vec<u8>)> {
    let rest = text
        .strip_prefix("kl:v")
        .ok_or_else(|| invalid("expected kl:vN:…"))?;
    let (version, data) = rest
        .split_once(':')
        .ok_or_else(|| invalid("expected kl:vN:…"))?;
    let version: i32 = version.parse().map_err(|_| invalid("bad key version"))?;
    Ok((
        version,
        STANDARD.decode(data).map_err(|_| invalid("bad base64"))?,
    ))
}

async fn run_operation(
    state: &CloudApiState,
    org: &str,
    slug: &str,
    name: &str,
    operation: &str,
    request: &Value,
) -> ApiResult<Value> {
    let (key_id, purpose, latest) = lookup(state, org, slug, name).await?;
    let data = |field: &str| -> ApiResult<Vec<u8>> {
        let encoded = request[field]
            .as_str()
            .ok_or_else(|| invalid(format!("{field} (base64) is required")))?;
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_| invalid(format!("{field} must be base64")))?;
        if bytes.len() > MAX_PLAINTEXT {
            return Err(invalid("data is limited to 64 KiB"));
        }
        Ok(bytes)
    };
    let context = request["context"]
        .as_str()
        .unwrap_or_default()
        .as_bytes()
        .to_vec();
    match (purpose.as_str(), operation) {
        ("encrypt", "encrypt") => {
            let key = SecretKey::from_bytes(*material(state, &key_id, latest).await?);
            let sealed = seal_symmetric(&key, &data("plaintext")?, &context)
                .map_err(|_| ApiError(KeyLeaseError::Crypto))?;
            let bytes =
                serde_json::to_vec(&sealed).map_err(|_| ApiError(KeyLeaseError::Storage))?;
            Ok(json!({"ciphertext": wrap_output(latest, &bytes), "version": latest}))
        }
        ("encrypt", "decrypt") => {
            let (version, bytes) =
                unwrap_output(request["ciphertext"].as_str().unwrap_or_default())?;
            let sealed: SymmetricBox =
                serde_json::from_slice(&bytes).map_err(|_| invalid("not a KeyLease ciphertext"))?;
            let key = SecretKey::from_bytes(*material(state, &key_id, version).await?);
            let plain = open_symmetric(&key, &sealed, &context)
                .map_err(|_| invalid("the ciphertext or context is wrong"))?;
            Ok(json!({"plaintext": STANDARD.encode(plain.as_slice()), "version": version}))
        }
        ("sign", "sign") => {
            let signing = SigningKey::from_bytes(&*material(state, &key_id, latest).await?);
            let signature = signing.sign(&data("message")?);
            Ok(
                json!({"signature": wrap_output(latest, &signature.to_bytes()), "public_key": STANDARD.encode(signing.verifying_key().to_bytes())}),
            )
        }
        ("sign", "verify") => {
            let (version, bytes) =
                unwrap_output(request["signature"].as_str().unwrap_or_default())?;
            let signing = SigningKey::from_bytes(&*material(state, &key_id, version).await?);
            let signature = ed25519_dalek::Signature::from_slice(&bytes)
                .map_err(|_| invalid("bad signature"))?;
            Ok(
                json!({"valid": signing.verifying_key().verify(&data("message")?, &signature).is_ok()}),
            )
        }
        ("mac", "mac") => {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(material(state, &key_id, latest).await?.as_ref())
                    .map_err(|_| ApiError(KeyLeaseError::Crypto))?;
            mac.update(&data("message")?);
            Ok(json!({"mac": wrap_output(latest, &mac.finalize().into_bytes())}))
        }
        ("mac", "verify") => {
            let (version, bytes) = unwrap_output(request["mac"].as_str().unwrap_or_default())?;
            let mut mac =
                Hmac::<Sha256>::new_from_slice(material(state, &key_id, version).await?.as_ref())
                    .map_err(|_| ApiError(KeyLeaseError::Crypto))?;
            mac.update(&data("message")?);
            Ok(json!({"valid": mac.verify_slice(&bytes).is_ok()}))
        }
        _ => Err(invalid(format!("a {purpose} key does not {operation}"))),
    }
}

async fn operate(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug, name, operation)): Path<(String, String, String, String)>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account =
        crate::managed::authorize(&state, &headers, &org, &slug, None, ProjectRole::Write).await?;
    let request: Value = serde_json::from_slice(&body).map_err(|_| invalid("expected JSON"))?;
    let result = run_operation(&state, &org, &slug, &name, &operation, &request).await?;
    crate::managed::audit_event(
        &state,
        &org,
        &slug,
        None,
        Some(&name),
        &format!("kms_{operation}"),
        &account,
    )
    .await?;
    Ok(Json(result))
}

/// The same operations for a project's machine identities.
async fn machine_operate(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((name, operation)): Path<(String, String)>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let caller = machine_caller(&state, &headers).await?;
    let request: Value = serde_json::from_slice(&body).map_err(|_| invalid("expected JSON"))?;
    let result = run_operation(
        &state,
        &caller.org,
        &caller.slug,
        &name,
        &operation,
        &request,
    )
    .await?;
    crate::managed::audit_event(
        &state,
        &caller.org,
        &caller.slug,
        None,
        Some(&name),
        &format!("kms_{operation}"),
        &format!("machine:{}", caller.identity_id),
    )
    .await?;
    Ok(Json(result))
}

// ----------------------------------------------------------- audit export

#[derive(Deserialize)]
struct ExportQuery {
    #[serde(default)]
    after: Option<i64>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

/// The organization's audit (Managed secrets, gateway, machines, KMS) as JSON
/// Lines (default) or RFC 5424 syslog. `after` is the last `id` received;
/// `x-keylease-next` names the next cursor.
async fn export_audit(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(org): Path<String>,
    Query(query): Query<ExportQuery>,
) -> ApiResult<Response> {
    let account = session(&state, &headers).await?;
    if org_role(&state, &org, &account).await? < OrgRole::Admin {
        return Err(denied("only an owner or admin exports the audit"));
    }
    let limit = query.limit.unwrap_or(1000).clamp(1, 10_000);
    let rows = sqlx::query(
        "SELECT id,slug,environment,name,action,account_id,at FROM managed_audit WHERE org_id=$1 AND id > $2 ORDER BY id LIMIT $3",
    )
    .bind(&org)
    .bind(query.after.unwrap_or(0))
    .bind(limit)
    .fetch_all(state.repository.pool())
    .await
    .map_err(storage)?;
    let syslog = query.format.as_deref() == Some("syslog");
    let mut out = String::new();
    let mut last = query.after.unwrap_or(0);
    for row in &rows {
        let id: i64 = row.get("id");
        last = id;
        let event = json!({
            "id": id,
            "org": org,
            "project": row.get::<String, _>("slug"),
            "environment": row.get::<Option<String>, _>("environment"),
            "name": row.get::<Option<String>, _>("name"),
            "action": row.get::<String, _>("action"),
            "actor": row.get::<String, _>("account_id"),
            "at": row.get::<DateTime<Utc>, _>("at"),
        });
        if syslog {
            // <110> = facility 13 (log audit), severity 6 (informational).
            out.push_str(&format!(
                "<110>1 {} keylease-server keylease - audit - {}\n",
                row.get::<DateTime<Utc>, _>("at").to_rfc3339(),
                event
            ));
        } else {
            out.push_str(&event.to_string());
            out.push('\n');
        }
    }
    let mut response = out.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(if syslog {
            "text/plain; charset=utf-8"
        } else {
            "application/x-ndjson"
        }),
    );
    if let Ok(value) = HeaderValue::from_str(&last.to_string()) {
        response.headers_mut().insert("x-keylease-next", value);
    }
    Ok(response)
}

// ------------------------------------------------------------------- SCIM

async fn create_scim_token(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(org): Path<String>,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = session(&state, &headers).await?;
    if org_role(&state, &org, &account).await? != OrgRole::Owner {
        return Err(denied("only an owner creates SCIM tokens"));
    }
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let token = format!("klscim_{}", URL_SAFE_NO_PAD.encode(bytes));
    sqlx::query("INSERT INTO team_scim_tokens(token_hash,org_id,created_by,created_at) VALUES($1,$2,$3,now())")
        .bind(sha256_hex(token.as_bytes()))
        .bind(&org)
        .bind(&account)
        .execute(state.repository.pool())
        .await
        .map_err(storage)?;
    Ok(Json(
        json!({"token": token, "base_url": format!("/scim/v2/orgs/{org}")}),
    ))
}

async fn scim_auth(state: &CloudApiState, org: &str, headers: &HeaderMap) -> ApiResult<()> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| denied("a SCIM token is required"))?;
    sqlx::query(
        "SELECT 1 FROM team_scim_tokens WHERE token_hash=$1 AND org_id=$2 AND revoked_at IS NULL",
    )
    .bind(sha256_hex(token.trim().as_bytes()))
    .bind(org)
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .map(|_| ())
    .ok_or_else(|| denied("the SCIM token is invalid"))
}

fn scim_user(row: &sqlx::postgres::PgRow) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": row.get::<String, _>("account_id"),
        "userName": row.get::<String, _>("display_name"),
        "displayName": row.get::<String, _>("display_name"),
        "active": true,
        "roles": [{"value": row.get::<String, _>("role")}],
    })
}

fn scim_json(status: StatusCode, body: Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/scim+json"),
    );
    response
}

async fn scim_list(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(org): Path<String>,
) -> ApiResult<Response> {
    scim_auth(&state, &org, &headers).await?;
    let rows = sqlx::query(
        "SELECT account_id,display_name,role FROM team_members WHERE org_id=$1 ORDER BY joined_at",
    )
    .bind(&org)
    .fetch_all(state.repository.pool())
    .await
    .map_err(storage)?;
    Ok(scim_json(
        StatusCode::OK,
        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": rows.len(),
            "startIndex": 1,
            "itemsPerPage": rows.len(),
            "Resources": rows.iter().map(scim_user).collect::<Vec<_>>(),
        }),
    ))
}

async fn scim_get(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, id)): Path<(String, String)>,
) -> ApiResult<Response> {
    scim_auth(&state, &org, &headers).await?;
    let row = sqlx::query(
        "SELECT account_id,display_name,role FROM team_members WHERE org_id=$1 AND account_id=$2",
    )
    .bind(&org)
    .bind(&id)
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .ok_or_else(|| {
        ApiError(KeyLeaseError::NotFound {
            resource: id.clone(),
        })
    })?;
    Ok(scim_json(StatusCode::OK, scim_user(&row)))
}

/// Removes a member (and their project access), keeping one owner.
async fn deprovision(state: &CloudApiState, org: &str, id: &str) -> ApiResult<()> {
    let role = org_role(state, org, id).await?;
    if role == OrgRole::Owner {
        let owners: i64 =
            sqlx::query("SELECT count(*) AS n FROM team_members WHERE org_id=$1 AND role='owner'")
                .bind(org)
                .fetch_one(state.repository.pool())
                .await
                .map_err(storage)?
                .get("n");
        if owners <= 1 {
            return Err(invalid("an organization keeps at least one owner"));
        }
    }
    let mut tx = state.repository.pool().begin().await.map_err(storage)?;
    for statement in [
        "DELETE FROM team_project_access WHERE org_id=$1 AND account_id=$2",
        "DELETE FROM team_members WHERE org_id=$1 AND account_id=$2",
    ] {
        sqlx::query(statement)
            .bind(org)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
    }
    tx.commit().await.map_err(storage)?;
    Ok(())
}

/// `active: false` (as identity providers send it) deprovisions.
async fn scim_patch(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, id)): Path<(String, String)>,
    body: Bytes,
) -> ApiResult<Response> {
    scim_auth(&state, &org, &headers).await?;
    let request: Value = parse(&body)?;
    let deactivate = request["Operations"].as_array().is_some_and(|operations| {
        operations.iter().any(|operation| {
            operation["value"]["active"] == json!(false)
                || (operation["path"] == "active" && operation["value"] == json!(false))
        })
    });
    if !deactivate {
        return Err(invalid("only deactivation (active: false) is supported"));
    }
    deprovision(&state, &org, &id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn scim_delete(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, id)): Path<(String, String)>,
) -> ApiResult<Response> {
    scim_auth(&state, &org, &headers).await?;
    deprovision(&state, &org, &id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
