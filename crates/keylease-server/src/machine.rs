//! Machine identities (v2 plan, step 15): workload identity federation for
//! CI/CD. A job presents its platform's OIDC token (GitHub Actions, GitLab
//! CI, a Kubernetes service account); when issuer, audience and subject match
//! an identity a project admin configured, it gets a 15-minute token that
//! reads one Managed project environment. No long-lived secret is stored in
//! the pipeline.

use crate::api::{ApiError, ApiResult, CloudApiState};
use crate::console::{require_csrf, session};
use crate::console_sso::{allowed_url, fetch_json, http};
use crate::managed::{audit_event, authorize, current, decrypt};
use crate::relay::{denied, invalid, parse, storage};
use crate::teams::ProjectRole;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use keylease_core::KeyLeaseError;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;

const TOKEN_MINUTES: i64 = 15;

pub(crate) fn router() -> Router<CloudApiState> {
    Router::new()
        .route(
            "/v1/orgs/{org}/projects/{slug}/machine-identities",
            get(list_identities).post(create_identity),
        )
        .route(
            "/v1/orgs/{org}/projects/{slug}/machine-identities/{identity}",
            delete(revoke_identity),
        )
        .route("/v1/machine/token", post(exchange))
        .route("/v1/machine/secrets", get(machine_secrets))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Exact match, or a prefix match when the pattern ends with `*`
/// (`repo:acme/shop:ref:refs/heads/*`).
fn subject_matches(pattern: &str, subject: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => !prefix.is_empty() && subject.starts_with(prefix),
        None => pattern == subject,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateIdentity {
    name: String,
    environment: String,
    issuer: String,
    audience: String,
    subject: String,
}

async fn create_identity(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug)): Path<(String, String)>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let request: CreateIdentity = parse(&body)?;
    let account = authorize(
        &state,
        &headers,
        &org,
        &slug,
        Some(&request.environment),
        ProjectRole::Admin,
    )
    .await?;
    let printable = |value: &str, max: usize| {
        !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
    };
    if !printable(&request.name, 100)
        || !printable(&request.audience, 255)
        || !printable(&request.subject, 512)
    {
        return Err(invalid("name, audience and subject must be printable"));
    }
    if request.subject.trim() == "*" || !allowed_url(&request.issuer) {
        return Err(invalid(
            "the issuer must be an https URL and the subject must not match everything",
        ));
    }
    let identity = format!("mid_{}", uuid::Uuid::now_v7().simple());
    sqlx::query(
        "INSERT INTO machine_identities(identity_id,org_id,slug,environment,name,issuer,audience,subject,created_by,created_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,now())",
    )
    .bind(&identity)
    .bind(&org)
    .bind(&slug)
    .bind(&request.environment)
    .bind(request.name.trim())
    .bind(request.issuer.trim_end_matches('/'))
    .bind(request.audience.trim())
    .bind(request.subject.trim())
    .bind(&account)
    .execute(state.repository.pool())
    .await
    .map_err(storage)?;
    audit_event(
        &state,
        &org,
        &slug,
        Some(&request.environment),
        None,
        "machine_identity_create",
        &account,
    )
    .await?;
    Ok(Json(json!({"identity_id": identity})))
}

async fn list_identities(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers, &org, &slug, None, ProjectRole::Admin).await?;
    let rows = sqlx::query(
        "SELECT identity_id,name,environment,issuer,audience,subject,created_at FROM machine_identities \
         WHERE org_id=$1 AND slug=$2 AND revoked_at IS NULL ORDER BY created_at",
    )
    .bind(&org)
    .bind(&slug)
    .fetch_all(state.repository.pool())
    .await
    .map_err(storage)?;
    Ok(Json(json!({
        "identities": rows.iter().map(|row| json!({
            "identity_id": row.get::<String, _>("identity_id"),
            "name": row.get::<String, _>("name"),
            "environment": row.get::<String, _>("environment"),
            "issuer": row.get::<String, _>("issuer"),
            "audience": row.get::<String, _>("audience"),
            "subject": row.get::<String, _>("subject"),
            "created_at": row.get::<DateTime<Utc>, _>("created_at"),
        })).collect::<Vec<_>>()
    })))
}

async fn revoke_identity(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug, identity)): Path<(String, String, String)>,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = session(&state, &headers).await?;
    authorize(&state, &headers, &org, &slug, None, ProjectRole::Admin).await?;
    let mut tx = state.repository.pool().begin().await.map_err(storage)?;
    let changed = sqlx::query(
        "UPDATE machine_identities SET revoked_at=now() WHERE identity_id=$1 AND org_id=$2 AND slug=$3 AND revoked_at IS NULL",
    )
    .bind(&identity)
    .bind(&org)
    .bind(&slug)
    .execute(&mut *tx)
    .await
    .map_err(storage)?
    .rows_affected();
    sqlx::query("DELETE FROM machine_tokens WHERE identity_id=$1")
        .bind(&identity)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    tx.commit().await.map_err(storage)?;
    if changed == 0 {
        return Err(ApiError(KeyLeaseError::NotFound { resource: identity }));
    }
    audit_event(
        &state,
        &org,
        &slug,
        None,
        None,
        "machine_identity_revoke",
        &account,
    )
    .await?;
    Ok(Json(json!({"revoked": identity})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    identity_id: String,
    /// The platform's OIDC token (a JWT).
    token: String,
}

/// Checks a workload JWT against the issuer's published keys.
async fn verify_workload_token(
    issuer: &str,
    audience: &str,
    token: &str,
) -> ApiResult<Map<String, Value>> {
    if token.len() > 16 * 1024 {
        return Err(denied("token too large"));
    }
    let header = decode_header(token).map_err(|_| denied("invalid token"))?;
    if !matches!(
        header.alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::EdDSA
    ) {
        return Err(denied("the token must use an asymmetric signature"));
    }
    let client = http()?;
    let discovery = fetch_json(
        &client,
        client.get(format!("{issuer}/.well-known/openid-configuration")),
    )
    .await?;
    let jwks_uri = discovery["jwks_uri"]
        .as_str()
        .filter(|uri| allowed_url(uri))
        .ok_or_else(|| denied("the issuer publishes no usable jwks_uri"))?;
    let set: JwkSet = serde_json::from_value(fetch_json(&client, client.get(jwks_uri)).await?)
        .map_err(|_| denied("invalid JWKS"))?;
    let jwk = match &header.kid {
        Some(kid) => set.find(kid),
        None if set.keys.len() == 1 => set.keys.first(),
        None => None,
    }
    .ok_or_else(|| denied("the token's signing key is unknown"))?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| denied("unsupported signing key"))?;
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.leeway = 30;
    Ok(decode::<Map<String, Value>>(token, &key, &validation)
        .map_err(|_| denied("the token's signature or claims are invalid"))?
        .claims)
}

async fn exchange(State(state): State<CloudApiState>, body: Bytes) -> ApiResult<Json<Value>> {
    let request: Exchange = parse(&body)?;
    let row = sqlx::query(
        "SELECT org_id,slug,environment,issuer,audience,subject FROM machine_identities WHERE identity_id=$1 AND revoked_at IS NULL",
    )
    .bind(&request.identity_id)
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .ok_or_else(|| denied("unknown or revoked machine identity"))?;
    let claims = verify_workload_token(
        &row.get::<String, _>("issuer"),
        &row.get::<String, _>("audience"),
        &request.token,
    )
    .await?;
    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !subject_matches(&row.get::<String, _>("subject"), subject) {
        return Err(denied(format!(
            "subject {subject:?} is not allowed for this identity"
        )));
    }
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let access = format!("klm_{}", URL_SAFE_NO_PAD.encode(bytes));
    let expires_at = Utc::now() + Duration::minutes(TOKEN_MINUTES);
    sqlx::query("DELETE FROM machine_tokens WHERE expires_at < now()")
        .execute(state.repository.pool())
        .await
        .map_err(storage)?;
    sqlx::query("INSERT INTO machine_tokens(token_hash,identity_id,expires_at) VALUES($1,$2,$3)")
        .bind(sha256_hex(access.as_bytes()))
        .bind(&request.identity_id)
        .bind(expires_at)
        .execute(state.repository.pool())
        .await
        .map_err(storage)?;
    let org: String = row.get("org_id");
    let slug: String = row.get("slug");
    let environment: String = row.get("environment");
    audit_event(
        &state,
        &org,
        &slug,
        Some(&environment),
        None,
        "machine_token",
        &format!("machine:{}:{subject}", request.identity_id),
    )
    .await?;
    Ok(Json(json!({
        "access_token": access,
        "expires_at": expires_at,
        "project": slug,
        "environment": environment,
    })))
}

/// Every secret of the identity's environment, for the bearer of a machine
/// token.
async fn machine_secrets(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| denied("a machine token is required"))?;
    let row = sqlx::query(
        "SELECT i.identity_id,i.org_id,i.slug,i.environment FROM machine_tokens t \
         JOIN machine_identities i ON i.identity_id=t.identity_id \
         WHERE t.token_hash=$1 AND t.expires_at > now() AND i.revoked_at IS NULL",
    )
    .bind(sha256_hex(token.trim().as_bytes()))
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .ok_or_else(|| denied("the machine token is invalid or expired"))?;
    let org: String = row.get("org_id");
    let slug: String = row.get("slug");
    let environment: String = row.get("environment");
    let mut secrets = Map::new();
    for secret in current(&state, &org, &slug, &environment).await? {
        let name: String = secret.get("name");
        let value = decrypt(&state, &org, &slug, &environment, &name, &secret).await?;
        secrets.insert(
            name,
            Value::String(String::from_utf8_lossy(&value).into_owned()),
        );
    }
    audit_event(
        &state,
        &org,
        &slug,
        Some(&environment),
        None,
        "machine_read",
        &format!("machine:{}", row.get::<String, _>("identity_id")),
    )
    .await?;
    let mut response =
        Json(json!({"project": slug, "environment": environment, "secrets": secrets}))
            .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::subject_matches;

    #[test]
    fn subjects_match_exactly_or_by_prefix() {
        assert!(subject_matches(
            "repo:acme/shop:ref:refs/heads/main",
            "repo:acme/shop:ref:refs/heads/main"
        ));
        assert!(!subject_matches(
            "repo:acme/shop:ref:refs/heads/main",
            "repo:acme/shop:ref:refs/heads/dev"
        ));
        assert!(subject_matches(
            "repo:acme/shop:*",
            "repo:acme/shop:pull_request"
        ));
        assert!(!subject_matches(
            "repo:acme/shop:*",
            "repo:acme/shopping:ref:x"
        ));
        assert!(!subject_matches("*", "anything"));
    }
}
