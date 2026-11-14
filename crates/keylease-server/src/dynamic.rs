//! Dynamic PostgreSQL credentials (v2 plan, step 18). A project admin names
//! the Managed secret that holds an admin connection URL and the role new
//! logins join; a machine identity then gets its own login that expires
//! (`VALID UNTIL`), so a pipeline never holds a standing database password.

use crate::api::{ApiError, ApiResult, CloudApiState};
use crate::console::require_csrf;
use crate::machine::machine_caller;
use crate::managed::{audit_event, authorize, current, decrypt};
use crate::relay::{invalid, parse, storage};
use crate::teams::ProjectRole;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post, put},
};
use chrono::{Duration, Utc};
use keylease_core::KeyLeaseError;
use rand::{Rng, distr::Alphanumeric};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Connection, Row};

pub(crate) fn router() -> Router<CloudApiState> {
    Router::new()
        .route("/v1/orgs/{org}/projects/{slug}/dynamic/postgres", get(list))
        .route(
            "/v1/orgs/{org}/projects/{slug}/dynamic/postgres/{name}",
            put(configure),
        )
        .route("/v1/machine/dynamic/postgres/{name}", post(issue))
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configure {
    admin_secret: String,
    grant_role: String,
    #[serde(default)]
    max_ttl_seconds: Option<i32>,
}

async fn configure(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug, name)): Path<(String, String, String)>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = authorize(&state, &headers, &org, &slug, None, ProjectRole::Admin).await?;
    let request: Configure = parse(&body)?;
    let ttl = request.max_ttl_seconds.unwrap_or(3600);
    if !identifier(&request.grant_role) || !(60..=86400).contains(&ttl) {
        return Err(invalid(
            "grant_role is a lower-case identifier; max_ttl_seconds is 60-86400",
        ));
    }
    sqlx::query(
        "INSERT INTO managed_dynamic_postgres(org_id,slug,name,admin_secret,grant_role,max_ttl_seconds,created_at) \
         VALUES($1,$2,$3,$4,$5,$6,now()) ON CONFLICT (org_id,slug,name) DO UPDATE SET \
         admin_secret=excluded.admin_secret, grant_role=excluded.grant_role, max_ttl_seconds=excluded.max_ttl_seconds",
    )
    .bind(&org)
    .bind(&slug)
    .bind(&name)
    .bind(&request.admin_secret)
    .bind(&request.grant_role)
    .bind(ttl)
    .execute(state.repository.pool())
    .await
    .map_err(|_| invalid("the name is a-z, 0-9 and -"))?;
    audit_event(
        &state,
        &org,
        &slug,
        None,
        Some(&name),
        "dynamic_postgres_configure",
        &account,
    )
    .await?;
    Ok(Json(
        json!({"name": name, "grant_role": request.grant_role, "max_ttl_seconds": ttl}),
    ))
}

async fn list(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers, &org, &slug, None, ProjectRole::Read).await?;
    let rows = sqlx::query("SELECT name,admin_secret,grant_role,max_ttl_seconds FROM managed_dynamic_postgres WHERE org_id=$1 AND slug=$2 ORDER BY name")
        .bind(&org)
        .bind(&slug)
        .fetch_all(state.repository.pool())
        .await
        .map_err(storage)?;
    Ok(Json(json!({
        "postgres": rows.iter().map(|row| json!({
            "name": row.get::<String, _>("name"),
            "admin_secret": row.get::<String, _>("admin_secret"),
            "grant_role": row.get::<String, _>("grant_role"),
            "max_ttl_seconds": row.get::<i32, _>("max_ttl_seconds"),
        })).collect::<Vec<_>>()
    })))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Issue {
    #[serde(default)]
    ttl_seconds: Option<i32>,
}

/// A machine identity's own login, in its environment's database.
async fn issue(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let caller = machine_caller(&state, &headers).await?;
    let request: Issue = if body.is_empty() {
        Issue::default()
    } else {
        parse(&body)?
    };
    let config = sqlx::query(
        "SELECT admin_secret,grant_role,max_ttl_seconds FROM managed_dynamic_postgres WHERE org_id=$1 AND slug=$2 AND name=$3",
    )
    .bind(&caller.org)
    .bind(&caller.slug)
    .bind(&name)
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .ok_or_else(|| ApiError(KeyLeaseError::NotFound { resource: format!("dynamic postgres {name}") }))?;
    let max_ttl: i32 = config.get("max_ttl_seconds");
    let ttl = request.ttl_seconds.unwrap_or(max_ttl).clamp(60, max_ttl);
    let admin_secret: String = config.get("admin_secret");
    let grant_role: String = config.get("grant_role");
    let admin_row = current(&state, &caller.org, &caller.slug, &caller.environment)
        .await?
        .into_iter()
        .find(|row| row.get::<String, _>("name") == admin_secret)
        .ok_or_else(|| {
            ApiError(KeyLeaseError::NotFound {
                resource: format!("secret {admin_secret} in {}", caller.environment),
            })
        })?;
    let admin_url = zeroize::Zeroizing::new(
        String::from_utf8_lossy(
            &decrypt(
                &state,
                &caller.org,
                &caller.slug,
                &caller.environment,
                &admin_secret,
                &admin_row,
            )
            .await?,
        )
        .into_owned(),
    );
    let parsed = url::Url::parse(&admin_url)
        .map_err(|_| invalid("the admin secret is not a postgres:// URL"))?;
    if !matches!(parsed.scheme(), "postgres" | "postgresql") {
        return Err(invalid("the admin secret is not a postgres:// URL"));
    }
    let role: String = format!(
        "kl_{}",
        rand::rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect::<String>()
            .to_ascii_lowercase()
    );
    let password: zeroize::Zeroizing<String> = zeroize::Zeroizing::new(
        rand::rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect(),
    );
    let expires_at = Utc::now() + Duration::seconds(i64::from(ttl));
    let mut connection = sqlx::PgConnection::connect(&admin_url)
        .await
        .map_err(|_| ApiError(KeyLeaseError::ConnectorUnavailable { retryable: true }))?;
    // Identifiers are checked above and the password is alphanumeric, so the
    // statement has no user-controlled quoting.
    let statement = format!(
        "CREATE ROLE \"{role}\" LOGIN PASSWORD '{}' VALID UNTIL '{}' IN ROLE \"{grant_role}\"",
        password.as_str(),
        expires_at.to_rfc3339()
    );
    sqlx::raw_sql(sqlx::AssertSqlSafe(statement))
        .execute(&mut connection)
        .await
        .map_err(|_| {
            invalid(format!(
                "could not create the login; does role {grant_role} exist?"
            ))
        })?;
    let _ = connection.close().await;
    sqlx::query(
        "INSERT INTO managed_dynamic_leases(lease_id,org_id,slug,environment,name,role_name,identity_id,expires_at,created_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,now())",
    )
    .bind(format!("dlease_{}", uuid::Uuid::now_v7().simple()))
    .bind(&caller.org)
    .bind(&caller.slug)
    .bind(&caller.environment)
    .bind(&name)
    .bind(&role)
    .bind(&caller.identity_id)
    .bind(expires_at)
    .execute(state.repository.pool())
    .await
    .map_err(storage)?;
    audit_event(
        &state,
        &caller.org,
        &caller.slug,
        Some(&caller.environment),
        Some(&name),
        "dynamic_postgres_issue",
        &format!("machine:{}", caller.identity_id),
    )
    .await?;
    let host = parsed.host_str().unwrap_or("localhost").to_owned();
    let port = parsed.port().unwrap_or(5432);
    let database = parsed.path().trim_start_matches('/').to_owned();
    let mut login = parsed.clone();
    let _ = login.set_username(&role);
    let _ = login.set_password(Some(&password));
    Ok(Json(json!({
        "username": role,
        "password": password.as_str(),
        "host": host,
        "port": port,
        "database": database,
        "url": login.as_str(),
        "expires_at": expires_at,
    })))
}
