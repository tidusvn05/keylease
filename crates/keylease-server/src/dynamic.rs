//! Dynamic database credentials (v2 plan, step 18). A project admin names the
//! Managed secret that holds an admin connection URL and the role new logins
//! join; a machine identity then gets its own login that expires, so a
//! pipeline never holds a standing database password.
//!
//! PostgreSQL logins carry `VALID UNTIL`; MySQL has no such clause, so their
//! expiry is the reaper's job. The reaper ([`spawn_reaper`]) runs every
//! minute: for each expired login it ends the login's sessions and drops it
//! (PostgreSQL: objects it owns are reassigned to the granted role first).

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
use chrono::{DateTime, Duration, Utc};
use keylease_core::KeyLeaseError;
use rand::{Rng, distr::Alphanumeric};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Connection, Row};
use zeroize::Zeroizing;

/// How often the reaper looks for expired logins.
const REAP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
/// Expired logins handled per round.
const REAP_BATCH: i64 = 200;
/// After this many failed attempts the reaper leaves a login alone; its
/// error stays visible in the lease list.
const REAP_MAX_ATTEMPTS: i32 = 10;

pub(crate) fn router() -> Router<CloudApiState> {
    Router::new()
        .route("/v1/orgs/{org}/projects/{slug}/dynamic/leases", get(leases))
        .route("/v1/orgs/{org}/projects/{slug}/dynamic/{engine}", get(list))
        .route(
            "/v1/orgs/{org}/projects/{slug}/dynamic/{engine}/{name}",
            put(configure),
        )
        .route("/v1/machine/dynamic/{engine}/{name}", post(issue))
}

/// The databases the broker can make logins in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Engine {
    Postgres,
    Mysql,
}

impl Engine {
    fn parse(value: &str) -> ApiResult<Self> {
        match value {
            "postgres" => Ok(Self::Postgres),
            "mysql" => Ok(Self::Mysql),
            _ => Err(ApiError(KeyLeaseError::NotFound {
                resource: format!("dynamic engine {value}"),
            })),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Mysql => "mysql",
        }
    }

    fn schemes(self) -> &'static [&'static str] {
        match self {
            Self::Postgres => &["postgres", "postgresql"],
            Self::Mysql => &["mysql"],
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Self::Postgres => 5432,
            Self::Mysql => 3306,
        }
    }
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// A login name this broker made (`kl_` and 16 lower-case letters or digits).
fn broker_login(value: &str) -> bool {
    value.len() == 19
        && value.starts_with("kl_")
        && value[3..]
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
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
    Path((org, slug, engine, name)): Path<(String, String, String, String)>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let engine = Engine::parse(&engine)?;
    let account = authorize(&state, &headers, &org, &slug, None, ProjectRole::Admin).await?;
    let request: Configure = parse(&body)?;
    let ttl = request.max_ttl_seconds.unwrap_or(3600);
    if !identifier(&request.grant_role) || !(60..=86400).contains(&ttl) {
        return Err(invalid(
            "grant_role is a lower-case identifier; max_ttl_seconds is 60-86400",
        ));
    }
    sqlx::query(
        "INSERT INTO managed_dynamic_postgres(org_id,slug,name,engine,admin_secret,grant_role,max_ttl_seconds,created_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,now()) ON CONFLICT (org_id,slug,name) DO UPDATE SET \
         engine=excluded.engine, admin_secret=excluded.admin_secret, grant_role=excluded.grant_role, \
         max_ttl_seconds=excluded.max_ttl_seconds",
    )
    .bind(&org)
    .bind(&slug)
    .bind(&name)
    .bind(engine.name())
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
        &format!("dynamic_{}_configure", engine.name()),
        &account,
    )
    .await?;
    Ok(Json(json!({
        "name": name,
        "engine": engine.name(),
        "grant_role": request.grant_role,
        "max_ttl_seconds": ttl,
    })))
}

async fn list(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug, engine)): Path<(String, String, String)>,
) -> ApiResult<Json<Value>> {
    let engine = Engine::parse(&engine)?;
    authorize(&state, &headers, &org, &slug, None, ProjectRole::Read).await?;
    let rows = sqlx::query(
        "SELECT name,admin_secret,grant_role,max_ttl_seconds FROM managed_dynamic_postgres \
         WHERE org_id=$1 AND slug=$2 AND engine=$3 ORDER BY name",
    )
    .bind(&org)
    .bind(&slug)
    .bind(engine.name())
    .fetch_all(state.repository.pool())
    .await
    .map_err(storage)?;
    Ok(Json(json!({
        engine.name(): rows.iter().map(|row| json!({
            "name": row.get::<String, _>("name"),
            "admin_secret": row.get::<String, _>("admin_secret"),
            "grant_role": row.get::<String, _>("grant_role"),
            "max_ttl_seconds": row.get::<i32, _>("max_ttl_seconds"),
        })).collect::<Vec<_>>()
    })))
}

/// Logins handed out in the project, newest first, with their revocation.
async fn leases(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers, &org, &slug, None, ProjectRole::Admin).await?;
    let rows = sqlx::query(
        "SELECT lease_id,engine,environment,name,role_name,identity_id,expires_at,created_at,revoked_at,revoke_attempts,revoke_error \
         FROM managed_dynamic_leases WHERE org_id=$1 AND slug=$2 ORDER BY created_at DESC LIMIT 200",
    )
    .bind(&org)
    .bind(&slug)
    .fetch_all(state.repository.pool())
    .await
    .map_err(storage)?;
    Ok(Json(json!({
        "leases": rows.iter().map(|row| json!({
            "lease_id": row.get::<String, _>("lease_id"),
            "engine": row.get::<String, _>("engine"),
            "environment": row.get::<String, _>("environment"),
            "name": row.get::<String, _>("name"),
            "username": row.get::<String, _>("role_name"),
            "identity_id": row.get::<String, _>("identity_id"),
            "expires_at": row.get::<DateTime<Utc>, _>("expires_at"),
            "created_at": row.get::<DateTime<Utc>, _>("created_at"),
            "revoked_at": row.get::<Option<DateTime<Utc>>, _>("revoked_at"),
            "revoke_attempts": row.get::<i32, _>("revoke_attempts"),
            "revoke_error": row.get::<Option<String>, _>("revoke_error"),
        })).collect::<Vec<_>>()
    })))
}

/// The admin URL of a broker in one environment, checked for the engine.
async fn admin_url(
    state: &CloudApiState,
    org: &str,
    slug: &str,
    environment: &str,
    admin_secret: &str,
    engine: Engine,
) -> ApiResult<(Zeroizing<String>, url::Url)> {
    let admin_row = current(state, org, slug, environment)
        .await?
        .into_iter()
        .find(|row| row.get::<String, _>("name") == admin_secret)
        .ok_or_else(|| {
            ApiError(KeyLeaseError::NotFound {
                resource: format!("secret {admin_secret} in {environment}"),
            })
        })?;
    let url = Zeroizing::new(
        String::from_utf8_lossy(
            &decrypt(state, org, slug, environment, admin_secret, &admin_row).await?,
        )
        .into_owned(),
    );
    let parsed = url::Url::parse(&url)
        .ok()
        .filter(|parsed| engine.schemes().contains(&parsed.scheme()))
        .ok_or_else(|| {
            invalid(format!(
                "the admin secret is not a {}:// URL",
                engine.schemes()[0]
            ))
        })?;
    Ok((url, parsed))
}

fn unavailable(_: sqlx::Error) -> ApiError {
    ApiError(KeyLeaseError::ConnectorUnavailable { retryable: true })
}

/// Makes the login. Identifiers are checked by the caller and the password is
/// alphanumeric, so the statements have no user-controlled quoting.
async fn create_login(
    engine: Engine,
    admin_url: &str,
    role: &str,
    password: &str,
    grant_role: &str,
    expires_at: DateTime<Utc>,
) -> ApiResult<()> {
    let refused = |_| {
        invalid(format!(
            "could not create the login; does role {grant_role} exist?"
        ))
    };
    match engine {
        Engine::Postgres => {
            let mut connection = sqlx::PgConnection::connect(admin_url)
                .await
                .map_err(unavailable)?;
            let statement = format!(
                "CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}' VALID UNTIL '{}' IN ROLE \"{grant_role}\"",
                expires_at.to_rfc3339()
            );
            let result = sqlx::raw_sql(sqlx::AssertSqlSafe(statement))
                .execute(&mut connection)
                .await
                .map_err(refused);
            let _ = connection.close().await;
            result.map(|_| ())
        }
        Engine::Mysql => {
            let mut connection = sqlx::MySqlConnection::connect(admin_url)
                .await
                .map_err(unavailable)?;
            let result = async {
                for statement in [
                    format!("CREATE USER '{role}'@'%' IDENTIFIED BY '{password}'"),
                    format!("GRANT `{grant_role}` TO '{role}'@'%'"),
                ] {
                    sqlx::raw_sql(sqlx::AssertSqlSafe(statement))
                        .execute(&mut connection)
                        .await?;
                }
                // MySQL 8 and MariaDB spell the default role differently.
                if sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                    "SET DEFAULT ROLE ALL TO '{role}'@'%'"
                )))
                .execute(&mut connection)
                .await
                .is_err()
                {
                    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                        "SET DEFAULT ROLE `{grant_role}` FOR '{role}'@'%'"
                    )))
                    .execute(&mut connection)
                    .await?;
                }
                Ok::<(), sqlx::Error>(())
            }
            .await
            .map_err(refused);
            if result.is_err() {
                let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                    "DROP USER IF EXISTS '{role}'@'%'"
                )))
                .execute(&mut connection)
                .await;
            }
            let _ = connection.close().await;
            result
        }
    }
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
    Path((engine, name)): Path<(String, String)>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let engine = Engine::parse(&engine)?;
    let caller = machine_caller(&state, &headers).await?;
    let request: Issue = if body.is_empty() {
        Issue::default()
    } else {
        parse(&body)?
    };
    let config = sqlx::query(
        "SELECT admin_secret,grant_role,max_ttl_seconds FROM managed_dynamic_postgres \
         WHERE org_id=$1 AND slug=$2 AND name=$3 AND engine=$4",
    )
    .bind(&caller.org)
    .bind(&caller.slug)
    .bind(&name)
    .bind(engine.name())
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .ok_or_else(|| {
        ApiError(KeyLeaseError::NotFound {
            resource: format!("dynamic {} {name}", engine.name()),
        })
    })?;
    let max_ttl: i32 = config.get("max_ttl_seconds");
    let ttl = request.ttl_seconds.unwrap_or(max_ttl).clamp(60, max_ttl);
    let admin_secret: String = config.get("admin_secret");
    let grant_role: String = config.get("grant_role");
    let (admin, parsed) = admin_url(
        &state,
        &caller.org,
        &caller.slug,
        &caller.environment,
        &admin_secret,
        engine,
    )
    .await?;
    let role: String = format!(
        "kl_{}",
        rand::rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect::<String>()
            .to_ascii_lowercase()
    );
    let password: Zeroizing<String> = Zeroizing::new(
        rand::rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect(),
    );
    let expires_at = Utc::now() + Duration::seconds(i64::from(ttl));
    create_login(engine, &admin, &role, &password, &grant_role, expires_at).await?;
    sqlx::query(
        "INSERT INTO managed_dynamic_leases(lease_id,org_id,slug,environment,name,engine,role_name,identity_id,expires_at,created_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,now())",
    )
    .bind(format!("dlease_{}", uuid::Uuid::now_v7().simple()))
    .bind(&caller.org)
    .bind(&caller.slug)
    .bind(&caller.environment)
    .bind(&name)
    .bind(engine.name())
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
        &format!("dynamic_{}_issue", engine.name()),
        &format!("machine:{}", caller.identity_id),
    )
    .await?;
    let host = parsed.host_str().unwrap_or("localhost").to_owned();
    let port = parsed.port().unwrap_or(engine.default_port());
    let database = parsed.path().trim_start_matches('/').to_owned();
    let mut login = parsed.clone();
    let _ = login.set_username(&role);
    let _ = login.set_password(Some(&password));
    Ok(Json(json!({
        "engine": engine.name(),
        "username": role,
        "password": password.as_str(),
        "host": host,
        "port": port,
        "database": database,
        "url": login.as_str(),
        "expires_at": expires_at,
    })))
}

// ---------------------------------------------------------------------------
// Reaper
// ---------------------------------------------------------------------------

/// Ends the login's sessions and drops it. Dropping a login that is already
/// gone succeeds.
async fn drop_login(
    engine: Engine,
    admin_url: &str,
    role: &str,
    grant_role: &str,
) -> Result<(), String> {
    if !broker_login(role) || !identifier(grant_role) {
        return Err("not a login this broker made".into());
    }
    let describe = |error: sqlx::Error| -> String {
        match error {
            sqlx::Error::Database(database) => database.message().chars().take(200).collect(),
            _ => "could not reach the database".into(),
        }
    };
    match engine {
        Engine::Postgres => {
            let mut connection = sqlx::PgConnection::connect(admin_url)
                .await
                .map_err(describe)?;
            let exists: Option<(String,)> =
                sqlx::query_as("SELECT rolname::text FROM pg_roles WHERE rolname=$1")
                    .bind(role)
                    .fetch_optional(&mut connection)
                    .await
                    .map_err(describe)?;
            if exists.is_some() {
                // Stop new sessions, end the open ones, keep what it created.
                for statement in [
                    format!("ALTER ROLE \"{role}\" NOLOGIN"),
                    format!(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{role}'"
                    ),
                    format!("REASSIGN OWNED BY \"{role}\" TO \"{grant_role}\""),
                    format!("DROP OWNED BY \"{role}\""),
                    format!("DROP ROLE \"{role}\""),
                ] {
                    sqlx::raw_sql(sqlx::AssertSqlSafe(statement))
                        .execute(&mut connection)
                        .await
                        .map_err(describe)?;
                }
            }
            let _ = connection.close().await;
            Ok(())
        }
        Engine::Mysql => {
            let mut connection = sqlx::MySqlConnection::connect(admin_url)
                .await
                .map_err(describe)?;
            sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "ALTER USER IF EXISTS '{role}'@'%' ACCOUNT LOCK"
            )))
            .execute(&mut connection)
            .await
            .map_err(describe)?;
            let sessions: Vec<(u64,)> = sqlx::query_as(
                "SELECT CAST(id AS UNSIGNED) FROM information_schema.processlist WHERE user = ?",
            )
            .bind(role)
            .fetch_all(&mut connection)
            .await
            .map_err(describe)?;
            for (id,) in sessions {
                let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!("KILL {id}")))
                    .execute(&mut connection)
                    .await;
            }
            sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "DROP USER IF EXISTS '{role}'@'%'"
            )))
            .execute(&mut connection)
            .await
            .map_err(describe)?;
            let _ = connection.close().await;
            Ok(())
        }
    }
}

/// One reaper round: drops the expired logins. Returns `(dropped, failed)`.
pub async fn reap_expired_logins(state: &CloudApiState) -> (usize, usize) {
    let pool = state.repository.pool();
    let Ok(rows) = sqlx::query(
        "SELECT l.lease_id,l.org_id,l.slug,l.environment,l.engine,l.role_name,c.admin_secret,c.grant_role \
         FROM managed_dynamic_leases l LEFT JOIN managed_dynamic_postgres c \
         ON c.org_id=l.org_id AND c.slug=l.slug AND c.name=l.name \
         WHERE l.revoked_at IS NULL AND l.expires_at <= now() AND l.revoke_attempts < $1 \
         ORDER BY l.expires_at LIMIT $2",
    )
    .bind(REAP_MAX_ATTEMPTS)
    .bind(REAP_BATCH)
    .fetch_all(pool)
    .await
    else {
        return (0, 0);
    };
    let (mut dropped, mut failed) = (0, 0);
    for row in rows {
        let lease: String = row.get("lease_id");
        let outcome = async {
            let engine = Engine::parse(&row.get::<String, _>("engine"))
                .map_err(|_| "unknown engine".to_owned())?;
            let (Some(admin_secret), Some(grant_role)) = (
                row.get::<Option<String>, _>("admin_secret"),
                row.get::<Option<String>, _>("grant_role"),
            ) else {
                return Err("the broker configuration was removed".to_owned());
            };
            let (admin, _) = admin_url(
                state,
                &row.get::<String, _>("org_id"),
                &row.get::<String, _>("slug"),
                &row.get::<String, _>("environment"),
                &admin_secret,
                engine,
            )
            .await
            .map_err(|_| "the admin secret is missing or not a database URL".to_owned())?;
            drop_login(
                engine,
                &admin,
                &row.get::<String, _>("role_name"),
                &grant_role,
            )
            .await
        }
        .await;
        let update = match &outcome {
            Ok(()) => {
                dropped += 1;
                sqlx::query("UPDATE managed_dynamic_leases SET revoked_at=now(), revoke_error=NULL WHERE lease_id=$1")
                    .bind(&lease)
                    .execute(pool)
                    .await
            }
            Err(error) => {
                failed += 1;
                sqlx::query(
                    "UPDATE managed_dynamic_leases SET revoke_attempts=revoke_attempts+1, revoke_error=$2 WHERE lease_id=$1",
                )
                .bind(&lease)
                .bind(error)
                .execute(pool)
                .await
            }
        };
        if update.is_err() {
            tracing::warn!(lease, "could not record the reaper outcome");
        }
    }
    (dropped, failed)
}

/// Runs [`reap_expired_logins`] every minute in the background.
pub fn spawn_reaper(state: CloudApiState) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(REAP_INTERVAL).await;
            let (dropped, failed) = reap_expired_logins(&state).await;
            if dropped + failed > 0 {
                tracing::info!(dropped, failed, "dynamic database logins reaped");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_broker_logins_are_dropped() {
        assert!(broker_login("kl_abcdefgh01234567"));
        assert!(!broker_login("kl_abc"));
        assert!(!broker_login("postgres"));
        assert!(!broker_login("kl_abcdefgh0123456\""));
        assert!(!broker_login("kl_ABCDEFGH01234567"));
    }
}
