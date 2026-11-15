//! Audit push: keylease-server sends each organization's audit (Managed
//! secrets, the MCP Gateway, machine identities, the KMS API) to the SIEM
//! destinations its owners and admins configure, as JSON Lines, RFC 5424
//! syslog or Splunk HTTP Event Collector events.
//!
//! Every destination keeps a cursor (the last audit id it accepted). The push
//! loop ([`spawn_audit_push`]) sends up to 500 events per destination every
//! 15 seconds; a destination that fails is retried with a growing delay (up
//! to an hour) and its last error is shown. Several server replicas can run
//! the loop: a destination is locked while it is sent.

use crate::api::{ApiError, ApiResult, CloudApiState};
use crate::console::{require_csrf, session};
use crate::gateway_upstream::checked_client;
use crate::managed::root;
use crate::relay::{denied, invalid, parse, storage};
use crate::teams::{OrgRole, org_role};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post, put},
};
use chrono::{DateTime, Duration, Utc};
use keylease_core::KeyLeaseError;
use keylease_crypto::sealed::{SymmetricBox, open_symmetric, seal_symmetric};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use zeroize::Zeroizing;

/// How often the loop looks for new events.
const PUSH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);
/// Events per request.
const BATCH: i64 = 500;
/// The longest wait after failures.
const MAX_BACKOFF_SECONDS: i64 = 3600;

pub(crate) fn router() -> Router<CloudApiState> {
    Router::new()
        .route("/v1/orgs/{org}/audit/destinations", get(list))
        .route(
            "/v1/orgs/{org}/audit/destinations/{name}",
            put(set).delete(remove),
        )
        .route("/v1/orgs/{org}/audit/destinations/{name}/test", post(test))
}

/// How events are written for a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    JsonLines,
    Syslog,
    SplunkHec,
}

impl Format {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "jsonl" => Some(Self::JsonLines),
            "syslog" => Some(Self::Syslog),
            "splunk_hec" => Some(Self::SplunkHec),
            _ => None,
        }
    }

    fn content_type(self) -> &'static str {
        match self {
            Self::JsonLines => "application/x-ndjson",
            Self::Syslog => "text/plain; charset=utf-8",
            Self::SplunkHec => "application/json",
        }
    }
}

/// One audit event as every format carries it.
pub(crate) fn audit_event_json(org: &str, row: &sqlx::postgres::PgRow) -> Value {
    json!({
        "id": row.get::<i64, _>("id"),
        "org": org,
        "project": row.get::<String, _>("slug"),
        "environment": row.get::<Option<String>, _>("environment"),
        "name": row.get::<Option<String>, _>("name"),
        "action": row.get::<String, _>("action"),
        "actor": row.get::<String, _>("account_id"),
        "at": row.get::<DateTime<Utc>, _>("at"),
    })
}

/// One line of the body for `event`.
pub(crate) fn audit_line(format: Format, event: &Value, at: DateTime<Utc>) -> String {
    match format {
        Format::JsonLines => format!("{event}\n"),
        // <110> = facility 13 (log audit), severity 6 (informational).
        Format::Syslog => format!(
            "<110>1 {} keylease-server keylease - audit - {event}\n",
            at.to_rfc3339()
        ),
        Format::SplunkHec => format!(
            "{}\n",
            json!({
                "time": at.timestamp_millis() as f64 / 1000.0,
                "source": "keylease-server",
                "sourcetype": "keylease:audit",
                "event": event,
            })
        ),
    }
}

fn aad(org: &str, name: &str) -> Vec<u8> {
    format!("keylease-siem-destination-v1|{org}|{name}").into_bytes()
}

async fn require_admin(state: &CloudApiState, headers: &HeaderMap, org: &str) -> ApiResult<String> {
    let account = session(state, headers).await?;
    if org_role(state, org, &account).await? < OrgRole::Admin {
        return Err(denied("only an owner or admin manages audit destinations"));
    }
    Ok(account)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetDestination {
    url: String,
    format: String,
    /// The header that carries the token (default `Authorization`).
    #[serde(default)]
    header: Option<String>,
    /// How the token is written (default `Bearer {secret}`; Splunk:
    /// `Splunk {secret}`).
    #[serde(default)]
    template: Option<String>,
    /// The collector's token; leave out to keep the current one.
    #[serde(default)]
    secret: Option<String>,
    /// `now` (default): only events from now on; `beginning`: everything.
    #[serde(default)]
    start: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
}

async fn set(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, name)): Path<(String, String)>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = require_admin(&state, &headers, &org).await?;
    let request: SetDestination = parse(&body)?;
    if !valid_name(&name) {
        return Err(invalid("the name is a-z, 0-9 and -"));
    }
    let format = Format::parse(&request.format)
        .ok_or_else(|| invalid("format is jsonl, syslog or splunk_hec"))?;
    let url = url::Url::parse(&request.url).map_err(|_| invalid("invalid URL"))?;
    checked_client(&state, &url).await?;
    let header = request.header.unwrap_or_else(|| "Authorization".into());
    let template = request.template.unwrap_or_else(|| {
        if format == Format::SplunkHec {
            "Splunk {secret}".into()
        } else {
            "Bearer {secret}".into()
        }
    });
    if !valid_header_name(&header)
        || !template.contains("{secret}")
        || template.contains(['\r', '\n'])
    {
        return Err(invalid(
            "the header is a header name and the template contains {secret}",
        ));
    }
    let sealed = match &request.secret {
        Some(secret) if secret.contains(['\r', '\n']) => {
            return Err(invalid("the token cannot be sent in a header"));
        }
        Some(secret) => Some(
            serde_json::to_string(
                &seal_symmetric(root(&state)?, secret.as_bytes(), &aad(&org, &name))
                    .map_err(|_| ApiError(KeyLeaseError::Crypto))?,
            )
            .map_err(|_| ApiError(KeyLeaseError::Storage))?,
        ),
        None => None,
    };
    let pool = state.repository.pool();
    let cursor: i64 = if request.start.as_deref() == Some("beginning") {
        0
    } else {
        sqlx::query("SELECT COALESCE(MAX(id), 0) AS id FROM managed_audit WHERE org_id=$1")
            .bind(&org)
            .fetch_one(pool)
            .await
            .map_err(storage)?
            .get("id")
    };
    sqlx::query(
        "INSERT INTO org_siem_destinations(org_id,name,url,format,header,template,secret_sealed,cursor,enabled,created_by,created_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now()) ON CONFLICT (org_id,name) DO UPDATE SET \
         url=excluded.url, format=excluded.format, header=excluded.header, template=excluded.template, \
         secret_sealed=COALESCE(excluded.secret_sealed, org_siem_destinations.secret_sealed), \
         enabled=excluded.enabled, failures=0, next_attempt_at=NULL, last_error=NULL",
    )
    .bind(&org)
    .bind(&name)
    .bind(url.as_str())
    .bind(&request.format)
    .bind(&header)
    .bind(&template)
    .bind(&sealed)
    .bind(cursor)
    .bind(request.enabled.unwrap_or(true))
    .bind(&account)
    .execute(pool)
    .await
    .map_err(storage)?;
    Ok(Json(
        json!({"name": name, "format": request.format, "url": url.as_str()}),
    ))
}

async fn list(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(org): Path<String>,
) -> ApiResult<Json<Value>> {
    require_admin(&state, &headers, &org).await?;
    let pool = state.repository.pool();
    let latest: i64 =
        sqlx::query("SELECT COALESCE(MAX(id), 0) AS id FROM managed_audit WHERE org_id=$1")
            .bind(&org)
            .fetch_one(pool)
            .await
            .map_err(storage)?
            .get("id");
    let rows = sqlx::query(
        "SELECT name,url,format,header,secret_sealed IS NOT NULL AS has_secret,cursor,enabled,failures,next_attempt_at,last_success_at,last_error \
         FROM org_siem_destinations WHERE org_id=$1 ORDER BY name",
    )
    .bind(&org)
    .fetch_all(pool)
    .await
    .map_err(storage)?;
    Ok(Json(json!({
        "destinations": rows.iter().map(|row| json!({
            "name": row.get::<String, _>("name"),
            "url": row.get::<String, _>("url"),
            "format": row.get::<String, _>("format"),
            "header": row.get::<String, _>("header"),
            "has_secret": row.get::<bool, _>("has_secret"),
            "enabled": row.get::<bool, _>("enabled"),
            "behind": (latest - row.get::<i64, _>("cursor")).max(0),
            "failures": row.get::<i32, _>("failures"),
            "next_attempt_at": row.get::<Option<DateTime<Utc>>, _>("next_attempt_at"),
            "last_success_at": row.get::<Option<DateTime<Utc>>, _>("last_success_at"),
            "last_error": row.get::<Option<String>, _>("last_error"),
        })).collect::<Vec<_>>()
    })))
}

async fn remove(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, name)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    require_admin(&state, &headers, &org).await?;
    let removed = sqlx::query("DELETE FROM org_siem_destinations WHERE org_id=$1 AND name=$2")
        .bind(&org)
        .bind(&name)
        .execute(state.repository.pool())
        .await
        .map_err(storage)?
        .rows_affected();
    Ok(Json(json!({"removed": removed})))
}

/// The destination as the sender needs it.
struct Destination {
    url: url::Url,
    format: Format,
    header: String,
    authorization: Option<Zeroizing<String>>,
}

fn destination(state: &CloudApiState, row: &sqlx::postgres::PgRow) -> Result<Destination, String> {
    let org: String = row.get("org_id");
    let name: String = row.get("name");
    let url =
        url::Url::parse(&row.get::<String, _>("url")).map_err(|_| "invalid URL".to_owned())?;
    let format = Format::parse(&row.get::<String, _>("format")).ok_or("unknown format")?;
    let authorization = match row.get::<Option<String>, _>("secret_sealed") {
        None => None,
        Some(sealed) => {
            let root = root(state).map_err(|_| "the server has no KMS root key".to_owned())?;
            let sealed: SymmetricBox = serde_json::from_str(&sealed)
                .map_err(|_| "the stored token is malformed".to_owned())?;
            let secret = Zeroizing::new(
                open_symmetric(root, &sealed, &aad(&org, &name))
                    .map_err(|_| "the stored token cannot be opened".to_owned())?,
            );
            Some(Zeroizing::new(
                row.get::<String, _>("template")
                    .replace("{secret}", &String::from_utf8_lossy(&secret)),
            ))
        }
    };
    Ok(Destination {
        url,
        format,
        header: row.get("header"),
        authorization,
    })
}

/// Posts one body. Returns a short error on failure.
async fn post_body(
    state: &CloudApiState,
    destination: &Destination,
    body: String,
) -> Result<(), String> {
    let client = checked_client(state, &destination.url)
        .await
        .map_err(|ApiError(error)| match error {
            KeyLeaseError::Denied { reason } | KeyLeaseError::InvalidRequest { reason } => reason,
            _ => "the collector could not be reached".to_owned(),
        })?;
    let mut request = client
        .post(destination.url.clone())
        .header(
            reqwest::header::CONTENT_TYPE,
            destination.format.content_type(),
        )
        .body(body);
    if let Some(authorization) = &destination.authorization {
        request = request.header(destination.header.as_str(), authorization.as_str());
    }
    let response = request
        .send()
        .await
        .map_err(|_| "the collector could not be reached".to_owned())?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("the collector answered {}", response.status()))
    }
}

/// Sends one test event (not from the audit) to check the destination.
async fn test(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, name)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = require_admin(&state, &headers, &org).await?;
    let row = sqlx::query("SELECT * FROM org_siem_destinations WHERE org_id=$1 AND name=$2")
        .bind(&org)
        .bind(&name)
        .fetch_optional(state.repository.pool())
        .await
        .map_err(storage)?
        .ok_or_else(|| {
            ApiError(KeyLeaseError::NotFound {
                resource: format!("destination {name}"),
            })
        })?;
    let destination = destination(&state, &row).map_err(invalid)?;
    let now = Utc::now();
    let event = json!({"id": 0, "org": org, "action": "audit_destination_test", "actor": account, "at": now});
    match post_body(
        &state,
        &destination,
        audit_line(destination.format, &event, now),
    )
    .await
    {
        Ok(()) => Ok(Json(json!({"ok": true}))),
        Err(error) => Ok(Json(json!({"ok": false, "error": error}))),
    }
}

/// One push round over every destination that is due. Returns how many
/// events were delivered.
pub async fn push_audit_once(state: &CloudApiState) -> usize {
    let pool = state.repository.pool();
    let Ok(due) = sqlx::query(
        "SELECT org_id,name FROM org_siem_destinations WHERE enabled AND (next_attempt_at IS NULL OR next_attempt_at <= now())",
    )
    .fetch_all(pool)
    .await
    else {
        return 0;
    };
    let mut delivered = 0;
    for key in due {
        let (org, name): (String, String) = (key.get("org_id"), key.get("name"));
        match push_destination(state, &org, &name).await {
            Ok(count) => delivered += count,
            Err(error) => tracing::warn!(org, name, error, "audit push failed"),
        }
    }
    delivered
}

async fn push_destination(state: &CloudApiState, org: &str, name: &str) -> Result<usize, String> {
    let pool = state.repository.pool();
    let mut transaction = pool.begin().await.map_err(|_| "storage".to_owned())?;
    // Another replica may be sending this destination right now.
    let Some(row) = sqlx::query(
        "SELECT * FROM org_siem_destinations WHERE org_id=$1 AND name=$2 FOR UPDATE SKIP LOCKED",
    )
    .bind(org)
    .bind(name)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| "storage".to_owned())?
    else {
        return Ok(0);
    };
    let cursor: i64 = row.get("cursor");
    let failures: i32 = row.get("failures");
    let events = sqlx::query(
        "SELECT id,slug,environment,name,action,account_id,at FROM managed_audit WHERE org_id=$1 AND id > $2 ORDER BY id LIMIT $3",
    )
    .bind(org)
    .bind(cursor)
    .bind(BATCH)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| "storage".to_owned())?;
    let Some(last) = events.last().map(|event| event.get::<i64, _>("id")) else {
        return Ok(0);
    };
    let outcome = match destination(state, &row) {
        Ok(destination) => {
            let body: String = events
                .iter()
                .map(|event| {
                    audit_line(
                        destination.format,
                        &audit_event_json(org, event),
                        event.get("at"),
                    )
                })
                .collect();
            post_body(state, &destination, body).await
        }
        Err(error) => Err(error),
    };
    match &outcome {
        Ok(()) => {
            sqlx::query(
                "UPDATE org_siem_destinations SET cursor=$1, failures=0, next_attempt_at=NULL, last_error=NULL, last_success_at=now() \
                 WHERE org_id=$2 AND name=$3",
            )
            .bind(last)
            .bind(org)
            .bind(name)
            .execute(&mut *transaction)
            .await
            .map_err(|_| "storage".to_owned())?;
        }
        Err(error) => {
            let wait = (15_i64 << failures.clamp(0, 12)).min(MAX_BACKOFF_SECONDS);
            sqlx::query(
                "UPDATE org_siem_destinations SET failures=failures+1, next_attempt_at=$1, last_error=$2 WHERE org_id=$3 AND name=$4",
            )
            .bind(Utc::now() + Duration::seconds(wait))
            .bind(error.chars().take(300).collect::<String>())
            .bind(org)
            .bind(name)
            .execute(&mut *transaction)
            .await
            .map_err(|_| "storage".to_owned())?;
        }
    }
    transaction
        .commit()
        .await
        .map_err(|_| "storage".to_owned())?;
    outcome.map(|()| events.len())
}

/// Runs [`push_audit_once`] every 15 seconds in the background.
pub fn spawn_audit_push(state: CloudApiState) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(PUSH_INTERVAL).await;
            push_audit_once(&state).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_format_writes_one_line_per_event() {
        let at = DateTime::parse_from_rfc3339("2026-11-15T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let event = json!({"id": 7, "action": "secret_reveal"});
        assert_eq!(
            audit_line(Format::JsonLines, &event, at),
            "{\"action\":\"secret_reveal\",\"id\":7}\n"
        );
        assert!(
            audit_line(Format::Syslog, &event, at).starts_with(
                "<110>1 2026-11-15T10:00:00+00:00 keylease-server keylease - audit - {"
            )
        );
        let hec: Value =
            serde_json::from_str(audit_line(Format::SplunkHec, &event, at).trim()).unwrap();
        assert_eq!(hec["sourcetype"], "keylease:audit");
        assert_eq!(hec["event"]["id"], 7);
        assert_eq!(hec["time"], 1_794_736_800.0);
    }
}
