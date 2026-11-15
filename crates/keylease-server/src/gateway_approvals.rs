//! Per-call approvals in the MCP Gateway. A gateway client can be set to need
//! a person's approval for writes (`writes`) or for every call (`all`). The
//! first call creates a pending approval for that exact request (client,
//! project, environment, binding, method, path and body digest) and fails
//! with its id; a project admin approves or denies it in the console; the
//! same call made again within 15 minutes then goes through, once.

use crate::api::{ApiError, ApiResult, CloudApiState};
use crate::console::{require_csrf, session};
use crate::managed::audit_event;
use crate::relay::{denied, invalid, parse, storage};
use crate::teams::{ProjectRole, project_role};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
};
use chrono::{DateTime, Duration, Utc};
use keylease_core::KeyLeaseError;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::collections::HashMap;

/// How long a pending or approved request stays valid.
const APPROVAL_MINUTES: i64 = 15;

pub(crate) fn router() -> Router<CloudApiState> {
    Router::new()
        .route("/v1/orgs/{org}/gateway/approvals", get(list))
        .route("/v1/orgs/{org}/gateway/approvals/{approval}", post(decide))
}

/// When a client needs approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApprovalMode {
    None,
    Writes,
    All,
}

impl ApprovalMode {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "writes" => Some(Self::Writes),
            "all" => Some(Self::All),
            _ => None,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Writes => "writes",
            Self::All => "all",
        }
    }

    fn needed(self, safe: bool) -> bool {
        match self {
            Self::None => false,
            Self::Writes => !safe,
            Self::All => true,
        }
    }
}

/// One gateway call, as an approval names it.
pub(crate) struct Call<'a> {
    pub(crate) client_id: &'a str,
    pub(crate) project: &'a str,
    pub(crate) environment: &'a str,
    pub(crate) binding: &'a str,
    pub(crate) method: &'a str,
    pub(crate) path: &'a str,
    pub(crate) body: Option<&'a [u8]>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Call<'_> {
    fn body_sha256(&self) -> Option<String> {
        self.body.map(|body| hex(&Sha256::digest(body)))
    }

    fn digest(&self) -> String {
        let canonical = json!([
            "keylease-gateway-call-v1",
            self.client_id,
            self.project,
            self.environment,
            self.binding,
            self.method,
            self.path,
            self.body_sha256(),
        ]);
        hex(&Sha256::digest(canonical.to_string().as_bytes()))
    }
}

/// Lets the call through, or fails with `ApprovalRequired` (creating the
/// pending approval and telling the approvers) or `Denied`.
pub(crate) async fn gate(
    state: &CloudApiState,
    org: &str,
    mode: ApprovalMode,
    safe: bool,
    call: Call<'_>,
) -> ApiResult<()> {
    if !mode.needed(safe) {
        return Ok(());
    }
    let pool = state.repository.pool();
    let digest = call.digest();
    let existing = sqlx::query(
        "SELECT approval_id,state FROM gateway_approvals WHERE client_id=$1 AND request_digest=$2 \
         AND state IN ('pending','approved','denied') AND expires_at > now() ORDER BY created_at DESC LIMIT 1",
    )
    .bind(call.client_id)
    .bind(&digest)
    .fetch_optional(pool)
    .await
    .map_err(storage)?;
    if let Some(row) = existing {
        let id: String = row.get("approval_id");
        return match row.get::<String, _>("state").as_str() {
            "approved" => {
                let consumed = sqlx::query(
                    "UPDATE gateway_approvals SET state='consumed', consumed_at=now() WHERE approval_id=$1 AND state='approved'",
                )
                .bind(&id)
                .execute(pool)
                .await
                .map_err(storage)?
                .rows_affected();
                if consumed == 1 {
                    Ok(())
                } else {
                    Err(ApiError(KeyLeaseError::ApprovalRequired {
                        approval_id: id,
                    }))
                }
            }
            "denied" => Err(denied(format!(
                "a project admin denied this request ({id})"
            ))),
            _ => Err(ApiError(KeyLeaseError::ApprovalRequired {
                approval_id: id,
            })),
        };
    }
    let id = format!("gwa_{}", uuid::Uuid::now_v7().simple());
    sqlx::query(
        "INSERT INTO gateway_approvals(approval_id,org_id,client_id,slug,environment,binding,method,path,body_sha256,body_bytes,request_digest,state,created_at,expires_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending',now(),$12)",
    )
    .bind(&id)
    .bind(org)
    .bind(call.client_id)
    .bind(call.project)
    .bind(call.environment)
    .bind(call.binding)
    .bind(call.method)
    .bind(call.path.chars().take(2048).collect::<String>())
    .bind(call.body_sha256())
    .bind(call.body.map_or(0, |body| i32::try_from(body.len()).unwrap_or(i32::MAX)))
    .bind(&digest)
    .bind(Utc::now() + Duration::minutes(APPROVAL_MINUTES))
    .execute(pool)
    .await
    .map_err(storage)?;
    notify_approvers(state, org, &call, &id).await;
    Err(ApiError(KeyLeaseError::ApprovalRequired {
        approval_id: id,
    }))
}

/// Web Push to the people who can approve: the organization's owners and
/// admins and the project's admins.
async fn notify_approvers(state: &CloudApiState, org: &str, call: &Call<'_>, id: &str) {
    let Some(subject) = state.console.origin() else {
        return;
    };
    let Ok(rows) = sqlx::query(
        "SELECT account_id FROM team_members WHERE org_id=$1 AND role IN ('owner','admin') \
         UNION SELECT account_id FROM team_project_access WHERE org_id=$1 AND slug=$2 AND role='admin'",
    )
    .bind(org)
    .bind(call.project)
    .fetch_all(state.repository.pool())
    .await
    else {
        return;
    };
    let client: Option<String> = sqlx::query("SELECT name FROM gateway_clients WHERE client_id=$1")
        .bind(call.client_id)
        .fetch_optional(state.repository.pool())
        .await
        .ok()
        .flatten()
        .map(|row| row.get("name"));
    for row in rows {
        crate::web_push::notify_account(
            state.repository.pool().clone(),
            subject.to_owned(),
            row.get("account_id"),
            json!({
                "kind": "gateway",
                "approval_id": id,
                "agent": client,
                "action": format!("{} {}", call.method, call.binding),
                "node": format!("{}/{}", call.project, call.environment),
                "count": 1,
            }),
        );
    }
}

/// Gateway approvals of the projects the person administers: pending first,
/// then the 50 most recent.
async fn list(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(org): Path<String>,
) -> ApiResult<Json<Value>> {
    let account = session(&state, &headers).await?;
    let rows = sqlx::query(
        "SELECT a.approval_id,a.client_id,c.name AS client_name,a.slug,a.environment,a.binding,a.method,a.path,a.body_bytes, \
         a.state,a.created_at,a.expires_at,a.decided_by,a.decided_at,a.consumed_at \
         FROM gateway_approvals a JOIN gateway_clients c ON c.client_id=a.client_id \
         WHERE a.org_id=$1 AND (a.state='pending' AND a.expires_at > now() OR a.created_at > now() - interval '7 days') \
         ORDER BY (a.state='pending') DESC, a.created_at DESC LIMIT 100",
    )
    .bind(&org)
    .fetch_all(state.repository.pool())
    .await
    .map_err(storage)?;
    let mut roles: HashMap<String, bool> = HashMap::new();
    let mut approvals = Vec::new();
    for row in rows {
        let slug: String = row.get("slug");
        let admin = match roles.get(&slug) {
            Some(admin) => *admin,
            None => {
                let admin =
                    project_role(&state, &org, &slug, &account).await? == Some(ProjectRole::Admin);
                roles.insert(slug.clone(), admin);
                admin
            }
        };
        if !admin {
            continue;
        }
        let expired = row.get::<String, _>("state") == "pending"
            && row.get::<DateTime<Utc>, _>("expires_at") <= Utc::now();
        approvals.push(json!({
            "approval_id": row.get::<String, _>("approval_id"),
            "client_id": row.get::<String, _>("client_id"),
            "client": row.get::<String, _>("client_name"),
            "project": slug,
            "environment": row.get::<String, _>("environment"),
            "binding": row.get::<String, _>("binding"),
            "method": row.get::<String, _>("method"),
            "path": row.get::<String, _>("path"),
            "body_bytes": row.get::<i32, _>("body_bytes"),
            "state": if expired { "expired".to_owned() } else { row.get::<String, _>("state") },
            "created_at": row.get::<DateTime<Utc>, _>("created_at"),
            "expires_at": row.get::<DateTime<Utc>, _>("expires_at"),
            "decided_by": row.get::<Option<String>, _>("decided_by"),
            "decided_at": row.get::<Option<DateTime<Utc>>, _>("decided_at"),
            "consumed_at": row.get::<Option<DateTime<Utc>>, _>("consumed_at"),
        }));
    }
    Ok(Json(json!({"approvals": approvals})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decide {
    approve: bool,
}

async fn decide(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, approval)): Path<(String, String)>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = session(&state, &headers).await?;
    let request: Decide = parse(&body)?;
    let pool = state.repository.pool();
    let row = sqlx::query(
        "SELECT slug,environment,binding FROM gateway_approvals WHERE approval_id=$1 AND org_id=$2",
    )
    .bind(&approval)
    .bind(&org)
    .fetch_optional(pool)
    .await
    .map_err(storage)?
    .ok_or_else(|| {
        ApiError(KeyLeaseError::NotFound {
            resource: "gateway approval".into(),
        })
    })?;
    let slug: String = row.get("slug");
    if project_role(&state, &org, &slug, &account).await? != Some(ProjectRole::Admin) {
        return Err(denied("only a project admin decides gateway calls"));
    }
    let changed = sqlx::query(
        "UPDATE gateway_approvals SET state=$1, decided_by=$2, decided_at=now() \
         WHERE approval_id=$3 AND state='pending' AND expires_at > now()",
    )
    .bind(if request.approve {
        "approved"
    } else {
        "denied"
    })
    .bind(&account)
    .bind(&approval)
    .execute(pool)
    .await
    .map_err(storage)?
    .rows_affected();
    if changed == 0 {
        return Err(invalid("the request is no longer pending"));
    }
    audit_event(
        &state,
        &org,
        &slug,
        Some(&row.get::<String, _>("environment")),
        Some(&row.get::<String, _>("binding")),
        if request.approve {
            "gateway_call_approve"
        } else {
            "gateway_call_deny"
        },
        &account,
    )
    .await?;
    Ok(Json(
        json!({"approval_id": approval, "state": if request.approve { "approved" } else { "denied" }}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_digest_covers_the_whole_request() {
        let call = |method, body: Option<&'static [u8]>| Call {
            client_id: "gwc_1",
            project: "shop",
            environment: "prod",
            binding: "stripe",
            method,
            path: "/v1/refunds",
            body,
        };
        let base = call("POST", Some(b"{\"amount\":5}")).digest();
        assert_eq!(base, call("POST", Some(b"{\"amount\":5}")).digest());
        assert_ne!(base, call("POST", Some(b"{\"amount\":500}")).digest());
        assert_ne!(base, call("PUT", Some(b"{\"amount\":5}")).digest());
        assert_ne!(call("GET", None).digest(), call("GET", Some(b"")).digest());
        assert!(ApprovalMode::Writes.needed(false));
        assert!(!ApprovalMode::Writes.needed(true));
        assert!(ApprovalMode::All.needed(true));
        assert!(!ApprovalMode::None.needed(false));
    }
}
