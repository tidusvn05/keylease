//! Organizations, members, roles and project access (v2 plan, step 12).
//!
//! Members are relay accounts signed in to the console. Organization roles:
//! `owner` and `admin` manage members and projects and have every project;
//! `member` and `viewer` see the projects they are granted (`read`, `write`,
//! `admin`; a viewer is capped at `read`). An organization always keeps an
//! owner.

use crate::api::{ApiError, ApiResult, CloudApiState};
use crate::console::{require_csrf, session};
use crate::relay::{denied, invalid, parse, storage};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::HeaderMap,
    routing::{delete, get, post, put},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use keylease_core::{KeyLeaseError, ProjectEnvironment};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;

const INVITE_DAYS: i64 = 7;
const MAX_ORGS_PER_ACCOUNT: i64 = 50;

pub(crate) fn router() -> Router<CloudApiState> {
    Router::new()
        .route("/v1/orgs", get(list_orgs).post(create_org))
        .route("/v1/orgs/join", post(join_org))
        .route("/v1/orgs/{org}", get(get_org))
        .route("/v1/orgs/{org}/invites", post(create_invite))
        .route(
            "/v1/orgs/{org}/members/{account}",
            put(set_member_role).delete(remove_member),
        )
        .route("/v1/orgs/{org}/projects", post(create_project))
        .route(
            "/v1/orgs/{org}/projects/{slug}/access/{account}",
            put(grant_access).delete(revoke_access),
        )
        .route("/v1/orgs/{org}/projects/{slug}", delete(delete_project))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum OrgRole {
    Viewer,
    Member,
    Admin,
    Owner,
}

impl OrgRole {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "owner" => Self::Owner,
            "admin" => Self::Admin,
            "member" => Self::Member,
            "viewer" => Self::Viewer,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
            Self::Viewer => "viewer",
        }
    }

    fn manages(self) -> bool {
        self >= Self::Admin
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ProjectRole {
    Read,
    Write,
    Admin,
}

impl ProjectRole {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "read" => Self::Read,
            "write" => Self::Write,
            "admin" => Self::Admin,
            _ => return None,
        })
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Admin => "admin",
        }
    }
}

fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", uuid::Uuid::now_v7().simple())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn valid_text(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty() && value.chars().count() <= 100 && !value.chars().any(char::is_control)
}

fn not_found(what: &str) -> ApiError {
    ApiError(KeyLeaseError::NotFound {
        resource: what.into(),
    })
}

/// The caller's role in `org`, or not found (non-members learn nothing).
pub(crate) async fn org_role(
    state: &CloudApiState,
    org: &str,
    account: &str,
) -> ApiResult<OrgRole> {
    let row = sqlx::query("SELECT role FROM team_members WHERE org_id=$1 AND account_id=$2")
        .bind(org)
        .bind(account)
        .fetch_optional(state.repository.pool())
        .await
        .map_err(storage)?
        .ok_or_else(|| not_found("organization"))?;
    OrgRole::parse(row.get::<String, _>("role").as_str()).ok_or(ApiError(KeyLeaseError::Storage))
}

/// The caller's effective role on a project, if any.
pub(crate) async fn project_role(
    state: &CloudApiState,
    org: &str,
    slug: &str,
    account: &str,
) -> ApiResult<Option<ProjectRole>> {
    let role = org_role(state, org, account).await?;
    if role.manages() {
        return Ok(Some(ProjectRole::Admin));
    }
    let granted = sqlx::query(
        "SELECT role FROM team_project_access WHERE org_id=$1 AND slug=$2 AND account_id=$3",
    )
    .bind(org)
    .bind(slug)
    .bind(account)
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .and_then(|row| ProjectRole::parse(row.get::<String, _>("role").as_str()));
    // A viewer never writes, whatever was granted.
    Ok(granted.map(|granted| {
        if role == OrgRole::Viewer {
            ProjectRole::Read
        } else {
            granted
        }
    }))
}

async fn require_manager(state: &CloudApiState, org: &str, account: &str) -> ApiResult<OrgRole> {
    let role = org_role(state, org, account).await?;
    if !role.manages() {
        return Err(denied("only an owner or admin can do this"));
    }
    Ok(role)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateOrg {
    name: String,
    /// How the creator appears to other members.
    display_name: String,
}

async fn create_org(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = session(&state, &headers).await?;
    let request: CreateOrg = parse(&body)?;
    if !valid_text(&request.name) || !valid_text(&request.display_name) {
        return Err(invalid(
            "name and display_name must be 1-100 printable characters",
        ));
    }
    let count: i64 = sqlx::query("SELECT count(*) AS n FROM team_members WHERE account_id=$1")
        .bind(&account)
        .fetch_one(state.repository.pool())
        .await
        .map_err(storage)?
        .get("n");
    if count >= MAX_ORGS_PER_ACCOUNT {
        return Err(invalid("too many organizations"));
    }
    let org = new_id("org");
    let mut tx = state.repository.pool().begin().await.map_err(storage)?;
    sqlx::query("INSERT INTO team_orgs(org_id,name,created_by,created_at) VALUES($1,$2,$3,now())")
        .bind(&org)
        .bind(request.name.trim())
        .bind(&account)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    sqlx::query("INSERT INTO team_members(org_id,account_id,display_name,role,joined_at) VALUES($1,$2,$3,'owner',now())")
        .bind(&org)
        .bind(&account)
        .bind(request.display_name.trim())
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    tx.commit().await.map_err(storage)?;
    Ok(Json(
        json!({"org_id": org, "name": request.name.trim(), "role": "owner"}),
    ))
}

async fn list_orgs(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let account = session(&state, &headers).await?;
    let rows = sqlx::query(
        "SELECT o.org_id,o.name,m.role FROM team_orgs o JOIN team_members m ON m.org_id=o.org_id WHERE m.account_id=$1 ORDER BY o.created_at",
    )
    .bind(&account)
    .fetch_all(state.repository.pool())
    .await
    .map_err(storage)?;
    Ok(Json(json!({
        "orgs": rows.iter().map(|row| json!({
            "org_id": row.get::<String, _>("org_id"),
            "name": row.get::<String, _>("name"),
            "role": row.get::<String, _>("role"),
        })).collect::<Vec<_>>()
    })))
}

async fn get_org(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(org): Path<String>,
) -> ApiResult<Json<Value>> {
    let account = session(&state, &headers).await?;
    let role = org_role(&state, &org, &account).await?;
    let pool = state.repository.pool();
    let name: String = sqlx::query("SELECT name FROM team_orgs WHERE org_id=$1")
        .bind(&org)
        .fetch_one(pool)
        .await
        .map_err(storage)?
        .get("name");
    let members = sqlx::query(
        "SELECT account_id,display_name,role,joined_at FROM team_members WHERE org_id=$1 ORDER BY joined_at",
    )
    .bind(&org)
    .fetch_all(pool)
    .await
    .map_err(storage)?;
    let projects = sqlx::query(
        "SELECT slug,name,environments FROM team_projects WHERE org_id=$1 ORDER BY slug",
    )
    .bind(&org)
    .fetch_all(pool)
    .await
    .map_err(storage)?;
    let access =
        sqlx::query("SELECT slug,account_id,role FROM team_project_access WHERE org_id=$1")
            .bind(&org)
            .fetch_all(pool)
            .await
            .map_err(storage)?;
    let mut visible = Vec::new();
    for project in &projects {
        let slug: String = project.get("slug");
        let Some(mine) = project_role(&state, &org, &slug, &account).await? else {
            continue;
        };
        let grants: Vec<Value> = if role.manages() {
            access
                .iter()
                .filter(|row| row.get::<String, _>("slug") == slug)
                .map(|row| json!({"account_id": row.get::<String, _>("account_id"), "role": row.get::<String, _>("role")}))
                .collect()
        } else {
            vec![]
        };
        visible.push(json!({
            "slug": slug,
            "name": project.get::<String, _>("name"),
            "environments": project.get::<Value, _>("environments"),
            "my_role": mine.name(),
            "access": grants,
        }));
    }
    Ok(Json(json!({
        "org_id": org,
        "name": name,
        "my_role": role.name(),
        "members": members.iter().map(|row| json!({
            "account_id": row.get::<String, _>("account_id"),
            "display_name": row.get::<String, _>("display_name"),
            "role": row.get::<String, _>("role"),
            "joined_at": row.get::<DateTime<Utc>, _>("joined_at"),
        })).collect::<Vec<_>>(),
        "projects": visible,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateInvite {
    role: String,
}

async fn create_invite(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(org): Path<String>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = session(&state, &headers).await?;
    let caller = require_manager(&state, &org, &account).await?;
    let request: CreateInvite = parse(&body)?;
    let role = OrgRole::parse(&request.role)
        .filter(|role| *role != OrgRole::Owner)
        .ok_or_else(|| invalid("invite as admin, member or viewer"))?;
    if role == OrgRole::Admin && caller != OrgRole::Owner {
        return Err(denied("only an owner invites admins"));
    }
    let mut bytes = [0_u8; 24];
    rand::rng().fill_bytes(&mut bytes);
    let code = format!("klorg_{}", URL_SAFE_NO_PAD.encode(bytes));
    let expires_at = Utc::now() + Duration::days(INVITE_DAYS);
    sqlx::query("INSERT INTO team_invites(code_hash,org_id,role,created_by,expires_at) VALUES($1,$2,$3,$4,$5)")
        .bind(sha256_hex(code.as_bytes()))
        .bind(&org)
        .bind(role.name())
        .bind(&account)
        .bind(expires_at)
        .execute(state.repository.pool())
        .await
        .map_err(storage)?;
    Ok(Json(
        json!({"code": code, "role": role.name(), "expires_at": expires_at}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinOrg {
    code: String,
    display_name: String,
}

async fn join_org(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = session(&state, &headers).await?;
    let request: JoinOrg = parse(&body)?;
    if !valid_text(&request.display_name) || request.code.len() > 128 {
        return Err(invalid("invalid invite or display name"));
    }
    let mut tx = state.repository.pool().begin().await.map_err(storage)?;
    let row = sqlx::query(
        "UPDATE team_invites SET used_by=$2, used_at=now() WHERE code_hash=$1 AND used_at IS NULL AND expires_at > now() RETURNING org_id,role",
    )
    .bind(sha256_hex(request.code.trim().as_bytes()))
    .bind(&account)
    .fetch_optional(&mut *tx)
    .await
    .map_err(storage)?
    .ok_or_else(|| denied("this invite is invalid, used or expired"))?;
    let org: String = row.get("org_id");
    let role: String = row.get("role");
    let inserted = sqlx::query(
        "INSERT INTO team_members(org_id,account_id,display_name,role,joined_at) VALUES($1,$2,$3,$4,now()) ON CONFLICT DO NOTHING",
    )
    .bind(&org)
    .bind(&account)
    .bind(request.display_name.trim())
    .bind(&role)
    .execute(&mut *tx)
    .await
    .map_err(storage)?;
    if inserted.rows_affected() == 0 {
        return Err(invalid("you are already a member of this organization"));
    }
    tx.commit().await.map_err(storage)?;
    Ok(Json(json!({"org_id": org, "role": role})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetRole {
    role: String,
}

async fn owners(state: &CloudApiState, org: &str) -> ApiResult<i64> {
    Ok(
        sqlx::query("SELECT count(*) AS n FROM team_members WHERE org_id=$1 AND role='owner'")
            .bind(org)
            .fetch_one(state.repository.pool())
            .await
            .map_err(storage)?
            .get("n"),
    )
}

async fn set_member_role(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, member)): Path<(String, String)>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = session(&state, &headers).await?;
    let caller = require_manager(&state, &org, &account).await?;
    let request: SetRole = parse(&body)?;
    let role = OrgRole::parse(&request.role).ok_or_else(|| invalid("unknown role"))?;
    let current = org_role(&state, &org, &member).await?;
    if (role >= OrgRole::Admin || current >= OrgRole::Admin) && caller != OrgRole::Owner {
        return Err(denied("only an owner changes owners and admins"));
    }
    if current == OrgRole::Owner && role != OrgRole::Owner && owners(&state, &org).await? <= 1 {
        return Err(invalid("an organization keeps at least one owner"));
    }
    sqlx::query("UPDATE team_members SET role=$3 WHERE org_id=$1 AND account_id=$2")
        .bind(&org)
        .bind(&member)
        .bind(role.name())
        .execute(state.repository.pool())
        .await
        .map_err(storage)?;
    Ok(Json(json!({"account_id": member, "role": role.name()})))
}

async fn remove_member(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, member)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = session(&state, &headers).await?;
    // Anyone may leave; managing others needs owner/admin.
    let caller = org_role(&state, &org, &account).await?;
    let current = org_role(&state, &org, &member).await?;
    if member != account
        && (!caller.manages() || (current >= OrgRole::Admin && caller != OrgRole::Owner))
    {
        return Err(denied("you cannot remove this member"));
    }
    if current == OrgRole::Owner && owners(&state, &org).await? <= 1 {
        return Err(invalid("an organization keeps at least one owner"));
    }
    let mut tx = state.repository.pool().begin().await.map_err(storage)?;
    sqlx::query("DELETE FROM team_project_access WHERE org_id=$1 AND account_id=$2")
        .bind(&org)
        .bind(&member)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    sqlx::query("DELETE FROM team_members WHERE org_id=$1 AND account_id=$2")
        .bind(&org)
        .bind(&member)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    tx.commit().await.map_err(storage)?;
    Ok(Json(json!({"removed": member})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateProject {
    slug: String,
    name: String,
    #[serde(default)]
    environments: Option<Vec<ProjectEnvironment>>,
}

async fn create_project(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(org): Path<String>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = session(&state, &headers).await?;
    require_manager(&state, &org, &account).await?;
    let request: CreateProject = parse(&body)?;
    let slug = request.slug.trim().to_ascii_lowercase();
    let valid_slug = !slug.is_empty()
        && slug.len() <= 63
        && slug.starts_with(|c: char| c.is_ascii_lowercase())
        && slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !valid_slug || !valid_text(&request.name) {
        return Err(invalid(
            "slug is a-z, 0-9 and -, starting with a letter; name 1-100 characters",
        ));
    }
    let environments = request
        .environments
        .unwrap_or_else(ProjectEnvironment::defaults);
    if environments.is_empty() || environments.len() > 16 {
        return Err(invalid("a project has 1-16 environments"));
    }
    sqlx::query("INSERT INTO team_projects(org_id,slug,name,environments,created_at) VALUES($1,$2,$3,$4,now())")
        .bind(&org)
        .bind(&slug)
        .bind(request.name.trim())
        .bind(serde_json::to_value(&environments).map_err(|_| ApiError(KeyLeaseError::Storage))?)
        .execute(state.repository.pool())
        .await
        .map_err(|_| invalid("a project with this slug exists"))?;
    Ok(Json(
        json!({"slug": slug, "name": request.name.trim(), "environments": environments}),
    ))
}

async fn delete_project(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = session(&state, &headers).await?;
    require_manager(&state, &org, &account).await?;
    let deleted = sqlx::query("DELETE FROM team_projects WHERE org_id=$1 AND slug=$2")
        .bind(&org)
        .bind(&slug)
        .execute(state.repository.pool())
        .await
        .map_err(|_| invalid("delete the project's secrets first"))?
        .rows_affected();
    if deleted == 0 {
        return Err(not_found("project"));
    }
    Ok(Json(json!({"deleted": slug})))
}

async fn grant_access(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug, member)): Path<(String, String, String)>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = session(&state, &headers).await?;
    if project_role(&state, &org, &slug, &account).await? != Some(ProjectRole::Admin) {
        return Err(denied("only a project admin grants access"));
    }
    org_role(&state, &org, &member).await?;
    let request: SetRole = parse(&body)?;
    let role =
        ProjectRole::parse(&request.role).ok_or_else(|| invalid("role is read, write or admin"))?;
    sqlx::query(
        "INSERT INTO team_project_access(org_id,slug,account_id,role,granted_at) VALUES($1,$2,$3,$4,now()) \
         ON CONFLICT (org_id,slug,account_id) DO UPDATE SET role=excluded.role, granted_at=excluded.granted_at",
    )
    .bind(&org)
    .bind(&slug)
    .bind(&member)
    .bind(role.name())
    .execute(state.repository.pool())
    .await
    .map_err(|_| not_found("project"))?;
    Ok(Json(
        json!({"slug": slug, "account_id": member, "role": role.name()}),
    ))
}

async fn revoke_access(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug, member)): Path<(String, String, String)>,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = session(&state, &headers).await?;
    if project_role(&state, &org, &slug, &account).await? != Some(ProjectRole::Admin) {
        return Err(denied("only a project admin revokes access"));
    }
    sqlx::query("DELETE FROM team_project_access WHERE org_id=$1 AND slug=$2 AND account_id=$3")
        .bind(&org)
        .bind(&slug)
        .bind(&member)
        .execute(state.repository.pool())
        .await
        .map_err(storage)?;
    Ok(Json(json!({"slug": slug, "revoked": member})))
}
