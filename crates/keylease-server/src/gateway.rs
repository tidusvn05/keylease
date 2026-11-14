//! The MCP Gateway (v2 plan, step 17): each organization publishes a remote
//! MCP endpoint (`POST /v1/orgs/{org}/mcp`, Streamable HTTP with JSON
//! responses). A gateway client (an agent or a team's assistant) holds a
//! token and may call the HTTP bindings of the project environments it is
//! granted: the server adds the Managed secret, sends the request and scrubs
//! the secret from the answer. The model never sees a credential.

use crate::api::{ApiError, ApiResult, CloudApiState};
use crate::console::{require_csrf, session};
use crate::managed::{audit_event, authorize, current, decrypt};
use crate::relay::{denied, invalid, parse, storage};
use crate::teams::{ProjectRole, org_role};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use keylease_core::KeyLeaseError;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use zeroize::Zeroizing;

const MAX_BODY: usize = 2 * 1024 * 1024;
const MAX_TOOL_TEXT: usize = 256 * 1024;
const PROTOCOL_VERSION: &str = "2025-06-18";
const REDACTED: &[u8] = b"[REDACTED by keylease]";
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "accept-encoding",
];

pub(crate) fn router() -> Router<CloudApiState> {
    Router::new()
        .route(
            "/v1/orgs/{org}/projects/{slug}/http-bindings",
            get(list_bindings),
        )
        .route(
            "/v1/orgs/{org}/projects/{slug}/http-bindings/{name}",
            put(set_binding).delete(delete_binding),
        )
        .route(
            "/v1/orgs/{org}/gateway/clients",
            get(list_clients).post(create_client),
        )
        .route(
            "/v1/orgs/{org}/gateway/clients/{client}",
            axum::routing::delete(revoke_client),
        )
        .route("/v1/orgs/{org}/mcp", post(mcp).get(mcp_stream))
        .route(
            "/v1/orgs/{org}/gateway/http/{project}/{environment}/{binding}/{*path}",
            axum::routing::any(http_proxy),
        )
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

// ------------------------------------------------------------------ bindings

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetBinding {
    base_url: String,
    #[serde(default = "default_header")]
    header: String,
    #[serde(default = "default_template")]
    template: String,
    /// The Managed secret (in each environment) that holds the credential.
    secret_name: String,
}

fn default_header() -> String {
    "Authorization".into()
}

fn default_template() -> String {
    "Bearer {secret}".into()
}

async fn set_binding(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug, name)): Path<(String, String, String)>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = authorize(&state, &headers, &org, &slug, None, ProjectRole::Admin).await?;
    let request: SetBinding = parse(&body)?;
    let url = url::Url::parse(&request.base_url).map_err(|_| invalid("base_url must be a URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.query().is_some()
        || !url.username().is_empty()
    {
        return Err(invalid(
            "base_url must be an https URL without query or user info",
        ));
    }
    if !valid_header_name(&request.header)
        || !request.template.contains("{secret}")
        || request.template.len() > 256
        || request.template.chars().any(char::is_control)
    {
        return Err(invalid(
            "invalid header or template (it must contain {secret})",
        ));
    }
    sqlx::query(
        "INSERT INTO managed_http_bindings(org_id,slug,name,base_url,header,template,secret_name,created_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,now()) ON CONFLICT (org_id,slug,name) DO UPDATE SET \
         base_url=excluded.base_url, header=excluded.header, template=excluded.template, secret_name=excluded.secret_name",
    )
    .bind(&org)
    .bind(&slug)
    .bind(&name)
    .bind(request.base_url.trim_end_matches('/'))
    .bind(&request.header)
    .bind(&request.template)
    .bind(&request.secret_name)
    .execute(state.repository.pool())
    .await
    .map_err(|_| invalid("the binding name is a-z, 0-9 and -"))?;
    audit_event(
        &state,
        &org,
        &slug,
        None,
        Some(&name),
        "http_binding_set",
        &account,
    )
    .await?;
    Ok(Json(json!({"name": name})))
}

async fn list_bindings(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers, &org, &slug, None, ProjectRole::Read).await?;
    let rows = sqlx::query("SELECT name,base_url,header,secret_name FROM managed_http_bindings WHERE org_id=$1 AND slug=$2 ORDER BY name")
        .bind(&org)
        .bind(&slug)
        .fetch_all(state.repository.pool())
        .await
        .map_err(storage)?;
    Ok(Json(json!({
        "bindings": rows.iter().map(|row| json!({
            "name": row.get::<String, _>("name"),
            "base_url": row.get::<String, _>("base_url"),
            "header": row.get::<String, _>("header"),
            "secret_name": row.get::<String, _>("secret_name"),
        })).collect::<Vec<_>>()
    })))
}

async fn delete_binding(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug, name)): Path<(String, String, String)>,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = authorize(&state, &headers, &org, &slug, None, ProjectRole::Admin).await?;
    sqlx::query("DELETE FROM managed_http_bindings WHERE org_id=$1 AND slug=$2 AND name=$3")
        .bind(&org)
        .bind(&slug)
        .bind(&name)
        .execute(state.repository.pool())
        .await
        .map_err(storage)?;
    audit_event(
        &state,
        &org,
        &slug,
        None,
        Some(&name),
        "http_binding_delete",
        &account,
    )
    .await?;
    Ok(Json(json!({"deleted": name})))
}

// ------------------------------------------------------------------- clients

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    project: String,
    environment: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateClient {
    name: String,
    #[serde(default)]
    allow_writes: bool,
    grants: Vec<Grant>,
}

async fn require_org_manager(
    state: &CloudApiState,
    headers: &HeaderMap,
    org: &str,
) -> ApiResult<String> {
    let account = session(state, headers).await?;
    if org_role(state, org, &account).await? < crate::teams::OrgRole::Admin {
        return Err(denied("only an owner or admin manages the MCP Gateway"));
    }
    Ok(account)
}

async fn create_client(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(org): Path<String>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = require_org_manager(&state, &headers, &org).await?;
    let request: CreateClient = parse(&body)?;
    if request.name.trim().is_empty()
        || request.name.len() > 100
        || request.grants.is_empty()
        || request.grants.len() > 50
    {
        return Err(invalid("a client needs a name and 1-50 grants"));
    }
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let token = format!("klgw_{}", URL_SAFE_NO_PAD.encode(bytes));
    let client = format!("gwc_{}", uuid::Uuid::now_v7().simple());
    let mut tx = state.repository.pool().begin().await.map_err(storage)?;
    sqlx::query(
        "INSERT INTO gateway_clients(client_id,org_id,name,token_hash,allow_writes,created_by,created_at) VALUES($1,$2,$3,$4,$5,$6,now())",
    )
    .bind(&client)
    .bind(&org)
    .bind(request.name.trim())
    .bind(sha256_hex(token.as_bytes()))
    .bind(request.allow_writes)
    .bind(&account)
    .execute(&mut *tx)
    .await
    .map_err(storage)?;
    for grant in &request.grants {
        sqlx::query("INSERT INTO gateway_grants(client_id,org_id,slug,environment) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
            .bind(&client)
            .bind(&org)
            .bind(&grant.project)
            .bind(&grant.environment)
            .execute(&mut *tx)
            .await
            .map_err(|_| invalid(format!("no project {}", grant.project)))?;
    }
    tx.commit().await.map_err(storage)?;
    let url = state
        .public_url
        .as_ref()
        .map(|base| format!("{base}/v1/orgs/{org}/mcp"));
    Ok(Json(
        json!({"client_id": client, "token": token, "url": url}),
    ))
}

async fn list_clients(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(org): Path<String>,
) -> ApiResult<Json<Value>> {
    require_org_manager(&state, &headers, &org).await?;
    let clients = sqlx::query(
        "SELECT client_id,name,allow_writes,created_at FROM gateway_clients WHERE org_id=$1 AND revoked_at IS NULL ORDER BY created_at",
    )
    .bind(&org)
    .fetch_all(state.repository.pool())
    .await
    .map_err(storage)?;
    let grants =
        sqlx::query("SELECT client_id,slug,environment FROM gateway_grants WHERE org_id=$1")
            .bind(&org)
            .fetch_all(state.repository.pool())
            .await
            .map_err(storage)?;
    Ok(Json(json!({
        "clients": clients.iter().map(|row| {
            let id: String = row.get("client_id");
            json!({
                "client_id": id,
                "name": row.get::<String, _>("name"),
                "allow_writes": row.get::<bool, _>("allow_writes"),
                "created_at": row.get::<DateTime<Utc>, _>("created_at"),
                "grants": grants.iter().filter(|grant| grant.get::<String, _>("client_id") == id)
                    .map(|grant| json!({"project": grant.get::<String, _>("slug"), "environment": grant.get::<String, _>("environment")}))
                    .collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>()
    })))
}

async fn revoke_client(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, client)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    require_org_manager(&state, &headers, &org).await?;
    sqlx::query("UPDATE gateway_clients SET revoked_at=now() WHERE client_id=$1 AND org_id=$2")
        .bind(&client)
        .bind(&org)
        .execute(state.repository.pool())
        .await
        .map_err(storage)?;
    Ok(Json(json!({"revoked": client})))
}

// ----------------------------------------------------------------------- MCP

struct Client {
    id: String,
    allow_writes: bool,
}

async fn client(state: &CloudApiState, org: &str, headers: &HeaderMap) -> ApiResult<Client> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| denied("a gateway token is required"))?;
    let row = sqlx::query(
        "SELECT client_id,allow_writes FROM gateway_clients WHERE token_hash=$1 AND org_id=$2 AND revoked_at IS NULL",
    )
    .bind(sha256_hex(token.trim().as_bytes()))
    .bind(org)
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .ok_or_else(|| denied("the gateway token is invalid or revoked"))?;
    Ok(Client {
        id: row.get("client_id"),
        allow_writes: row.get("allow_writes"),
    })
}

/// No server-initiated stream: answers are plain JSON.
async fn mcp_stream() -> StatusCode {
    StatusCode::METHOD_NOT_ALLOWED
}

fn tools() -> Value {
    json!([
        {
            "name": "list_apis",
            "description": "List the HTTP APIs this gateway client may call: project, environment, binding name and base URL. No credentials are returned.",
            "inputSchema": {"type": "object", "properties": {}},
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "http_request",
            "description": "Call an HTTP API through the KeyLease MCP Gateway. The gateway adds the credential and removes it from the answer; never ask for the credential. The path is relative to the binding's base URL.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": {"type": "string"},
                    "environment": {"type": "string"},
                    "binding": {"type": "string", "description": "A binding name from list_apis."},
                    "method": {"type": "string", "default": "GET"},
                    "path": {"type": "string", "description": "Path and query below the base URL, e.g. /v1/charges?limit=3."},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                    "json": {"description": "A JSON body."},
                    "body": {"type": "string", "description": "A text body, instead of json."}
                },
                "required": ["project", "environment", "binding", "path"]
            }
        }
    ])
}

fn rpc_result(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn tool_text(text: String, is_error: bool) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": is_error})
}

async fn mcp(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(org): Path<String>,
    body: Bytes,
) -> ApiResult<Response> {
    let caller = client(&state, &org, &headers).await?;
    let request: Value =
        serde_json::from_slice(&body).map_err(|_| invalid("expected a JSON-RPC message"))?;
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request["method"].as_str().unwrap_or_default();
    if request.get("id").is_none() {
        // A notification (`notifications/initialized`, …): accepted, no answer.
        return Ok(StatusCode::ACCEPTED.into_response());
    }
    let answer = match method {
        "initialize" => rpc_result(
            &id,
            json!({
                "protocolVersion": request["params"]["protocolVersion"].as_str().unwrap_or(PROTOCOL_VERSION),
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "keylease-mcp-gateway", "version": env!("CARGO_PKG_VERSION")},
                "instructions": "Call list_apis, then http_request. Credentials are added by KeyLease and never shown.",
            }),
        ),
        "ping" => rpc_result(&id, json!({})),
        "tools/list" => rpc_result(&id, json!({"tools": tools()})),
        "tools/call" => {
            let name = request["params"]["name"].as_str().unwrap_or_default();
            let arguments = request["params"]["arguments"].clone();
            let outcome = match name {
                "list_apis" => list_apis(&state, &org, &caller).await,
                "http_request" => http_request(&state, &org, &caller, arguments).await,
                _ => Err(invalid(format!("unknown tool {name}"))),
            };
            match outcome {
                Ok(text) => rpc_result(&id, tool_text(text, false)),
                Err(ApiError(error)) => rpc_result(
                    &id,
                    tool_text(format!("KeyLease: {}", explain(&error)), true),
                ),
            }
        }
        _ => rpc_error(&id, -32601, "method not found"),
    };
    Ok(Json(answer).into_response())
}

fn explain(error: &KeyLeaseError) -> String {
    match error {
        KeyLeaseError::Denied { reason } | KeyLeaseError::InvalidRequest { reason } => {
            reason.clone()
        }
        KeyLeaseError::NotFound { resource } => format!("{resource} not found"),
        KeyLeaseError::ConnectorUnavailable { .. } => "the API could not be reached".into(),
        _ => "internal error".into(),
    }
}

async fn list_apis(state: &CloudApiState, org: &str, caller: &Client) -> ApiResult<String> {
    let rows = sqlx::query(
        "SELECT g.slug,g.environment,b.name,b.base_url FROM gateway_grants g \
         JOIN managed_http_bindings b ON b.org_id=g.org_id AND b.slug=g.slug \
         WHERE g.client_id=$1 AND g.org_id=$2 ORDER BY g.slug,g.environment,b.name",
    )
    .bind(&caller.id)
    .bind(org)
    .fetch_all(state.repository.pool())
    .await
    .map_err(storage)?;
    let apis: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "project": row.get::<String, _>("slug"),
                "environment": row.get::<String, _>("environment"),
                "binding": row.get::<String, _>("name"),
                "base_url": row.get::<String, _>("base_url"),
            })
        })
        .collect();
    Ok(
        serde_json::to_string_pretty(&json!({"apis": apis, "writes_allowed": caller.allow_writes}))
            .unwrap_or_default(),
    )
}

fn public_address(address: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match address {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 198 && (o[1] & 0xfe) == 18))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return public_address(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80)
        }
    }
}

fn target(base: &url::Url, path: &str) -> ApiResult<url::Url> {
    if !path.starts_with('/') || path.starts_with("//") || path.contains('\\') || path.len() > 8192
    {
        return Err(invalid("path must start with a single /"));
    }
    let (path_part, query) = path
        .split_once('?')
        .map_or((path, None), |(p, q)| (p, Some(q)));
    if path_part
        .split('/')
        .any(|segment| matches!(segment, "." | "..") || segment.eq_ignore_ascii_case("%2e%2e"))
    {
        return Err(invalid("path must not contain . or .. segments"));
    }
    let mut url = base.clone();
    url.set_path(&format!(
        "{}{}",
        base.path().trim_end_matches('/'),
        path_part
    ));
    url.set_query(query);
    Ok(url)
}

fn scrub(body: &[u8], secrets: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut index = 0;
    'outer: while index < body.len() {
        for secret in secrets {
            if !secret.is_empty() && body[index..].starts_with(secret) {
                out.extend_from_slice(REDACTED);
                index += secret.len();
                continue 'outer;
            }
        }
        out.push(body[index]);
        index += 1;
    }
    out
}

struct Forward {
    project: String,
    environment: String,
    binding: String,
    method: reqwest::Method,
    path: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
}

struct Forwarded {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Checks the grant, adds the Managed secret, sends the request and scrubs
/// the answer. Shared by the `http_request` tool and the base-URL proxy.
async fn forward(
    state: &CloudApiState,
    org: &str,
    caller: &Client,
    request: Forward,
) -> ApiResult<Forwarded> {
    let Forward {
        project,
        environment,
        binding: binding_name,
        method,
        path,
        headers,
        body,
    } = request;
    let safe = matches!(
        method,
        reqwest::Method::GET | reqwest::Method::HEAD | reqwest::Method::OPTIONS
    );
    if !safe && !caller.allow_writes {
        return Err(denied(
            "this gateway client may only read (GET, HEAD, OPTIONS)",
        ));
    }
    if method == reqwest::Method::CONNECT || method == reqwest::Method::TRACE {
        return Err(invalid("CONNECT and TRACE are not forwarded"));
    }
    if body.as_ref().is_some_and(|body| body.len() > MAX_BODY) {
        return Err(invalid("the body is too large"));
    }
    let granted = sqlx::query("SELECT 1 FROM gateway_grants WHERE client_id=$1 AND org_id=$2 AND slug=$3 AND environment=$4")
        .bind(&caller.id)
        .bind(org)
        .bind(&project)
        .bind(&environment)
        .fetch_optional(state.repository.pool())
        .await
        .map_err(storage)?;
    if granted.is_none() {
        return Err(denied(format!(
            "this client has no access to {project}/{environment}"
        )));
    }
    let binding = sqlx::query("SELECT base_url,header,template,secret_name FROM managed_http_bindings WHERE org_id=$1 AND slug=$2 AND name=$3")
        .bind(org)
        .bind(&project)
        .bind(&binding_name)
        .fetch_optional(state.repository.pool())
        .await
        .map_err(storage)?
        .ok_or_else(|| ApiError(KeyLeaseError::NotFound { resource: format!("binding {binding_name}") }))?;
    let secret_name: String = binding.get("secret_name");
    let secret_row = current(state, org, &project, &environment)
        .await?
        .into_iter()
        .find(|row| row.get::<String, _>("name") == secret_name)
        .ok_or_else(|| {
            ApiError(KeyLeaseError::NotFound {
                resource: format!("secret {secret_name} in {environment}"),
            })
        })?;
    let secret = Zeroizing::new(
        String::from_utf8_lossy(
            &decrypt(
                state,
                org,
                &project,
                &environment,
                &secret_name,
                &secret_row,
            )
            .await?,
        )
        .into_owned(),
    );
    let value = Zeroizing::new(
        binding
            .get::<String, _>("template")
            .replace("{secret}", &secret),
    );
    if value.contains(['\r', '\n']) {
        return Err(invalid("the secret cannot be sent in a header"));
    }
    let base = url::Url::parse(&binding.get::<String, _>("base_url"))
        .map_err(|_| ApiError(KeyLeaseError::Storage))?;
    let url = target(&base, &path)?;
    let host = url
        .host_str()
        .unwrap_or_default()
        .trim_matches(['[', ']'])
        .to_owned();
    let port = url.port_or_known_default().unwrap_or(443);
    let addresses: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|_| ApiError(KeyLeaseError::ConnectorUnavailable { retryable: true }))?
        .collect();
    let address = *addresses
        .first()
        .ok_or(ApiError(KeyLeaseError::ConnectorUnavailable {
            retryable: true,
        }))?;
    if addresses
        .iter()
        .any(|address| !public_address(address.ip()))
    {
        return Err(denied(format!("{host} resolves to a private address")));
    }
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(60))
        .resolve(&host, address)
        .build()
        .map_err(|_| ApiError(KeyLeaseError::Storage))?;
    let header_name: String = binding.get("header");
    let mut outgoing = http.request(method.clone(), url);
    for (name, value) in &headers {
        let lower = name.to_ascii_lowercase();
        if valid_header_name(name)
            && !HOP_BY_HOP.contains(&lower.as_str())
            && lower != header_name.to_ascii_lowercase()
            && lower != "x-keylease-token"
            && !value.contains(['\r', '\n'])
        {
            outgoing = outgoing.header(name.as_str(), value.as_str());
        }
    }
    outgoing = outgoing
        .header("accept-encoding", "identity")
        .header(header_name.as_str(), value.as_str());
    if let Some(body) = body {
        outgoing = outgoing.body(body);
    }
    let mut response = outgoing
        .send()
        .await
        .map_err(|_| ApiError(KeyLeaseError::ConnectorUnavailable { retryable: true }))?;
    let status = response.status().as_u16();
    let response_headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .filter(|(name, _)| !HOP_BY_HOP.contains(&name.as_str()))
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect();
    let mut received = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| ApiError(KeyLeaseError::ConnectorUnavailable { retryable: true }))?
    {
        if received.len() + chunk.len() > MAX_BODY {
            return Err(invalid("the answer is larger than 2 MiB"));
        }
        received.extend_from_slice(&chunk);
    }
    let forms = vec![
        secret.as_bytes().to_vec(),
        base64::engine::general_purpose::STANDARD
            .encode(secret.as_bytes())
            .into_bytes(),
        value.as_bytes().to_vec(),
    ];
    let headers = response_headers
        .into_iter()
        .map(|(name, value)| {
            (
                name,
                String::from_utf8_lossy(&scrub(value.as_bytes(), &forms)).into_owned(),
            )
        })
        .collect();
    audit_event(
        state,
        org,
        &project,
        Some(&environment),
        Some(&binding_name),
        &format!("gateway_{}_{status}", method.as_str().to_ascii_lowercase()),
        &format!("gateway:{}", caller.id),
    )
    .await?;
    Ok(Forwarded {
        status,
        headers,
        body: scrub(&received, &forms),
    })
}

async fn http_request(
    state: &CloudApiState,
    org: &str,
    caller: &Client,
    arguments: Value,
) -> ApiResult<String> {
    let text = |name: &str| {
        arguments[name]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| invalid(format!("{name} is required")))
    };
    let method = arguments["method"]
        .as_str()
        .unwrap_or("GET")
        .to_ascii_uppercase();
    let method =
        reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| invalid("invalid method"))?;
    let mut headers: Vec<(String, String)> = arguments["headers"]
        .as_object()
        .map(|extra| {
            extra
                .iter()
                .filter_map(|(name, value)| {
                    value.as_str().map(|value| (name.clone(), value.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default();
    let body = if let Some(json_body) = arguments.get("json").filter(|value| !value.is_null()) {
        headers.push(("content-type".into(), "application/json".into()));
        Some(serde_json::to_vec(json_body).map_err(|_| invalid("json is not serializable"))?)
    } else {
        arguments["body"]
            .as_str()
            .map(|body| body.as_bytes().to_vec())
    };
    let forwarded = forward(
        state,
        org,
        caller,
        Forward {
            project: text("project")?,
            environment: text("environment")?,
            binding: text("binding")?,
            method,
            path: text("path")?,
            headers,
            body,
        },
    )
    .await?;
    let content_type = forwarded
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.as_str())
        .unwrap_or_default();
    let mut text = String::from_utf8_lossy(&forwarded.body).into_owned();
    if text.len() > MAX_TOOL_TEXT {
        let mut end = MAX_TOOL_TEXT;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str("\n[truncated by KeyLease]");
    }
    Ok(format!(
        "HTTP {}\ncontent-type: {content_type}\n\n{text}",
        forwarded.status
    ))
}

/// The base-URL proxy: `…/gateway/http/{project}/{environment}/{binding}` is
/// a drop-in API base URL for tools and SDKs. The gateway token travels in
/// `x-keylease-token`, so the tool's own `Authorization` slot stays free.
async fn http_proxy(
    State(state): State<CloudApiState>,
    Path(segments): Path<Vec<(String, String)>>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let segment = |name: &str| {
        segments
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
            .unwrap_or_default()
    };
    let org = segment("org");
    let token = headers
        .get("x-keylease-token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let mut auth = HeaderMap::new();
    if let Ok(value) = format!("Bearer {token}").parse() {
        auth.insert(header::AUTHORIZATION, value);
    }
    let caller = match client(&state, &org, &auth).await {
        Ok(caller) => caller,
        Err(error) => return error.into_response(),
    };
    let mut path = format!("/{}", segment("path"));
    if let Some(query) = uri.query() {
        path.push('?');
        path.push_str(query);
    }
    let Ok(method) = reqwest::Method::from_bytes(method.as_str().as_bytes()) else {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    };
    let request = Forward {
        project: segment("project"),
        environment: segment("environment"),
        binding: segment("binding"),
        method,
        path,
        headers: headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect(),
        body: (!body.is_empty()).then(|| body.to_vec()),
    };
    match forward(&state, &org, &caller, request).await {
        Ok(forwarded) => {
            let mut response = Response::new(axum::body::Body::from(forwarded.body));
            *response.status_mut() =
                StatusCode::from_u16(forwarded.status).unwrap_or(StatusCode::BAD_GATEWAY);
            for (name, value) in forwarded.headers {
                if let (Ok(name), Ok(value)) = (
                    axum::http::HeaderName::from_bytes(name.as_bytes()),
                    axum::http::HeaderValue::from_str(&value),
                ) {
                    response.headers_mut().append(name, value);
                }
            }
            response
        }
        Err(error) => error.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_stay_below_the_base_and_secrets_are_scrubbed() {
        let base = url::Url::parse("https://api.example.com/v1").unwrap();
        assert_eq!(
            target(&base, "/charges?x=1").unwrap().as_str(),
            "https://api.example.com/v1/charges?x=1"
        );
        for bad in ["charges", "//evil", "/../x", "/a/%2e%2e/b"] {
            assert!(target(&base, bad).is_err(), "{bad}");
        }
        assert_eq!(
            scrub(b"token=abc123", &[b"abc123".to_vec()]),
            b"token=[REDACTED by keylease]".to_vec()
        );
        assert!(!public_address("10.1.2.3".parse().unwrap()));
        assert!(public_address("140.82.112.3".parse().unwrap()));
    }
}
