//! Upstream MCP servers in the MCP Gateway. A project admin adds a remote MCP
//! server (Streamable HTTP) to a project, with no credential, a bearer token
//! kept as a Managed secret, or OAuth: the gateway discovers the server's
//! authorization server (protected resource metadata, RFC 9728; server
//! metadata, RFC 8414), registers itself (RFC 7591) and connects one
//! environment at a time with the authorization code flow and PKCE. The
//! tokens are a Managed secret of that environment, refreshed when needed.
//!
//! Gateway clients granted the environment then see the upstream's tools,
//! named `UPSTREAM__TOOL`, next to the gateway's own. A call goes through the
//! same per-call approvals and is audited; the credential stays on the server.

use crate::api::{ApiError, ApiResult, CloudApiState};
use crate::console::require_csrf;
use crate::gateway::public_address;
use crate::managed::{audit_event, authorize, current, decrypt, write_version};
use crate::relay::{denied, invalid, parse, storage};
use crate::teams::ProjectRole;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post, put},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use keylease_core::KeyLeaseError;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroizing;

const PROTOCOL_VERSION: &str = "2025-06-18";
/// Largest answer read from an upstream server or authorization server.
const MAX_ANSWER: usize = 4 * 1024 * 1024;
/// How long an upstream's tool list is reused.
const TOOLS_CACHE_SECONDS: i64 = 60;
/// How long a person has to finish the OAuth sign-in.
const OAUTH_STATE_MINUTES: i64 = 10;
/// Longest tool name clients accept.
const MAX_TOOL_NAME: usize = 64;

pub(crate) fn router() -> Router<CloudApiState> {
    Router::new()
        .route(
            "/v1/orgs/{org}/projects/{slug}/mcp-upstreams",
            get(list_upstreams),
        )
        .route(
            "/v1/orgs/{org}/projects/{slug}/mcp-upstreams/{name}",
            put(set_upstream).delete(delete_upstream),
        )
        .route(
            "/v1/orgs/{org}/projects/{slug}/mcp-upstreams/{name}/connect",
            post(connect),
        )
        .route("/v1/gateway/oauth/callback", get(oauth_callback))
}

fn valid_upstream_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 31
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// The Managed secret that holds an upstream's OAuth tokens.
fn oauth_secret_name(upstream: &str) -> String {
    format!(
        "MCP_OAUTH_{}",
        upstream.to_ascii_uppercase().replace('-', "_")
    )
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn unreachable_error() -> ApiError {
    ApiError(KeyLeaseError::ConnectorUnavailable { retryable: true })
}

// ---------------------------------------------------------------------------
// HTTP to upstreams and authorization servers
// ---------------------------------------------------------------------------

/// A client pinned to the host's checked addresses: HTTPS (HTTP only with
/// private addresses allowed), public addresses unless the server allows
/// private ones, no redirects.
async fn checked_client(state: &CloudApiState, url: &url::Url) -> ApiResult<reqwest::Client> {
    let allow_private = state.allow_private_network;
    if url.scheme() != "https" && !(allow_private && url.scheme() == "http") {
        return Err(invalid("upstream and authorization URLs must use https"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| invalid("the URL has no host"))?
        .trim_matches(['[', ']'])
        .to_owned();
    let port = url.port_or_known_default().unwrap_or(443);
    let addresses: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|_| unreachable_error())?
        .collect();
    let address = *addresses.first().ok_or_else(unreachable_error)?;
    if !allow_private
        && addresses
            .iter()
            .any(|address| !public_address(address.ip()))
    {
        return Err(denied(format!("{host} resolves to a private address")));
    }
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(60))
        .user_agent(concat!("keylease-mcp-gateway/", env!("CARGO_PKG_VERSION")))
        .resolve(&host, address)
        .build()
        .map_err(|_| ApiError(KeyLeaseError::Storage))
}

async fn read_limited(mut response: reqwest::Response) -> ApiResult<Vec<u8>> {
    let mut received = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| unreachable_error())? {
        if received.len() + chunk.len() > MAX_ANSWER {
            return Err(invalid("the upstream answer is too large"));
        }
        received.extend_from_slice(&chunk);
    }
    Ok(received)
}

async fn get_json(state: &CloudApiState, url: &url::Url) -> Option<Value> {
    let client = checked_client(state, url).await.ok()?;
    let response = client
        .get(url.clone())
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    serde_json::from_slice(&read_limited(response).await.ok()?).ok()
}

/// RFC 8414 / OpenID discovery URLs for an issuer, most specific first.
fn metadata_urls(issuer: &url::Url) -> Vec<url::Url> {
    let path = issuer.path().trim_end_matches('/');
    let origin = issuer.origin().ascii_serialization();
    let mut urls = vec![
        format!("{origin}/.well-known/oauth-authorization-server{path}"),
        format!("{origin}/.well-known/openid-configuration{path}"),
    ];
    if !path.is_empty() {
        urls.push(format!("{origin}{path}/.well-known/openid-configuration"));
    }
    urls.iter()
        .filter_map(|url| url::Url::parse(url).ok())
        .collect()
}

/// The `resource_metadata` URL in a `WWW-Authenticate` challenge.
fn resource_metadata_hint(challenge: &str) -> Option<String> {
    let start = challenge.find("resource_metadata=")? + "resource_metadata=".len();
    let rest = &challenge[start..];
    let value = if let Some(quoted) = rest.strip_prefix('"') {
        quoted.split('"').next()?
    } else {
        rest.split([',', ' ']).next()?
    };
    Some(value.to_owned())
}

/// Finds the upstream's authorization server and registers the gateway with
/// it. Returns what the upstream row keeps.
async fn discover(
    state: &CloudApiState,
    upstream: &url::Url,
    redirect_uri: &str,
    client_id: Option<String>,
    scope: Option<String>,
) -> ApiResult<Value> {
    // 1. Protected resource metadata: the well-known URL for the path, the
    //    host's, or the hint of a 401 challenge.
    let origin = upstream.origin().ascii_serialization();
    let path = upstream.path().trim_end_matches('/');
    let mut candidates = vec![
        format!("{origin}/.well-known/oauth-protected-resource{path}"),
        format!("{origin}/.well-known/oauth-protected-resource"),
    ];
    if let Ok(client) = checked_client(state, upstream).await
        && let Ok(response) = client
            .post(upstream.clone())
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .body(r#"{"jsonrpc":"2.0","id":0,"method":"ping"}"#)
            .send()
            .await
        && let Some(hint) = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .and_then(resource_metadata_hint)
    {
        candidates.insert(0, hint);
    }
    let mut issuer = None;
    for candidate in candidates {
        let Ok(url) = url::Url::parse(&candidate) else {
            continue;
        };
        if let Some(metadata) = get_json(state, &url).await
            && let Some(server) = metadata["authorization_servers"][0].as_str()
        {
            issuer = url::Url::parse(server).ok();
            break;
        }
    }
    // Servers without resource metadata act as their own authorization server.
    let issuer = issuer.unwrap_or_else(|| {
        url::Url::parse(&format!("{origin}/")).unwrap_or_else(|_| upstream.clone())
    });
    // 2. Authorization server metadata.
    let mut metadata = None;
    for url in metadata_urls(&issuer) {
        if let Some(found) = get_json(state, &url).await
            && found["authorization_endpoint"].is_string()
            && found["token_endpoint"].is_string()
        {
            metadata = Some(found);
            break;
        }
    }
    let metadata = metadata.ok_or_else(|| {
        invalid(format!(
            "could not find the OAuth metadata of {issuer} (RFC 8414)"
        ))
    })?;
    if let Some(methods) = metadata["code_challenge_methods_supported"].as_array()
        && !methods.iter().any(|method| method == "S256")
    {
        return Err(invalid(
            "the authorization server does not support PKCE S256",
        ));
    }
    // 3. The gateway's client: given, or registered now (RFC 7591).
    let (client_id, client_secret) = match client_id {
        Some(id) => (id, None),
        None => {
            let endpoint = metadata["registration_endpoint"]
                .as_str()
                .and_then(|value| url::Url::parse(value).ok())
                .ok_or_else(|| {
                    invalid(
                        "the authorization server has no registration endpoint; give a client_id",
                    )
                })?;
            let client = checked_client(state, &endpoint).await?;
            let response = client
                .post(endpoint)
                .json(&json!({
                    "client_name": "KeyLease MCP Gateway",
                    "redirect_uris": [redirect_uri],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "none",
                }))
                .send()
                .await
                .map_err(|_| unreachable_error())?;
            if !response.status().is_success() {
                return Err(invalid(format!(
                    "the authorization server refused the client registration ({})",
                    response.status()
                )));
            }
            let registered: Value = serde_json::from_slice(&read_limited(response).await?)
                .map_err(|_| invalid("malformed client registration"))?;
            let id = registered["client_id"]
                .as_str()
                .ok_or_else(|| invalid("the client registration has no client_id"))?
                .to_owned();
            (id, registered["client_secret"].as_str().map(str::to_owned))
        }
    };
    Ok(json!({
        "issuer": issuer.as_str(),
        "authorization_endpoint": metadata["authorization_endpoint"],
        "token_endpoint": metadata["token_endpoint"],
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope,
    }))
}

// ---------------------------------------------------------------------------
// Console: upstream configuration and OAuth connection
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetUpstream {
    url: String,
    /// `none`, `bearer` or `oauth`.
    auth: String,
    /// For `bearer`: the Managed secret with the token.
    #[serde(default)]
    secret_name: Option<String>,
    /// For `oauth` without dynamic client registration.
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

fn redirect_uri(state: &CloudApiState) -> ApiResult<String> {
    state
        .public_url
        .as_ref()
        .map(|base| format!("{base}/v1/gateway/oauth/callback"))
        .ok_or_else(|| invalid("OAuth needs KEYLEASE_SERVER_PUBLIC_URL on the server"))
}

async fn set_upstream(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug, name)): Path<(String, String, String)>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = authorize(&state, &headers, &org, &slug, None, ProjectRole::Admin).await?;
    let request: SetUpstream = parse(&body)?;
    if !valid_upstream_name(&name) {
        return Err(invalid("the name is a-z, 0-9 and -, at most 31 characters"));
    }
    let url = url::Url::parse(&request.url).map_err(|_| invalid("invalid URL"))?;
    checked_client(&state, &url).await?;
    let (secret_name, oauth) = match request.auth.as_str() {
        "none" => (None, None),
        "bearer" => {
            let secret = request
                .secret_name
                .filter(|secret| !secret.is_empty() && secret.len() <= 128)
                .ok_or_else(|| invalid("bearer needs secret_name"))?;
            (Some(secret), None)
        }
        "oauth" => {
            let oauth = discover(
                &state,
                &url,
                &redirect_uri(&state)?,
                request.client_id,
                request.scope,
            )
            .await?;
            (Some(oauth_secret_name(&name)), Some(oauth))
        }
        _ => return Err(invalid("auth is none, bearer or oauth")),
    };
    sqlx::query(
        "INSERT INTO managed_mcp_upstreams(org_id,slug,name,url,auth,secret_name,oauth,created_by,created_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,now()) ON CONFLICT (org_id,slug,name) DO UPDATE SET \
         url=excluded.url, auth=excluded.auth, secret_name=excluded.secret_name, oauth=excluded.oauth, created_by=excluded.created_by",
    )
    .bind(&org)
    .bind(&slug)
    .bind(&name)
    .bind(url.as_str())
    .bind(&request.auth)
    .bind(&secret_name)
    .bind(&oauth)
    .bind(&account)
    .execute(state.repository.pool())
    .await
    .map_err(storage)?;
    forget_tools(&org, &slug, &name);
    audit_event(
        &state,
        &org,
        &slug,
        None,
        Some(&name),
        "mcp_upstream_set",
        &account,
    )
    .await?;
    Ok(Json(json!({
        "name": name,
        "url": url.as_str(),
        "auth": request.auth,
        "secret_name": secret_name,
        "issuer": oauth.as_ref().map(|oauth| oauth["issuer"].clone()),
    })))
}

async fn delete_upstream(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug, name)): Path<(String, String, String)>,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account = authorize(&state, &headers, &org, &slug, None, ProjectRole::Admin).await?;
    let removed =
        sqlx::query("DELETE FROM managed_mcp_upstreams WHERE org_id=$1 AND slug=$2 AND name=$3")
            .bind(&org)
            .bind(&slug)
            .bind(&name)
            .execute(state.repository.pool())
            .await
            .map_err(storage)?
            .rows_affected();
    forget_tools(&org, &slug, &name);
    audit_event(
        &state,
        &org,
        &slug,
        None,
        Some(&name),
        "mcp_upstream_delete",
        &account,
    )
    .await?;
    Ok(Json(json!({"removed": removed})))
}

async fn list_upstreams(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &headers, &org, &slug, None, ProjectRole::Read).await?;
    let pool = state.repository.pool();
    let rows = sqlx::query(
        "SELECT name,url,auth,secret_name,oauth FROM managed_mcp_upstreams WHERE org_id=$1 AND slug=$2 ORDER BY name",
    )
    .bind(&org)
    .bind(&slug)
    .fetch_all(pool)
    .await
    .map_err(storage)?;
    // Which environments hold the credential.
    let secrets = sqlx::query(
        "SELECT DISTINCT ON (environment,name) environment,name,deleted FROM managed_secrets \
         WHERE org_id=$1 AND slug=$2 ORDER BY environment,name,version DESC",
    )
    .bind(&org)
    .bind(&slug)
    .fetch_all(pool)
    .await
    .map_err(storage)?;
    Ok(Json(json!({
        "upstreams": rows.iter().map(|row| {
            let secret: Option<String> = row.get("secret_name");
            let connected: Vec<String> = secret.as_ref().map(|secret| {
                secrets.iter()
                    .filter(|s| s.get::<String, _>("name") == *secret && !s.get::<bool, _>("deleted"))
                    .map(|s| s.get::<String, _>("environment"))
                    .collect()
            }).unwrap_or_default();
            let oauth: Option<Value> = row.get("oauth");
            json!({
                "name": row.get::<String, _>("name"),
                "url": row.get::<String, _>("url"),
                "auth": row.get::<String, _>("auth"),
                "secret_name": secret,
                "issuer": oauth.as_ref().map(|oauth| oauth["issuer"].clone()),
                "environments": connected,
            })
        }).collect::<Vec<_>>()
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Connect {
    environment: String,
}

/// Starts the OAuth sign-in for one environment; returns the URL to open.
async fn connect(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path((org, slug, name)): Path<(String, String, String)>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let request: Connect = parse(&body)?;
    let account = authorize(
        &state,
        &headers,
        &org,
        &slug,
        Some(&request.environment),
        ProjectRole::Admin,
    )
    .await?;
    let row = sqlx::query(
        "SELECT url,oauth FROM managed_mcp_upstreams WHERE org_id=$1 AND slug=$2 AND name=$3 AND auth='oauth'",
    )
    .bind(&org)
    .bind(&slug)
    .bind(&name)
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .ok_or_else(|| ApiError(KeyLeaseError::NotFound { resource: format!("OAuth upstream {name}") }))?;
    let oauth: Value = row.get("oauth");
    let resource: String = row.get("url");
    let state_token = random_token();
    let verifier = random_token();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    sqlx::query(
        "INSERT INTO gateway_oauth_states(state_hash,org_id,slug,name,environment,code_verifier,account_id,expires_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(sha256_hex(state_token.as_bytes()))
    .bind(&org)
    .bind(&slug)
    .bind(&name)
    .bind(&request.environment)
    .bind(&verifier)
    .bind(&account)
    .bind(Utc::now() + Duration::minutes(OAUTH_STATE_MINUTES))
    .execute(state.repository.pool())
    .await
    .map_err(storage)?;
    let mut url = url::Url::parse(oauth["authorization_endpoint"].as_str().unwrap_or_default())
        .map_err(|_| invalid("the authorization endpoint is not a URL"))?;
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", oauth["client_id"].as_str().unwrap_or_default())
            .append_pair("redirect_uri", &redirect_uri(&state)?)
            .append_pair("state", &state_token)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("resource", &resource);
        if let Some(scope) = oauth["scope"].as_str() {
            query.append_pair("scope", scope);
        }
    }
    Ok(Json(json!({"authorize_url": url.as_str()})))
}

/// Exchanges a code or a refresh token at the token endpoint.
async fn token_request(
    state: &CloudApiState,
    oauth: &Value,
    resource: &str,
    grant: &[(&str, &str)],
) -> ApiResult<Value> {
    let endpoint = url::Url::parse(oauth["token_endpoint"].as_str().unwrap_or_default())
        .map_err(|_| invalid("the token endpoint is not a URL"))?;
    let mut form: Vec<(&str, &str)> = grant.to_vec();
    form.push(("client_id", oauth["client_id"].as_str().unwrap_or_default()));
    form.push(("resource", resource));
    if let Some(secret) = oauth["client_secret"].as_str() {
        form.push(("client_secret", secret));
    }
    let client = checked_client(state, &endpoint).await?;
    let response = client
        .post(endpoint)
        .header(header::ACCEPT, "application/json")
        .form(&form)
        .send()
        .await
        .map_err(|_| unreachable_error())?;
    let status = response.status();
    let body: Value = serde_json::from_slice(&read_limited(response).await?).unwrap_or(Value::Null);
    if !status.is_success() || !body["access_token"].is_string() {
        return Err(denied(format!(
            "the authorization server refused the token request ({status} {})",
            body["error"].as_str().unwrap_or_default()
        )));
    }
    Ok(body)
}

fn stored_tokens(answer: &Value, previous_refresh: Option<&str>) -> Value {
    json!({
        "access_token": answer["access_token"],
        "refresh_token": answer["refresh_token"].as_str().or(previous_refresh),
        "expires_at": answer["expires_in"].as_i64().map(|seconds| Utc::now() + Duration::seconds(seconds)),
    })
}

#[derive(Deserialize)]
struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

fn callback_page(status: StatusCode, message: &str) -> Response {
    let escaped = message
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let mut response = (
        status,
        Html(format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>KeyLease</title></head>\
             <body><h1>KeyLease MCP Gateway</h1><p>{escaped}</p></body></html>"
        )),
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    response
}

/// Where the authorization server sends the browser back. The `state` is
/// single use and names the project environment and the admin who started.
async fn oauth_callback(
    State(state): State<CloudApiState>,
    Query(callback): Query<Callback>,
) -> Response {
    match finish_oauth(&state, callback).await {
        Ok(message) => callback_page(StatusCode::OK, &message),
        Err(ApiError(error)) => callback_page(
            StatusCode::BAD_REQUEST,
            &format!(
                "The connection failed: {}",
                match error {
                    KeyLeaseError::Denied { reason } | KeyLeaseError::InvalidRequest { reason } =>
                        reason,
                    KeyLeaseError::ConnectorUnavailable { .. } =>
                        "the authorization server could not be reached".into(),
                    _ => "internal error".into(),
                }
            ),
        ),
    }
}

async fn finish_oauth(state: &CloudApiState, callback: Callback) -> ApiResult<String> {
    if let Some(error) = callback.error {
        return Err(denied(format!("the authorization server answered {error}")));
    }
    let (Some(code), Some(state_token)) = (callback.code, callback.state) else {
        return Err(invalid("missing code or state"));
    };
    let pool = state.repository.pool();
    let row = sqlx::query(
        "DELETE FROM gateway_oauth_states WHERE state_hash=$1 RETURNING org_id,slug,name,environment,code_verifier,account_id,expires_at",
    )
    .bind(sha256_hex(state_token.as_bytes()))
    .fetch_optional(pool)
    .await
    .map_err(storage)?
    .ok_or_else(|| invalid("this sign-in link was already used or is unknown; start again from the console"))?;
    if row.get::<DateTime<Utc>, _>("expires_at") < Utc::now() {
        return Err(invalid(
            "the sign-in took too long; start again from the console",
        ));
    }
    let (org, slug, name, environment): (String, String, String, String) = (
        row.get("org_id"),
        row.get("slug"),
        row.get("name"),
        row.get("environment"),
    );
    let account: String = row.get("account_id");
    let verifier: String = row.get("code_verifier");
    let upstream = sqlx::query(
        "SELECT url,oauth,secret_name FROM managed_mcp_upstreams WHERE org_id=$1 AND slug=$2 AND name=$3 AND auth='oauth'",
    )
    .bind(&org)
    .bind(&slug)
    .bind(&name)
    .fetch_optional(pool)
    .await
    .map_err(storage)?
    .ok_or_else(|| invalid("the upstream was removed"))?;
    let oauth: Value = upstream.get("oauth");
    let resource: String = upstream.get("url");
    let redirect = redirect_uri(state)?;
    let answer = token_request(
        state,
        &oauth,
        &resource,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect),
            ("code_verifier", &verifier),
        ],
    )
    .await?;
    let tokens = Zeroizing::new(stored_tokens(&answer, None).to_string());
    let secret: String = upstream.get("secret_name");
    write_version(
        state,
        &org,
        &slug,
        &environment,
        &secret,
        Some(tokens.as_bytes()),
        &account,
    )
    .await?;
    forget_tools(&org, &slug, &name);
    audit_event(
        state,
        &org,
        &slug,
        Some(&environment),
        Some(&name),
        "mcp_upstream_connect",
        &account,
    )
    .await?;
    Ok(format!(
        "{name} is connected for {slug}/{environment}. You can close this tab."
    ))
}

// ---------------------------------------------------------------------------
// Calling upstreams
// ---------------------------------------------------------------------------

/// An upstream as the gateway calls it.
#[derive(Clone)]
struct Upstream {
    org: String,
    slug: String,
    environment: String,
    name: String,
    url: url::Url,
    auth: String,
    secret_name: Option<String>,
    oauth: Option<Value>,
    created_by: String,
}

/// The `Authorization` value for an upstream, refreshing OAuth tokens that
/// expire within a minute (or at once with `force_refresh`).
async fn authorization(
    state: &CloudApiState,
    upstream: &Upstream,
    force_refresh: bool,
) -> ApiResult<Option<Zeroizing<String>>> {
    let Some(secret) = &upstream.secret_name else {
        return Ok(None);
    };
    let row = current(state, &upstream.org, &upstream.slug, &upstream.environment)
        .await?
        .into_iter()
        .find(|row| row.get::<String, _>("name") == *secret && !row.get::<bool, _>("deleted"))
        .ok_or_else(|| {
            denied(format!(
                "{} is not connected for {}/{}{}",
                upstream.name,
                upstream.slug,
                upstream.environment,
                if upstream.auth == "oauth" {
                    " (Connect it in the console)"
                } else {
                    ""
                }
            ))
        })?;
    let value = decrypt(
        state,
        &upstream.org,
        &upstream.slug,
        &upstream.environment,
        secret,
        &row,
    )
    .await?;
    if upstream.auth == "bearer" {
        let token = String::from_utf8_lossy(&value).trim().to_owned();
        return Ok(Some(Zeroizing::new(format!("Bearer {token}"))));
    }
    let tokens: Value = serde_json::from_slice(&value)
        .map_err(|_| invalid("the stored OAuth tokens are malformed"))?;
    let expiring = tokens["expires_at"]
        .as_str()
        .and_then(|at| DateTime::parse_from_rfc3339(at).ok())
        .is_some_and(|at| at.with_timezone(&Utc) <= Utc::now() + Duration::seconds(60));
    let refresh = tokens["refresh_token"].as_str();
    if (expiring || force_refresh)
        && let (Some(refresh), Some(oauth)) = (refresh, &upstream.oauth)
    {
        let answer = token_request(
            state,
            oauth,
            upstream.url.as_str(),
            &[("grant_type", "refresh_token"), ("refresh_token", refresh)],
        )
        .await?;
        let stored = Zeroizing::new(stored_tokens(&answer, Some(refresh)).to_string());
        write_version(
            state,
            &upstream.org,
            &upstream.slug,
            &upstream.environment,
            secret,
            Some(stored.as_bytes()),
            &upstream.created_by,
        )
        .await?;
        let token = answer["access_token"].as_str().unwrap_or_default();
        return Ok(Some(Zeroizing::new(format!("Bearer {token}"))));
    }
    let token = tokens["access_token"].as_str().unwrap_or_default();
    Ok(Some(Zeroizing::new(format!("Bearer {token}"))))
}

/// The JSON-RPC message with `id` in an answer that is JSON or an SSE stream.
fn rpc_answer(content_type: &str, body: &[u8], id: i64) -> Option<Value> {
    if content_type.starts_with("text/event-stream") {
        let text = String::from_utf8_lossy(body);
        for event in text.split("\n\n") {
            let data: Vec<&str> = event
                .lines()
                .filter_map(|line| line.strip_prefix("data:"))
                .map(str::trim_start)
                .collect();
            if data.is_empty() {
                continue;
            }
            if let Ok(message) = serde_json::from_str::<Value>(&data.join("\n"))
                && message["id"] == id
            {
                return Some(message);
            }
        }
        None
    } else {
        serde_json::from_slice::<Value>(body)
            .ok()
            .filter(|message| message["id"] == id)
    }
}

enum Upstreamed {
    Answer(Value),
    Unauthorized,
}

/// One JSON-RPC request in a fresh session (initialize, initialized, the
/// request, end of session).
async fn session_call(
    state: &CloudApiState,
    upstream: &Upstream,
    authorization: Option<&str>,
    method: &str,
    params: Value,
) -> ApiResult<Upstreamed> {
    let client = checked_client(state, &upstream.url).await?;
    let post = |body: Value, session: Option<&str>| {
        let mut request = client
            .post(upstream.url.clone())
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("mcp-protocol-version", PROTOCOL_VERSION)
            .json(&body);
        if let Some(value) = authorization {
            request = request.header(header::AUTHORIZATION, value);
        }
        if let Some(session) = session {
            request = request.header("mcp-session-id", session);
        }
        request.send()
    };
    let response = post(
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "keylease-mcp-gateway", "version": env!("CARGO_PKG_VERSION")},
        }}),
        None,
    )
    .await
    .map_err(|_| unreachable_error())?;
    if response.status() == StatusCode::UNAUTHORIZED {
        return Ok(Upstreamed::Unauthorized);
    }
    if !response.status().is_success() {
        return Err(invalid(format!(
            "{} answered {}",
            upstream.name,
            response.status()
        )));
    }
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    rpc_answer(&content_type, &read_limited(response).await?, 1)
        .filter(|answer| answer.get("result").is_some())
        .ok_or_else(|| invalid(format!("{} did not initialize", upstream.name)))?;
    let _ = post(
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        session.as_deref(),
    )
    .await;
    let response = post(
        json!({"jsonrpc": "2.0", "id": 2, "method": method, "params": params}),
        session.as_deref(),
    )
    .await
    .map_err(|_| unreachable_error())?;
    if response.status() == StatusCode::UNAUTHORIZED {
        return Ok(Upstreamed::Unauthorized);
    }
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let answer = rpc_answer(&content_type, &read_limited(response).await?, 2)
        .ok_or_else(|| invalid(format!("{} gave no answer", upstream.name)))?;
    if let Some(session) = &session {
        let mut request = client
            .delete(upstream.url.clone())
            .header("mcp-session-id", session.as_str());
        if let Some(value) = authorization {
            request = request.header(header::AUTHORIZATION, value);
        }
        let _ = request.send().await;
    }
    Ok(Upstreamed::Answer(answer))
}

/// A JSON-RPC request to an upstream, refreshing an OAuth token once if the
/// upstream says it is no longer valid. Returns the `result`.
async fn call_upstream(
    state: &CloudApiState,
    upstream: &Upstream,
    method: &str,
    params: Value,
) -> ApiResult<(Value, Option<Zeroizing<String>>)> {
    let mut auth = authorization(state, upstream, false).await?;
    for attempt in 0..2 {
        match session_call(
            state,
            upstream,
            auth.as_deref().map(String::as_str),
            method,
            params.clone(),
        )
        .await?
        {
            Upstreamed::Answer(answer) => {
                if let Some(error) = answer.get("error") {
                    return Err(invalid(format!(
                        "{}: {}",
                        upstream.name,
                        error["message"].as_str().unwrap_or("error")
                    )));
                }
                return Ok((answer["result"].clone(), auth));
            }
            Upstreamed::Unauthorized if attempt == 0 && upstream.auth == "oauth" => {
                auth = authorization(state, upstream, true).await?;
            }
            Upstreamed::Unauthorized => {
                return Err(denied(format!("{} refused the credential", upstream.name)));
            }
        }
    }
    Err(denied(format!("{} refused the credential", upstream.name)))
}

type ToolCache = Mutex<HashMap<(String, String, String, String), (DateTime<Utc>, Vec<Value>)>>;

fn tool_cache() -> &'static ToolCache {
    static CACHE: OnceLock<ToolCache> = OnceLock::new();
    CACHE.get_or_init(Default::default)
}

fn forget_tools(org: &str, slug: &str, name: &str) {
    if let Ok(mut cache) = tool_cache().lock() {
        cache.retain(|key, _| !(key.0 == org && key.1 == slug && key.3 == name));
    }
}

async fn upstream_tool_list(state: &CloudApiState, upstream: &Upstream) -> ApiResult<Vec<Value>> {
    let key = (
        upstream.org.clone(),
        upstream.slug.clone(),
        upstream.environment.clone(),
        upstream.name.clone(),
    );
    if let Ok(cache) = tool_cache().lock()
        && let Some((at, tools)) = cache.get(&key)
        && Utc::now() - *at < Duration::seconds(TOOLS_CACHE_SECONDS)
    {
        return Ok(tools.clone());
    }
    let (result, _) = call_upstream(state, upstream, "tools/list", json!({})).await?;
    let tools: Vec<Value> = result["tools"].as_array().cloned().unwrap_or_default();
    if let Ok(mut cache) = tool_cache().lock() {
        cache.insert(key, (Utc::now(), tools.clone()));
    }
    Ok(tools)
}

/// An upstream tool as a gateway client sees it.
pub(crate) struct ExposedTool {
    pub(crate) name: String,
    pub(crate) definition: Value,
    upstream: Upstream,
    tool: String,
    read_only: bool,
}

fn tool_name_part(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// `UPSTREAM__TOOL`, or `PROJECT_ENVIRONMENT_UPSTREAM__TOOL` when the client
/// sees the same upstream name in several places; at most 64 characters.
fn exposed_name(prefix: &str, tool: &str) -> String {
    let name = format!("{}__{}", tool_name_part(prefix), tool_name_part(tool));
    if name.len() <= MAX_TOOL_NAME {
        return name;
    }
    let digest = sha256_hex(name.as_bytes());
    format!("{}_{}", &name[..MAX_TOOL_NAME - 9], &digest[..8])
}

/// The upstream tools a gateway client may call.
pub(crate) async fn client_tools(
    state: &CloudApiState,
    org: &str,
    client_id: &str,
) -> ApiResult<Vec<ExposedTool>> {
    let rows = sqlx::query(
        "SELECT u.slug,g.environment,u.name,u.url,u.auth,u.secret_name,u.oauth,u.created_by \
         FROM gateway_grants g JOIN managed_mcp_upstreams u ON u.org_id=g.org_id AND u.slug=g.slug \
         WHERE g.client_id=$1 AND g.org_id=$2 ORDER BY u.slug,g.environment,u.name",
    )
    .bind(client_id)
    .bind(org)
    .fetch_all(state.repository.pool())
    .await
    .map_err(storage)?;
    let mut seen: HashMap<String, usize> = HashMap::new();
    for row in &rows {
        *seen.entry(row.get::<String, _>("name")).or_default() += 1;
    }
    let mut exposed = Vec::new();
    for row in rows {
        let Ok(url) = url::Url::parse(&row.get::<String, _>("url")) else {
            continue;
        };
        let upstream = Upstream {
            org: org.to_owned(),
            slug: row.get("slug"),
            environment: row.get("environment"),
            name: row.get("name"),
            url,
            auth: row.get("auth"),
            secret_name: row.get("secret_name"),
            oauth: row.get("oauth"),
            created_by: row.get("created_by"),
        };
        let prefix = if seen.get(&upstream.name).copied().unwrap_or(0) > 1 {
            format!(
                "{}_{}_{}",
                upstream.slug, upstream.environment, upstream.name
            )
        } else {
            upstream.name.clone()
        };
        let tools = match upstream_tool_list(state, &upstream).await {
            Ok(tools) => tools,
            Err(_) => {
                tracing::warn!(upstream = upstream.name, "could not list upstream tools");
                continue;
            }
        };
        for tool in tools {
            let Some(tool_name) = tool["name"].as_str().map(str::to_owned) else {
                continue;
            };
            let name = exposed_name(&prefix, &tool_name);
            let mut definition = tool.clone();
            definition["name"] = json!(name);
            definition["description"] = json!(format!(
                "[{} via KeyLease, {}/{}] {}",
                upstream.name,
                upstream.slug,
                upstream.environment,
                tool["description"].as_str().unwrap_or_default()
            ));
            exposed.push(ExposedTool {
                name,
                definition,
                read_only: tool["annotations"]["readOnlyHint"] == true,
                upstream: upstream.clone(),
                tool: tool_name,
            });
        }
    }
    Ok(exposed)
}

/// Calls an upstream tool for a gateway client, after the per-call approval
/// gate. Returns the upstream's `tools/call` result.
pub(crate) async fn call_tool(
    state: &CloudApiState,
    org: &str,
    client_id: &str,
    approval: crate::gateway_approvals::ApprovalMode,
    tool: &ExposedTool,
    arguments: Value,
) -> ApiResult<Value> {
    let body = serde_json::to_vec(&arguments).unwrap_or_default();
    crate::gateway_approvals::gate(
        state,
        org,
        approval,
        tool.read_only,
        crate::gateway_approvals::Call {
            client_id,
            project: &tool.upstream.slug,
            environment: &tool.upstream.environment,
            binding: &tool.upstream.name,
            method: "TOOL",
            path: &tool.tool,
            body: Some(&body),
        },
    )
    .await?;
    let outcome = call_upstream(
        state,
        &tool.upstream,
        "tools/call",
        json!({"name": tool.tool, "arguments": arguments}),
    )
    .await;
    audit_event(
        state,
        org,
        &tool.upstream.slug,
        Some(&tool.upstream.environment),
        Some(&tool.upstream.name),
        if outcome.is_ok() {
            "gateway_mcp_call"
        } else {
            "gateway_mcp_call_failed"
        },
        &format!("gateway:{client_id}"),
    )
    .await?;
    let (result, auth) = outcome?;
    // The upstream should never echo the credential; scrub it anyway.
    let mut text = result.to_string();
    if let Some(auth) = auth {
        let token = auth.trim_start_matches("Bearer ");
        if token.len() >= 8 {
            text = text.replace(token, "[REDACTED by keylease]");
        }
    }
    serde_json::from_str(&text).map_err(|_| ApiError(KeyLeaseError::Storage))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_names_are_short_and_safe() {
        assert_eq!(
            exposed_name("github", "create_issue"),
            "github__create_issue"
        );
        assert_eq!(
            exposed_name("shop_prod_linear", "list.issues"),
            "shop_prod_linear__list_issues"
        );
        let long = exposed_name(&"a".repeat(40), &"b".repeat(40));
        assert_eq!(long.len(), 64);
        assert_ne!(long, exposed_name(&"a".repeat(40), &"c".repeat(40)));
    }

    #[test]
    fn answers_come_as_json_or_server_sent_events() {
        let sse = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"ok\":true}}\n\n";
        assert_eq!(
            rpc_answer("text/event-stream", sse, 2).unwrap()["result"]["ok"],
            true
        );
        assert!(rpc_answer("text/event-stream", sse, 3).is_none());
        assert_eq!(
            rpc_answer(
                "application/json",
                br#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
                1
            )
            .unwrap()["id"],
            1
        );
    }

    #[test]
    fn the_resource_metadata_hint_is_read_from_the_challenge() {
        assert_eq!(
            resource_metadata_hint(r#"Bearer realm="mcp", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource""#).as_deref(),
            Some("https://mcp.example.com/.well-known/oauth-protected-resource")
        );
        assert_eq!(
            resource_metadata_hint(
                "Bearer resource_metadata=https://x.example/m, error=\"invalid_token\""
            )
            .as_deref(),
            Some("https://x.example/m")
        );
        assert!(resource_metadata_hint("Bearer realm=\"x\"").is_none());
        let urls = metadata_urls(&url::Url::parse("https://auth.example.com/tenant1").unwrap());
        assert_eq!(
            urls[0].as_str(),
            "https://auth.example.com/.well-known/oauth-authorization-server/tenant1"
        );
        assert_eq!(
            urls[2].as_str(),
            "https://auth.example.com/tenant1/.well-known/openid-configuration"
        );
    }
}
