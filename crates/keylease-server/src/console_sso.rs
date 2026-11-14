//! Console sign-in with an OpenID Connect provider (v2 plan, step 14):
//! authorization code flow with PKCE (S256), `state` and `nonce`, ID token
//! signatures checked against the provider's JWKS.
//!
//! A provider identity is **linked** to an account from a signed-in console
//! (`/v1/console/sso/start?link=1`); afterwards it signs that account in.
//! An unlinked identity signs nobody in.

use crate::api::{ApiError, ApiResult, CloudApiState};
use crate::console::{session, start_session};
use crate::relay::{denied, invalid, storage};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use keylease_core::KeyLeaseError;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;

const STATE_MINUTES: i64 = 10;
const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// The provider, from `KEYLEASE_OIDC_*`.
#[derive(Clone, Default)]
pub struct ConsoleOidc {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Email domains allowed to sign in (empty: any).
    pub allowed_email_domains: Vec<String>,
}

impl std::fmt::Debug for ConsoleOidc {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConsoleOidc")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

pub(crate) fn router() -> Router<CloudApiState> {
    Router::new()
        .route("/v1/console/sso", get(status))
        .route("/v1/console/sso/start", get(start))
        .route("/v1/console/sso/callback", get(callback))
        .route("/v1/console/sso/identities", get(identities))
        .route("/v1/console/sso/identities/{subject}", delete(unlink))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// https, or http to a loopback host (local providers and tests).
fn allowed_url(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    parsed.scheme() == "https"
        || (parsed.scheme() == "http"
            && matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")))
}

fn provider(state: &CloudApiState) -> ApiResult<&ConsoleOidc> {
    state
        .oidc
        .as_ref()
        .ok_or_else(|| invalid("single sign-on is not configured on this server"))
}

fn public_base(state: &CloudApiState) -> ApiResult<String> {
    state
        .public_url
        .clone()
        .ok_or_else(|| invalid("single sign-on needs KEYLEASE_SERVER_PUBLIC_URL"))
}

fn http() -> ApiResult<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| ApiError(KeyLeaseError::Storage))
}

async fn fetch_json(
    client: &reqwest::Client,
    request: reqwest::RequestBuilder,
) -> ApiResult<Value> {
    let _ = client;
    let mut response = request
        .send()
        .await
        .map_err(|_| ApiError(KeyLeaseError::ConnectorUnavailable { retryable: true }))?;
    if !response.status().is_success() {
        return Err(denied("the identity provider refused the request"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| ApiError(KeyLeaseError::ConnectorUnavailable { retryable: true }))?
    {
        if bytes.len() + chunk.len() > MAX_DOCUMENT_BYTES {
            return Err(denied("the identity provider's answer is too large"));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| denied("the identity provider's answer is not JSON"))
}

struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

async fn discover(oidc: &ConsoleOidc) -> ApiResult<Discovery> {
    let client = http()?;
    let url = format!(
        "{}/.well-known/openid-configuration",
        oidc.issuer.trim_end_matches('/')
    );
    let document = fetch_json(&client, client.get(&url)).await?;
    let field = |name: &str| -> ApiResult<String> {
        document[name]
            .as_str()
            .filter(|value| allowed_url(value))
            .map(str::to_owned)
            .ok_or_else(|| denied("the identity provider's discovery document is incomplete"))
    };
    if document["issuer"].as_str() != Some(oidc.issuer.as_str()) {
        return Err(denied("the identity provider's issuer does not match"));
    }
    Ok(Discovery {
        authorization_endpoint: field("authorization_endpoint")?,
        token_endpoint: field("token_endpoint")?,
        jwks_uri: field("jwks_uri")?,
    })
}

async fn status(State(state): State<CloudApiState>) -> Json<Value> {
    Json(json!({
        "enabled": state.oidc.is_some() && state.public_url.is_some(),
        "issuer": state.oidc.as_ref().map(|oidc| oidc.issuer.clone()),
    }))
}

#[derive(Deserialize)]
struct StartQuery {
    #[serde(default)]
    link: Option<String>,
}

fn redirect(location: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Sends the browser to the provider. With `link=1` (and a session) the
/// identity that comes back is linked to the signed-in account.
async fn start(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Query(query): Query<StartQuery>,
) -> ApiResult<Response> {
    let oidc = provider(&state)?;
    let base = public_base(&state)?;
    let link_account = match query.link.as_deref() {
        Some("1") => Some(session(&state, &headers).await?),
        _ => None,
    };
    let discovery = discover(oidc).await?;
    let state_token = random_token();
    let verifier = random_token();
    let nonce = random_token();
    sqlx::query("DELETE FROM console_sso_states WHERE expires_at < now()")
        .execute(state.repository.pool())
        .await
        .map_err(storage)?;
    sqlx::query(
        "INSERT INTO console_sso_states(state_hash,code_verifier,nonce,link_account,expires_at) VALUES($1,$2,$3,$4,$5)",
    )
    .bind(sha256_hex(state_token.as_bytes()))
    .bind(&verifier)
    .bind(&nonce)
    .bind(&link_account)
    .bind(Utc::now() + Duration::minutes(STATE_MINUTES))
    .execute(state.repository.pool())
    .await
    .map_err(storage)?;
    let mut url = url::Url::parse(&discovery.authorization_endpoint)
        .map_err(|_| denied("invalid authorization endpoint"))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &oidc.client_id)
        .append_pair("redirect_uri", &format!("{base}/v1/console/sso/callback"))
        .append_pair("scope", "openid email profile")
        .append_pair("state", &state_token)
        .append_pair("nonce", &nonce)
        .append_pair(
            "code_challenge",
            &URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
        )
        .append_pair("code_challenge_method", "S256");
    Ok(redirect(url.as_str()))
}

#[derive(Deserialize)]
struct CallbackQuery {
    #[serde(default)]
    code: Option<String>,
    state: String,
}

#[derive(Deserialize)]
struct IdClaims {
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

async fn verify_id_token(oidc: &ConsoleOidc, jwks_uri: &str, token: &str) -> ApiResult<IdClaims> {
    let header = decode_header(token).map_err(|_| denied("invalid ID token"))?;
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
        return Err(denied("the ID token must use an asymmetric signature"));
    }
    let client = http()?;
    let set: JwkSet = serde_json::from_value(fetch_json(&client, client.get(jwks_uri)).await?)
        .map_err(|_| denied("invalid JWKS"))?;
    let jwk = match &header.kid {
        Some(kid) => set.find(kid),
        None if set.keys.len() == 1 => set.keys.first(),
        None => None,
    }
    .ok_or_else(|| denied("the ID token's signing key is unknown"))?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| denied("unsupported signing key"))?;
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[oidc.issuer.as_str()]);
    validation.set_audience(&[oidc.client_id.as_str()]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.leeway = 30;
    let claims = decode::<IdClaims>(token, &key, &validation)
        .map_err(|_| denied("the ID token's signature or claims are invalid"))?
        .claims;
    if claims.sub.is_empty() || claims.sub.len() > 255 || claims.sub.chars().any(char::is_control) {
        return Err(denied("invalid subject"));
    }
    Ok(claims)
}

/// The provider sends the browser back here.
async fn callback(
    State(state): State<CloudApiState>,
    Query(query): Query<CallbackQuery>,
) -> ApiResult<Response> {
    let oidc = provider(&state)?;
    let base = public_base(&state)?;
    let row = sqlx::query(
        "DELETE FROM console_sso_states WHERE state_hash=$1 AND expires_at > now() RETURNING code_verifier,nonce,link_account",
    )
    .bind(sha256_hex(query.state.as_bytes()))
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .ok_or_else(|| denied("this sign-in expired or was already used; start again"))?;
    let Some(code) = query
        .code
        .filter(|code| !code.is_empty() && code.len() <= 4096)
    else {
        return Ok(redirect(&format!("{base}/console/#sso=cancelled")));
    };
    let discovery = discover(oidc).await?;
    let client = http()?;
    let mut form = vec![
        ("grant_type", "authorization_code".to_owned()),
        ("code", code),
        ("redirect_uri", format!("{base}/v1/console/sso/callback")),
        ("client_id", oidc.client_id.clone()),
        ("code_verifier", row.get::<String, _>("code_verifier")),
    ];
    if let Some(secret) = &oidc.client_secret {
        form.push(("client_secret", secret.clone()));
    }
    let tokens = fetch_json(&client, client.post(&discovery.token_endpoint).form(&form)).await?;
    let id_token = tokens["id_token"]
        .as_str()
        .ok_or_else(|| denied("the identity provider returned no ID token"))?;
    let claims = verify_id_token(oidc, &discovery.jwks_uri, id_token).await?;
    if claims.nonce.as_deref() != Some(row.get::<String, _>("nonce").as_str()) {
        return Err(denied("the ID token's nonce does not match"));
    }
    if !oidc.allowed_email_domains.is_empty() {
        let domain = claims
            .email
            .as_deref()
            .and_then(|email| email.rsplit_once('@'))
            .map(|(_, domain)| domain);
        if domain.is_none_or(|domain| {
            !oidc
                .allowed_email_domains
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(domain))
        }) {
            return Err(denied("this email domain may not sign in"));
        }
    }
    let pool = state.repository.pool();
    if let Some(account) = row.get::<Option<String>, _>("link_account") {
        sqlx::query(
            "INSERT INTO console_sso_identities(issuer,subject,account_id,email,linked_at) VALUES($1,$2,$3,$4,now()) \
             ON CONFLICT (issuer,subject) DO NOTHING",
        )
        .bind(&oidc.issuer)
        .bind(&claims.sub)
        .bind(&account)
        .bind(&claims.email)
        .execute(pool)
        .await
        .map_err(storage)?;
    }
    let linked =
        sqlx::query("SELECT account_id FROM console_sso_identities WHERE issuer=$1 AND subject=$2")
            .bind(&oidc.issuer)
            .bind(&claims.sub)
            .fetch_optional(pool)
            .await
            .map_err(storage)?;
    let Some(linked) = linked else {
        return Ok(redirect(&format!("{base}/console/#sso=unlinked")));
    };
    let account: String = linked.get("account_id");
    let session = start_session(&state, &account, "sso").await?;
    let mut response = redirect(&format!("{base}/console/"));
    if let Some(cookie) = session.headers().get(header::SET_COOKIE) {
        response
            .headers_mut()
            .insert(header::SET_COOKIE, cookie.clone());
    }
    Ok(response)
}

async fn identities(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let account = session(&state, &headers).await?;
    let rows = sqlx::query("SELECT issuer,subject,email,linked_at FROM console_sso_identities WHERE account_id=$1 ORDER BY linked_at")
        .bind(&account)
        .fetch_all(state.repository.pool())
        .await
        .map_err(storage)?;
    Ok(Json(json!({
        "identities": rows.iter().map(|row| json!({
            "issuer": row.get::<String, _>("issuer"),
            "subject": row.get::<String, _>("subject"),
            "email": row.get::<Option<String>, _>("email"),
            "linked_at": row.get::<chrono::DateTime<Utc>, _>("linked_at"),
        })).collect::<Vec<_>>()
    })))
}

async fn unlink(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(subject): Path<String>,
) -> ApiResult<Json<Value>> {
    crate::console::require_csrf(&headers)?;
    let account = session(&state, &headers).await?;
    sqlx::query("DELETE FROM console_sso_identities WHERE account_id=$1 AND subject=$2")
        .bind(&account)
        .bind(&subject)
        .execute(state.repository.pool())
        .await
        .map_err(storage)?;
    Ok(Json(json!({"unlinked": subject})))
}
