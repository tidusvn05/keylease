//! KeyLease Console sign-in and session API (ADR 0008).
//!
//! The user is a relay account. Two ways in:
//!
//! - **Device link:** the owner device signs `POST /v1/relay/console-links`
//!   with the hash of a random token and shows `…/console/#login=TOKEN`. The
//!   browser exchanges the token once for a session.
//! - **Passkey:** registered from a signed-in console (ES256, `none`
//!   attestation), then used to sign in without the device.
//!
//! Sessions are random cookies (`kl_session`, HttpOnly, Secure,
//! SameSite=Strict) stored as hashes. Requests that change state also need the
//! header `x-keylease-console: 1`, which a cross-site form cannot send.

use crate::api::{ApiError, ApiResult, CloudApiState};
use crate::relay::{Caller, denied, invalid, parse, storage, verify};
use crate::webauthn;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, HeaderValue, Method, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Duration, Utc};
use keylease_core::{KeyLeaseError, relay::RelayRole};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;

const SESSION_COOKIE: &str = "kl_session";
const SESSION_HOURS: i64 = 12;
const LINK_MAX_MINUTES: i64 = 15;
const CHALLENGE_MINUTES: i64 = 5;
const CSRF_HEADER: &str = "x-keylease-console";

/// Where passkeys are bound: the relying-party ID (host) and the origin.
#[derive(Debug, Clone, Default)]
pub(crate) struct ConsoleConfig {
    relying_party: Option<(String, String)>,
}

impl ConsoleConfig {
    pub(crate) fn from_public_url(url: Option<&str>) -> keylease_core::Result<Self> {
        let Some(url) = url else {
            return Ok(Self::default());
        };
        let parsed = url::Url::parse(url).map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "KEYLEASE_SERVER_PUBLIC_URL must be a URL like https://vault.example.com"
                .into(),
        })?;
        let host = parsed
            .host_str()
            .ok_or_else(|| KeyLeaseError::InvalidRequest {
                reason: "KEYLEASE_SERVER_PUBLIC_URL needs a host".into(),
            })?
            .to_owned();
        if parsed.scheme() != "https" && host != "localhost" {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "KEYLEASE_SERVER_PUBLIC_URL must use https (http only for localhost)"
                    .into(),
            });
        }
        let origin = parsed.origin().ascii_serialization();
        Ok(Self {
            relying_party: Some((host, origin)),
        })
    }

    fn require(&self) -> ApiResult<(&str, &str)> {
        self.relying_party
            .as_ref()
            .map(|(id, origin)| (id.as_str(), origin.as_str()))
            .ok_or_else(|| invalid("passkeys need KEYLEASE_SERVER_PUBLIC_URL on the server"))
    }
}

pub(crate) fn router() -> Router<CloudApiState> {
    Router::new()
        .route("/v1/relay/console-links", post(create_link))
        .route("/v1/console/session", post(exchange_link))
        .route("/v1/console/me", get(me))
        .route("/v1/console/logout", post(logout))
        .route("/v1/console/devices", get(devices))
        .route("/v1/console/devices/{member}", delete(revoke_device))
        .route("/v1/console/passkeys", get(list_passkeys))
        .route("/v1/console/passkeys/{credential}", delete(delete_passkey))
        .route(
            "/v1/console/passkeys/register/options",
            post(register_options),
        )
        .route("/v1/console/passkeys/register", post(register_passkey))
        .route("/v1/console/passkeys/login/options", post(login_options))
        .route("/v1/console/passkeys/login", post(login_passkey))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn random_bytes() -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

pub(crate) fn require_csrf(headers: &HeaderMap) -> ApiResult<()> {
    if headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
        != Some("1")
    {
        return Err(denied("missing x-keylease-console header"));
    }
    Ok(())
}

/// The account of a valid session cookie.
pub(crate) async fn session(state: &CloudApiState, headers: &HeaderMap) -> ApiResult<String> {
    let token = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == SESSION_COOKIE)
        .map(|(_, value)| value.to_owned())
        .ok_or_else(|| denied("not signed in"))?;
    let row = sqlx::query(
        "SELECT account_id FROM console_sessions WHERE session_hash=$1 AND revoked_at IS NULL AND expires_at > now()",
    )
    .bind(sha256_hex(token.as_bytes()))
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .ok_or_else(|| denied("not signed in"))?;
    Ok(row.get("account_id"))
}

/// Starts a session and returns the response that sets its cookie.
async fn start_session(state: &CloudApiState, account_id: &str, via: &str) -> ApiResult<Response> {
    let token = URL_SAFE_NO_PAD.encode(random_bytes());
    let expires_at = Utc::now() + Duration::hours(SESSION_HOURS);
    sqlx::query(
        "INSERT INTO console_sessions(session_hash,account_id,via,created_at,expires_at) VALUES($1,$2,$3,now(),$4)",
    )
    .bind(sha256_hex(token.as_bytes()))
    .bind(account_id)
    .bind(via)
    .bind(expires_at)
    .execute(state.repository.pool())
    .await
    .map_err(storage)?;
    let cookie = format!(
        "{SESSION_COOKIE}={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={}",
        SESSION_HOURS * 3600
    );
    let mut response =
        Json(json!({"account_id": account_id, "expires_at": expires_at})).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(|_| ApiError(KeyLeaseError::Storage))?,
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateLink {
    lookup_hash: String,
    expires_at: DateTime<Utc>,
}

/// Owner device: registers a one-time console sign-in token by its hash.
async fn create_link(
    State(state): State<CloudApiState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let caller: Caller = verify(&state, &method, &uri, &headers, &body).await?;
    if caller.role != RelayRole::Owner {
        return Err(denied("only the owner device signs in to the console"));
    }
    let link: CreateLink = parse(&body)?;
    let ttl = link.expires_at - Utc::now();
    if link.lookup_hash.len() != 64
        || !link
            .lookup_hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || ttl <= Duration::zero()
        || ttl > Duration::minutes(LINK_MAX_MINUTES)
    {
        return Err(invalid("invalid console link"));
    }
    sqlx::query(
        "INSERT INTO console_login_tokens(lookup_hash,account_id,member_id,expires_at) VALUES($1,$2,$3,$4)",
    )
    .bind(link.lookup_hash.to_ascii_lowercase())
    .bind(&caller.account_id)
    .bind(&caller.member_id)
    .bind(link.expires_at)
    .execute(state.repository.pool())
    .await
    .map_err(storage)?;
    Ok(Json(json!({"ok": true, "expires_at": link.expires_at})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeLink {
    token: String,
}

/// Browser: exchanges a device link token, once, for a session.
async fn exchange_link(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    require_csrf(&headers)?;
    let exchange: ExchangeLink = parse(&body)?;
    if exchange.token.len() > 128 {
        return Err(invalid("invalid sign-in link"));
    }
    let row = sqlx::query(
        "UPDATE console_login_tokens SET used_at=now() WHERE lookup_hash=$1 AND used_at IS NULL AND expires_at > now() RETURNING account_id",
    )
    .bind(sha256_hex(exchange.token.as_bytes()))
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .ok_or_else(|| denied("this sign-in link is invalid, used or expired; make a new one"))?;
    let account_id: String = row.get("account_id");
    start_session(&state, &account_id, "device_link").await
}

async fn me(State(state): State<CloudApiState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let account_id = session(&state, &headers).await?;
    let owner = sqlx::query(
        "SELECT m.name FROM relay_accounts a JOIN relay_members m ON m.member_id=a.owner_member_id WHERE a.account_id=$1",
    )
    .bind(&account_id)
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?;
    let passkeys: i64 =
        sqlx::query("SELECT count(*) AS n FROM console_passkeys WHERE account_id=$1")
            .bind(&account_id)
            .fetch_one(state.repository.pool())
            .await
            .map_err(storage)?
            .get("n");
    Ok(Json(json!({
        "account_id": account_id,
        "owner_device": owner.map(|row| row.get::<String, _>("name")),
        "passkeys": passkeys,
        "passkeys_available": state.console.require().is_ok(),
    })))
}

async fn logout(State(state): State<CloudApiState>, headers: HeaderMap) -> ApiResult<Response> {
    require_csrf(&headers)?;
    let account_id = session(&state, &headers).await?;
    let token = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .split(';')
                .filter_map(|pair| pair.trim().split_once('='))
                .find(|(name, _)| *name == SESSION_COOKIE)
                .map(|(_, value)| value.to_owned())
        })
        .unwrap_or_default();
    sqlx::query(
        "UPDATE console_sessions SET revoked_at=now() WHERE session_hash=$1 AND account_id=$2",
    )
    .bind(sha256_hex(token.as_bytes()))
    .bind(&account_id)
    .execute(state.repository.pool())
    .await
    .map_err(storage)?;
    let mut response = Json(json!({"ok": true})).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "kl_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0",
        ),
    );
    Ok(response)
}

async fn devices(State(state): State<CloudApiState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let account_id = session(&state, &headers).await?;
    let rows = sqlx::query(
        "SELECT member_id,role,name,created_at,revoked_at FROM relay_members WHERE account_id=$1 ORDER BY created_at",
    )
    .bind(&account_id)
    .fetch_all(state.repository.pool())
    .await
    .map_err(storage)?;
    Ok(Json(json!({
        "devices": rows.iter().map(|row| json!({
            "member_id": row.get::<String, _>("member_id"),
            "role": row.get::<String, _>("role"),
            "name": row.get::<String, _>("name"),
            "created_at": row.get::<DateTime<Utc>, _>("created_at"),
            "revoked_at": row.get::<Option<DateTime<Utc>>, _>("revoked_at"),
        })).collect::<Vec<_>>()
    })))
}

/// Revokes a node: it can no longer use the relay. The owner device keeps
/// its own state and is never revoked from the console.
async fn revoke_device(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(member): Path<String>,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account_id = session(&state, &headers).await?;
    let changed = sqlx::query(
        "UPDATE relay_members SET revoked_at=now() WHERE member_id=$1 AND account_id=$2 AND role IN ('node','device') AND revoked_at IS NULL",
    )
    .bind(&member)
    .bind(&account_id)
    .execute(state.repository.pool())
    .await
    .map_err(storage)?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError(KeyLeaseError::NotFound {
            resource: format!("node {member}"),
        }));
    }
    Ok(Json(json!({"revoked": member})))
}

async fn list_passkeys(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let account_id = session(&state, &headers).await?;
    let rows = sqlx::query(
        "SELECT credential_id,name,created_at,last_used_at FROM console_passkeys WHERE account_id=$1 ORDER BY created_at",
    )
    .bind(&account_id)
    .fetch_all(state.repository.pool())
    .await
    .map_err(storage)?;
    Ok(Json(json!({
        "passkeys": rows.iter().map(|row| json!({
            "credential_id": row.get::<String, _>("credential_id"),
            "name": row.get::<String, _>("name"),
            "created_at": row.get::<DateTime<Utc>, _>("created_at"),
            "last_used_at": row.get::<Option<DateTime<Utc>>, _>("last_used_at"),
        })).collect::<Vec<_>>()
    })))
}

async fn delete_passkey(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Path(credential): Path<String>,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account_id = session(&state, &headers).await?;
    sqlx::query("DELETE FROM console_passkeys WHERE credential_id=$1 AND account_id=$2")
        .bind(&credential)
        .bind(&account_id)
        .execute(state.repository.pool())
        .await
        .map_err(storage)?;
    Ok(Json(json!({"deleted": credential})))
}

async fn new_challenge(
    state: &CloudApiState,
    account_id: Option<&str>,
    purpose: &str,
) -> ApiResult<[u8; 32]> {
    let challenge = random_bytes();
    sqlx::query("DELETE FROM console_challenges WHERE expires_at < now()")
        .execute(state.repository.pool())
        .await
        .map_err(storage)?;
    sqlx::query(
        "INSERT INTO console_challenges(challenge_hash,account_id,purpose,expires_at) VALUES($1,$2,$3,$4)",
    )
    .bind(sha256_hex(&challenge))
    .bind(account_id)
    .bind(purpose)
    .bind(Utc::now() + Duration::minutes(CHALLENGE_MINUTES))
    .execute(state.repository.pool())
    .await
    .map_err(storage)?;
    Ok(challenge)
}

/// Consumes a challenge named in the client data; returns it and its account.
async fn take_challenge(
    state: &CloudApiState,
    client_data_json: &[u8],
    purpose: &str,
) -> ApiResult<([u8; 32], Option<String>)> {
    let challenge: [u8; 32] = serde_json::from_slice::<Value>(client_data_json)
        .ok()
        .and_then(|data| data["challenge"].as_str().map(str::to_owned))
        .and_then(|value| URL_SAFE_NO_PAD.decode(value.trim_end_matches('=')).ok())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| invalid("invalid passkey response"))?;
    let row = sqlx::query(
        "DELETE FROM console_challenges WHERE challenge_hash=$1 AND purpose=$2 AND expires_at > now() RETURNING account_id",
    )
    .bind(sha256_hex(&challenge))
    .bind(purpose)
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .ok_or_else(|| denied("the passkey challenge expired; try again"))?;
    Ok((challenge, row.get("account_id")))
}

fn b64url(text: &str) -> ApiResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(text.trim_end_matches('='))
        .map_err(|_| invalid("invalid passkey response"))
}

async fn register_options(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account_id = session(&state, &headers).await?;
    let (rp_id, _) = state.console.require()?;
    let challenge = new_challenge(&state, Some(&account_id), "register").await?;
    let existing: Vec<String> =
        sqlx::query("SELECT credential_id FROM console_passkeys WHERE account_id=$1")
            .bind(&account_id)
            .fetch_all(state.repository.pool())
            .await
            .map_err(storage)?
            .iter()
            .map(|row| row.get("credential_id"))
            .collect();
    Ok(Json(json!({
        "challenge": URL_SAFE_NO_PAD.encode(challenge),
        "rp": {"id": rp_id, "name": "KeyLease"},
        "user": {
            "id": URL_SAFE_NO_PAD.encode(Sha256::digest(account_id.as_bytes())),
            "name": format!("KeyLease {}", &account_id[..account_id.len().min(16)]),
            "displayName": "KeyLease",
        },
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "attestation": "none",
        "authenticatorSelection": {"residentKey": "required", "userVerification": "preferred"},
        "excludeCredentials": existing.iter().map(|id| json!({"type": "public-key", "id": id})).collect::<Vec<_>>(),
        "timeout": CHALLENGE_MINUTES * 60_000,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterPasskey {
    client_data_json: String,
    attestation_object: String,
    #[serde(default)]
    name: Option<String>,
}

async fn register_passkey(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account_id = session(&state, &headers).await?;
    let (rp_id, origin) = state.console.require()?;
    let request: RegisterPasskey = parse(&body)?;
    let client_data = b64url(&request.client_data_json)?;
    let (challenge, challenge_account) = take_challenge(&state, &client_data, "register").await?;
    if challenge_account.as_deref() != Some(account_id.as_str()) {
        return Err(denied("the passkey challenge belongs to another session"));
    }
    let registration = webauthn::verify_registration(
        &client_data,
        &b64url(&request.attestation_object)?,
        &challenge,
        origin,
        rp_id,
    )
    .map_err(|error| invalid(format!("passkey not accepted: {error:?}")))?;
    let name = request
        .name
        .map(|name| name.trim().chars().take(64).collect::<String>())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "Passkey".into());
    let credential_id = URL_SAFE_NO_PAD.encode(&registration.credential_id);
    sqlx::query(
        "INSERT INTO console_passkeys(credential_id,account_id,name,public_key_b64,sign_count,created_at) VALUES($1,$2,$3,$4,$5,now())",
    )
    .bind(&credential_id)
    .bind(&account_id)
    .bind(&name)
    .bind(STANDARD.encode(&registration.public_key))
    .bind(i64::from(registration.sign_count))
    .execute(state.repository.pool())
    .await
    .map_err(|_| invalid("this passkey is already registered"))?;
    Ok(Json(json!({"credential_id": credential_id, "name": name})))
}

async fn login_options(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let (rp_id, _) = state.console.require()?;
    let challenge = new_challenge(&state, None, "login").await?;
    Ok(Json(json!({
        "challenge": URL_SAFE_NO_PAD.encode(challenge),
        "rpId": rp_id,
        "userVerification": "preferred",
        "timeout": CHALLENGE_MINUTES * 60_000,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginPasskey {
    credential_id: String,
    client_data_json: String,
    authenticator_data: String,
    signature: String,
}

async fn login_passkey(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    require_csrf(&headers)?;
    let (rp_id, origin) = state.console.require()?;
    let request: LoginPasskey = parse(&body)?;
    let client_data = b64url(&request.client_data_json)?;
    let (challenge, _) = take_challenge(&state, &client_data, "login").await?;
    let row = sqlx::query(
        "SELECT account_id,public_key_b64,sign_count FROM console_passkeys WHERE credential_id=$1",
    )
    .bind(request.credential_id.trim_end_matches('='))
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .ok_or_else(|| denied("unknown passkey"))?;
    let account_id: String = row.get("account_id");
    let public_key = STANDARD
        .decode(row.get::<String, _>("public_key_b64"))
        .map_err(|_| ApiError(KeyLeaseError::Storage))?;
    let stored = u32::try_from(row.get::<i64, _>("sign_count")).unwrap_or(u32::MAX);
    let count = webauthn::verify_assertion(
        &client_data,
        &b64url(&request.authenticator_data)?,
        &b64url(&request.signature)?,
        &public_key,
        stored,
        &challenge,
        origin,
        rp_id,
    )
    .map_err(|_| denied("passkey sign-in failed"))?;
    sqlx::query(
        "UPDATE console_passkeys SET sign_count=$1, last_used_at=now() WHERE credential_id=$2",
    )
    .bind(i64::from(count))
    .bind(request.credential_id.trim_end_matches('='))
    .execute(state.repository.pool())
    .await
    .map_err(storage)?;
    start_session(&state, &account_id, "passkey").await
}
