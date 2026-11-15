//! Web Push for the console: a browser that subscribed is told when a node
//! reports a new pending approval (ADR 0011).
//!
//! Messages are encrypted for the browser (RFC 8291, `aes128gcm`), so the push
//! service only carries ciphertext, and the server identifies itself with a
//! VAPID key (RFC 8292) that it generates on first use. A message names the
//! node, the agent and the action, never an item or a secret.

use crate::api::{ApiResult, CloudApiState};
use crate::console::{require_csrf, session};
use crate::relay::{invalid, parse, storage};
use aes_gcm::{Aes128Gcm, KeyInit, aead::Aead};
use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use hkdf::Hkdf;
use p256::{
    PublicKey, SecretKey,
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::sec1::ToEncodedPoint,
};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::{PgPool, Row};

/// Subscriptions one account may keep (browsers and devices).
const MAX_SUBSCRIPTIONS: i64 = 20;
/// How long a push service keeps an undelivered message.
const TTL_SECONDS: u32 = 600;
/// The record size announced in the `aes128gcm` header.
const RECORD_SIZE: u32 = 4096;

pub(crate) fn router() -> Router<CloudApiState> {
    Router::new()
        .route("/v1/console/push/key", get(public_key))
        .route(
            "/v1/console/push/subscriptions",
            post(subscribe).delete(unsubscribe),
        )
}

// ---------------------------------------------------------------------------
// Encryption (RFC 8291) and VAPID (RFC 8292)
// ---------------------------------------------------------------------------

/// Encrypts `plaintext` for a subscription, as one `aes128gcm` record.
/// `sender` and `salt` are fresh for every message; they are parameters so the
/// RFC 8291 test vector can be checked.
pub(crate) fn encrypt(
    browser_public: &[u8],
    auth_secret: &[u8],
    plaintext: &[u8],
    sender: &SecretKey,
    salt: [u8; 16],
) -> Option<Vec<u8>> {
    let browser = PublicKey::from_sec1_bytes(browser_public).ok()?;
    let browser_bytes = browser.to_encoded_point(false);
    let sender_public = sender.public_key().to_encoded_point(false);
    let shared = p256::ecdh::diffie_hellman(sender.to_nonzero_scalar(), browser.as_affine());
    // IKM = HKDF(auth_secret, ecdh_secret, "WebPush: info\0" || ua_public || as_public, 32)
    let mut info = b"WebPush: info\0".to_vec();
    info.extend_from_slice(browser_bytes.as_bytes());
    info.extend_from_slice(sender_public.as_bytes());
    let mut ikm = [0_u8; 32];
    Hkdf::<Sha256>::new(Some(auth_secret), shared.raw_secret_bytes())
        .expand(&info, &mut ikm)
        .ok()?;
    let content = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut key = [0_u8; 16];
    let mut nonce = [0_u8; 12];
    content
        .expand(b"Content-Encoding: aes128gcm\0", &mut key)
        .ok()?;
    content
        .expand(b"Content-Encoding: nonce\0", &mut nonce)
        .ok()?;
    let mut record = plaintext.to_vec();
    // The last (and only) record ends with the padding delimiter 2.
    record.push(2);
    let sealed = Aes128Gcm::new_from_slice(&key)
        .ok()?
        .encrypt(&nonce.into(), record.as_slice())
        .ok()?;
    let mut body = salt.to_vec();
    body.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    body.push(65);
    body.extend_from_slice(sender_public.as_bytes());
    body.extend_from_slice(&sealed);
    Some(body)
}

/// The `Authorization` header for a push service (`vapid t=…, k=…`).
fn vapid_authorization(key: &SigningKey, endpoint: &str, subject: &str) -> Option<String> {
    let audience = url::Url::parse(endpoint)
        .ok()?
        .origin()
        .ascii_serialization();
    let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "aud": audience,
            "exp": Utc::now().timestamp() + 12 * 3600,
            "sub": subject,
        }))
        .ok()?,
    );
    let signing_input = format!("{header}.{claims}");
    let signature: Signature = key.sign(signing_input.as_bytes());
    let public = key.verifying_key().to_encoded_point(false);
    Some(format!(
        "vapid t={signing_input}.{}, k={}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        URL_SAFE_NO_PAD.encode(public.as_bytes())
    ))
}

/// The server's VAPID key, made on first use.
async fn vapid_key(pool: &PgPool) -> ApiResult<SigningKey> {
    let mut scalar = [0_u8; 32];
    loop {
        rand::rng().fill_bytes(&mut scalar);
        if SigningKey::from_slice(&scalar).is_ok() {
            break;
        }
    }
    sqlx::query(
        "INSERT INTO console_settings(name,value) VALUES('web_push_vapid_key',$1) ON CONFLICT (name) DO NOTHING",
    )
    .bind(URL_SAFE_NO_PAD.encode(scalar))
    .execute(pool)
    .await
    .map_err(storage)?;
    let stored: String =
        sqlx::query("SELECT value FROM console_settings WHERE name='web_push_vapid_key'")
            .fetch_one(pool)
            .await
            .map_err(storage)?
            .get("value");
    URL_SAFE_NO_PAD
        .decode(stored)
        .ok()
        .and_then(|bytes| SigningKey::from_slice(&bytes).ok())
        .ok_or_else(|| invalid("the stored Web Push key is malformed"))
}

// ---------------------------------------------------------------------------
// Console endpoints
// ---------------------------------------------------------------------------

/// The `applicationServerKey` browsers subscribe with.
async fn public_key(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    session(&state, &headers).await?;
    let key = vapid_key(state.repository.pool()).await?;
    Ok(Json(json!({
        "key": URL_SAFE_NO_PAD.encode(key.verifying_key().to_encoded_point(false).as_bytes()),
    })))
}

#[derive(Deserialize)]
struct SubscriptionKeys {
    p256dh: String,
    auth: String,
}

#[derive(Deserialize)]
struct Subscribe {
    endpoint: String,
    keys: SubscriptionKeys,
    #[serde(default)]
    name: Option<String>,
}

/// A push service endpoint: HTTPS on a named host. The server posts to it, so
/// addresses on the server's own network are refused.
fn valid_endpoint(endpoint: &str) -> bool {
    let Ok(url) = url::Url::parse(endpoint) else {
        return false;
    };
    let named_host = matches!(url.host(), Some(url::Host::Domain(host))
        if host.contains('.') && !host.eq_ignore_ascii_case("localhost") && !host.ends_with(".local") && !host.ends_with(".internal"));
    url.scheme() == "https" && named_host && endpoint.len() <= 1024
}

async fn subscribe(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account_id = session(&state, &headers).await?;
    let request: Subscribe = parse(&body)?;
    if !valid_endpoint(&request.endpoint) {
        return Err(invalid("not a push service endpoint"));
    }
    let browser = URL_SAFE_NO_PAD
        .decode(request.keys.p256dh.trim_end_matches('='))
        .ok()
        .filter(|key| PublicKey::from_sec1_bytes(key).is_ok());
    let auth = URL_SAFE_NO_PAD
        .decode(request.keys.auth.trim_end_matches('='))
        .ok()
        .filter(|auth| auth.len() == 16);
    let (Some(browser), Some(auth)) = (browser, auth) else {
        return Err(invalid("malformed subscription keys"));
    };
    let pool = state.repository.pool();
    let count: i64 = sqlx::query(
        "SELECT count(*) AS n FROM console_push_subscriptions WHERE account_id=$1 AND endpoint<>$2",
    )
    .bind(&account_id)
    .bind(&request.endpoint)
    .fetch_one(pool)
    .await
    .map_err(storage)?
    .get("n");
    if count >= MAX_SUBSCRIPTIONS {
        return Err(invalid(
            "too many notification subscriptions; remove one first",
        ));
    }
    let name: String = request
        .name
        .unwrap_or_else(|| "browser".into())
        .chars()
        .take(80)
        .collect();
    sqlx::query(
        "INSERT INTO console_push_subscriptions(endpoint,account_id,p256dh,auth,name,created_at) VALUES($1,$2,$3,$4,$5,now()) \
         ON CONFLICT (endpoint) DO UPDATE SET account_id=EXCLUDED.account_id, p256dh=EXCLUDED.p256dh, auth=EXCLUDED.auth, name=EXCLUDED.name",
    )
    .bind(&request.endpoint)
    .bind(&account_id)
    .bind(URL_SAFE_NO_PAD.encode(browser))
    .bind(URL_SAFE_NO_PAD.encode(auth))
    .bind(name)
    .execute(pool)
    .await
    .map_err(storage)?;
    Ok(Json(json!({"ok": true})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Unsubscribe {
    endpoint: String,
}

async fn unsubscribe(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account_id = session(&state, &headers).await?;
    let request: Unsubscribe = parse(&body)?;
    let removed =
        sqlx::query("DELETE FROM console_push_subscriptions WHERE endpoint=$1 AND account_id=$2")
            .bind(&request.endpoint)
            .bind(&account_id)
            .execute(state.repository.pool())
            .await
            .map_err(storage)?
            .rows_affected();
    Ok(Json(json!({"removed": removed})))
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

/// Posts one encrypted message. Returns the push service's status code.
async fn deliver(
    http: &reqwest::Client,
    vapid: &SigningKey,
    subject: &str,
    endpoint: &str,
    browser_public: &[u8],
    auth: &[u8],
    message: &[u8],
) -> Option<u16> {
    let sender = SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let mut salt = [0_u8; 16];
    rand::rng().fill_bytes(&mut salt);
    let body = encrypt(browser_public, auth, message, &sender, salt)?;
    let response = http
        .post(endpoint)
        .header("TTL", TTL_SECONDS.to_string())
        .header("Content-Encoding", "aes128gcm")
        .header("Content-Type", "application/octet-stream")
        .header("Urgency", "high")
        .header(
            "Authorization",
            vapid_authorization(vapid, endpoint, subject)?,
        )
        .body(body)
        .send()
        .await
        .ok()?;
    Some(response.status().as_u16())
}

/// Tells every subscribed browser of the account about new pending approvals.
/// Runs in the background; a subscription the push service no longer knows is
/// removed.
pub(crate) fn notify_account(pool: PgPool, subject: String, account_id: String, message: Value) {
    tokio::spawn(async move {
        let Ok(rows) = sqlx::query(
            "SELECT endpoint,p256dh,auth FROM console_push_subscriptions WHERE account_id=$1",
        )
        .bind(&account_id)
        .fetch_all(&pool)
        .await
        else {
            return;
        };
        if rows.is_empty() {
            return;
        }
        let Ok(vapid) = vapid_key(&pool).await else {
            return;
        };
        let Ok(http) = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
        else {
            return;
        };
        let message = message.to_string();
        for row in rows {
            let endpoint: String = row.get("endpoint");
            let keys = (
                URL_SAFE_NO_PAD.decode(row.get::<String, _>("p256dh")),
                URL_SAFE_NO_PAD.decode(row.get::<String, _>("auth")),
            );
            let (Ok(browser), Ok(auth)) = keys else {
                continue;
            };
            let status = deliver(
                &http,
                &vapid,
                &subject,
                &endpoint,
                &browser,
                &auth,
                message.as_bytes(),
            )
            .await;
            match status {
                Some(404 | 410) => {
                    let _ = sqlx::query("DELETE FROM console_push_subscriptions WHERE endpoint=$1")
                        .bind(&endpoint)
                        .execute(&pool)
                        .await;
                }
                Some(status) if (200..300).contains(&status) => {
                    let _ = sqlx::query(
                        "UPDATE console_push_subscriptions SET last_used_at=now() WHERE endpoint=$1",
                    )
                    .bind(&endpoint)
                    .execute(&pool)
                    .await;
                }
                other => tracing::warn!(?other, "web push delivery failed"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(text: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(text).unwrap()
    }

    /// RFC 8291, appendix A.
    #[test]
    fn encryption_matches_the_rfc_8291_example() {
        let sender =
            SecretKey::from_slice(&b64("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")).unwrap();
        let salt: [u8; 16] = b64("DGv6ra1nlYgDCS1FRnbzlw").try_into().unwrap();
        let body = encrypt(
            &b64("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"),
            &b64("BTBZMqHH6r4Tts7J_aSIgg"),
            b"When I grow up, I want to be a watermelon",
            &sender,
            salt,
        )
        .unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(body),
            "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
        );
    }

    #[test]
    fn the_vapid_token_is_a_valid_es256_jwt_for_the_push_origin() {
        let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let header = vapid_authorization(
            &key,
            "https://push.example.net/send/abc",
            "https://vault.example.com",
        )
        .unwrap();
        let token = header
            .strip_prefix("vapid t=")
            .and_then(|rest| rest.split(", k=").next())
            .unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        let claims: Value = serde_json::from_slice(&b64(parts[1])).unwrap();
        assert_eq!(claims["aud"], "https://push.example.net");
        let signature = Signature::from_slice(&b64(parts[2])).unwrap();
        use p256::ecdsa::signature::Verifier;
        key.verifying_key()
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .unwrap();
    }

    #[test]
    fn only_public_https_endpoints_are_accepted() {
        assert!(valid_endpoint("https://fcm.googleapis.com/fcm/send/abc"));
        assert!(valid_endpoint(
            "https://updates.push.services.mozilla.com/wpush/v2/x"
        ));
        assert!(!valid_endpoint("http://fcm.googleapis.com/fcm/send/abc"));
        assert!(!valid_endpoint("https://127.0.0.1/push"));
        assert!(!valid_endpoint("https://[::1]/push"));
        assert!(!valid_endpoint("https://localhost/push"));
        assert!(!valid_endpoint("https://intranet/push"));
        assert!(!valid_endpoint("https://db.internal/push"));
    }

    /// The browser's side of RFC 8291, to check what `deliver` sends.
    fn decrypt(browser: &SecretKey, auth: &[u8], body: &[u8]) -> Vec<u8> {
        let salt = &body[..16];
        assert_eq!(
            u32::from_be_bytes(body[16..20].try_into().unwrap()),
            RECORD_SIZE
        );
        assert_eq!(body[20], 65);
        let sender = PublicKey::from_sec1_bytes(&body[21..86]).unwrap();
        let shared = p256::ecdh::diffie_hellman(browser.to_nonzero_scalar(), sender.as_affine());
        let mut info = b"WebPush: info\0".to_vec();
        info.extend_from_slice(browser.public_key().to_encoded_point(false).as_bytes());
        info.extend_from_slice(sender.to_encoded_point(false).as_bytes());
        let mut ikm = [0_u8; 32];
        Hkdf::<Sha256>::new(Some(auth), shared.raw_secret_bytes())
            .expand(&info, &mut ikm)
            .unwrap();
        let content = Hkdf::<Sha256>::new(Some(salt), &ikm);
        let (mut key, mut nonce) = ([0_u8; 16], [0_u8; 12]);
        content
            .expand(b"Content-Encoding: aes128gcm\0", &mut key)
            .unwrap();
        content
            .expand(b"Content-Encoding: nonce\0", &mut nonce)
            .unwrap();
        let mut plain = Aes128Gcm::new_from_slice(&key)
            .unwrap()
            .decrypt(&nonce.into(), &body[86..])
            .unwrap();
        assert_eq!(plain.pop(), Some(2));
        plain
    }

    #[tokio::test]
    async fn a_delivered_message_opens_in_the_browser() {
        use std::sync::{Arc, Mutex};
        let received: Arc<Mutex<Option<(HeaderMap, Bytes)>>> = Arc::default();
        let sink = received.clone();
        let app = Router::new().route(
            "/push/abc",
            post(move |headers: HeaderMap, body: Bytes| {
                let sink = sink.clone();
                async move {
                    *sink.lock().unwrap() = Some((headers, body));
                    axum::http::StatusCode::CREATED
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let browser = SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let auth = [9_u8; 16];
        let vapid = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let status = deliver(
            &reqwest::Client::new(),
            &vapid,
            "https://vault.example.com",
            &format!("http://{address}/push/abc"),
            browser.public_key().to_encoded_point(false).as_bytes(),
            &auth,
            br#"{"kind":"approval"}"#,
        )
        .await;
        assert_eq!(status, Some(201));
        let (headers, body) = received.lock().unwrap().take().unwrap();
        assert_eq!(headers["content-encoding"], "aes128gcm");
        assert_eq!(headers["ttl"], "600");
        assert!(
            headers["authorization"]
                .to_str()
                .unwrap()
                .starts_with("vapid t=")
        );
        assert_eq!(decrypt(&browser, &auth, &body), br#"{"kind":"approval"}"#);
    }
}
