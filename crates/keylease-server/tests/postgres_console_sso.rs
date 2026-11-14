//! Console single sign-on (v2 plan, step 14) against a fake OpenID Connect
//! provider on loopback and a real PostgreSQL.

use axum::{
    Form, Json, Router,
    body::Body,
    extract::State,
    http::Request,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use keylease_protocol::ControlSigner;
use keylease_server::{CloudApiConfig, CloudApiState, CloudRepository, ConsoleOidc, router};
use p256::pkcs8::EncodePrivateKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

/// code → (subject, nonce, code_challenge)
type Codes = Arc<Mutex<HashMap<String, (String, String, String)>>>;

#[derive(Clone)]
struct Provider {
    issuer: String,
    key: Arc<p256::ecdsa::SigningKey>,
    codes: Codes,
}

async fn discovery(State(provider): State<Provider>) -> Json<Value> {
    Json(json!({
        "issuer": provider.issuer,
        "authorization_endpoint": format!("{}/authorize", provider.issuer),
        "token_endpoint": format!("{}/token", provider.issuer),
        "jwks_uri": format!("{}/jwks", provider.issuer),
    }))
}

async fn jwks(State(provider): State<Provider>) -> Json<Value> {
    let point = provider.key.verifying_key().to_encoded_point(false);
    Json(json!({"keys": [{
        "kty": "EC", "crv": "P-256", "kid": "test-key", "alg": "ES256", "use": "sig",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    }]}))
}

async fn token(
    State(provider): State<Provider>,
    Form(form): Form<HashMap<String, String>>,
) -> Json<Value> {
    let (subject, nonce, challenge) = provider
        .codes
        .lock()
        .unwrap()
        .remove(&form["code"])
        .expect("known code");
    // PKCE: the verifier must hash to the challenge sent at /authorize.
    assert_eq!(
        URL_SAFE_NO_PAD.encode(Sha256::digest(form["code_verifier"].as_bytes())),
        challenge
    );
    assert_eq!(form["client_id"], "keylease-console");
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("test-key".into());
    let der = provider.key.to_pkcs8_der().unwrap();
    let id_token = encode(
        &header,
        &json!({
            "iss": provider.issuer, "aud": "keylease-console", "sub": subject,
            "email": format!("{subject}@example.com"), "nonce": nonce,
            "exp": chrono::Utc::now().timestamp() + 300, "iat": chrono::Utc::now().timestamp(),
        }),
        &EncodingKey::from_ec_der(der.as_bytes()),
    )
    .unwrap();
    Json(json!({"id_token": id_token, "token_type": "Bearer"}))
}

async fn send(
    app: &Router,
    uri: &str,
    cookie: Option<&str>,
) -> (u16, Option<String>, Option<String>) {
    let mut request = Request::builder().uri(uri);
    if let Some(cookie) = cookie {
        request = request.header("cookie", cookie);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let location = header("location");
    let cookie =
        header("set-cookie").map(|value| value.split(';').next().unwrap_or_default().to_owned());
    (response.status().as_u16(), location, cookie)
}

/// Plays the provider's login: returns the callback URL for `subject`.
fn authorize(provider: &Provider, location: &str, subject: &str) -> String {
    let url = url::Url::parse(location).unwrap();
    let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(query["code_challenge_method"], "S256");
    let code = format!("code-{subject}-{}", uuid::Uuid::now_v7().simple());
    provider.codes.lock().unwrap().insert(
        code.clone(),
        (
            subject.to_owned(),
            query["nonce"].clone(),
            query["code_challenge"].clone(),
        ),
    );
    format!(
        "/v1/console/sso/callback?code={code}&state={}",
        query["state"]
    )
}

#[tokio::test]
async fn single_sign_on_links_an_identity_then_signs_in_with_it() {
    let Some(database_url) = std::env::var("KEYLEASE_TEST_DATABASE_URL").ok() else {
        eprintln!("skipping PostgreSQL SSO test; KEYLEASE_TEST_DATABASE_URL is unset");
        return;
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let provider = Provider {
        issuer: issuer.clone(),
        key: Arc::new(p256::ecdsa::SigningKey::random(
            &mut p256::elliptic_curve::rand_core::OsRng,
        )),
        codes: Arc::default(),
    };
    let idp = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/token", post(token))
        .with_state(provider.clone());
    tokio::spawn(async move { axum::serve(listener, idp).await.unwrap() });

    let repository = CloudRepository::connect(&database_url, 2).await.unwrap();
    repository.migrate().await.unwrap();
    let app = router(
        CloudApiState::new(
            repository.clone(),
            ControlSigner::generate("sso-test").unwrap(),
            CloudApiConfig {
                admin_token: "sso-test-administrator-token-at-least-32-bytes".into(),
                public_url: Some("https://vault.example.com/api".into()),
                oidc: Some(ConsoleOidc {
                    issuer: issuer.clone(),
                    client_id: "keylease-console".into(),
                    client_secret: Some("secret".into()),
                    allowed_email_domains: vec!["example.com".into()],
                }),
                ..Default::default()
            },
        )
        .unwrap(),
    );

    // An account with a console session (as after a device link).
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let account = format!("acct_sso_{suffix}");
    let pool = repository.pool();
    sqlx::query("INSERT INTO relay_accounts(account_id,owner_member_id,recovery_lookup_hash,recovery_kit,created_at) VALUES($1,$2,$3,'{}',now())")
        .bind(&account).bind(format!("member_{suffix}")).bind(format!("{:x}", Sha256::digest(account.as_bytes())))
        .execute(pool).await.unwrap();
    let token = format!("token-{suffix}");
    sqlx::query("INSERT INTO console_sessions(session_hash,account_id,via,created_at,expires_at) VALUES($1,$2,'device_link',now(),now() + interval '1 hour')")
        .bind(format!("{:x}", Sha256::digest(token.as_bytes()))).bind(&account)
        .execute(pool).await.unwrap();
    let session = format!("kl_session={token}");
    let subject = format!("user-{suffix}");

    // An identity nobody linked signs nobody in.
    let (status, location, _) = send(&app, "/v1/console/sso/start", None).await;
    assert_eq!(status, 303);
    let (_, back, cookie) = send(
        &app,
        &authorize(&provider, &location.unwrap(), &subject),
        None,
    )
    .await;
    assert_eq!(
        back.as_deref(),
        Some("https://vault.example.com/api/console/#sso=unlinked")
    );
    assert!(cookie.is_none());

    // Linking needs a session; then the identity signs the account in.
    assert_eq!(
        send(&app, "/v1/console/sso/start?link=1", None).await.0,
        403
    );
    let (_, location, _) = send(&app, "/v1/console/sso/start?link=1", Some(&session)).await;
    let (status, back, cookie) = send(
        &app,
        &authorize(&provider, &location.unwrap(), &subject),
        None,
    )
    .await;
    assert_eq!(
        (status, back.as_deref()),
        (303, Some("https://vault.example.com/api/console/"))
    );
    assert!(cookie.is_some());

    let (_, location, _) = send(&app, "/v1/console/sso/start", None).await;
    let callback = authorize(&provider, &location.unwrap(), &subject);
    let (_, _, cookie) = send(&app, &callback, None).await;
    let cookie = cookie.expect("signed in by SSO");
    let me = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/console/me")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let me: Value =
        serde_json::from_slice(&me.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(me["account_id"], account.as_str());
    // A state works once.
    assert_eq!(send(&app, &callback, None).await.0, 403);
}
