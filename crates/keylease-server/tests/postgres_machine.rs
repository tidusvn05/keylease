//! Machine identities (v2 plan, step 15): a CI job's OIDC token, from a fake
//! issuer on loopback, buys a short-lived token that reads one environment.

use axum::{Json, Router, body::Body, extract::State, http::Request, routing::get};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use keylease_protocol::ControlSigner;
use keylease_server::{CloudApiConfig, CloudApiState, CloudRepository, router};
use p256::pkcs8::EncodePrivateKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tower::ServiceExt;

#[derive(Clone)]
struct Issuer {
    url: String,
    key: Arc<p256::ecdsa::SigningKey>,
}

impl Issuer {
    fn token(&self, audience: &str, subject: &str) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("ci".into());
        let now = chrono::Utc::now().timestamp();
        encode(
            &header,
            &json!({"iss": self.url, "aud": audience, "sub": subject, "iat": now, "exp": now + 300}),
            &EncodingKey::from_ec_der(self.key.to_pkcs8_der().unwrap().as_bytes()),
        )
        .unwrap()
    }
}

async fn discovery(State(issuer): State<Issuer>) -> Json<Value> {
    Json(json!({"issuer": issuer.url, "jwks_uri": format!("{}/jwks", issuer.url)}))
}

async fn jwks(State(issuer): State<Issuer>) -> Json<Value> {
    let point = issuer.key.verifying_key().to_encoded_point(false);
    Json(
        json!({"keys": [{"kty": "EC", "crv": "P-256", "kid": "ci", "alg": "ES256",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()), "y": URL_SAFE_NO_PAD.encode(point.y().unwrap())}]}),
    )
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    auth: (&str, &str),
    body: Value,
) -> (u16, Value) {
    let bytes = if body.is_null() {
        vec![]
    } else {
        serde_json::to_vec(&body).unwrap()
    };
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("x-keylease-console", "1")
        .header(auth.0, auth.1)
        .body(Body::from(bytes))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn a_ci_job_reads_its_environment_with_its_oidc_token() {
    let Some(database_url) = std::env::var("KEYLEASE_TEST_DATABASE_URL").ok() else {
        eprintln!("skipping PostgreSQL machine identity test; KEYLEASE_TEST_DATABASE_URL is unset");
        return;
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = Issuer {
        url: format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port()),
        key: Arc::new(p256::ecdsa::SigningKey::random(
            &mut p256::elliptic_curve::rand_core::OsRng,
        )),
    };
    let fake = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .with_state(issuer.clone());
    tokio::spawn(async move { axum::serve(listener, fake).await.unwrap() });

    let repository = CloudRepository::connect(&database_url, 2).await.unwrap();
    repository.migrate().await.unwrap();
    let app = router(
        CloudApiState::new(
            repository.clone(),
            ControlSigner::generate("machine-test").unwrap(),
            CloudApiConfig {
                admin_token: "machine-test-administrator-token-at-least-32".into(),
                kms_root_key: Some([9_u8; 32]),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    // An organization owner with a console session.
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let account = format!("acct_ci_{suffix}");
    let pool = repository.pool();
    sqlx::query("INSERT INTO relay_accounts(account_id,owner_member_id,recovery_lookup_hash,recovery_kit,created_at) VALUES($1,$2,$3,'{}',now())")
        .bind(&account).bind(format!("member_{suffix}")).bind(format!("{:x}", Sha256::digest(account.as_bytes())))
        .execute(pool).await.unwrap();
    let token = format!("token-{suffix}");
    sqlx::query("INSERT INTO console_sessions(session_hash,account_id,via,created_at,expires_at) VALUES($1,$2,'device_link',now(),now() + interval '1 hour')")
        .bind(format!("{:x}", Sha256::digest(token.as_bytes()))).bind(&account)
        .execute(pool).await.unwrap();
    let cookie = format!("kl_session={token}");
    let owner = ("cookie", cookie.as_str());
    let (_, org) = call(
        &app,
        "POST",
        "/v1/orgs",
        owner,
        json!({"name": "Acme", "display_name": "Ann"}),
    )
    .await;
    let org = org["org_id"].as_str().unwrap().to_owned();
    call(
        &app,
        "POST",
        &format!("/v1/orgs/{org}/projects"),
        owner,
        json!({"slug": "shop", "name": "Shop"}),
    )
    .await;
    let base = format!("/v1/orgs/{org}/projects/shop");
    call(
        &app,
        "PUT",
        &format!("{base}/secrets/staging/DATABASE_URL"),
        owner,
        json!({"value": "postgres://staging"}),
    )
    .await;
    call(
        &app,
        "PUT",
        &format!("{base}/secrets/production/DATABASE_URL"),
        owner,
        json!({"value": "postgres://prod"}),
    )
    .await;

    assert_eq!(
        call(&app, "POST", &format!("{base}/machine-identities"), owner, json!({
            "name": "everything", "environment": "staging", "issuer": issuer.url, "audience": "keylease", "subject": "*"
        })).await.0,
        400
    );
    let (status, created) = call(
        &app,
        "POST",
        &format!("{base}/machine-identities"),
        owner,
        json!({
            "name": "GitHub main", "environment": "staging", "issuer": issuer.url,
            "audience": "keylease", "subject": "repo:acme/shop:ref:refs/heads/*",
        }),
    )
    .await;
    assert_eq!(status, 200, "{created:?}");
    let identity = created["identity_id"].as_str().unwrap().to_owned();
    let exchange = |jwt: String| json!({"identity_id": identity, "token": jwt});
    let none = ("x-none", "1");

    // Wrong subject, wrong audience: refused.
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/machine/token",
            none,
            exchange(issuer.token("keylease", "repo:evil/shop:ref:refs/heads/main"))
        )
        .await
        .0,
        403
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/machine/token",
            none,
            exchange(issuer.token("other", "repo:acme/shop:ref:refs/heads/main"))
        )
        .await
        .0,
        403
    );
    let (status, granted) = call(
        &app,
        "POST",
        "/v1/machine/token",
        none,
        exchange(issuer.token("keylease", "repo:acme/shop:ref:refs/heads/main")),
    )
    .await;
    assert_eq!(status, 200, "{granted:?}");
    let bearer = format!("Bearer {}", granted["access_token"].as_str().unwrap());
    let (status, read) = call(
        &app,
        "GET",
        "/v1/machine/secrets",
        ("authorization", &bearer),
        Value::Null,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(read["environment"], "staging");
    assert_eq!(
        read["secrets"]["DATABASE_URL"], "postgres://staging",
        "only its own environment"
    );

    // An access key (for the External Secrets Operator) reads the same environment.
    let (status, key) = call(
        &app,
        "POST",
        &format!("{base}/machine-identities/{identity}/keys"),
        owner,
        json!({"days": 30}),
    )
    .await;
    assert_eq!(status, 200, "{key:?}");
    let key_bearer = format!("Bearer {}", key["key"].as_str().unwrap());
    let (_, by_key) = call(
        &app,
        "GET",
        "/v1/machine/secrets",
        ("authorization", &key_bearer),
        Value::Null,
    )
    .await;
    assert_eq!(by_key["secrets"]["DATABASE_URL"], "postgres://staging");
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("{base}/machine-identities/{identity}/keys"),
            owner,
            json!({"days": 999})
        )
        .await
        .0,
        400
    );

    // Revoking the identity ends its tokens and keys.
    assert_eq!(
        call(
            &app,
            "DELETE",
            &format!("{base}/machine-identities/{identity}"),
            owner,
            Value::Null
        )
        .await
        .0,
        200
    );
    assert_eq!(
        call(
            &app,
            "GET",
            "/v1/machine/secrets",
            ("authorization", &bearer),
            Value::Null
        )
        .await
        .0,
        403
    );
}
