//! Server-side brokers (v2 plan, step 18): dynamic PostgreSQL logins and the
//! gateway's base-URL proxy.

use axum::{Router, body::Body, http::Request};
use http_body_util::BodyExt;
use keylease_protocol::ControlSigner;
use keylease_server::{CloudApiConfig, CloudApiState, CloudRepository, router};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

async fn call(app: &Router, method: &str, path: &str, cookie: &str, body: Value) -> (u16, Value) {
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
        .header("cookie", cookie)
        .body(Body::from(bytes))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// An account signed in to the console: its id and session cookie.
async fn signed_in(repository: &CloudRepository, name: &str) -> (String, String) {
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let account = format!("acct_{name}_{suffix}");
    let member = format!("member_{name}_{suffix}");
    let pool = repository.pool();
    sqlx::query("INSERT INTO relay_accounts(account_id,owner_member_id,recovery_lookup_hash,recovery_kit,created_at) VALUES($1,$2,$3,'{}',now())")
        .bind(&account).bind(&member).bind(format!("{:x}", Sha256::digest(account.as_bytes())))
        .execute(pool).await.unwrap();
    sqlx::query("INSERT INTO relay_members(member_id,account_id,role,name,sign_public_b64,box_public_b64,created_at) VALUES($1,$2,'owner',$3,$4,'box',now())")
        .bind(&member).bind(&account).bind(name).bind(format!("sign-{suffix}"))
        .execute(pool).await.unwrap();
    let token = format!("token-{suffix}");
    sqlx::query("INSERT INTO console_sessions(session_hash,account_id,via,created_at,expires_at) VALUES($1,$2,'device_link',now(),now() + interval '1 hour')")
        .bind(format!("{:x}", Sha256::digest(token.as_bytes()))).bind(&account)
        .execute(pool).await.unwrap();
    (account, format!("kl_session={token}"))
}

#[tokio::test]
async fn machines_get_expiring_postgres_logins_and_gateway_clients_a_base_url() {
    let Some(database_url) = std::env::var("KEYLEASE_TEST_DATABASE_URL").ok() else {
        eprintln!("skipping PostgreSQL broker test; KEYLEASE_TEST_DATABASE_URL is unset");
        return;
    };
    let repository = CloudRepository::connect(&database_url, 2).await.unwrap();
    repository.migrate().await.unwrap();
    sqlx::raw_sql("DO $$ BEGIN CREATE ROLE kl_test_readers NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$")
        .execute(repository.pool())
        .await
        .unwrap();
    let app = router(
        CloudApiState::new(
            repository.clone(),
            ControlSigner::generate("broker-test").unwrap(),
            CloudApiConfig {
                admin_token: "broker-test-administrator-token-at-least-32".into(),
                kms_root_key: Some([3_u8; 32]),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let (_alice, a) = signed_in(&repository, "alice").await;
    let (_, created) = call(
        &app,
        "POST",
        "/v1/orgs",
        &a,
        json!({"name": "Acme", "display_name": "Alice"}),
    )
    .await;
    let org = created["org_id"].as_str().unwrap().to_owned();
    call(
        &app,
        "POST",
        &format!("/v1/orgs/{org}/projects"),
        &a,
        json!({"slug": "shop", "name": "Shop"}),
    )
    .await;
    let base = format!("/v1/orgs/{org}/projects/shop");
    call(
        &app,
        "PUT",
        &format!("{base}/secrets/staging/PG_ADMIN"),
        &a,
        json!({"value": database_url}),
    )
    .await;
    assert_eq!(
        call(
            &app,
            "PUT",
            &format!("{base}/dynamic/postgres/main"),
            &a,
            json!({"admin_secret": "PG_ADMIN", "grant_role": "bad role"})
        )
        .await
        .0,
        400
    );
    assert_eq!(call(&app, "PUT", &format!("{base}/dynamic/postgres/main"), &a, json!({"admin_secret": "PG_ADMIN", "grant_role": "kl_test_readers", "max_ttl_seconds": 600})).await.0, 200);
    let (_, identity) = call(&app, "POST", &format!("{base}/machine-identities"), &a, json!({
        "name": "migrations", "environment": "staging", "issuer": "http://127.0.0.1:1", "audience": "keylease", "subject": "job"
    })).await;
    let identity = identity["identity_id"].as_str().unwrap().to_owned();
    let (_, key) = call(
        &app,
        "POST",
        &format!("{base}/machine-identities/{identity}/keys"),
        &a,
        json!({}),
    )
    .await;
    let bearer = format!("Bearer {}", key["key"].as_str().unwrap());

    let request = Request::builder()
        .method("POST")
        .uri("/v1/machine/dynamic/postgres/main")
        .header("authorization", &bearer)
        .body(Body::from(r#"{"ttl_seconds": 120}"#))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let login: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let role = login["username"].as_str().unwrap().to_owned();
    assert!(role.starts_with("kl_"));
    // The new login works, is a member of the granted role and expires.
    use sqlx::Connection;
    let mut connection = sqlx::PgConnection::connect(login["url"].as_str().unwrap())
        .await
        .unwrap();
    let who: (String, bool) = sqlx::query_as(
        "SELECT current_user::text, pg_has_role(current_user, 'kl_test_readers', 'member')",
    )
    .fetch_one(&mut connection)
    .await
    .unwrap();
    assert_eq!(who, (role.clone(), true));
    connection.close().await.unwrap();
    let until: (Option<chrono::DateTime<chrono::Utc>>,) =
        sqlx::query_as("SELECT rolvaliduntil FROM pg_roles WHERE rolname=$1")
            .bind(&role)
            .fetch_one(repository.pool())
            .await
            .unwrap();
    let left = until.0.unwrap() - chrono::Utc::now();
    assert!(
        left > chrono::Duration::seconds(60) && left <= chrono::Duration::seconds(125),
        "{left:?}"
    );
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP ROLE \"{role}\"")))
        .execute(repository.pool())
        .await
        .unwrap();

    // The gateway's base-URL proxy (needs the network for a public API).
    if std::env::var("KEYLEASE_TEST_NETWORK").is_ok() {
        call(
            &app,
            "PUT",
            &format!("{base}/secrets/staging/ECHO"),
            &a,
            json!({"value": "proxy-secret-987654321"}),
        )
        .await;
        call(
            &app,
            "PUT",
            &format!("{base}/http-bindings/echo"),
            &a,
            json!({"base_url": "https://httpbin.org", "secret_name": "ECHO"}),
        )
        .await;
        let (_, client) = call(
            &app,
            "POST",
            &format!("/v1/orgs/{org}/gateway/clients"),
            &a,
            json!({
                "name": "sdk", "grants": [{"project": "shop", "environment": "staging"}]
            }),
        )
        .await;
        let request = Request::builder()
            .uri(format!(
                "/v1/orgs/{org}/gateway/http/shop/staging/echo/anything?x=1"
            ))
            .header("x-keylease-token", client["token"].as_str().unwrap())
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status().as_u16(), 200);
        let text = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(
            text.contains("[REDACTED by keylease]") && !text.contains("proxy-secret-987654321"),
            "{text}"
        );
        assert!(
            !text.contains("klgw_"),
            "the gateway token is not forwarded: {text}"
        );
    }
}
