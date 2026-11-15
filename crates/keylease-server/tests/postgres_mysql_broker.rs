//! Dynamic MySQL logins and their reaper, against a real PostgreSQL (the
//! server) and a real MySQL 8 (`KEYLEASE_TEST_MYSQL_URL`, an admin URL such as
//! `mysql://root:root@127.0.0.1:3306/mysql`).

use axum::{Router, body::Body, http::Request};
use http_body_util::BodyExt;
use keylease_protocol::ControlSigner;
use keylease_server::{CloudApiConfig, CloudApiState, CloudRepository, router};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Connection;
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
async fn machines_get_expiring_mysql_logins() {
    let (Some(database_url), Some(mysql_url)) = (
        std::env::var("KEYLEASE_TEST_DATABASE_URL").ok(),
        std::env::var("KEYLEASE_TEST_MYSQL_URL").ok(),
    ) else {
        eprintln!(
            "skipping MySQL broker test; KEYLEASE_TEST_DATABASE_URL or KEYLEASE_TEST_MYSQL_URL is unset"
        );
        return;
    };
    let mut admin = sqlx::MySqlConnection::connect(&mysql_url).await.unwrap();
    sqlx::raw_sql("CREATE ROLE IF NOT EXISTS kl_test_readers; GRANT SELECT ON mysql.help_topic TO kl_test_readers")
        .execute(&mut admin)
        .await
        .unwrap();
    let repository = CloudRepository::connect(&database_url, 2).await.unwrap();
    repository.migrate().await.unwrap();
    let state = CloudApiState::new(
        repository.clone(),
        ControlSigner::generate("mysql-broker-test").unwrap(),
        CloudApiConfig {
            admin_token: "broker-test-administrator-token-at-least-32".into(),
            kms_root_key: Some([4_u8; 32]),
            ..Default::default()
        },
    )
    .unwrap();
    let app = router(state.clone());
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
        &format!("{base}/secrets/staging/MYSQL_ADMIN"),
        &a,
        json!({"value": mysql_url}),
    )
    .await;
    // A PostgreSQL URL is not a MySQL admin secret.
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
            &format!("{base}/dynamic/mysql/wrong"),
            &a,
            json!({"admin_secret": "PG_ADMIN", "grant_role": "kl_test_readers"})
        )
        .await
        .0,
        200
    );
    let (status, configured) = call(&app, "PUT", &format!("{base}/dynamic/mysql/main"), &a,
        json!({"admin_secret": "MYSQL_ADMIN", "grant_role": "kl_test_readers", "max_ttl_seconds": 600})).await;
    assert_eq!(status, 200, "{configured:?}");
    let (_, listed) = call(
        &app,
        "GET",
        &format!("{base}/dynamic/mysql"),
        &a,
        Value::Null,
    )
    .await;
    assert_eq!(listed["mysql"].as_array().unwrap().len(), 2);
    let (_, identity) = call(&app, "POST", &format!("{base}/machine-identities"), &a, json!({
        "name": "jobs", "environment": "staging", "issuer": "http://127.0.0.1:1", "audience": "keylease", "subject": "job"
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
    let issue = |name: &str| {
        Request::builder()
            .method("POST")
            .uri(format!("/v1/machine/dynamic/mysql/{name}"))
            .header("authorization", &bearer)
            .body(Body::from(r#"{"ttl_seconds": 120}"#))
            .unwrap()
    };
    assert_eq!(
        app.clone()
            .oneshot(issue("wrong"))
            .await
            .unwrap()
            .status()
            .as_u16(),
        400
    );
    let response = app.clone().oneshot(issue("main")).await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let login: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let user = login["username"].as_str().unwrap().to_owned();
    assert_eq!(login["engine"], "mysql");
    assert_eq!(login["port"], 3306);

    // The login works and has the granted role by default.
    let mut connection = sqlx::MySqlConnection::connect(login["url"].as_str().unwrap())
        .await
        .unwrap();
    let roles: (String,) = sqlx::query_as("SELECT CAST(CURRENT_ROLE() AS CHAR)")
        .fetch_one(&mut connection)
        .await
        .unwrap();
    assert!(roles.0.contains("kl_test_readers"), "{roles:?}");

    // Expired: the reaper ends the session and drops the user.
    sqlx::query("UPDATE managed_dynamic_leases SET expires_at=now() - interval '1 second' WHERE role_name=$1")
        .bind(&user)
        .execute(repository.pool())
        .await
        .unwrap();
    let (dropped, _) = keylease_server::reap_expired_logins(&state).await;
    assert!(dropped >= 1);
    assert!(
        sqlx::query("SELECT 1")
            .execute(&mut connection)
            .await
            .is_err()
    );
    let left: Vec<(String,)> =
        sqlx::query_as("SELECT CAST(user AS CHAR) FROM mysql.user WHERE user = ?")
            .bind(&user)
            .fetch_all(&mut admin)
            .await
            .unwrap();
    assert!(left.is_empty());
    let (_, leases) = call(
        &app,
        "GET",
        &format!("{base}/dynamic/leases"),
        &a,
        Value::Null,
    )
    .await;
    let lease = leases["leases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["username"] == user.as_str())
        .unwrap();
    assert!(lease["revoked_at"].is_string(), "{lease:?}");
}
