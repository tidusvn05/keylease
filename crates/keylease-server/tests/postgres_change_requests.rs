//! Change requests for protected environments (v2 plan, step 14) on PostgreSQL.

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
async fn protected_environments_need_another_admins_approval() {
    let Some(database_url) = std::env::var("KEYLEASE_TEST_DATABASE_URL").ok() else {
        eprintln!("skipping PostgreSQL change request test; KEYLEASE_TEST_DATABASE_URL is unset");
        return;
    };
    let repository = CloudRepository::connect(&database_url, 2).await.unwrap();
    repository.migrate().await.unwrap();
    let app = router(
        CloudApiState::new(
            repository.clone(),
            ControlSigner::generate("change-test").unwrap(),
            CloudApiConfig {
                admin_token: "change-test-administrator-token-at-least-32".into(),
                kms_root_key: Some([7_u8; 32]),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let (_alice, a) = signed_in(&repository, "alice").await;
    let (bob, b) = signed_in(&repository, "bob").await;
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
    let (_, invite) = call(
        &app,
        "POST",
        &format!("/v1/orgs/{org}/invites"),
        &a,
        json!({"role": "member"}),
    )
    .await;
    call(
        &app,
        "POST",
        "/v1/orgs/join",
        &b,
        json!({"code": invite["code"], "display_name": "Bob"}),
    )
    .await;
    call(
        &app,
        "PUT",
        &format!("/v1/orgs/{org}/projects/shop/access/{bob}"),
        &a,
        json!({"role": "write"}),
    )
    .await;
    let base = format!("/v1/orgs/{org}/projects/shop");

    // dev is not protected: Bob's change applies at once.
    let (_, dev) = call(
        &app,
        "PUT",
        &format!("{base}/secrets/dev/API_KEY"),
        &b,
        json!({"value": "dev-1"}),
    )
    .await;
    assert_eq!(dev["version"], 1);
    // production is: it waits, and nothing is stored yet.
    let (status, proposed) = call(
        &app,
        "PUT",
        &format!("{base}/secrets/production/API_KEY"),
        &b,
        json!({"value": "prod-1"}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(proposed["status"], "pending");
    let request = proposed["change_request_id"].as_str().unwrap().to_owned();
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("{base}/secrets/production/API_KEY"),
            &a,
            Value::Null
        )
        .await
        .0,
        404
    );
    let (_, pending) = call(
        &app,
        "GET",
        &format!("{base}/change-requests"),
        &b,
        Value::Null,
    )
    .await;
    assert_eq!(pending["change_requests"][0]["name"], "API_KEY");
    assert!(
        !pending.to_string().contains("prod-1"),
        "pending values are not listed"
    );

    // Bob cannot approve (not an admin); Alice can, and the change is Bob's.
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("{base}/change-requests/{request}/approve"),
            &b,
            Value::Null
        )
        .await
        .0,
        403
    );
    let (status, approved) = call(
        &app,
        "POST",
        &format!("{base}/change-requests/{request}/approve"),
        &a,
        Value::Null,
    )
    .await;
    assert_eq!(status, 200, "{approved:?}");
    let (_, revealed) = call(
        &app,
        "GET",
        &format!("{base}/secrets/production/API_KEY"),
        &a,
        Value::Null,
    )
    .await;
    assert_eq!(revealed["value"], "prod-1");
    let (_, listed) = call(
        &app,
        "GET",
        &format!("{base}/secrets?environment=production"),
        &a,
        Value::Null,
    )
    .await;
    assert_eq!(listed["secrets"][0]["updated_by"], bob.as_str());
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("{base}/change-requests/{request}/approve"),
            &a,
            Value::Null
        )
        .await
        .0,
        404,
        "decided once"
    );

    // A rejected deletion leaves the secret.
    let (_, proposed) = call(
        &app,
        "DELETE",
        &format!("{base}/secrets/production/API_KEY"),
        &b,
        Value::Null,
    )
    .await;
    let request = proposed["change_request_id"].as_str().unwrap().to_owned();
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("{base}/change-requests/{request}/reject"),
            &a,
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
            &format!("{base}/secrets/production/API_KEY"),
            &a,
            Value::Null
        )
        .await
        .0,
        200
    );

    // Nobody approves their own change, even after becoming an admin.
    let (_, proposed) = call(
        &app,
        "PUT",
        &format!("{base}/secrets/production/API_KEY"),
        &b,
        json!({"value": "prod-2"}),
    )
    .await;
    let request = proposed["change_request_id"].as_str().unwrap().to_owned();
    call(
        &app,
        "PUT",
        &format!("/v1/orgs/{org}/members/{bob}"),
        &a,
        json!({"role": "admin"}),
    )
    .await;
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("{base}/change-requests/{request}/approve"),
            &b,
            Value::Null
        )
        .await
        .0,
        403
    );
    // Admins change protected environments directly.
    let (_, direct) = call(
        &app,
        "PUT",
        &format!("{base}/secrets/production/OTHER"),
        &b,
        json!({"value": "x"}),
    )
    .await;
    assert_eq!(direct["version"], 1);
}
