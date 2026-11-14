//! Organizations, roles and project access (v2 plan, step 12) on PostgreSQL.

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
async fn organizations_roles_and_project_access() {
    let Some(database_url) = std::env::var("KEYLEASE_TEST_DATABASE_URL").ok() else {
        eprintln!("skipping PostgreSQL teams test; KEYLEASE_TEST_DATABASE_URL is unset");
        return;
    };
    let repository = CloudRepository::connect(&database_url, 2).await.unwrap();
    repository.migrate().await.unwrap();
    let app = router(
        CloudApiState::new(
            repository.clone(),
            ControlSigner::generate("teams-test").unwrap(),
            CloudApiConfig {
                admin_token: "teams-test-administrator-token-at-least-32b".into(),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let (alice, a) = signed_in(&repository, "alice").await;
    let (bob, b) = signed_in(&repository, "bob").await;

    let (status, created) = call(
        &app,
        "POST",
        "/v1/orgs",
        &a,
        json!({"name": "Acme", "display_name": "Alice"}),
    )
    .await;
    assert_eq!(status, 200, "{created:?}");
    let org = created["org_id"].as_str().unwrap().to_owned();
    // Bob is not a member: the organization does not exist for him.
    assert_eq!(
        call(&app, "GET", &format!("/v1/orgs/{org}"), &b, Value::Null)
            .await
            .0,
        404
    );

    let (_, invite) = call(
        &app,
        "POST",
        &format!("/v1/orgs/{org}/invites"),
        &a,
        json!({"role": "member"}),
    )
    .await;
    let code = invite["code"].as_str().unwrap().to_owned();
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/orgs/join",
            &b,
            json!({"code": code, "display_name": "Bob"})
        )
        .await
        .0,
        200
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/orgs/join",
            &b,
            json!({"code": code, "display_name": "Bob"})
        )
        .await
        .0,
        403,
        "single use"
    );

    // Projects: created by managers, visible to members only when granted.
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("/v1/orgs/{org}/projects"),
            &b,
            json!({"slug": "evil", "name": "x"})
        )
        .await
        .0,
        403
    );
    let (status, project) = call(
        &app,
        "POST",
        &format!("/v1/orgs/{org}/projects"),
        &a,
        json!({"slug": "shop", "name": "Shop"}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(project["environments"][2]["slug"], "production");
    let projects = |body: &Value| body["projects"].as_array().unwrap().len();
    assert_eq!(
        projects(
            &call(&app, "GET", &format!("/v1/orgs/{org}"), &b, Value::Null)
                .await
                .1
        ),
        0
    );
    assert_eq!(
        call(
            &app,
            "PUT",
            &format!("/v1/orgs/{org}/projects/shop/access/{bob}"),
            &a,
            json!({"role": "write"})
        )
        .await
        .0,
        200
    );
    let (_, seen) = call(&app, "GET", &format!("/v1/orgs/{org}"), &b, Value::Null).await;
    assert_eq!(seen["projects"][0]["my_role"], "write");
    assert!(
        seen["projects"][0]["access"].as_array().unwrap().is_empty(),
        "members do not see grants"
    );
    // A member cannot grant, invite or promote.
    assert_eq!(
        call(
            &app,
            "PUT",
            &format!("/v1/orgs/{org}/projects/shop/access/{bob}"),
            &b,
            json!({"role": "admin"})
        )
        .await
        .0,
        403
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("/v1/orgs/{org}/invites"),
            &b,
            json!({"role": "viewer"})
        )
        .await
        .0,
        403
    );
    assert_eq!(
        call(
            &app,
            "PUT",
            &format!("/v1/orgs/{org}/members/{bob}"),
            &b,
            json!({"role": "owner"})
        )
        .await
        .0,
        403
    );

    // A viewer reads at most, whatever the grant says.
    assert_eq!(
        call(
            &app,
            "PUT",
            &format!("/v1/orgs/{org}/members/{bob}"),
            &a,
            json!({"role": "viewer"})
        )
        .await
        .0,
        200
    );
    let (_, seen) = call(&app, "GET", &format!("/v1/orgs/{org}"), &b, Value::Null).await;
    assert_eq!(seen["projects"][0]["my_role"], "read");

    // The last owner cannot leave or step down.
    assert_eq!(
        call(
            &app,
            "PUT",
            &format!("/v1/orgs/{org}/members/{alice}"),
            &a,
            json!({"role": "admin"})
        )
        .await
        .0,
        400
    );
    assert_eq!(
        call(
            &app,
            "DELETE",
            &format!("/v1/orgs/{org}/members/{alice}"),
            &a,
            Value::Null
        )
        .await
        .0,
        400
    );
    // Bob leaves; his access goes with him.
    assert_eq!(
        call(
            &app,
            "DELETE",
            &format!("/v1/orgs/{org}/members/{bob}"),
            &b,
            Value::Null
        )
        .await
        .0,
        200
    );
    assert_eq!(
        call(&app, "GET", &format!("/v1/orgs/{org}"), &b, Value::Null)
            .await
            .0,
        404
    );
    let (_, listed) = call(&app, "GET", "/v1/orgs", &a, Value::Null).await;
    assert!(
        listed["orgs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["org_id"] == org.as_str() && o["role"] == "owner")
    );
}
