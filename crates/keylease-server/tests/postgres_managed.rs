//! Managed projects (v2 plan, step 13) on PostgreSQL.

use axum::{Router, body::Body, http::Request};
use http_body_util::BodyExt;
use keylease_protocol::ControlSigner;
use keylease_server::{CloudApiConfig, CloudApiState, CloudRepository, router};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
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
async fn managed_secrets_are_encrypted_versioned_and_role_checked() {
    let Some(database_url) = std::env::var("KEYLEASE_TEST_DATABASE_URL").ok() else {
        eprintln!("skipping PostgreSQL managed test; KEYLEASE_TEST_DATABASE_URL is unset");
        return;
    };
    let repository = CloudRepository::connect(&database_url, 2).await.unwrap();
    repository.migrate().await.unwrap();
    let app = |kms: Option<[u8; 32]>| {
        router(
            CloudApiState::new(
                repository.clone(),
                ControlSigner::generate("managed-test").unwrap(),
                CloudApiConfig {
                    admin_token: "managed-test-administrator-token-at-least-32".into(),
                    kms_root_key: kms,
                    ..Default::default()
                },
            )
            .unwrap(),
        )
    };
    let without_kms = app(None);
    let app = app(Some([42_u8; 32]));
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
    let base = format!("/v1/orgs/{org}/projects/shop");

    assert_eq!(
        call(
            &without_kms,
            "PUT",
            &format!("{base}/secrets/production/STRIPE_KEY"),
            &a,
            json!({"value": "x"})
        )
        .await
        .0,
        400
    );
    let (status, set) = call(
        &app,
        "PUT",
        &format!("{base}/secrets/production/STRIPE_KEY"),
        &a,
        json!({"value": "sk_live_1"}),
    )
    .await;
    assert_eq!(status, 200, "{set:?}");
    assert_eq!(
        call(
            &app,
            "PUT",
            &format!("{base}/secrets/qa/X"),
            &a,
            json!({"value": "x"})
        )
        .await
        .0,
        400,
        "unknown environment"
    );
    assert_eq!(
        call(
            &app,
            "PUT",
            &format!("{base}/secrets/production/bad-name"),
            &a,
            json!({"value": "x"})
        )
        .await
        .0,
        400
    );
    // Stored encrypted.
    let stored: String = sqlx::query(
        "SELECT ciphertext_json FROM managed_secrets WHERE org_id=$1 AND name='STRIPE_KEY'",
    )
    .bind(&org)
    .fetch_one(repository.pool())
    .await
    .unwrap()
    .get::<Option<String>, _>("ciphertext_json")
    .unwrap();
    assert!(!stored.contains("sk_live_1"));

    // Bob has no access until granted; read lets him reveal but not write.
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("{base}/secrets?environment=production"),
            &b,
            Value::Null
        )
        .await
        .0,
        404
    );
    call(
        &app,
        "PUT",
        &format!("/v1/orgs/{org}/projects/shop/access/{bob}"),
        &a,
        json!({"role": "read"}),
    )
    .await;
    let (_, listed) = call(
        &app,
        "GET",
        &format!("{base}/secrets?environment=production"),
        &b,
        Value::Null,
    )
    .await;
    assert_eq!(listed["secrets"][0]["name"], "STRIPE_KEY");
    assert!(
        listed.to_string().find("sk_live_1").is_none(),
        "listing has no values"
    );
    let (_, revealed) = call(
        &app,
        "GET",
        &format!("{base}/secrets/production/STRIPE_KEY"),
        &b,
        Value::Null,
    )
    .await;
    assert_eq!(revealed["value"], "sk_live_1");
    assert_eq!(
        call(
            &app,
            "PUT",
            &format!("{base}/secrets/production/STRIPE_KEY"),
            &b,
            json!({"value": "evil"})
        )
        .await
        .0,
        403
    );

    // Versions, delete, restore; rotation keeps old versions readable.
    call(
        &app,
        "PUT",
        &format!("{base}/secrets/production/STRIPE_KEY"),
        &a,
        json!({"value": "sk_live_2"}),
    )
    .await;
    assert_eq!(
        call(&app, "POST", &format!("{base}/rotate-key"), &b, Value::Null)
            .await
            .0,
        403
    );
    let (_, rotated) = call(&app, "POST", &format!("{base}/rotate-key"), &a, Value::Null).await;
    assert_eq!(rotated["key_version"], 2);
    call(
        &app,
        "PUT",
        &format!("{base}/secrets/production/STRIPE_KEY"),
        &a,
        json!({"value": "sk_live_3"}),
    )
    .await;
    assert_eq!(
        call(
            &app,
            "DELETE",
            &format!("{base}/secrets/production/STRIPE_KEY"),
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
            &format!("{base}/secrets/production/STRIPE_KEY"),
            &a,
            Value::Null
        )
        .await
        .0,
        404
    );
    let (_, history) = call(
        &app,
        "GET",
        &format!("{base}/secrets/production/STRIPE_KEY/versions"),
        &a,
        Value::Null,
    )
    .await;
    assert_eq!(history["versions"].as_array().unwrap().len(), 4);
    let (status, restored) = call(
        &app,
        "POST",
        &format!("{base}/secrets/production/STRIPE_KEY/restore"),
        &a,
        json!({"version": 1}),
    )
    .await;
    assert_eq!(status, 200, "{restored:?}");
    let (_, revealed) = call(
        &app,
        "GET",
        &format!("{base}/secrets/production/STRIPE_KEY"),
        &a,
        Value::Null,
    )
    .await;
    assert_eq!(
        revealed["value"], "sk_live_1",
        "version 1 was written under key version 1"
    );
    call(
        &app,
        "PUT",
        &format!("{base}/secrets/production/DATABASE_URL"),
        &a,
        json!({"value": "postgres://u:\"p\"@db/x"}),
    )
    .await;

    let export = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("{base}/export?environment=production"))
                .header("cookie", &b)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let text = String::from_utf8(
        export
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(text.contains("STRIPE_KEY=\"sk_live_1\"\n"), "{text}");
    assert!(
        text.contains(r#"DATABASE_URL="postgres://u:\"p\"@db/x""#),
        "{text}"
    );

    let (_, audit) = call(&app, "GET", &format!("{base}/audit"), &a, Value::Null).await;
    let actions: Vec<String> = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap().to_owned())
        .collect();
    for action in ["set", "reveal", "delete", "restore", "rotate_key", "export"] {
        assert!(
            actions.iter().any(|known| known == action),
            "{action} in {actions:?}"
        );
    }
}
