//! Enterprise features (v2 plan, step 19): KMS API, audit export, SCIM.

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

async fn raw(
    app: &Router,
    method: &str,
    path: &str,
    auth: (&str, &str),
    body: Value,
) -> (u16, String, Option<String>) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header(auth.0, auth.1)
        .body(Body::from(if body.is_null() {
            vec![]
        } else {
            serde_json::to_vec(&body).unwrap()
        }))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let next = response
        .headers()
        .get("x-keylease-next")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
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
    (status, text, next)
}

#[tokio::test]
async fn kms_keys_audit_export_and_scim_deprovisioning() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let Some(database_url) = std::env::var("KEYLEASE_TEST_DATABASE_URL").ok() else {
        eprintln!("skipping PostgreSQL enterprise test; KEYLEASE_TEST_DATABASE_URL is unset");
        return;
    };
    let repository = CloudRepository::connect(&database_url, 2).await.unwrap();
    repository.migrate().await.unwrap();
    let app = router(
        CloudApiState::new(
            repository.clone(),
            ControlSigner::generate("enterprise-test").unwrap(),
            CloudApiConfig {
                admin_token: "enterprise-test-administrator-token-at-least".into(),
                kms_root_key: Some([4_u8; 32]),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let (alice, a) = signed_in(&repository, "alice").await;
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
    let base = format!("/v1/orgs/{org}/projects/shop/kms/keys");

    // Encrypt, rotate, and the old ciphertext still decrypts.
    assert_eq!(
        call(
            &app,
            "POST",
            &base,
            &a,
            json!({"name": "data", "purpose": "encrypt"})
        )
        .await
        .0,
        200
    );
    let plaintext = STANDARD.encode(b"card 4242");
    let (_, sealed) = call(
        &app,
        "POST",
        &format!("{base}/data/encrypt"),
        &a,
        json!({"plaintext": plaintext, "context": "order-1"}),
    )
    .await;
    let ciphertext = sealed["ciphertext"].as_str().unwrap().to_owned();
    assert!(ciphertext.starts_with("kl:v1:"));
    call(
        &app,
        "POST",
        &format!("{base}/data/rotate"),
        &a,
        Value::Null,
    )
    .await;
    let (_, newer) = call(
        &app,
        "POST",
        &format!("{base}/data/encrypt"),
        &a,
        json!({"plaintext": plaintext}),
    )
    .await;
    assert!(newer["ciphertext"].as_str().unwrap().starts_with("kl:v2:"));
    let (_, opened) = call(
        &app,
        "POST",
        &format!("{base}/data/decrypt"),
        &a,
        json!({"ciphertext": ciphertext, "context": "order-1"}),
    )
    .await;
    assert_eq!(opened["plaintext"], plaintext);
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("{base}/data/decrypt"),
            &a,
            json!({"ciphertext": ciphertext, "context": "other"})
        )
        .await
        .0,
        400
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("{base}/data/sign"),
            &a,
            json!({"message": plaintext})
        )
        .await
        .0,
        400,
        "wrong purpose"
    );

    // Sign and MAC keys.
    call(
        &app,
        "POST",
        &base,
        &a,
        json!({"name": "release", "purpose": "sign"}),
    )
    .await;
    let message = STANDARD.encode(b"v1.2.3");
    let (_, signed) = call(
        &app,
        "POST",
        &format!("{base}/release/sign"),
        &a,
        json!({"message": message}),
    )
    .await;
    let (_, verified) = call(
        &app,
        "POST",
        &format!("{base}/release/verify"),
        &a,
        json!({"message": message, "signature": signed["signature"]}),
    )
    .await;
    assert_eq!(verified["valid"], true);
    let (_, tampered) = call(
        &app,
        "POST",
        &format!("{base}/release/verify"),
        &a,
        json!({"message": STANDARD.encode(b"v9"), "signature": signed["signature"]}),
    )
    .await;
    assert_eq!(tampered["valid"], false);
    call(
        &app,
        "POST",
        &base,
        &a,
        json!({"name": "webhook", "purpose": "mac"}),
    )
    .await;
    let (_, mac) = call(
        &app,
        "POST",
        &format!("{base}/webhook/mac"),
        &a,
        json!({"message": message}),
    )
    .await;
    let (_, checked) = call(
        &app,
        "POST",
        &format!("{base}/webhook/verify"),
        &a,
        json!({"message": message, "mac": mac["mac"]}),
    )
    .await;
    assert_eq!(checked["valid"], true);

    // A machine identity of the project uses the KMS API too.
    let (_, identity) = call(&app, "POST", &format!("/v1/orgs/{org}/projects/shop/machine-identities"), &a, json!({
        "name": "worker", "environment": "staging", "issuer": "http://127.0.0.1:1", "audience": "keylease", "subject": "job"
    })).await;
    let identity = identity["identity_id"].as_str().unwrap().to_owned();
    let (_, key) = call(
        &app,
        "POST",
        &format!("/v1/orgs/{org}/projects/shop/machine-identities/{identity}/keys"),
        &a,
        json!({}),
    )
    .await;
    let bearer = format!("Bearer {}", key["key"].as_str().unwrap());
    let (status, by_machine, _) = raw(
        &app,
        "POST",
        "/v1/machine/kms/data/decrypt",
        ("authorization", &bearer),
        json!({"ciphertext": ciphertext, "context": "order-1"}),
    )
    .await;
    assert_eq!(status, 200, "{by_machine}");
    assert!(by_machine.contains(&plaintext));

    // Audit export: JSON Lines with a cursor, or syslog.
    let (status, lines, next) = raw(
        &app,
        "GET",
        &format!("/v1/orgs/{org}/audit/export?limit=3"),
        ("cookie", &a),
        Value::Null,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(lines.lines().count(), 3);
    let first: Value = serde_json::from_str(lines.lines().next().unwrap()).unwrap();
    assert_eq!(first["action"], "kms_key_create");
    let (_, rest, _) = raw(
        &app,
        "GET",
        &format!("/v1/orgs/{org}/audit/export?after={}", next.unwrap()),
        ("cookie", &a),
        Value::Null,
    )
    .await;
    assert!(rest.contains("machine:") && rest.contains("kms_decrypt"));
    let (_, syslog, _) = raw(
        &app,
        "GET",
        &format!("/v1/orgs/{org}/audit/export?format=syslog&limit=1"),
        ("cookie", &a),
        Value::Null,
    )
    .await;
    assert!(syslog.starts_with("<110>1 "), "{syslog}");

    // SCIM: an identity provider lists members and deprovisions Bob.
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
    let (_, scim) = call(
        &app,
        "POST",
        &format!("/v1/orgs/{org}/scim-tokens"),
        &a,
        Value::Null,
    )
    .await;
    let scim_bearer = format!("Bearer {}", scim["token"].as_str().unwrap());
    let (_, users, _) = raw(
        &app,
        "GET",
        &format!("/scim/v2/orgs/{org}/Users"),
        ("authorization", &scim_bearer),
        Value::Null,
    )
    .await;
    let users: Value = serde_json::from_str(&users).unwrap();
    assert_eq!(users["totalResults"], 2);
    let (status, _, _) = raw(
        &app,
        "PATCH",
        &format!("/scim/v2/orgs/{org}/Users/{bob}"),
        ("authorization", &scim_bearer),
        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "value": {"active": false}}]
        }),
    )
    .await;
    assert_eq!(status, 204);
    assert_eq!(
        call(&app, "GET", &format!("/v1/orgs/{org}"), &b, Value::Null)
            .await
            .0,
        404
    );
    assert_eq!(
        raw(
            &app,
            "DELETE",
            &format!("/scim/v2/orgs/{org}/Users/{alice}"),
            ("authorization", &scim_bearer),
            Value::Null
        )
        .await
        .0,
        400,
        "the last owner stays"
    );
    assert_eq!(
        raw(
            &app,
            "GET",
            &format!("/scim/v2/orgs/{org}/Users"),
            ("authorization", "Bearer wrong"),
            Value::Null
        )
        .await
        .0,
        403
    );
}
