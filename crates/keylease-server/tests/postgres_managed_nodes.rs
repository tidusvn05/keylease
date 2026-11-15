//! Managed nodes (ADR 0012) against a real PostgreSQL.

use axum::{Router, body::Body, http::Request};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use http_body_util::BodyExt;
use keylease_core::managed::{ManagedPolicy, managed_policy_signing_input};
use keylease_core::relay::{
    HEADER_MEMBER, HEADER_SIGNATURE, HEADER_TIMESTAMP, relay_request_signing_input,
};
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

async fn node(
    app: &Router,
    key: &SigningKey,
    member: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let bytes = body
        .map(|b| serde_json::to_vec(&b).unwrap())
        .unwrap_or_default();
    let timestamp = Utc::now().timestamp();
    let signature = key.sign(&relay_request_signing_input(
        method, path, timestamp, &bytes,
    ));
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header(HEADER_MEMBER, member)
        .header(HEADER_TIMESTAMP, timestamp.to_string())
        .header(HEADER_SIGNATURE, STANDARD.encode(signature.to_bytes()))
        .body(Body::from(bytes))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

fn check_signature(answer: &Value, verifying_key: &str) -> ManagedPolicy {
    let policy = &answer["policy"];
    let key: [u8; 32] = STANDARD_NO_PAD
        .decode(verifying_key)
        .unwrap()
        .try_into()
        .unwrap();
    let signature: [u8; 64] = STANDARD_NO_PAD
        .decode(policy["signature"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let payload = policy["payload"].as_str().unwrap();
    VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify(
            &managed_policy_signing_input(payload),
            &Signature::from_bytes(&signature),
        )
        .unwrap();
    serde_json::from_str(payload).unwrap()
}

#[tokio::test]
async fn an_organization_signs_policy_for_its_managed_nodes() {
    let Some(database_url) = std::env::var("KEYLEASE_TEST_DATABASE_URL").ok() else {
        eprintln!("skipping PostgreSQL managed node test; KEYLEASE_TEST_DATABASE_URL is unset");
        return;
    };
    let repository = CloudRepository::connect(&database_url, 2).await.unwrap();
    repository.migrate().await.unwrap();
    let app = router(
        CloudApiState::new(
            repository.clone(),
            ControlSigner::generate("managed-nodes-test").unwrap(),
            CloudApiConfig {
                admin_token: "managed-nodes-test-administrator-token-32".into(),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let (alice, a) = signed_in(&repository, "alice").await;
    let (_bob, b) = signed_in(&repository, "bob").await;
    let (_, created) = call(
        &app,
        "POST",
        "/v1/orgs",
        &a,
        json!({"name": "Acme", "display_name": "Alice"}),
    )
    .await;
    let org = created["org_id"].as_str().unwrap().to_owned();
    // Alice's VPS, a relay node of her account.
    let member = format!("member_node_{}", uuid::Uuid::now_v7().simple());
    let key = SigningKey::from_bytes(&Sha256::digest(member.as_bytes()).into());
    sqlx::query("INSERT INTO relay_members(member_id,account_id,role,name,sign_public_b64,box_public_b64,created_at) VALUES($1,$2,'node','vps-1',$3,'box',now())")
        .bind(&member).bind(&alice).bind(STANDARD.encode(key.verifying_key().to_bytes()))
        .execute(repository.pool()).await.unwrap();

    // Only owners and admins enroll; a code works once.
    assert_ne!(
        call(
            &app,
            "POST",
            &format!("/v1/orgs/{org}/nodes/enrollments"),
            &b,
            Value::Null
        )
        .await
        .0,
        200
    );
    let (status, enrollment) = call(
        &app,
        "POST",
        &format!("/v1/orgs/{org}/nodes/enrollments"),
        &a,
        Value::Null,
    )
    .await;
    assert_eq!(status, 200, "{enrollment:?}");
    let code = enrollment["code"].as_str().unwrap().to_owned();
    assert!(code.starts_with("klnode_"));
    assert_eq!(
        node(
            &app,
            &key,
            &member,
            "POST",
            "/v1/relay/org-nodes/join",
            Some(json!({"code": "klnode_wrong"}))
        )
        .await
        .0,
        403
    );
    let (status, joined) = node(
        &app,
        &key,
        &member,
        "POST",
        "/v1/relay/org-nodes/join",
        Some(json!({"code": code})),
    )
    .await;
    assert_eq!(status, 200, "{joined:?}");
    assert_eq!(joined["org_id"], org.as_str());
    assert_eq!(joined["org_name"], "Acme");
    let verifying_key = joined["verifying_key"].as_str().unwrap().to_owned();
    assert_eq!(
        node(
            &app,
            &key,
            &member,
            "POST",
            "/v1/relay/org-nodes/join",
            Some(json!({"code": code}))
        )
        .await
        .0,
        403
    );

    // No policy yet.
    let (_, empty) = node(&app, &key, &member, "GET", "/v1/relay/org-policy", None).await;
    assert_eq!(empty["policy"], Value::Null);

    // Managed rules only tighten.
    let policy_path = format!("/v1/orgs/{org}/node-policy");
    assert_eq!(
        call(
            &app,
            "PUT",
            &policy_path,
            &a,
            json!({"rules": [{"id": "open", "effect": "allow", "actions": ["entry:read_secret"]}]})
        )
        .await
        .0,
        400
    );
    let (status, set) = call(
        &app,
        "PUT",
        &policy_path,
        &a,
        json!({"rules": [
            {"id": "no-delete", "effect": "deny", "actions": ["entry:delete"]},
            {"id": "ask-secrets", "effect": "require_approval", "actions": ["entry:read_secret"]},
        ]}),
    )
    .await;
    assert_eq!(status, 200, "{set:?}");
    assert_eq!(set["version"], 1);

    let (_, answer) = node(&app, &key, &member, "GET", "/v1/relay/org-policy", None).await;
    let policy = check_signature(&answer, &verifying_key);
    assert_eq!(policy.org_id, org);
    assert_eq!(policy.version, 1);
    assert_eq!(policy.rules.len(), 2);
    assert!(policy.only_tightens());
    assert_eq!(
        node(
            &app,
            &key,
            &member,
            "PUT",
            "/v1/relay/org-policy/applied",
            Some(json!({"version": 1}))
        )
        .await
        .0,
        200
    );
    let (_, listed) = call(
        &app,
        "GET",
        &format!("/v1/orgs/{org}/nodes"),
        &a,
        Value::Null,
    )
    .await;
    assert_eq!(listed["nodes"][0]["name"], "vps-1");
    assert_eq!(listed["nodes"][0]["applied_version"], 1);
    assert_eq!(listed["policy"]["version"], 1);
    assert_eq!(listed["policy"]["rules"][1]["id"], "ask-secrets");

    // Close to expiry, the server signs the same rules again.
    sqlx::query("UPDATE org_node_policies SET expires_at=now() + interval '1 day' WHERE org_id=$1")
        .bind(&org)
        .execute(repository.pool())
        .await
        .unwrap();
    let (_, renewed) = node(&app, &key, &member, "GET", "/v1/relay/org-policy", None).await;
    let renewed = check_signature(&renewed, &verifying_key);
    assert_eq!(renewed.version, 2);
    assert_eq!(renewed.rules, policy.rules);
    assert!(renewed.expires_at > Utc::now() + chrono::Duration::days(29));

    // A removed node no longer gets the policy.
    assert_eq!(
        call(
            &app,
            "DELETE",
            &format!("/v1/orgs/{org}/nodes/{member}"),
            &a,
            Value::Null
        )
        .await
        .0,
        200
    );
    assert_eq!(
        node(&app, &key, &member, "GET", "/v1/relay/org-policy", None)
            .await
            .0,
        404
    );
}
