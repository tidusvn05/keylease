//! The MCP Gateway (v2 plan, step 17) on PostgreSQL.

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

async fn mcp(app: &Router, org: &str, token: &str, body: Value) -> (u16, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(format!("/v1/orgs/{org}/mcp"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

fn tool(name: &str, arguments: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": name, "arguments": arguments}})
}

#[tokio::test]
async fn gateway_clients_call_granted_apis_without_seeing_credentials() {
    let Some(database_url) = std::env::var("KEYLEASE_TEST_DATABASE_URL").ok() else {
        eprintln!("skipping PostgreSQL gateway test; KEYLEASE_TEST_DATABASE_URL is unset");
        return;
    };
    let repository = CloudRepository::connect(&database_url, 2).await.unwrap();
    repository.migrate().await.unwrap();
    let app = router(
        CloudApiState::new(
            repository.clone(),
            ControlSigner::generate("gateway-test").unwrap(),
            CloudApiConfig {
                admin_token: "gateway-test-administrator-token-at-least-32".into(),
                kms_root_key: Some([5_u8; 32]),
                public_url: Some("https://vault.example.com/api".into()),
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
        &format!("{base}/secrets/staging/ECHO_TOKEN"),
        &a,
        json!({"value": "test-secret-0123456789"}),
    )
    .await;
    assert_eq!(
        call(
            &app,
            "PUT",
            &format!("{base}/http-bindings/echo"),
            &a,
            json!({"base_url": "http://httpbin.org", "secret_name": "ECHO_TOKEN"})
        )
        .await
        .0,
        400,
        "https only"
    );
    assert_eq!(
        call(
            &app,
            "PUT",
            &format!("{base}/http-bindings/echo"),
            &a,
            json!({"base_url": "https://httpbin.org", "secret_name": "ECHO_TOKEN"})
        )
        .await
        .0,
        200
    );

    let (status, client) = call(&app, "POST", &format!("/v1/orgs/{org}/gateway/clients"), &a, json!({
        "name": "Claude Code", "allow_writes": false, "grants": [{"project": "shop", "environment": "staging"}]
    })).await;
    assert_eq!(status, 200, "{client:?}");
    assert_eq!(
        client["url"],
        format!("https://vault.example.com/api/v1/orgs/{org}/mcp")
    );
    let token = client["token"].as_str().unwrap().to_owned();

    assert_eq!(
        mcp(
            &app,
            &org,
            "klgw_wrong",
            json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})
        )
        .await
        .0,
        403
    );
    let (_, init) = mcp(&app, &org, &token, json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})).await;
    assert_eq!(init["result"]["serverInfo"]["name"], "keylease-mcp-gateway");
    assert_eq!(
        mcp(
            &app,
            &org,
            &token,
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
        )
        .await
        .0,
        202
    );
    let (_, listed) = mcp(
        &app,
        &org,
        &token,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    )
    .await;
    assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 2);
    let (_, apis) = mcp(&app, &org, &token, tool("list_apis", json!({}))).await;
    let text = apis["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("\"binding\": \"echo\"") && !text.contains("test-secret"),
        "{text}"
    );

    // Read-only client: no POST; no other environment.
    let (_, write) = mcp(&app, &org, &token, tool("http_request", json!({"project": "shop", "environment": "staging", "binding": "echo", "method": "POST", "path": "/post"}))).await;
    assert_eq!(write["result"]["isError"], true);
    let (_, other) = mcp(&app, &org, &token, tool("http_request", json!({"project": "shop", "environment": "production", "binding": "echo", "path": "/get"}))).await;
    assert!(
        other["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("no access")
    );

    // A real call (needs the network): the API sees the credential, the model does not.
    if std::env::var("KEYLEASE_TEST_NETWORK").is_ok() {
        let (_, echoed) = mcp(&app, &org, &token, tool("http_request", json!({"project": "shop", "environment": "staging", "binding": "echo", "path": "/anything"}))).await;
        let text = echoed["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("HTTP 200"), "{text}");
        assert!(
            text.contains("Bearer [REDACTED by keylease]")
                || text.contains("[REDACTED by keylease]"),
            "{text}"
        );
        assert!(!text.contains("test-secret-0123456789"), "{text}");
    }

    let client_id = client["client_id"].as_str().unwrap();
    assert_eq!(
        call(
            &app,
            "DELETE",
            &format!("/v1/orgs/{org}/gateway/clients/{client_id}"),
            &a,
            Value::Null
        )
        .await
        .0,
        200
    );
    assert_eq!(
        mcp(
            &app,
            &org,
            &token,
            json!({"jsonrpc": "2.0", "id": 3, "method": "ping"})
        )
        .await
        .0,
        403
    );
}

#[tokio::test]
async fn a_gateway_client_can_need_approval_per_call() {
    let Some(database_url) = std::env::var("KEYLEASE_TEST_DATABASE_URL").ok() else {
        eprintln!("skipping PostgreSQL gateway approval test; KEYLEASE_TEST_DATABASE_URL is unset");
        return;
    };
    let repository = CloudRepository::connect(&database_url, 2).await.unwrap();
    repository.migrate().await.unwrap();
    let app = router(
        CloudApiState::new(
            repository.clone(),
            ControlSigner::generate("gateway-approval-test").unwrap(),
            CloudApiConfig {
                admin_token: "gateway-test-administrator-token-at-least-32".into(),
                kms_root_key: Some([6_u8; 32]),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let (_alice, a) = signed_in(&repository, "alice").await;
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
        &format!("{base}/secrets/staging/ECHO_TOKEN"),
        &a,
        json!({"value": "test-secret-0123456789"}),
    )
    .await;
    call(
        &app,
        "PUT",
        &format!("{base}/http-bindings/echo"),
        &a,
        json!({"base_url": "https://httpbin.org", "secret_name": "ECHO_TOKEN"}),
    )
    .await;
    assert_eq!(call(&app, "POST", &format!("/v1/orgs/{org}/gateway/clients"), &a, json!({
        "name": "bad", "approval": "sometimes", "grants": [{"project": "shop", "environment": "staging"}]
    })).await.0, 400);
    let (status, client) = call(
        &app,
        "POST",
        &format!("/v1/orgs/{org}/gateway/clients"),
        &a,
        json!({
            "name": "Deploy bot", "allow_writes": true, "approval": "writes",
            "grants": [{"project": "shop", "environment": "staging"}]
        }),
    )
    .await;
    assert_eq!(status, 200, "{client:?}");
    let token = client["token"].as_str().unwrap().to_owned();
    let (_, clients) = call(
        &app,
        "GET",
        &format!("/v1/orgs/{org}/gateway/clients"),
        &a,
        Value::Null,
    )
    .await;
    assert_eq!(clients["clients"][0]["approval"], "writes");

    let refund = json!({"project": "shop", "environment": "staging", "binding": "echo",
                        "method": "POST", "path": "/post", "json": {"amount": 5}});
    // A write waits for a person; asking again does not make a second request.
    let (_, first) = mcp(&app, &org, &token, tool("http_request", refund.clone())).await;
    let text = first["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(first["result"]["isError"], true);
    assert!(text.contains("approval required (gwa_"), "{text}");
    let id = text
        .split("approval required (")
        .nth(1)
        .unwrap()
        .split(')')
        .next()
        .unwrap()
        .to_owned();
    let (_, again) = mcp(&app, &org, &token, tool("http_request", refund.clone())).await;
    assert!(
        again["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains(&id)
    );
    let (_, listed) = call(
        &app,
        "GET",
        &format!("/v1/orgs/{org}/gateway/approvals"),
        &a,
        Value::Null,
    )
    .await;
    let pending: Vec<&Value> = listed["approvals"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["state"] == "pending")
        .collect();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["approval_id"], id.as_str());
    assert_eq!(pending[0]["method"], "POST");
    assert_eq!(pending[0]["path"], "/post");
    assert_eq!(pending[0]["client"], "Deploy bot");
    // Someone without the project admin role neither sees nor decides it.
    let (status, foreign) = call(
        &app,
        "GET",
        &format!("/v1/orgs/{org}/gateway/approvals"),
        &b,
        Value::Null,
    )
    .await;
    assert!(
        status != 200 || foreign["approvals"] == json!([]),
        "{status} {foreign:?}"
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("/v1/orgs/{org}/gateway/approvals/{id}"),
            &b,
            json!({"approve": true})
        )
        .await
        .0,
        404,
        "not a member of the organization"
    );

    // Reads go through without approval (they fail later only for lack of network).
    let (_, read) = mcp(
        &app,
        &org,
        &token,
        tool(
            "http_request",
            json!({"project": "shop", "environment": "staging", "binding": "echo", "path": "/get"}),
        ),
    )
    .await;
    assert!(
        !read["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("approval required")
    );

    // Approved: the same call passes the gate once; a different body needs its own approval.
    let (status, decided) = call(
        &app,
        "POST",
        &format!("/v1/orgs/{org}/gateway/approvals/{id}"),
        &a,
        json!({"approve": true}),
    )
    .await;
    assert_eq!(status, 200, "{decided:?}");
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("/v1/orgs/{org}/gateway/approvals/{id}"),
            &a,
            json!({"approve": false})
        )
        .await
        .0,
        400
    );
    let mut other = refund.clone();
    other["json"]["amount"] = json!(500);
    let (_, changed) = mcp(&app, &org, &token, tool("http_request", other.clone())).await;
    let changed_text = changed["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        changed_text.contains("approval required") && !changed_text.contains(&id),
        "{changed_text}"
    );
    let (_, passed) = mcp(&app, &org, &token, tool("http_request", refund.clone())).await;
    let passed_text = passed["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!passed_text.contains("approval required"), "{passed_text}");
    let (_, after) = mcp(&app, &org, &token, tool("http_request", refund.clone())).await;
    assert!(
        after["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("approval required"),
        "used once"
    );

    // Denied: the same call is refused until the request expires.
    let other_id = changed_text
        .split("approval required (")
        .nth(1)
        .unwrap()
        .split(')')
        .next()
        .unwrap()
        .to_owned();
    call(
        &app,
        "POST",
        &format!("/v1/orgs/{org}/gateway/approvals/{other_id}"),
        &a,
        json!({"approve": false}),
    )
    .await;
    let (_, refused) = mcp(&app, &org, &token, tool("http_request", other)).await;
    assert!(
        refused["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("denied"),
        "{refused:?}"
    );

    // The base-URL proxy answers 403 approval_required.
    let request = Request::builder()
        .method("DELETE")
        .uri(format!(
            "/v1/orgs/{org}/gateway/http/shop/staging/echo/delete"
        ))
        .header("x-keylease-token", &token)
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status().as_u16(), 403);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["error"], "approval_required");
}
