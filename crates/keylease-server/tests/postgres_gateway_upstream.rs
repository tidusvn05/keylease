//! Upstream MCP servers in the MCP Gateway, against a real PostgreSQL and a
//! mock MCP server with its own OAuth authorization server.

use axum::{
    Form, Json, Router,
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use keylease_protocol::ControlSigner;
use keylease_server::{CloudApiConfig, CloudApiState, CloudRepository, router};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
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

#[derive(Default)]
struct Mock {
    base: String,
    challenge: String,
    /// The access token the MCP server accepts now.
    valid_token: String,
    registrations: usize,
    refreshes: usize,
    calls: Vec<Value>,
}

type Shared = Arc<Mutex<Mock>>;

async fn protected_resource(State(mock): State<Shared>) -> Json<Value> {
    let base = mock.lock().unwrap().base.clone();
    Json(
        json!({"resource": format!("{base}/mcp"), "authorization_servers": [format!("{base}/as")]}),
    )
}

async fn authorization_server(State(mock): State<Shared>) -> Json<Value> {
    let base = mock.lock().unwrap().base.clone();
    Json(json!({
        "issuer": format!("{base}/as"),
        "authorization_endpoint": format!("{base}/as/authorize"),
        "token_endpoint": format!("{base}/as/token"),
        "registration_endpoint": format!("{base}/as/register"),
        "code_challenge_methods_supported": ["S256"],
    }))
}

async fn register(State(mock): State<Shared>, Json(body): Json<Value>) -> Json<Value> {
    assert_eq!(body["token_endpoint_auth_method"], "none");
    mock.lock().unwrap().registrations += 1;
    Json(json!({"client_id": "gateway-client-1"}))
}

async fn token(State(mock): State<Shared>, Form(form): Form<HashMap<String, String>>) -> Response {
    let mut mock = mock.lock().unwrap();
    assert_eq!(form["client_id"], "gateway-client-1");
    assert!(form["resource"].ends_with("/mcp"));
    match form["grant_type"].as_str() {
        "authorization_code" => {
            let verifier = &form["code_verifier"];
            if form["code"] != "code-1"
                || URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) != mock.challenge
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "invalid_grant"})),
                )
                    .into_response();
            }
            mock.valid_token = "access-token-one".into();
            Json(json!({"access_token": "access-token-one", "refresh_token": "rt-1", "expires_in": 3600, "token_type": "Bearer"})).into_response()
        }
        "refresh_token" => {
            assert_eq!(form["refresh_token"], "rt-1");
            mock.refreshes += 1;
            mock.valid_token = "access-token-two".into();
            Json(json!({"access_token": "access-token-two", "expires_in": 3600, "token_type": "Bearer"}))
                .into_response()
        }
        _ => StatusCode::BAD_REQUEST.into_response(),
    }
}

async fn mcp_server(
    State(mock): State<Shared>,
    headers: HeaderMap,
    Json(message): Json<Value>,
) -> Response {
    let valid = format!("Bearer {}", mock.lock().unwrap().valid_token);
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(valid.as_str()) {
        let base = mock.lock().unwrap().base.clone();
        let mut response = StatusCode::UNAUTHORIZED.into_response();
        response.headers_mut().insert(
            "www-authenticate",
            format!("Bearer resource_metadata=\"{base}/.well-known/oauth-protected-resource/mcp\"")
                .parse()
                .unwrap(),
        );
        return response;
    }
    let id = message["id"].clone();
    match message["method"].as_str().unwrap_or_default() {
        "initialize" => {
            let mut response = Json(json!({"jsonrpc": "2.0", "id": id, "result": {
                "protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "mock", "version": "1"}
            }})).into_response();
            response
                .headers_mut()
                .insert("mcp-session-id", "session-1".parse().unwrap());
            response
        }
        "notifications/initialized" => StatusCode::ACCEPTED.into_response(),
        "tools/list" => {
            assert_eq!(headers["mcp-session-id"], "session-1");
            let body = format!(
                "event: message\ndata: {}\n\n",
                json!({"jsonrpc": "2.0", "id": id, "result": {"tools": [
                    {"name": "echo", "description": "Echo text.", "inputSchema": {"type": "object"}, "annotations": {"readOnlyHint": true}},
                    {"name": "delete_repo", "description": "Delete a repository.", "inputSchema": {"type": "object"}},
                ]}})
            );
            ([("content-type", "text/event-stream")], body).into_response()
        }
        "tools/call" => {
            mock.lock().unwrap().calls.push(message["params"].clone());
            let text = format!(
                "echo: {} (token {})",
                message["params"]["arguments"]["text"]
                    .as_str()
                    .unwrap_or(""),
                valid
            );
            Json(json!({"jsonrpc": "2.0", "id": id, "result": {"content": [{"type": "text", "text": text}], "isError": false}})).into_response()
        }
        _ => {
            Json(json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "nope"}}))
                .into_response()
        }
    }
}

async fn mock_server() -> Shared {
    let mock: Shared = Arc::default();
    let app = Router::new()
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server/as",
            get(authorization_server),
        )
        .route("/as/register", post(register))
        .route("/as/token", post(token))
        .route("/mcp", post(mcp_server).delete(|| async { StatusCode::OK }))
        .with_state(mock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    mock.lock().unwrap().base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    mock
}

async fn gateway(app: &Router, org: &str, token: &str, body: Value) -> Value {
    let request = Request::builder()
        .method("POST")
        .uri(format!("/v1/orgs/{org}/mcp"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
        .unwrap_or(Value::Null)
}

fn tool_call(name: &str, arguments: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": name, "arguments": arguments}})
}

#[tokio::test]
async fn gateway_clients_use_an_upstream_mcp_server_connected_with_oauth() {
    let Some(database_url) = std::env::var("KEYLEASE_TEST_DATABASE_URL").ok() else {
        eprintln!("skipping PostgreSQL upstream MCP test; KEYLEASE_TEST_DATABASE_URL is unset");
        return;
    };
    let mock = mock_server().await;
    let base_url = mock.lock().unwrap().base.clone();
    let repository = CloudRepository::connect(&database_url, 2).await.unwrap();
    repository.migrate().await.unwrap();
    let app = router(
        CloudApiState::new(
            repository.clone(),
            ControlSigner::generate("upstream-test").unwrap(),
            CloudApiConfig {
                admin_token: "gateway-test-administrator-token-at-least-32".into(),
                kms_root_key: Some([7_u8; 32]),
                public_url: Some("https://vault.example.com/api".into()),
                allow_private_network: true,
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

    // Adding the upstream discovers its authorization server and registers.
    let (status, upstream) = call(
        &app,
        "PUT",
        &format!("{base}/mcp-upstreams/tracker"),
        &a,
        json!({"url": format!("{base_url}/mcp"), "auth": "oauth"}),
    )
    .await;
    assert_eq!(status, 200, "{upstream:?}");
    assert_eq!(upstream["secret_name"], "MCP_OAUTH_TRACKER");
    assert_eq!(upstream["issuer"], format!("{base_url}/as"));
    assert_eq!(mock.lock().unwrap().registrations, 1);
    let (_, listed) = call(
        &app,
        "GET",
        &format!("{base}/mcp-upstreams"),
        &a,
        Value::Null,
    )
    .await;
    assert_eq!(listed["upstreams"][0]["environments"], json!([]));

    // Connect staging: the authorize URL carries PKCE, state and the resource.
    let (status, started) = call(
        &app,
        "POST",
        &format!("{base}/mcp-upstreams/tracker/connect"),
        &a,
        json!({"environment": "staging"}),
    )
    .await;
    assert_eq!(status, 200, "{started:?}");
    let authorize = url::Url::parse(started["authorize_url"].as_str().unwrap()).unwrap();
    let query: HashMap<String, String> = authorize.query_pairs().into_owned().collect();
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(
        query["redirect_uri"],
        "https://vault.example.com/api/v1/gateway/oauth/callback"
    );
    assert_eq!(query["resource"], format!("{base_url}/mcp"));
    mock.lock().unwrap().challenge = query["code_challenge"].clone();
    let callback = |code: &str, state: &str| {
        Request::builder()
            .uri(format!(
                "/v1/gateway/oauth/callback?code={code}&state={state}"
            ))
            .body(Body::empty())
            .unwrap()
    };
    // A wrong state does nothing; the right one connects, once.
    assert_eq!(
        app.clone()
            .oneshot(callback("code-1", "forged"))
            .await
            .unwrap()
            .status()
            .as_u16(),
        400
    );
    let done = app
        .clone()
        .oneshot(callback("code-1", &query["state"]))
        .await
        .unwrap();
    assert_eq!(done.status().as_u16(), 200);
    assert_eq!(
        app.clone()
            .oneshot(callback("code-1", &query["state"]))
            .await
            .unwrap()
            .status()
            .as_u16(),
        400
    );
    let (_, listed) = call(
        &app,
        "GET",
        &format!("{base}/mcp-upstreams"),
        &a,
        Value::Null,
    )
    .await;
    assert_eq!(listed["upstreams"][0]["environments"], json!(["staging"]));
    // The tokens are a Managed secret: an admin may see them, a gateway client never.

    let (_, client) = call(&app, "POST", &format!("/v1/orgs/{org}/gateway/clients"), &a, json!({
        "name": "Agent", "approval": "writes", "grants": [{"project": "shop", "environment": "staging"}]
    })).await;
    let token = client["token"].as_str().unwrap().to_owned();
    let listed = gateway(
        &app,
        &org,
        &token,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    )
    .await;
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "list_apis",
            "http_request",
            "tracker__echo",
            "tracker__delete_repo"
        ]
    );
    assert!(
        listed["result"]["tools"][2]["description"]
            .as_str()
            .unwrap()
            .starts_with("[tracker via KeyLease, shop/staging]")
    );

    // A read-only tool goes straight through, with the credential scrubbed from the answer.
    let echoed = gateway(
        &app,
        &org,
        &token,
        tool_call("tracker__echo", json!({"text": "hi"})),
    )
    .await;
    let text = echoed["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(echoed["result"]["isError"], false, "{echoed:?}");
    assert!(
        text.starts_with("echo: hi") && !text.contains("access-token-one"),
        "{text}"
    );
    assert_eq!(mock.lock().unwrap().calls[0]["name"], "echo");

    // A tool without readOnlyHint needs approval for this client.
    let waiting = gateway(
        &app,
        &org,
        &token,
        tool_call("tracker__delete_repo", json!({"repo": "x"})),
    )
    .await;
    assert!(
        waiting["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("approval required"),
        "{waiting:?}"
    );
    assert_eq!(mock.lock().unwrap().calls.len(), 1);

    // The upstream stops accepting the token: the gateway refreshes it once.
    // (The mock accepts at-2 once it has issued it on refresh.)
    mock.lock().unwrap().valid_token = "revoked".into();
    let refreshed = gateway(
        &app,
        &org,
        &token,
        tool_call("tracker__echo", json!({"text": "again"})),
    )
    .await;
    assert_eq!(mock.lock().unwrap().refreshes, 1, "{refreshed:?}");
    assert!(
        refreshed["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .starts_with("echo: again"),
        "{refreshed:?}"
    );

    // Unknown tools and other environments are refused.
    let unknown = gateway(&app, &org, &token, tool_call("tracker__nope", json!({}))).await;
    assert_eq!(unknown["result"]["isError"], true);
}
