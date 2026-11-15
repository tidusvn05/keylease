//! Audit push to SIEM collectors, against a real PostgreSQL and a mock
//! collector.

use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    routing::post,
};
use http_body_util::BodyExt;
use keylease_protocol::ControlSigner;
use keylease_server::{CloudApiConfig, CloudApiState, CloudRepository, router};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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
struct Collector {
    failing: bool,
    received: Vec<(String, String, String)>,
}

async fn collect(
    State(collector): State<Arc<Mutex<Collector>>>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let mut collector = collector.lock().unwrap();
    if collector.failing {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    collector.received.push((
        header("authorization"),
        header("content-type"),
        String::from_utf8_lossy(&body).into_owned(),
    ));
    StatusCode::OK
}

#[tokio::test]
async fn the_audit_is_pushed_to_siem_collectors() {
    let Some(database_url) = std::env::var("KEYLEASE_TEST_DATABASE_URL").ok() else {
        eprintln!("skipping PostgreSQL audit push test; KEYLEASE_TEST_DATABASE_URL is unset");
        return;
    };
    let collector: Arc<Mutex<Collector>> = Arc::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let collector_url = format!(
        "http://{}/services/collector",
        listener.local_addr().unwrap()
    );
    let mock = Router::new()
        .route("/services/collector", post(collect))
        .with_state(collector.clone());
    tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });

    let repository = CloudRepository::connect(&database_url, 2).await.unwrap();
    repository.migrate().await.unwrap();
    let state = CloudApiState::new(
        repository.clone(),
        ControlSigner::generate("audit-push-test").unwrap(),
        CloudApiConfig {
            admin_token: "audit-push-test-administrator-token-at-least-32".into(),
            kms_root_key: Some([8_u8; 32]),
            allow_private_network: true,
            ..Default::default()
        },
    )
    .unwrap();
    let app = router(state.clone());
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
    for name in ["ONE", "TWO"] {
        call(
            &app,
            "PUT",
            &format!("{base}/secrets/staging/{name}"),
            &a,
            json!({"value": "v"}),
        )
        .await;
    }

    // Only owners and admins configure destinations.
    let destination = format!("/v1/orgs/{org}/audit/destinations/splunk");
    let config = json!({"url": collector_url, "format": "splunk_hec", "secret": "hec-token-123", "start": "beginning"});
    assert_ne!(
        call(&app, "PUT", &destination, &b, config.clone()).await.0,
        200
    );
    assert_eq!(
        call(
            &app,
            "PUT",
            &destination,
            &a,
            json!({"url": collector_url, "format": "csv"})
        )
        .await
        .0,
        400
    );
    let (status, set) = call(&app, "PUT", &destination, &a, config).await;
    assert_eq!(status, 200, "{set:?}");
    let (_, tested) = call(
        &app,
        "POST",
        &format!("{destination}/test"),
        &a,
        Value::Null,
    )
    .await;
    assert_eq!(tested["ok"], true, "{tested:?}");
    collector.lock().unwrap().received.clear();

    // A push sends every event so far, with the token in the header.
    assert!(keylease_server::push_audit_once(&state).await >= 2);
    {
        let collector = collector.lock().unwrap();
        let (authorization, content_type, body) = collector.received.last().unwrap();
        assert_eq!(authorization, "Splunk hec-token-123");
        assert_eq!(content_type, "application/json");
        let events: Vec<Value> = body
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert!(events.len() >= 2);
        assert!(
            events
                .iter()
                .all(|event| event["sourcetype"] == "keylease:audit"
                    && event["event"]["org"] == org.as_str())
        );
        assert!(!body.contains("hec-token-123"));
    }
    let (_, listed) = call(
        &app,
        "GET",
        &format!("/v1/orgs/{org}/audit/destinations"),
        &a,
        Value::Null,
    )
    .await;
    assert_eq!(listed["destinations"][0]["behind"], 0);
    assert_eq!(listed["destinations"][0]["has_secret"], true);
    assert!(!listed.to_string().contains("hec-token-123"));

    // The collector fails: the cursor stays and the error shows.
    collector.lock().unwrap().failing = true;
    call(
        &app,
        "PUT",
        &format!("{base}/secrets/staging/THREE"),
        &a,
        json!({"value": "v"}),
    )
    .await;
    keylease_server::push_audit_once(&state).await;
    let (_, listed) = call(
        &app,
        "GET",
        &format!("/v1/orgs/{org}/audit/destinations"),
        &a,
        Value::Null,
    )
    .await;
    let failing = &listed["destinations"][0];
    assert_eq!(failing["failures"], 1);
    assert!(
        failing["last_error"].as_str().unwrap().contains("503"),
        "{failing:?}"
    );
    assert!(failing["behind"].as_i64().unwrap() >= 1);
    // Backing off: nothing is sent before the next attempt is due.
    collector.lock().unwrap().failing = false;
    keylease_server::push_audit_once(&state).await;
    assert!(collector.lock().unwrap().received.len() == 1);
    sqlx::query("UPDATE org_siem_destinations SET next_attempt_at=now() WHERE org_id=$1")
        .bind(&org)
        .execute(repository.pool())
        .await
        .unwrap();
    assert!(keylease_server::push_audit_once(&state).await >= 1);
    let (_, listed) = call(
        &app,
        "GET",
        &format!("/v1/orgs/{org}/audit/destinations"),
        &a,
        Value::Null,
    )
    .await;
    assert_eq!(listed["destinations"][0]["behind"], 0);
    assert_eq!(listed["destinations"][0]["failures"], 0);

    // The pull export uses the same lines.
    let request = Request::builder()
        .uri(format!("/v1/orgs/{org}/audit/export?format=syslog"))
        .header("cookie", &a)
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
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
        text.lines().all(|line| line.starts_with("<110>1 ")),
        "{text}"
    );
}
