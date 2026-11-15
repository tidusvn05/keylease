//! Console approvals and node audit (ADR 0011) against a real PostgreSQL.

use axum::{Router, body::Body, http::Request};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use keylease_core::relay::{
    HEADER_MEMBER, HEADER_SIGNATURE, HEADER_TIMESTAMP, relay_request_signing_input,
};
use keylease_crypto::webauthn::testing::{ORIGIN, authenticator_data, client_data, sign};
use keylease_protocol::ControlSigner;
use keylease_server::{CloudApiConfig, CloudApiState, CloudRepository, router};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

async fn send(app: &Router, request: Request<Body>) -> (u16, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn console(method: &str, path: &str, cookie: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("x-keylease-console", "1")
        .header("cookie", cookie)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn node(
    key: &SigningKey,
    member: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Request<Body> {
    let bytes = body
        .map(|b| serde_json::to_vec(&b).unwrap())
        .unwrap_or_default();
    let timestamp = Utc::now().timestamp();
    let signature = key.sign(&relay_request_signing_input(
        method, path, timestamp, &bytes,
    ));
    Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header(HEADER_MEMBER, member)
        .header(HEADER_TIMESTAMP, timestamp.to_string())
        .header(HEADER_SIGNATURE, STANDARD.encode(signature.to_bytes()))
        .body(Body::from(bytes))
        .unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn rand_bytes() -> [u8; 32] {
    use rand::RngCore;
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

fn approval(id: &str, state: &str) -> Value {
    json!({
        "id": id,
        "request_digest_hex": "cd".repeat(32),
        "policy_version": 7,
        "state": state,
        "expires_at": Utc::now() + Duration::minutes(5),
        "agent_id": "agent-1",
        "action": "ssh:sign",
        "resource": "kl://vault/item/1",
        "created_at": Utc::now(),
    })
}

fn audit_event(action: &str) -> Value {
    json!({
        "schema_version": 1,
        "timestamp": Utc::now(),
        "request_id": uuid::Uuid::now_v7().to_string(),
        "agent_id": "agent-1",
        "workload_id": null,
        "on_behalf_of": null,
        "action": action,
        "resource": "kl://vault/item/1",
        "connection_id": null,
        "policy_version": 7,
        "decision": "allow",
        "connector": null,
        "outcome": "ok",
        "item_count": null,
        "cell_count": null,
        "byte_count": null,
        "changed_fields": [],
    })
}

/// An account with an owner device, one node, a passkey and a console
/// session. Returns (account, node member id, node key, cookie, passkey key,
/// credential id).
async fn account(
    pool: &sqlx::PgPool,
) -> (
    String,
    String,
    SigningKey,
    String,
    p256::ecdsa::SigningKey,
    String,
) {
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let account = format!("acct_{suffix}");
    let owner = format!("member_owner_{suffix}");
    let node = format!("member_node_{suffix}");
    let node_key = SigningKey::from_bytes(&rand_bytes());
    sqlx::query("INSERT INTO relay_accounts(account_id,owner_member_id,recovery_lookup_hash,recovery_kit,created_at) VALUES($1,$2,$3,'{}',now())")
        .bind(&account).bind(&owner).bind(sha256_hex(suffix.as_bytes()))
        .execute(pool).await.unwrap();
    for (member, role, key) in [
        (&owner, "owner", SigningKey::from_bytes(&rand_bytes())),
        (&node, "node", node_key.clone()),
    ] {
        sqlx::query("INSERT INTO relay_members(member_id,account_id,role,name,sign_public_b64,box_public_b64,created_at) VALUES($1,$2,$3,$4,$5,'box',now())")
            .bind(member).bind(&account).bind(role).bind(format!("{role}-vps"))
            .bind(STANDARD.encode(key.verifying_key().to_bytes()))
            .execute(pool).await.unwrap();
    }
    let passkey = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let credential = URL_SAFE_NO_PAD.encode(format!("cred-{suffix}"));
    sqlx::query("INSERT INTO console_passkeys(credential_id,account_id,name,public_key_b64,sign_count,created_at) VALUES($1,$2,'Laptop',$3,0,now())")
        .bind(&credential).bind(&account)
        .bind(STANDARD.encode(passkey.verifying_key().to_encoded_point(false).as_bytes()))
        .execute(pool).await.unwrap();
    let token = URL_SAFE_NO_PAD.encode(rand_bytes());
    sqlx::query("INSERT INTO console_sessions(session_hash,account_id,via,created_at,expires_at) VALUES($1,$2,'device_link',now(),now() + interval '1 hour')")
        .bind(sha256_hex(token.as_bytes())).bind(&account)
        .execute(pool).await.unwrap();
    (
        account,
        node,
        node_key,
        format!("kl_session={token}"),
        passkey,
        credential,
    )
}

fn assertion(
    passkey: &p256::ecdsa::SigningKey,
    credential: &str,
    challenge: &[u8],
    count: u32,
) -> Value {
    let client = client_data("webauthn.get", challenge);
    let auth = authenticator_data(count, None);
    json!({
        "credential_id": credential,
        "client_data_json": URL_SAFE_NO_PAD.encode(&client),
        "authenticator_data": URL_SAFE_NO_PAD.encode(&auth),
        "signature": URL_SAFE_NO_PAD.encode(sign(passkey, &auth, &client)),
    })
}

#[tokio::test]
async fn a_node_approval_is_decided_in_the_console_and_its_audit_listed() {
    let Some(database_url) = std::env::var("KEYLEASE_TEST_DATABASE_URL").ok() else {
        eprintln!(
            "skipping PostgreSQL console approvals test; KEYLEASE_TEST_DATABASE_URL is unset"
        );
        return;
    };
    let repository = CloudRepository::connect(&database_url, 2).await.unwrap();
    repository.migrate().await.unwrap();
    let app = router(
        CloudApiState::new(
            repository.clone(),
            ControlSigner::generate("console-approvals-test").unwrap(),
            CloudApiConfig {
                admin_token: "console-test-administrator-token-at-least-32".into(),
                maximum_body_bytes: 1024 * 1024,
                operations_status_file: None,
                public_url: Some(ORIGIN.into()),
                kms_root_key: None,
                oidc: None,
            },
        )
        .unwrap(),
    );
    let pool = repository.pool();
    let (account, member, node_key, cookie, passkey, credential) = account(pool).await;
    let (_, _, _, other_cookie, _, _) = self::account(pool).await;

    // The node pins the account's passkeys.
    let (status, passkeys) = send(
        &app,
        node(
            &node_key,
            &member,
            "GET",
            "/v1/relay/console/passkeys",
            None,
        ),
    )
    .await;
    assert_eq!(status, 200, "{passkeys:?}");
    assert_eq!(passkeys["rp_id"], "vault.example.com");
    assert_eq!(passkeys["origin"], ORIGIN);
    assert_eq!(
        passkeys["passkeys"][0]["credential_id"],
        credential.as_str()
    );

    // It reports one pending approval (and one already decided, dropped).
    let report = json!({"approvals": [approval("ap-1", "pending"), approval("ap-0", "approved")]});
    let (status, reply) = send(
        &app,
        node(
            &node_key,
            &member,
            "PUT",
            "/v1/relay/console/report",
            Some(report.clone()),
        ),
    )
    .await;
    assert_eq!(status, 200, "{reply:?}");
    assert_eq!(reply["decisions"], json!([]));
    let (_, listed) = send(
        &app,
        console("GET", "/v1/console/approvals", &cookie, Value::Null),
    )
    .await;
    assert_eq!(listed["nodes"][0]["name"], "node-vps");
    assert_eq!(listed["nodes"][0]["approvals"].as_array().unwrap().len(), 1);
    // Another account sees nothing of it.
    let (_, foreign) = send(
        &app,
        console("GET", "/v1/console/approvals", &other_cookie, Value::Null),
    )
    .await;
    assert_eq!(foreign["nodes"], json!([]));
    let (status, _) = send(
        &app,
        console(
            "POST",
            "/v1/console/approvals/challenge",
            &other_cookie,
            json!({"member_id": member, "approval_id": "ap-1", "approve": true}),
        ),
    )
    .await;
    assert_eq!(status, 400);

    // The person approves with a one-hour trust.
    let (status, options) = send(
        &app,
        console(
            "POST",
            "/v1/console/approvals/challenge",
            &cookie,
            json!({"member_id": member, "approval_id": "ap-1", "approve": true,
               "trust": {"scope": "item", "duration": "1h"}}),
        ),
    )
    .await;
    assert_eq!(status, 200, "{options:?}");
    let payload = options["payload"].as_str().unwrap().to_owned();
    let signed: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(signed["account_id"], account.as_str());
    assert_eq!(signed["request_digest_hex"], "cd".repeat(32));
    assert_eq!(signed["policy_version"], 7);
    assert_eq!(signed["trust"]["duration"], "1h");
    let challenge = URL_SAFE_NO_PAD
        .decode(options["challenge"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        challenge,
        keylease_core::console::decision_challenge(&payload)
    );
    assert_eq!(options["allow_credentials"][0], credential.as_str());

    // A signature over another payload is refused; denying cannot grant trust.
    let (status, _) = send(
        &app,
        console(
            "POST",
            "/v1/console/approvals/decide",
            &cookie,
            json!({"payload": payload.replace("\"approve\":true", "\"approve\":false"),
               "assertion": assertion(&passkey, &credential, &challenge, 1)}),
        ),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = send(
        &app,
        console(
            "POST",
            "/v1/console/approvals/challenge",
            &cookie,
            json!({"member_id": member, "approval_id": "ap-1", "approve": false,
               "trust": {"scope": "item", "duration": "1h"}}),
        ),
    )
    .await;
    assert_eq!(status, 400);

    let (status, decided) = send(&app, console("POST", "/v1/console/approvals/decide", &cookie,
        json!({"payload": payload, "assertion": assertion(&passkey, &credential, &challenge, 2)}))).await;
    assert_eq!(status, 200, "{decided:?}");
    let decision_id = decided["decision_id"].as_str().unwrap().to_owned();
    // The same assertion again: the counter did not increase.
    let (status, _) = send(&app, console("POST", "/v1/console/approvals/decide", &cookie,
        json!({"payload": payload, "assertion": assertion(&passkey, &credential, &challenge, 2)}))).await;
    assert_eq!(status, 403);

    // The node's next report picks the decision up, byte for byte.
    let (_, reply) = send(
        &app,
        node(
            &node_key,
            &member,
            "PUT",
            "/v1/relay/console/report",
            Some(report),
        ),
    )
    .await;
    let decisions = reply["decisions"].as_array().unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0]["id"], decision_id.as_str());
    assert_eq!(decisions[0]["payload"], payload.as_str());
    let (status, _) = send(
        &app,
        node(
            &node_key,
            &member,
            "POST",
            "/v1/relay/console/results",
            Some(json!({"results": [{"id": decision_id, "outcome": "approved"}]})),
        ),
    )
    .await;
    assert_eq!(status, 200);
    let (_, reply) = send(
        &app,
        node(
            &node_key,
            &member,
            "PUT",
            "/v1/relay/console/report",
            Some(json!({"approvals": []})),
        ),
    )
    .await;
    assert_eq!(reply["decisions"], json!([]));
    let (_, listed) = send(
        &app,
        console("GET", "/v1/console/approvals", &cookie, Value::Null),
    )
    .await;
    assert_eq!(listed["decisions"][0]["outcome"], "approved");
    assert_eq!(listed["decisions"][0]["passkey_name"], "Laptop");
    assert_eq!(listed["nodes"][0]["approvals"], json!([]));

    // Audit: the node uploads what the server does not have yet.
    let (_, cursor) = send(
        &app,
        node(&node_key, &member, "GET", "/v1/relay/console/audit", None),
    )
    .await;
    assert_eq!(cursor["last_seq"], 0);
    let events: Vec<Value> = ["vault:reveal", "ssh:sign", "approval:decide"]
        .iter()
        .enumerate()
        .map(|(index, action)| json!({"seq": index + 1, "event": audit_event(action)}))
        .collect();
    let (status, stored) = send(
        &app,
        node(
            &node_key,
            &member,
            "POST",
            "/v1/relay/console/audit",
            Some(json!({"events": events})),
        ),
    )
    .await;
    assert_eq!(status, 200, "{stored:?}");
    assert_eq!(stored["last_seq"], 3);
    // Uploading the same events again changes nothing.
    send(
        &app,
        node(
            &node_key,
            &member,
            "POST",
            "/v1/relay/console/audit",
            Some(json!({"events": events})),
        ),
    )
    .await;
    let (_, page) = send(
        &app,
        console("GET", "/v1/console/audit?limit=2", &cookie, Value::Null),
    )
    .await;
    assert_eq!(page["events"].as_array().unwrap().len(), 2);
    assert_eq!(page["events"][0]["node"], "node-vps");
    let next = page["next"].as_str().unwrap().to_owned();
    let (_, rest) = send(
        &app,
        console(
            "GET",
            &format!("/v1/console/audit?limit=2&before={}", urlencode(&next)),
            &cookie,
            Value::Null,
        ),
    )
    .await;
    assert_eq!(rest["events"].as_array().unwrap().len(), 1);
    assert_eq!(rest["next"], Value::Null);
    let mut seqs: Vec<i64> = page["events"]
        .as_array()
        .unwrap()
        .iter()
        .chain(rest["events"].as_array().unwrap())
        .map(|event| event["seq"].as_i64().unwrap())
        .collect();
    seqs.sort();
    assert_eq!(seqs, [1, 2, 3]);
    let (_, foreign) = send(
        &app,
        console("GET", "/v1/console/audit", &other_cookie, Value::Null),
    )
    .await;
    assert_eq!(foreign["events"], json!([]));
}

fn urlencode(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}
