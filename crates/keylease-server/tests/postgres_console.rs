//! KeyLease Console sign-in (ADR 0008) against a real PostgreSQL.

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
use keylease_protocol::ControlSigner;
use keylease_server::{CloudApiConfig, CloudApiState, CloudRepository, router};
use p256::ecdsa::signature::Signer as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const ORIGIN: &str = "https://vault.example.com";

struct Reply {
    status: u16,
    cookie: Option<String>,
    body: Value,
}

async fn send(app: &Router, request: Request<Body>) -> Reply {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let cookie = response
        .headers()
        .get("set-cookie")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or_default().to_owned());
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        cookie,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    }
}

fn console(method: &str, path: &str, cookie: Option<&str>, body: Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("x-keylease-console", "1");
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    builder
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[tokio::test]
async fn console_sign_in_by_device_link_and_passkey() {
    let Some(database_url) = std::env::var("KEYLEASE_TEST_DATABASE_URL").ok() else {
        eprintln!("skipping PostgreSQL console test; KEYLEASE_TEST_DATABASE_URL is unset");
        return;
    };
    let repository = CloudRepository::connect(&database_url, 2).await.unwrap();
    repository.migrate().await.unwrap();
    let app = router(
        CloudApiState::new(
            repository.clone(),
            ControlSigner::generate("console-test").unwrap(),
            CloudApiConfig {
                admin_token: "console-test-administrator-token-at-least-32".into(),
                maximum_body_bytes: 1024 * 1024,
                operations_status_file: None,
                public_url: Some(ORIGIN.into()),
            },
        )
        .unwrap(),
    );

    // An account with an owner device and a node, as the relay creates them.
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let account = format!("acct_{suffix}");
    let owner = format!("member_owner_{suffix}");
    let node = format!("member_node_{suffix}");
    let owner_key = SigningKey::from_bytes(&rand_bytes());
    let pool = repository.pool();
    sqlx::query("INSERT INTO relay_accounts(account_id,owner_member_id,recovery_lookup_hash,recovery_kit,created_at) VALUES($1,$2,$3,'{}',now())")
        .bind(&account).bind(&owner).bind(sha256_hex(suffix.as_bytes()))
        .execute(pool).await.unwrap();
    for (member, role, key) in [
        (
            &owner,
            "owner",
            STANDARD.encode(owner_key.verifying_key().to_bytes()),
        ),
        (
            &node,
            "node",
            STANDARD.encode(
                SigningKey::from_bytes(&rand_bytes())
                    .verifying_key()
                    .to_bytes(),
            ),
        ),
    ] {
        sqlx::query("INSERT INTO relay_members(member_id,account_id,role,name,sign_public_b64,box_public_b64,created_at) VALUES($1,$2,$3,$4,$5,'box',now())")
            .bind(member).bind(&account).bind(role).bind(role).bind(key)
            .execute(pool).await.unwrap();
    }

    // The owner device registers a one-time token by its hash.
    let token = URL_SAFE_NO_PAD.encode(rand_bytes());
    let link = serde_json::to_vec(&json!({
        "lookup_hash": sha256_hex(token.as_bytes()),
        "expires_at": Utc::now() + Duration::minutes(10),
    }))
    .unwrap();
    let timestamp = Utc::now().timestamp();
    let signature = owner_key.sign(&relay_request_signing_input(
        "POST",
        "/v1/relay/console-links",
        timestamp,
        &link,
    ));
    let created = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/v1/relay/console-links")
            .header("content-type", "application/json")
            .header(HEADER_MEMBER, &owner)
            .header(HEADER_TIMESTAMP, timestamp.to_string())
            .header(HEADER_SIGNATURE, STANDARD.encode(signature.to_bytes()))
            .body(Body::from(link))
            .unwrap(),
    )
    .await;
    assert_eq!(created.status, 200, "{:?}", created.body);

    // Without the CSRF header, or with a wrong token, there is no session.
    let mut no_csrf = console("POST", "/v1/console/session", None, json!({"token": token}));
    no_csrf.headers_mut().remove("x-keylease-console");
    assert_eq!(send(&app, no_csrf).await.status, 403);
    assert_eq!(
        send(
            &app,
            console(
                "POST",
                "/v1/console/session",
                None,
                json!({"token": "wrong"})
            )
        )
        .await
        .status,
        403
    );
    let session = send(
        &app,
        console("POST", "/v1/console/session", None, json!({"token": token})),
    )
    .await;
    assert_eq!(session.status, 200, "{:?}", session.body);
    let cookie = session.cookie.expect("a session cookie");
    // The link works once.
    assert_eq!(
        send(
            &app,
            console("POST", "/v1/console/session", None, json!({"token": token}))
        )
        .await
        .status,
        403
    );

    let me = send(
        &app,
        console("GET", "/v1/console/me", Some(&cookie), Value::Null),
    )
    .await;
    assert_eq!(me.body["account_id"], account.as_str());
    assert_eq!(me.body["passkeys_available"], true);
    let devices = send(
        &app,
        console("GET", "/v1/console/devices", Some(&cookie), Value::Null),
    )
    .await;
    assert_eq!(devices.body["devices"].as_array().unwrap().len(), 2);
    // The owner cannot be revoked from the console; the node can.
    assert_eq!(
        send(
            &app,
            console(
                "DELETE",
                &format!("/v1/console/devices/{owner}"),
                Some(&cookie),
                Value::Null
            )
        )
        .await
        .status,
        404
    );
    assert_eq!(
        send(
            &app,
            console(
                "DELETE",
                &format!("/v1/console/devices/{node}"),
                Some(&cookie),
                Value::Null
            )
        )
        .await
        .status,
        200
    );

    // Register a passkey, then sign in with it.
    let options = send(
        &app,
        console(
            "POST",
            "/v1/console/passkeys/register/options",
            Some(&cookie),
            Value::Null,
        ),
    )
    .await;
    let challenge = URL_SAFE_NO_PAD
        .decode(options.body["challenge"].as_str().unwrap())
        .unwrap();
    assert_eq!(options.body["rp"]["id"], "vault.example.com");
    let passkey = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let credential = format!("cred-{suffix}");
    let registration = json!({
        "client_data_json": URL_SAFE_NO_PAD.encode(client_data("webauthn.create", &challenge)),
        "attestation_object": URL_SAFE_NO_PAD.encode(attestation_object(&authenticator_data(0, Some((credential.as_bytes(), &passkey))))),
        "name": "Laptop",
    });
    let registered = send(
        &app,
        console(
            "POST",
            "/v1/console/passkeys/register",
            Some(&cookie),
            registration.clone(),
        ),
    )
    .await;
    assert_eq!(registered.status, 200, "{:?}", registered.body);
    // The challenge is single use.
    assert_ne!(
        send(
            &app,
            console(
                "POST",
                "/v1/console/passkeys/register",
                Some(&cookie),
                registration
            )
        )
        .await
        .status,
        200
    );

    let login = send(
        &app,
        console(
            "POST",
            "/v1/console/passkeys/login/options",
            None,
            Value::Null,
        ),
    )
    .await;
    let challenge = URL_SAFE_NO_PAD
        .decode(login.body["challenge"].as_str().unwrap())
        .unwrap();
    let auth = authenticator_data(1, None);
    let data = client_data("webauthn.get", &challenge);
    let mut message = auth.clone();
    message.extend_from_slice(&Sha256::digest(&data));
    let signature: p256::ecdsa::Signature = passkey.sign(&message);
    let signed_in = send(
        &app,
        console(
            "POST",
            "/v1/console/passkeys/login",
            None,
            json!({
                "credential_id": URL_SAFE_NO_PAD.encode(credential.as_bytes()),
                "client_data_json": URL_SAFE_NO_PAD.encode(&data),
                "authenticator_data": URL_SAFE_NO_PAD.encode(&auth),
                "signature": URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
            }),
        ),
    )
    .await;
    assert_eq!(signed_in.status, 200, "{:?}", signed_in.body);
    let passkey_cookie = signed_in.cookie.unwrap();
    assert_eq!(
        send(
            &app,
            console("GET", "/v1/console/me", Some(&passkey_cookie), Value::Null)
        )
        .await
        .body["passkeys"],
        1
    );

    // Signing out ends that session only.
    assert_eq!(
        send(
            &app,
            console(
                "POST",
                "/v1/console/logout",
                Some(&passkey_cookie),
                Value::Null
            )
        )
        .await
        .status,
        200
    );
    assert_eq!(
        send(
            &app,
            console("GET", "/v1/console/me", Some(&passkey_cookie), Value::Null)
        )
        .await
        .status,
        403
    );
    assert_eq!(
        send(
            &app,
            console("GET", "/v1/console/me", Some(&cookie), Value::Null)
        )
        .await
        .status,
        200
    );
}

fn rand_bytes() -> [u8; 32] {
    use rand::RngCore;
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

fn cbor_bytes(out: &mut Vec<u8>, major: u8, bytes: &[u8]) {
    let length = bytes.len();
    if length < 24 {
        out.push((major << 5) | length as u8);
    } else if length < 256 {
        out.push((major << 5) | 24);
        out.push(length as u8);
    } else {
        out.push((major << 5) | 25);
        out.extend_from_slice(&(length as u16).to_be_bytes());
    }
    out.extend_from_slice(bytes);
}

fn authenticator_data(
    count: u32,
    credential: Option<(&[u8], &p256::ecdsa::SigningKey)>,
) -> Vec<u8> {
    let mut data = Sha256::digest(b"vault.example.com").to_vec();
    data.push(if credential.is_some() { 0x45 } else { 0x05 });
    data.extend_from_slice(&count.to_be_bytes());
    if let Some((id, key)) = credential {
        data.extend_from_slice(&[0_u8; 16]);
        data.extend_from_slice(&(id.len() as u16).to_be_bytes());
        data.extend_from_slice(id);
        let point = key.verifying_key().to_encoded_point(false);
        data.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21]);
        cbor_bytes(&mut data, 2, point.x().unwrap());
        data.push(0x22);
        cbor_bytes(&mut data, 2, point.y().unwrap());
    }
    data
}

fn client_data(kind: &str, challenge: &[u8]) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"type": kind, "challenge": URL_SAFE_NO_PAD.encode(challenge), "origin": ORIGIN}),
    )
    .unwrap()
}

fn attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa3];
    cbor_bytes(&mut out, 3, b"fmt");
    cbor_bytes(&mut out, 3, b"none");
    cbor_bytes(&mut out, 3, b"attStmt");
    out.push(0xa0);
    cbor_bytes(&mut out, 3, b"authData");
    cbor_bytes(&mut out, 2, auth_data);
    out
}
