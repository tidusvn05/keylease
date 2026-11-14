//! Personal devices in the relay (v2 plan, step 10) against PostgreSQL:
//! device invites, joining as a device, and which message kinds may flow.

use axum::{Router, body::Body, http::Request};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use keylease_core::relay::{
    HEADER_MEMBER, HEADER_SIGNATURE, HEADER_TIMESTAMP, RelayMemberKeys, relay_request_signing_input,
};
use keylease_protocol::ControlSigner;
use keylease_server::{CloudApiConfig, CloudApiState, CloudRepository, router};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

fn key() -> SigningKey {
    use rand::RngCore;
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    SigningKey::from_bytes(&bytes)
}

fn keys(sign: &SigningKey) -> RelayMemberKeys {
    RelayMemberKeys {
        sign_public_b64: STANDARD.encode(sign.verifying_key().to_bytes()),
        box_public_b64: STANDARD.encode([7_u8; 32]),
    }
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    signer: Option<(&str, &SigningKey)>,
    body: Value,
) -> (u16, Value) {
    let bytes = if body.is_null() {
        vec![]
    } else {
        serde_json::to_vec(&body).unwrap()
    };
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some((member, key)) = signer {
        let timestamp = Utc::now().timestamp();
        let signature = key.sign(&relay_request_signing_input(
            method, path, timestamp, &bytes,
        ));
        request = request
            .header(HEADER_MEMBER, member)
            .header(HEADER_TIMESTAMP, timestamp.to_string())
            .header(HEADER_SIGNATURE, STANDARD.encode(signature.to_bytes()));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(bytes)).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn devices_join_with_a_device_invite_and_exchange_only_sync_messages() {
    let Some(database_url) = std::env::var("KEYLEASE_TEST_DATABASE_URL").ok() else {
        eprintln!("skipping PostgreSQL device test; KEYLEASE_TEST_DATABASE_URL is unset");
        return;
    };
    let repository = CloudRepository::connect(&database_url, 2).await.unwrap();
    repository.migrate().await.unwrap();
    let app = router(
        CloudApiState::new(
            repository.clone(),
            ControlSigner::generate("devices-test").unwrap(),
            CloudApiConfig {
                admin_token: "devices-test-administrator-token-at-least-32".into(),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let owner_key = key();
    let owner_keys = keys(&owner_key);
    let owner = owner_keys.member_id();
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let account = format!("acct_{suffix}");
    sqlx::query("INSERT INTO relay_accounts(account_id,owner_member_id,recovery_lookup_hash,recovery_kit,created_at) VALUES($1,$2,$3,'{}',now())")
        .bind(&account).bind(&owner).bind(format!("{:x}", Sha256::digest(suffix.as_bytes())))
        .execute(repository.pool()).await.unwrap();
    sqlx::query("INSERT INTO relay_members(member_id,account_id,role,name,sign_public_b64,box_public_b64,created_at) VALUES($1,$2,'owner','laptop',$3,$4,now())")
        .bind(&owner).bind(&account).bind(&owner_keys.sign_public_b64).bind(&owner_keys.box_public_b64)
        .execute(repository.pool()).await.unwrap();

    // An owner invite for a device; an "owner" invite is refused.
    let lookup = format!("LOOKUP{}", &suffix[..12]).to_ascii_uppercase();
    let lookup_hash = keylease_core::relay::relay_digest(lookup.as_bytes());
    let invite = |role: &str| {
        json!({
            "lookup_hash": lookup_hash, "name": "phone",
            "expires_at": Utc::now() + Duration::hours(1),
            "owner_tag_b64": STANDARD.encode([1_u8; 32]), "role": role,
        })
    };
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/relay/invites",
            Some((&owner, &owner_key)),
            invite("owner")
        )
        .await
        .0,
        400
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/relay/invites",
            Some((&owner, &owner_key)),
            invite("device")
        )
        .await
        .0,
        200
    );
    let (status, seen) = call(
        &app,
        "GET",
        &format!("/v1/relay/invites/{lookup}"),
        None,
        Value::Null,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(seen["role"], "device");

    let device_key = key();
    let device_keys = keys(&device_key);
    let (status, joined) = call(
        &app,
        "POST",
        "/v1/relay/join",
        None,
        json!({
            "lookup": lookup, "keys": device_keys, "node_tag_b64": STANDARD.encode([2_u8; 32]),
        }),
    )
    .await;
    assert_eq!(status, 200, "{joined:?}");
    let device = joined["member_id"].as_str().unwrap().to_owned();
    let (_, members) = call(
        &app,
        "GET",
        "/v1/relay/members",
        Some((&owner, &owner_key)),
        Value::Null,
    )
    .await;
    assert!(
        members
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["member_id"] == device.as_str() && m["role"] == "device")
    );

    let envelope = |from: &str, to: &str, kind: &str| {
        json!({
            "message_id": format!("msg_{}", uuid::Uuid::now_v7().simple()),
            "account_id": account, "from_member_id": from, "to_member_id": to,
            "kind": kind, "object_id": "item_1", "revision": 1,
            "sealed_json": "{}", "signature_b64": STANDARD.encode([0_u8; 64]),
            "created_at": Utc::now(),
        })
    };
    // sync flows both ways; node message kinds do not reach a device.
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/relay/messages",
            Some((&owner, &owner_key)),
            envelope(&owner, &device, "sync")
        )
        .await
        .0,
        200
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/relay/messages",
            Some((&device, &device_key)),
            envelope(&device, &owner, "sync")
        )
        .await
        .0,
        200
    );
    assert_ne!(
        call(
            &app,
            "POST",
            "/v1/relay/messages",
            Some((&owner, &owner_key)),
            envelope(&owner, &device, "share")
        )
        .await
        .0,
        200
    );
    assert_ne!(
        call(
            &app,
            "POST",
            "/v1/relay/messages",
            Some((&device, &device_key)),
            envelope(&device, &owner, "share_request")
        )
        .await
        .0,
        200
    );
}
