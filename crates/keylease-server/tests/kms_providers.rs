//! The KMS root key wrapped by AWS KMS, Google Cloud KMS (mock services) and
//! a PKCS#11 token (SoftHSM, when `KEYLEASE_TEST_PKCS11_MODULE` is set and
//! the `pkcs11` feature is on).

use axum::{
    Json, Router,
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use keylease_server::kms_root::{
    AwsCredentials, AwsKms, GcpKms, KmsSettings, RootKeyProvider, load_root_key, wrap_root_key,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// The mock "encryption": a reversible marker the test can recognize.
fn seal(plain: &[u8]) -> Vec<u8> {
    let mut out = b"sealed:".to_vec();
    out.extend(plain.iter().map(|byte| byte ^ 0x5a));
    out
}

fn open(sealed: &[u8]) -> Option<Vec<u8>> {
    sealed
        .strip_prefix(b"sealed:".as_slice())
        .map(|rest| rest.iter().map(|byte| byte ^ 0x5a).collect())
}

async fn aws(headers: HeaderMap, body: axum::body::Bytes) -> Response {
    let body: Value = serde_json::from_slice(&body).unwrap();
    let authorization = headers["authorization"].to_str().unwrap();
    assert!(
        authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIDTEST/"),
        "{authorization}"
    );
    assert!(authorization.contains("/eu-west-1/kms/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature="));
    assert_eq!(headers["x-amz-security-token"], "session-token");
    assert_eq!(headers["content-type"], "application/x-amz-json-1.1");
    match headers["x-amz-target"].to_str().unwrap() {
        "TrentService.Encrypt" => {
            assert_eq!(body["KeyId"], "alias/keylease");
            let plain = STANDARD
                .decode(body["Plaintext"].as_str().unwrap())
                .unwrap();
            Json(json!({"CiphertextBlob": STANDARD.encode(seal(&plain)), "KeyId": "arn:aws:kms:eu-west-1:1:key/k"})).into_response()
        }
        "TrentService.Decrypt" => match open(
            &STANDARD
                .decode(body["CiphertextBlob"].as_str().unwrap())
                .unwrap(),
        ) {
            Some(plain) => Json(json!({"Plaintext": STANDARD.encode(plain)})).into_response(),
            None => (
                StatusCode::BAD_REQUEST,
                Json(json!({"__type": "InvalidCiphertextException"})),
            )
                .into_response(),
        },
        _ => StatusCode::BAD_REQUEST.into_response(),
    }
}

async fn gcp_token(headers: HeaderMap) -> Json<Value> {
    assert_eq!(headers["metadata-flavor"], "Google");
    Json(json!({"access_token": "gcp-token", "expires_in": 3600}))
}

async fn gcp_kms(
    Path(path): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    assert_eq!(headers["authorization"], "Bearer gcp-token");
    let (key, operation) = path.rsplit_once(':').unwrap();
    assert_eq!(
        key,
        "projects/p/locations/global/keyRings/r/cryptoKeys/root"
    );
    match operation {
        "encrypt" => {
            let plain = STANDARD
                .decode(body["plaintext"].as_str().unwrap())
                .unwrap();
            Json(json!({"ciphertext": STANDARD.encode(seal(&plain))})).into_response()
        }
        "decrypt" => match open(
            &STANDARD
                .decode(body["ciphertext"].as_str().unwrap())
                .unwrap(),
        ) {
            Some(plain) => Json(json!({"plaintext": STANDARD.encode(plain)})).into_response(),
            None => (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": {"message": "Decryption failed"}})),
            )
                .into_response(),
        },
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    address.to_string()
}

/// Wraps a key, writes the wrapped file, loads it back.
async fn round_trip(provider: RootKeyProvider) -> (Vec<u8>, [u8; 32]) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("root.wrapped");
    let settings = KmsSettings {
        provider,
        wrapped_file: Some(path.clone()),
    };
    let key = [42_u8; 32];
    let wrapped = wrap_root_key(&settings, &key).await.unwrap();
    std::fs::write(&path, format!("{wrapped}\n")).unwrap();
    let loaded = load_root_key(&settings).await.unwrap();
    // A wrapped file the provider cannot open is an error, not a key.
    std::fs::write(&path, STANDARD.encode(b"garbage")).unwrap();
    assert!(load_root_key(&settings).await.is_err());
    (STANDARD.decode(wrapped).unwrap(), *loaded)
}

#[tokio::test]
async fn aws_kms_wraps_the_root_key() {
    let address = serve(Router::new().route("/", post(aws))).await;
    let (wrapped, loaded) = round_trip(RootKeyProvider::Aws(AwsKms {
        region: "eu-west-1".into(),
        key_id: Some("alias/keylease".into()),
        endpoint: Some(format!("http://{address}")),
        credentials: Some(AwsCredentials {
            access_key_id: "AKIDTEST".into(),
            secret_access_key: Zeroizing::new("secret".into()),
            session_token: Some(Zeroizing::new("session-token".into())),
        }),
    }))
    .await;
    assert!(wrapped.starts_with(b"sealed:"));
    assert!(!wrapped.windows(32).any(|window| window == [42_u8; 32]));
    assert_eq!(loaded, [42_u8; 32]);
}

#[tokio::test]
async fn google_cloud_kms_wraps_the_root_key() {
    let address = serve(
        Router::new()
            .route(
                "/computeMetadata/v1/instance/service-accounts/default/token",
                get(gcp_token),
            )
            .route("/v1/{*path}", post(gcp_kms)),
    )
    .await;
    let (wrapped, loaded) = round_trip(RootKeyProvider::Gcp(GcpKms {
        key: "projects/p/locations/global/keyRings/r/cryptoKeys/root".into(),
        endpoint: Some(format!("http://{address}")),
        credentials_file: None,
        metadata_host: Some(address.clone()),
    }))
    .await;
    assert!(wrapped.starts_with(b"sealed:"));
    assert_eq!(loaded, [42_u8; 32]);
}

#[cfg(feature = "pkcs11")]
#[tokio::test]
async fn a_pkcs11_token_wraps_the_root_key() {
    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use cryptoki::mechanism::Mechanism;
    use cryptoki::object::Attribute;
    use cryptoki::session::UserType;
    use cryptoki::types::AuthPin;
    let Some(module) = std::env::var("KEYLEASE_TEST_PKCS11_MODULE").ok() else {
        eprintln!("skipping PKCS#11 test; KEYLEASE_TEST_PKCS11_MODULE is unset");
        return;
    };
    let token =
        std::env::var("KEYLEASE_TEST_PKCS11_TOKEN").unwrap_or_else(|_| "keylease-test".into());
    let pin = std::env::var("KEYLEASE_TEST_PKCS11_PIN").unwrap_or_else(|_| "1234".into());
    let label = format!("keylease-root-{}", uuid::Uuid::now_v7().simple());
    {
        // Make the AES key on the token, as an operator would.
        let pkcs11 = Pkcs11::new(&module).unwrap();
        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .unwrap();
        let slot = pkcs11
            .get_slots_with_token()
            .unwrap()
            .into_iter()
            .find(|slot| pkcs11.get_token_info(*slot).unwrap().label().trim() == token)
            .unwrap();
        let session = pkcs11.open_rw_session(slot).unwrap();
        session
            .login(UserType::User, Some(&AuthPin::from(pin.clone())))
            .unwrap();
        session
            .generate_key(
                &Mechanism::AesKeyGen,
                &[
                    Attribute::Token(true),
                    Attribute::Label(label.as_bytes().to_vec()),
                    Attribute::ValueLen(32.into()),
                    Attribute::Encrypt(true),
                    Attribute::Decrypt(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                ],
            )
            .unwrap();
        pkcs11.finalize().unwrap();
    }
    let (wrapped, loaded) = round_trip(RootKeyProvider::Pkcs11(
        keylease_server::kms_root::Pkcs11Kms {
            module: module.into(),
            token_label: token,
            pin: Zeroizing::new(pin),
            key_label: label,
        },
    ))
    .await;
    assert_eq!(wrapped.len(), 12 + 32 + 16);
    assert_eq!(loaded, [42_u8; 32]);
}
