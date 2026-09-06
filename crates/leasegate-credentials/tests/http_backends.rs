use axum::{
    Router,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{SecondsFormat, Utc};
use ed25519_dalek::{Signer, SigningKey};
use keylease_core::{ConnectionId, CredentialLeaseId};
use leasegate_credentials::{
    AwsStsWebIdentityBackend, AwsStsWebIdentityConfig, CREDENTIAL_CONTRACT_VERSION,
    CredentialBackend, CredentialKind, CredentialLeaseRequest, CredentialMaterial,
    OAuthTokenExchangeBackend, OAuthTokenExchangeConfig,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

fn secret_file(directory: &tempfile::TempDir, name: &str, value: &str) -> std::path::PathBuf {
    let path = directory.path().join(name);
    std::fs::write(&path, value).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

async fn server(router: Router) -> (url::Url, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (
        url::Url::parse(&format!("http://{address}/token")).unwrap(),
        task,
    )
}

#[tokio::test]
async fn oauth_exchange_enforces_audience_scope_and_real_expiry() {
    let router =
        Router::new().route(
            "/token",
            post(|body: Bytes| async move {
                let form = String::from_utf8(body.to_vec()).unwrap();
                assert!(form.contains(
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"
                ));
                assert!(form.contains("subject_token=upstream-subject-token"));
                axum::Json(serde_json::json!({
                    "access_token":"downstream-access-token",
                    "token_type":"Bearer",
                    "issued_token_type":"urn:ietf:params:oauth:token-type:access_token",
                    "expires_in":60,
                    "scope":"issues:read"
                }))
            }),
        );
    let (endpoint, server) = server(router).await;
    let directory = tempfile::tempdir().unwrap();
    let connection_id = ConnectionId("conn_oauth".into());
    let backend = OAuthTokenExchangeBackend::new(OAuthTokenExchangeConfig {
        backend_id: "oauth-test".into(),
        connection_id: connection_id.clone(),
        token_endpoint: endpoint,
        subject_token_file: secret_file(&directory, "subject-token", "upstream-subject-token"),
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".into(),
        client_id: "leasegate-test".into(),
        client_secret_file: None,
        allowed_audiences: BTreeSet::from(["issue-api".into()]),
        allowed_scopes: BTreeSet::from(["issues:read".into()]),
        maximum_ttl_seconds: 120,
    })
    .unwrap();
    let now = Utc::now();
    let request = CredentialLeaseRequest {
        schema_version: CREDENTIAL_CONTRACT_VERSION,
        connection_id,
        backend_id: "oauth-test".into(),
        kind: CredentialKind::OAuthTokenExchange,
        target: "issue-api".into(),
        requested_ttl_seconds: 60,
        idempotency_key: "oauth-test".into(),
        task_id: None,
        approval_id: None,
        claims: BTreeMap::from([
            ("audience".into(), "issue-api".into()),
            ("scope".into(), "issues:read".into()),
        ]),
    };
    let issue = backend
        .issue(&CredentialLeaseId::new(), &request, 60, now)
        .await
        .unwrap();
    assert_eq!(issue.expires_at, now + chrono::Duration::seconds(60));
    assert!(matches!(
        &issue.credential,
        CredentialMaterial::OAuth { access_token, .. } if access_token == "downstream-access-token"
    ));
    let mut unsafe_request = request;
    unsafe_request
        .claims
        .insert("dpop_jkt".into(), "unverified-thumbprint".into());
    assert!(
        backend
            .issue(&CredentialLeaseId::new(), &unsafe_request, 60, now)
            .await
            .is_err()
    );
    server.abort();
}

#[tokio::test]
async fn oauth_exchange_verifies_dpop_and_provider_confirmation() {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let public = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
    let jwk = serde_json::json!({"kty":"OKP","crv":"Ed25519","x":public});
    let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(
        serde_json_canonicalizer::to_vec(&jwk).unwrap(),
    ));
    let confirmed_jkt = jkt.clone();
    let router = Router::new().route(
        "/token",
        post(move |headers: HeaderMap| {
            let confirmed_jkt = confirmed_jkt.clone();
            async move {
                assert!(headers.get("dpop").is_some());
                axum::Json(serde_json::json!({
                    "access_token":"dpop-bound-token",
                    "token_type":"DPoP",
                    "expires_in":60,
                    "cnf":{"jkt":confirmed_jkt}
                }))
            }
        }),
    );
    let (endpoint, server) = server(router).await;
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({"typ":"dpop+jwt","alg":"EdDSA","jwk":jwk})).unwrap(),
    );
    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({
            "htm":"POST","htu":endpoint.as_str(),"iat":Utc::now().timestamp(),"jti":"proof-1"
        }))
        .unwrap(),
    );
    let input = format!("{header}.{claims}");
    let proof = format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(signing_key.sign(input.as_bytes()).to_bytes())
    );
    let directory = tempfile::tempdir().unwrap();
    let connection_id = ConnectionId("conn_dpop".into());
    let backend = OAuthTokenExchangeBackend::new(OAuthTokenExchangeConfig {
        backend_id: "oauth-dpop".into(),
        connection_id: connection_id.clone(),
        token_endpoint: endpoint,
        subject_token_file: secret_file(&directory, "subject", "subject-token"),
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".into(),
        client_id: "leasegate-test".into(),
        client_secret_file: None,
        allowed_audiences: BTreeSet::from(["api".into()]),
        allowed_scopes: BTreeSet::new(),
        maximum_ttl_seconds: 60,
    })
    .unwrap();
    let request = CredentialLeaseRequest {
        schema_version: CREDENTIAL_CONTRACT_VERSION,
        connection_id,
        backend_id: "oauth-dpop".into(),
        kind: CredentialKind::OAuthTokenExchange,
        target: "api".into(),
        requested_ttl_seconds: 60,
        idempotency_key: "dpop-test".into(),
        task_id: None,
        approval_id: None,
        claims: BTreeMap::from([
            ("audience".into(), "api".into()),
            ("dpop_proof".into(), proof),
        ]),
    };
    let issue = backend
        .issue(&CredentialLeaseId::new(), &request, 60, Utc::now())
        .await
        .unwrap();
    assert!(
        matches!(&issue.sender_constraint, leasegate_credentials::SenderConstraint::Dpop { jkt: actual } if actual == &jkt)
    );
    assert!(
        backend
            .issue(&CredentialLeaseId::new(), &request, 60, Utc::now())
            .await
            .is_err()
    );
    server.abort();
}

#[tokio::test]
async fn aws_web_identity_parses_only_bounded_short_lived_credentials() {
    let expiration =
        (Utc::now() + chrono::Duration::seconds(900)).to_rfc3339_opts(SecondsFormat::Secs, true);
    let router = Router::new().route(
        "/token",
        post(move |body: Bytes| {
            let expiration = expiration.clone();
            async move {
                let form = String::from_utf8(body.to_vec()).unwrap();
                assert!(form.contains("Action=AssumeRoleWithWebIdentity"));
                assert!(form.contains("WebIdentityToken=web-identity-fixture"));
                format!(
                    "<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>temporary-access</AccessKeyId><SecretAccessKey>temporary-secret</SecretAccessKey><SessionToken>temporary-session</SessionToken><Expiration>{expiration}</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>"
                )
            }
        }),
    );
    let (endpoint, server) = server(router).await;
    let directory = tempfile::tempdir().unwrap();
    let role = "arn:aws:iam::123456789012:role/leasegate-test";
    let connection_id = ConnectionId("conn_aws".into());
    let backend = AwsStsWebIdentityBackend::new(AwsStsWebIdentityConfig {
        backend_id: "aws-test".into(),
        connection_id: connection_id.clone(),
        endpoint,
        role_arn: role.into(),
        web_identity_token_file: secret_file(
            &directory,
            "web-identity-token",
            "web-identity-fixture",
        ),
        minimum_ttl_seconds: 900,
        maximum_ttl_seconds: 900,
    })
    .unwrap();
    let now = Utc::now();
    let issue = backend
        .issue(
            &CredentialLeaseId::new(),
            &CredentialLeaseRequest {
                schema_version: CREDENTIAL_CONTRACT_VERSION,
                connection_id,
                backend_id: "aws-test".into(),
                kind: CredentialKind::AwsSts,
                target: role.into(),
                requested_ttl_seconds: 900,
                idempotency_key: "aws-test".into(),
                task_id: None,
                approval_id: None,
                claims: BTreeMap::new(),
            },
            900,
            now,
        )
        .await
        .unwrap();
    assert!(matches!(
        &issue.credential,
        CredentialMaterial::Aws { session_token, .. } if session_token == "temporary-session"
    ));
    assert!(!format!("{issue:?}").contains("temporary-secret"));
    server.abort();
}

#[tokio::test]
async fn token_exchange_does_not_follow_secret_bearing_redirects() {
    let leaked = Arc::new(AtomicBool::new(false));
    let observed = leaked.clone();
    let router = Router::new()
        .route(
            "/token",
            post(|| async {
                (
                    StatusCode::TEMPORARY_REDIRECT,
                    [("location", "/leak")],
                    "redirect",
                )
            }),
        )
        .route(
            "/leak",
            post(move || {
                let observed = observed.clone();
                async move {
                    observed.store(true, Ordering::Release);
                    StatusCode::OK
                }
            }),
        );
    let (endpoint, server) = server(router).await;
    let directory = tempfile::tempdir().unwrap();
    let backend = OAuthTokenExchangeBackend::new(OAuthTokenExchangeConfig {
        backend_id: "oauth-redirect".into(),
        connection_id: ConnectionId("conn_oauth_redirect".into()),
        token_endpoint: endpoint,
        subject_token_file: secret_file(&directory, "subject", "must-not-leak"),
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".into(),
        client_id: "leasegate-test".into(),
        client_secret_file: None,
        allowed_audiences: BTreeSet::from(["api".into()]),
        allowed_scopes: BTreeSet::new(),
        maximum_ttl_seconds: 60,
    })
    .unwrap();
    let result = backend
        .issue(
            &CredentialLeaseId::new(),
            &CredentialLeaseRequest {
                schema_version: CREDENTIAL_CONTRACT_VERSION,
                connection_id: ConnectionId("conn_oauth_redirect".into()),
                backend_id: "oauth-redirect".into(),
                kind: CredentialKind::OAuthTokenExchange,
                target: "api".into(),
                requested_ttl_seconds: 60,
                idempotency_key: "redirect-test".into(),
                task_id: None,
                approval_id: None,
                claims: BTreeMap::from([("audience".into(), "api".into())]),
            },
            60,
            Utc::now(),
        )
        .await;
    assert!(result.is_err());
    assert!(!leaked.load(Ordering::Acquire));
    server.abort();
}
