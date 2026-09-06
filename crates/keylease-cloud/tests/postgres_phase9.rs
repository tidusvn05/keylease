use axum::{body::Body, http::Request};
use chrono::Utc;
use http_body_util::BodyExt;
use keylease_cloud::{CloudApiConfig, CloudApiState, CloudRepository, router};
use leasegate_policy_bundle::ControlSigner;
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt};
use tower::ServiceExt;

#[tokio::test]
async fn phase9_host_status_is_authenticated_redacted_and_freshness_checked() {
    let Some(database_url) = std::env::var("KEYLEASE_TEST_DATABASE_URL").ok() else {
        eprintln!("skipping PostgreSQL Phase 9 test; KEYLEASE_TEST_DATABASE_URL is unset");
        return;
    };
    let repository = CloudRepository::connect(&database_url, 2).await.unwrap();
    repository.migrate().await.unwrap();
    let directory = tempfile::tempdir().unwrap();
    let status_file = directory.path().join("operations-status.json");
    fs::write(
        &status_file,
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "available": true,
            "profile": "single_vps",
            "generated_at": Utc::now(),
            "release_id": "phase9-test",
            "healthy": true,
            "issues": [],
            "services": {"expected": 6, "running": 6, "control_plane_ready": true, "gateway_ready": true},
            "disk": {"used_percent": 25},
            "backup": {"age_seconds": 60},
            "tls": {"expiry_seconds": 86400},
            "soak": {"consecutive_seconds": 300, "failures": 0}
        }))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&status_file, fs::Permissions::from_mode(0o644)).unwrap();
    let application = router(
        CloudApiState::new(
            repository,
            ControlSigner::generate("phase9-test").unwrap(),
            CloudApiConfig {
                admin_token: "phase9-administrator-token-at-least-32-bytes".into(),
                maximum_body_bytes: 1024 * 1024,
                operations_status_file: Some(status_file),
            },
        )
        .unwrap(),
    );

    let unauthorized = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/system/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 403);

    let authorized = application
        .oneshot(
            Request::builder()
                .uri("/v1/system/status")
                .header(
                    "authorization",
                    "Bearer phase9-administrator-token-at-least-32-bytes",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorized.status(), 200);
    let body = authorized.into_body().collect().await.unwrap().to_bytes();
    let status: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status["profile"], "single_vps");
    assert_eq!(status["healthy"], true);
    assert_eq!(status["stale"], false);
    assert!(status.get("credential").is_none());
    assert!(status.get("environment").is_none());
}
