use chrono::Utc;
use keylease_core::{ConnectionId, CredentialLeaseId};
use leasegate_credentials::{
    CREDENTIAL_CONTRACT_VERSION, CredentialBackend, CredentialKind, CredentialLeaseRequest,
    CredentialMaterial, PostgresRoleBackend, PostgresRoleConfig,
};
use std::collections::BTreeMap;

#[tokio::test]
async fn postgresql_backend_creates_expiring_role_and_disables_it_on_revoke() {
    let Some(database_url) = std::env::var("KEYLEASE_TEST_DATABASE_URL").ok() else {
        eprintln!(
            "skipping PostgreSQL credential backend test; KEYLEASE_TEST_DATABASE_URL is unset"
        );
        return;
    };
    let directory = tempfile::tempdir().unwrap();
    let secret_path = directory.path().join("database-url");
    std::fs::write(&secret_path, &database_url).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let connection_id = ConnectionId("conn_backend_test".into());
    let backend = PostgresRoleBackend::connect(PostgresRoleConfig {
        backend_id: "postgres-test".into(),
        connection_id: connection_id.clone(),
        database_url_file: secret_path,
        advertised_host: "127.0.0.1".into(),
        advertised_port: 55435,
        advertised_database: "leasegate_test".into(),
        grant_role: "pg_read_all_data".into(),
        role_prefix: "lgtest".into(),
        maximum_ttl_seconds: 300,
        tls_required: false,
    })
    .await
    .unwrap();
    let lease_id = CredentialLeaseId::new();
    let issue = backend
        .issue(
            &lease_id,
            &CredentialLeaseRequest {
                schema_version: CREDENTIAL_CONTRACT_VERSION,
                connection_id,
                backend_id: "postgres-test".into(),
                kind: CredentialKind::PostgresqlRole,
                target: "leasegate_test".into(),
                requested_ttl_seconds: 120,
                idempotency_key: "postgres-backend-test".into(),
                task_id: None,
                approval_id: None,
                claims: BTreeMap::new(),
            },
            120,
            Utc::now(),
        )
        .await
        .unwrap();
    let CredentialMaterial::Postgresql {
        username, password, ..
    } = &issue.credential
    else {
        panic!("expected PostgreSQL credential")
    };
    assert!(password.starts_with("lgdb_"));
    assert!(!format!("{issue:?}").contains(password));
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let can_login: bool = sqlx::query_scalar("SELECT rolcanlogin FROM pg_roles WHERE rolname=$1")
        .bind(username)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(can_login);
    backend
        .revoke(issue.revocation_handle.as_deref())
        .await
        .unwrap();
    let can_login: bool = sqlx::query_scalar("SELECT rolcanlogin FROM pg_roles WHERE rolname=$1")
        .bind(username)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!can_login);
}
