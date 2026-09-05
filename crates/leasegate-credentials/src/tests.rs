use super::*;
use async_trait::async_trait;
use chrono::Utc;
use keylease_core::{ActorContext, AgentId, ConnectionId, CredentialLeaseId};
use std::{collections::BTreeMap, sync::Mutex};

#[derive(Default)]
struct MemoryRepository {
    rows: Mutex<Vec<(CredentialLeaseRecord, String, Option<String>)>>,
}

impl CredentialLeaseRepository for MemoryRepository {
    fn find_idempotent(
        &self,
        agent_id: &AgentId,
        idempotency_key: &str,
    ) -> Result<Option<CredentialLeaseRecord>> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .find(|(record, key, _)| &record.agent_id == agent_id && key == idempotency_key)
            .map(|row| row.0.clone()))
    }

    fn begin(&self, record: &CredentialLeaseRecord, key: &str) -> Result<()> {
        self.rows
            .lock()
            .unwrap()
            .push((record.clone(), key.into(), None));
        Ok(())
    }

    fn activate(&self, record: &CredentialLeaseRecord, handle: Option<&str>) -> Result<()> {
        let mut rows = self.rows.lock().unwrap();
        let row = rows
            .iter_mut()
            .find(|row| row.0.lease_id == record.lease_id)
            .unwrap();
        row.0 = record.clone();
        row.2 = handle.map(str::to_owned);
        Ok(())
    }

    fn fail(&self, lease_id: &CredentialLeaseId, code: &str) -> Result<()> {
        let mut rows = self.rows.lock().unwrap();
        let row = rows
            .iter_mut()
            .find(|row| &row.0.lease_id == lease_id)
            .unwrap();
        row.0.state = CredentialLeaseState::Failed;
        row.0.failure_code = Some(code.into());
        Ok(())
    }

    fn get_with_handle(
        &self,
        lease_id: &CredentialLeaseId,
    ) -> Result<Option<(CredentialLeaseRecord, Option<String>)>> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .find(|row| &row.0.lease_id == lease_id)
            .map(|row| (row.0.clone(), row.2.clone())))
    }

    fn list_for_agent(&self, agent_id: &AgentId) -> Result<Vec<CredentialLeaseRecord>> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|row| &row.0.agent_id == agent_id)
            .map(|row| row.0.clone())
            .collect())
    }

    fn list_reapable(&self, now: chrono::DateTime<Utc>) -> Result<Vec<CredentialLeaseRecord>> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|row| {
                row.0.state == CredentialLeaseState::Revoking
                    || (row.0.state == CredentialLeaseState::Pending
                        && row.0.issued_at <= now - chrono::Duration::minutes(5))
                    || (row.0.state == CredentialLeaseState::Active && row.0.expires_at <= now)
            })
            .map(|row| row.0.clone())
            .collect())
    }

    fn mark_revoking(&self, lease_id: &CredentialLeaseId) -> Result<()> {
        let mut rows = self.rows.lock().unwrap();
        rows.iter_mut()
            .find(|row| &row.0.lease_id == lease_id)
            .unwrap()
            .0
            .state = CredentialLeaseState::Revoking;
        Ok(())
    }

    fn mark_terminal(
        &self,
        lease_id: &CredentialLeaseId,
        state: CredentialLeaseState,
        now: chrono::DateTime<Utc>,
    ) -> Result<()> {
        let mut rows = self.rows.lock().unwrap();
        let record = &mut rows
            .iter_mut()
            .find(|row| &row.0.lease_id == lease_id)
            .unwrap()
            .0;
        record.state = state;
        record.revoked_at = Some(now);
        Ok(())
    }
}

struct AllowAuthorizer;

#[async_trait]
impl CredentialAuthorizer for AllowAuthorizer {
    async fn authorize(
        &self,
        _actor: &ActorContext,
        _request: &CredentialLeaseRequest,
        _now: chrono::DateTime<Utc>,
    ) -> Result<CredentialAuthorization> {
        Ok(CredentialAuthorization {
            policy_version: 7,
            maximum_ttl_seconds: 120,
        })
    }
}

struct FakeBackend;

#[async_trait]
impl CredentialBackend for FakeBackend {
    fn id(&self) -> &str {
        "db-test"
    }

    fn kind(&self) -> CredentialKind {
        CredentialKind::PostgresqlRole
    }

    fn connection_id(&self) -> &ConnectionId {
        static CONNECTION: std::sync::LazyLock<ConnectionId> =
            std::sync::LazyLock::new(|| ConnectionId("conn_db".into()));
        &CONNECTION
    }

    async fn issue(
        &self,
        lease_id: &CredentialLeaseId,
        _request: &CredentialLeaseRequest,
        ttl: u64,
        now: chrono::DateTime<Utc>,
    ) -> Result<BackendIssue> {
        Ok(BackendIssue {
            credential: CredentialMaterial::Postgresql {
                username: "temporary".into(),
                password: "secret-value".into(),
                host: "db.internal".into(),
                port: 5432,
                database: "app".into(),
                tls_required: true,
            },
            revocation_handle: Some(lease_id.0.clone()),
            expires_at: now + chrono::Duration::seconds(ttl as i64),
            sender_constraint: SenderConstraint::None,
            renewable: false,
        })
    }

    async fn revoke(&self, _revocation_handle: Option<&str>) -> Result<()> {
        Ok(())
    }
}

fn actor() -> ActorContext {
    ActorContext {
        agent_id: AgentId("agent_test".into()),
        workload_id: None,
        human_principal: None,
        on_behalf_of: None,
        client_session_id: "credential-test".into(),
    }
}

fn request() -> CredentialLeaseRequest {
    CredentialLeaseRequest {
        schema_version: CREDENTIAL_CONTRACT_VERSION,
        connection_id: ConnectionId("conn_db".into()),
        backend_id: "db-test".into(),
        kind: CredentialKind::PostgresqlRole,
        target: "app".into(),
        requested_ttl_seconds: 300,
        idempotency_key: "one-request".into(),
        task_id: None,
        approval_id: None,
        claims: BTreeMap::new(),
    }
}

#[tokio::test]
async fn gateway_clamps_ttl_returns_secret_once_and_revokes() {
    let repository = std::sync::Arc::new(MemoryRepository::default());
    let gateway = LocalCredentialGateway::new(
        repository.clone(),
        std::sync::Arc::new(AllowAuthorizer),
        vec![std::sync::Arc::new(FakeBackend)],
    )
    .unwrap();
    let now = Utc::now();
    let issued = gateway.issue(&actor(), request(), now).await.unwrap();
    assert_eq!(
        issued.lease.expires_at,
        now + chrono::Duration::seconds(120)
    );
    assert!(!format!("{issued:?}").contains("secret-value"));
    assert!(matches!(
        gateway.issue(&actor(), request(), now).await,
        Err(KeyLeaseError::IdempotencyConflict)
    ));
    let revoked = gateway
        .revoke(&actor(), &issued.lease.lease_id, now)
        .await
        .unwrap();
    assert_eq!(revoked.state, CredentialLeaseState::Revoked);
}

#[test]
fn request_digest_binds_identity_claims_and_policy() {
    let first = request().digest(&actor(), 1);
    let mut changed = request();
    changed.claims.insert("scope".into(), "read".into());
    assert_ne!(first, changed.digest(&actor(), 1));
    assert_ne!(first, request().digest(&actor(), 2));
}

#[test]
fn credential_debug_never_contains_material() {
    let material = CredentialMaterial::Aws {
        access_key_id: "access-fixture".into(),
        secret_access_key: "secret-fixture".into(),
        session_token: "token-fixture".into(),
    };
    let output = format!("{material:?}");
    assert!(!output.contains("access-fixture"));
    assert!(!output.contains("secret-fixture"));
    assert!(!output.contains("token-fixture"));
}
