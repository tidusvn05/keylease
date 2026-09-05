use chrono::{Duration, Utc};
use keylease_cloud::CloudRepository;
use keylease_core::{
    AccountId, AgentId, ApprovalId, ApprovalSemanticSummary, ConnectionId, DeviceId, ItemId,
    PolicyBundleId, RequestId, RiskTier, SyncMutationId, VaultId,
};
use leasegate_control::{
    ApprovalRequest, CONTROL_CONTRACT_VERSION, ControlEvent, OfflineAuthorization,
    PolicyBundlePayload, Revocation, RevocationScope, SyncMutationEnvelope, SyncMutationStatus,
};
use leasegate_policy_bundle::{ControlSigner, verify_policy_bundle};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

#[tokio::test]
async fn phase3_postgres_contracts_are_tenant_scoped_and_ciphertext_only() {
    let Some(database_url) = std::env::var("KEYLEASE_TEST_DATABASE_URL").ok() else {
        eprintln!("skipping PostgreSQL integration test; KEYLEASE_TEST_DATABASE_URL is unset");
        return;
    };
    let repository = CloudRepository::connect(&database_url, 5).await.unwrap();
    repository.migrate().await.unwrap();

    let account = AccountId::new();
    let (organization, project, _) = repository
        .bootstrap_tenant(
            account.clone(),
            "Phase 3 integration organization",
            "primary",
            "https://issuer.test",
            &format!("subject-{}", account.0),
            "Test owner",
        )
        .await
        .unwrap();
    let other_account = AccountId::new();
    let (other_organization, other_project, _) = repository
        .bootstrap_tenant(
            other_account.clone(),
            "Other integration organization",
            "primary",
            "https://issuer.test",
            &format!("subject-{}", other_account.0),
            "Other owner",
        )
        .await
        .unwrap();

    let created_agent = repository
        .register_agent(&organization.id, &project.id, "integration-agent")
        .await
        .unwrap();
    assert!(created_agent.credential.starts_with("kla_"));
    assert_ne!(
        created_agent.credential,
        created_agent.registration.credential_digest
    );
    let stored_digest: String =
        sqlx::query_scalar("SELECT credential_digest FROM agents WHERE agent_id=$1")
            .bind(&created_agent.registration.agent_id.0)
            .fetch_one(repository.pool())
            .await
            .unwrap();
    assert_eq!(
        stored_digest,
        hex(&Sha256::digest(created_agent.credential.as_bytes()))
    );

    let signer = ControlSigner::generate("integration-control").unwrap();
    let now = Utc::now();
    let first = signer
        .sign_policy(PolicyBundlePayload {
            schema_version: CONTROL_CONTRACT_VERSION,
            bundle_id: PolicyBundleId::new(),
            organization_id: organization.id.clone(),
            project_id: project.id.clone(),
            version: 1,
            previous_bundle_digest: None,
            issued_at: now,
            not_before: now - Duration::seconds(1),
            expires_at: now + Duration::hours(1),
            revocation_epoch: 0,
            minimum_edge_version: "0.1.0".into(),
            offline: OfflineAuthorization {
                allow_r0_r1: true,
                max_seconds: 300,
            },
            rules: vec![],
        })
        .unwrap();
    verify_policy_bundle(&first, &signer.verifying_key_base64(), now, None).unwrap();
    let first_event = repository.activate_policy(&first).await.unwrap();
    assert_eq!(first_event.sequence, 1);

    let other_bundle = signer
        .sign_policy(PolicyBundlePayload {
            schema_version: CONTROL_CONTRACT_VERSION,
            bundle_id: PolicyBundleId::new(),
            organization_id: other_organization.id.clone(),
            project_id: other_project.id.clone(),
            version: 1,
            previous_bundle_digest: None,
            issued_at: now,
            not_before: now - Duration::seconds(1),
            expires_at: now + Duration::hours(1),
            revocation_epoch: 0,
            minimum_edge_version: "0.1.0".into(),
            offline: OfflineAuthorization::default(),
            rules: vec![],
        })
        .unwrap();
    let other_event = repository.activate_policy(&other_bundle).await.unwrap();
    assert_eq!(
        other_event.sequence, 1,
        "control cursors are per organization"
    );
    let persisted_first_event: serde_json::Value = sqlx::query_scalar(
        "SELECT event_json FROM control_events WHERE organization_id=$1 AND sequence=1",
    )
    .bind(&organization.id.0)
    .fetch_one(repository.pool())
    .await
    .unwrap();
    let persisted_first_event: ControlEvent =
        serde_json::from_value(persisted_first_event).unwrap();
    assert_eq!(persisted_first_event.organization_id, organization.id);
    assert_eq!(persisted_first_event.project_id, Some(project.id.clone()));

    let revocation_event = repository
        .append_revocation(&Revocation {
            organization_id: organization.id.clone(),
            project_id: Some(project.id.clone()),
            epoch: 1,
            scope: RevocationScope::Task,
            target_id: "task-revoked".into(),
            reason: "integration test".into(),
            created_at: now,
        })
        .await
        .unwrap();
    assert_eq!(revocation_event.sequence, 2);

    let device_id = DeviceId::new();
    repository
        .register_device_key(&account, &device_id, &signer.verifying_key_base64())
        .await
        .unwrap();
    let enrollment = repository
        .create_edge_enrollment(
            &organization.id,
            &project.id,
            "integration-edge",
            Duration::minutes(5),
        )
        .await
        .unwrap();
    let enrolled = repository
        .enroll_edge(
            &enrollment.secret,
            device_id.clone(),
            &signer.verifying_key_base64(),
            "0.1.0",
        )
        .await
        .unwrap();
    assert!(
        repository
            .authenticate_edge(
                &enrolled.edge.id,
                "wrong-edge-credential-that-is-long-enough"
            )
            .await
            .is_err()
    );
    assert_eq!(
        repository
            .authenticate_edge(&enrolled.edge.id, &enrolled.credential)
            .await
            .unwrap()
            .project_id,
        project.id
    );
    let edge_credential_in_database: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM edges WHERE edge_id=$1 AND credential_digest=$2")
            .bind(&enrolled.edge.id.0)
            .bind(&enrolled.credential)
            .fetch_one(repository.pool())
            .await
            .unwrap();
    assert_eq!(edge_credential_in_database, 0);
    let vault_id = VaultId::new();
    repository
        .create_vault(
            &account,
            Some(&organization.id),
            &vault_id,
            "opaque-encrypted-header",
        )
        .await
        .unwrap();
    let ciphertext = "opaque-aead-envelope-that-is-not-the-plaintext";
    let mut mutation = SyncMutationEnvelope {
        schema_version: CONTROL_CONTRACT_VERSION,
        mutation_id: SyncMutationId::new(),
        account_id: account.clone(),
        vault_id: vault_id.clone(),
        object_id: ItemId::new().0,
        device_id,
        base_revision: 0,
        result_revision: 1,
        idempotency_key: "sync-once".into(),
        ciphertext: ciphertext.into(),
        ciphertext_digest: hex(&Sha256::digest(ciphertext.as_bytes())),
        tombstone: false,
        created_at: now,
        device_signature_base64: String::new(),
    };
    signer.sign_sync_mutation(&mut mutation).unwrap();
    let pushed = repository
        .push_sync(&account, &vault_id, vec![mutation.clone()])
        .await
        .unwrap();
    assert_eq!(pushed.results[0].status, SyncMutationStatus::Applied);
    let replay = repository
        .push_sync(&account, &vault_id, vec![mutation])
        .await
        .unwrap();
    assert_eq!(replay.results[0].status, SyncMutationStatus::Replay);
    let persisted: String =
        sqlx::query_scalar("SELECT ciphertext FROM vault_objects WHERE vault_id=$1 LIMIT 1")
            .bind(&vault_id.0)
            .fetch_one(repository.pool())
            .await
            .unwrap();
    assert_eq!(persisted, ciphertext);
    assert!(!persisted.contains("fixture plaintext secret"));

    let approval = ApprovalRequest {
        schema_version: CONTROL_CONTRACT_VERSION,
        approval_id: ApprovalId::new(),
        organization_id: organization.id.clone(),
        project_id: project.id.clone(),
        agent_id: AgentId("agent-approval".into()),
        workload_id: None,
        on_behalf_of: None,
        task_id: Some("task-approval".into()),
        connection_id: ConnectionId("conn-approval".into()),
        action: "github.issue.create".into(),
        resource: "github://owner/repo".into(),
        request_digest_hex: "exact-request-digest".into(),
        policy_version: 1,
        risk: RiskTier::R2,
        summary: ApprovalSemanticSummary {
            operation: "Create GitHub issue".into(),
            target: "github://owner/repo".into(),
            changed_fields: vec!["title".into(), "body".into()],
            argument_fingerprints: vec![],
            blast_radius: "one issue".into(),
        },
        created_at: now,
        expires_at: now + Duration::minutes(5),
    };
    repository.create_approval(&approval).await.unwrap();
    let pending = repository
        .pending_approvals(&organization.id, &project.id, 50)
        .await
        .unwrap();
    assert!(
        pending
            .iter()
            .any(|value| value.approval_id == approval.approval_id)
    );

    let _ = RequestId::new();
}
