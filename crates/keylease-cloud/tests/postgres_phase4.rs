use chrono::{Duration, Utc};
use keylease_cloud::{AuditQueryFilter, CloudRepository};
use keylease_core::{
    AccountId, AuditEvent, ConnectionHealth, ConnectionId, DataBudget, DeviceId, PolicyBundleId,
    PolicyEffect, PolicyProposalId, PolicyRule, RequestId,
};
use leasegate_connector_sdk::{
    CONNECTOR_PACKAGE_VERSION, ConnectorPackagePayload, ConnectorPackageSigner,
};
use leasegate_connectors::notion_manifest;
use leasegate_control::{
    AuditBatch, CONTROL_CONTRACT_VERSION, ConnectionDescriptor, OfflineAuthorization,
    PolicyBundlePayload, PolicyProposal, PolicyProposalDecision, PolicyProposalReviewRequest,
    PolicyProposalStatus,
};
use leasegate_policy_bundle::{ControlSigner, verify_policy_bundle};

#[tokio::test]
async fn phase4_registry_proposal_connections_and_audit_are_tenant_scoped() {
    let Some(database_url) = std::env::var("KEYLEASE_TEST_DATABASE_URL").ok() else {
        eprintln!("skipping PostgreSQL Phase 4 test; KEYLEASE_TEST_DATABASE_URL is unset");
        return;
    };
    let repository = CloudRepository::connect(&database_url, 5).await.unwrap();
    repository.migrate().await.unwrap();
    repository.readiness().await.unwrap();

    let account = AccountId::new();
    let (organization, project, membership) = repository
        .bootstrap_tenant(
            account.clone(),
            "Phase 4 integration organization",
            "platform",
            "https://issuer.phase4.test",
            &format!("subject-{}", account.0),
            "Phase 4 owner",
        )
        .await
        .unwrap();
    let agent_secret = repository
        .register_agent(&organization.id, &project.id, "phase4-agent")
        .await
        .unwrap();
    repository
        .authenticate_agent(
            &organization.id,
            &project.id,
            &agent_secret.registration.agent_id,
            &agent_secret.credential,
        )
        .await
        .unwrap();
    assert!(
        repository
            .authenticate_agent(
                &organization.id,
                &project.id,
                &agent_secret.registration.agent_id,
                "wrong-credential-with-more-than-32-bytes",
            )
            .await
            .is_err()
    );

    let signing_key = [9_u8; 32];
    let key_source =
        ConnectorPackageSigner::from_bytes("bootstrap_identity", &signing_key).unwrap();
    let publisher = repository
        .register_connector_publisher(
            &organization.id,
            &project.id,
            "Integration publisher",
            &key_source.verifying_key_base64(),
        )
        .await
        .unwrap();
    let mismatched_signer =
        ConnectorPackageSigner::from_bytes("wrong_publisher", &signing_key).unwrap();
    let mismatched = mismatched_signer
        .sign(ConnectorPackagePayload {
            schema_version: CONNECTOR_PACKAGE_VERSION,
            manifest: notion_manifest(),
            artifact_digest_sha256: "a".repeat(64),
            published_at: Utc::now(),
        })
        .unwrap();
    assert!(
        repository
            .publish_connector(&organization.id, &project.id, &publisher.id, &mismatched,)
            .await
            .is_err()
    );
    let signer = ConnectorPackageSigner::from_bytes(publisher.id.0.clone(), &signing_key).unwrap();
    let package = signer
        .sign(ConnectorPackagePayload {
            schema_version: CONNECTOR_PACKAGE_VERSION,
            manifest: notion_manifest(),
            artifact_digest_sha256: "b".repeat(64),
            published_at: Utc::now(),
        })
        .unwrap();
    let entry = repository
        .publish_connector(&organization.id, &project.id, &publisher.id, &package)
        .await
        .unwrap();
    assert_eq!(entry.provider, "notion");
    assert_eq!(
        repository
            .connector_versions(&organization.id, &project.id)
            .await
            .unwrap()
            .len(),
        1
    );

    let now = Utc::now();
    let connection = ConnectionDescriptor {
        schema_version: CONTROL_CONTRACT_VERSION,
        connection_id: ConnectionId::new(),
        organization_id: organization.id.clone(),
        project_id: project.id.clone(),
        provider: "notion".into(),
        connector_version: "1-beta".into(),
        display_name: "Notion integration".into(),
        auth_method: "oauth_public".into(),
        health: ConnectionHealth::Connected,
        health_reason: None,
        reauthorization_required: false,
        granted_permissions: vec!["content:read".into()],
        authorized_resources: vec!["notion:page/page123".into()],
        created_at: now,
        updated_at: now,
    };
    repository
        .upsert_connection_descriptor(&connection)
        .await
        .unwrap();
    let mut repointed_connection = connection.clone();
    repointed_connection.provider = "slack".into();
    assert!(
        repository
            .upsert_connection_descriptor(&repointed_connection)
            .await
            .is_err()
    );
    assert_eq!(
        repository
            .connection_descriptor(&organization.id, &project.id, &connection.connection_id)
            .await
            .unwrap()
            .granted_permissions,
        vec!["content:read"]
    );

    let control_signer = ControlSigner::generate("phase4-control").unwrap();
    let first = control_signer
        .sign_policy(PolicyBundlePayload {
            schema_version: CONTROL_CONTRACT_VERSION,
            bundle_id: PolicyBundleId::new(),
            organization_id: organization.id.clone(),
            project_id: project.id.clone(),
            version: 1,
            previous_bundle_digest: None,
            issued_at: now,
            not_before: now - Duration::seconds(1),
            expires_at: now + Duration::days(1),
            revocation_epoch: 0,
            minimum_edge_version: "0.1.0".into(),
            offline: OfflineAuthorization::default(),
            rules: Vec::new(),
        })
        .unwrap();
    repository.activate_policy(&first).await.unwrap();
    let rule = PolicyRule {
        id: "proposal-notion-read".into(),
        version: 2,
        effect: PolicyEffect::Allow,
        agent_id: Some(agent_secret.registration.agent_id.clone()),
        connection_id: Some(connection.connection_id.0.clone()),
        resource_prefix: "notion:page/page123".into(),
        actions: vec!["notion.page.get_markdown".into()],
        argument_equals: Default::default(),
        not_before: None,
        expires_at: Some(now + Duration::hours(2)),
        max_lease_ttl_seconds: 60,
        max_uses: 10,
        budget: DataBudget {
            max_response_bytes: Some(4096),
            max_task_requests: Some(20),
            ..Default::default()
        },
    };
    let mut proposal = PolicyProposal {
        schema_version: CONTROL_CONTRACT_VERSION,
        proposal_id: PolicyProposalId::new(),
        organization_id: organization.id.clone(),
        project_id: project.id.clone(),
        proposed_by_agent_id: agent_secret.registration.agent_id.clone(),
        base_policy_version: 1,
        title: "Read selected Notion page".into(),
        reason: "Summarize the selected project page".into(),
        rules: vec![rule.clone()],
        proposal_digest_sha256: String::new(),
        status: PolicyProposalStatus::Pending,
        created_at: now,
        expires_at: now + Duration::hours(1),
    };
    proposal.proposal_digest_sha256 = proposal.calculate_digest();
    repository.create_policy_proposal(&proposal).await.unwrap();
    let (reviewed, _) = repository
        .review_policy_proposal(
            &organization.id,
            &project.id,
            &proposal.proposal_id,
            &PolicyProposalReviewRequest {
                schema_version: CONTROL_CONTRACT_VERSION,
                reviewer_id: membership.human_id,
                decision: PolicyProposalDecision::Approve,
                expected_proposal_digest_sha256: proposal.proposal_digest_sha256.clone(),
                expected_base_policy_version: 1,
                note: "bounded read approved".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(reviewed.status, PolicyProposalStatus::Approved);
    let second = control_signer
        .sign_policy(PolicyBundlePayload {
            schema_version: CONTROL_CONTRACT_VERSION,
            bundle_id: PolicyBundleId::new(),
            organization_id: organization.id.clone(),
            project_id: project.id.clone(),
            version: 2,
            previous_bundle_digest: Some(first.payload_digest_sha256.clone()),
            issued_at: now,
            not_before: now,
            expires_at: now + Duration::days(1),
            revocation_epoch: 0,
            minimum_edge_version: "0.1.0".into(),
            offline: OfflineAuthorization::default(),
            rules: vec![rule],
        })
        .unwrap();
    verify_policy_bundle(
        &second,
        &control_signer.verifying_key_base64(),
        now,
        repository
            .latest_policy_state(&organization.id, &project.id)
            .await
            .unwrap()
            .as_ref(),
    )
    .unwrap();
    repository
        .activate_reviewed_proposal(&proposal.proposal_id, &second)
        .await
        .unwrap();
    assert_eq!(
        repository
            .policy_proposal(&organization.id, &project.id, &proposal.proposal_id)
            .await
            .unwrap()
            .status,
        PolicyProposalStatus::Activated
    );

    let mut expiring_proposal = proposal.clone();
    expiring_proposal.proposal_id = PolicyProposalId::new();
    expiring_proposal.base_policy_version = 2;
    expiring_proposal.status = PolicyProposalStatus::Pending;
    expiring_proposal.created_at = Utc::now();
    expiring_proposal.expires_at = expiring_proposal.created_at + Duration::minutes(1);
    expiring_proposal.proposal_digest_sha256 = expiring_proposal.calculate_digest();
    repository
        .create_policy_proposal(&expiring_proposal)
        .await
        .unwrap();
    assert_eq!(
        repository
            .expire_pending_policy_proposals(expiring_proposal.expires_at)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        repository
            .policy_proposal(
                &organization.id,
                &project.id,
                &expiring_proposal.proposal_id,
            )
            .await
            .unwrap()
            .status,
        PolicyProposalStatus::Expired
    );

    let device = DeviceId::new();
    repository
        .register_device_key(&account, &device, "fixture-verifying-key")
        .await
        .unwrap();
    let enrollment = repository
        .create_edge_enrollment(
            &organization.id,
            &project.id,
            "audit edge",
            Duration::minutes(5),
        )
        .await
        .unwrap();
    let edge = repository
        .enroll_edge(&enrollment.secret, device, "fixture-public-key", "0.1.0")
        .await
        .unwrap();
    let event = AuditEvent {
        schema_version: 1,
        timestamp: Utc::now(),
        request_id: RequestId::new(),
        agent_id: agent_secret.registration.agent_id.clone(),
        workload_id: None,
        on_behalf_of: None,
        action: "notion.page.get_markdown".into(),
        resource: "notion:page/page123".into(),
        connection_id: Some(connection.connection_id.clone()),
        policy_version: Some(2),
        decision: "allow".into(),
        connector: Some("notion".into()),
        outcome: "success".into(),
        item_count: Some(1),
        cell_count: None,
        byte_count: Some(128),
        changed_fields: Vec::new(),
        trust_id: None,
    };
    repository
        .ingest_audit(
            &organization.id,
            &project.id,
            &AuditBatch {
                schema_version: CONTROL_CONTRACT_VERSION,
                edge_id: edge.edge.id.clone(),
                first_sequence: 1,
                events: vec![event.clone()],
            },
        )
        .await
        .unwrap();
    let integrity = repository
        .verify_audit_integrity(&organization.id, &project.id)
        .await
        .unwrap();
    assert!(integrity.valid);
    assert_eq!(integrity.event_count, 1);
    assert_eq!(integrity.verified_event_count, 1);
    assert_eq!(integrity.legacy_unverifiable_event_count, 0);
    let mut conflicting_event = event.clone();
    conflicting_event.outcome = "conflicting-replay".into();
    assert!(
        repository
            .ingest_audit(
                &organization.id,
                &project.id,
                &AuditBatch {
                    schema_version: CONTROL_CONTRACT_VERSION,
                    edge_id: edge.edge.id.clone(),
                    first_sequence: 1,
                    events: vec![conflicting_event],
                },
            )
            .await
            .is_err()
    );
    sqlx::query("UPDATE audit_event_index SET previous_chain_digest_sha256=NULL,chain_position=NULL WHERE organization_id=$1 AND project_id=$2")
        .bind(&organization.id.0)
        .bind(&project.id.0)
        .execute(repository.pool())
        .await
        .unwrap();
    let mut second_event = event;
    second_event.request_id = RequestId::new();
    second_event.timestamp += Duration::seconds(1);
    second_event.action = "notion.page.phase7_integrity_fixture".into();
    repository
        .ingest_audit(
            &organization.id,
            &project.id,
            &AuditBatch {
                schema_version: CONTROL_CONTRACT_VERSION,
                edge_id: edge.edge.id,
                first_sequence: 2,
                events: vec![second_event],
            },
        )
        .await
        .unwrap();
    let legacy_integrity = repository
        .verify_audit_integrity(&organization.id, &project.id)
        .await
        .unwrap();
    assert!(legacy_integrity.valid);
    assert_eq!(legacy_integrity.event_count, 2);
    assert_eq!(legacy_integrity.verified_event_count, 1);
    assert_eq!(legacy_integrity.legacy_unverifiable_event_count, 1);
    sqlx::query("UPDATE audit_event_index SET event_json=jsonb_set(event_json,'{outcome}',to_jsonb('tampered'::text),true) WHERE organization_id=$1 AND project_id=$2 AND chain_position=2")
        .bind(&organization.id.0)
        .bind(&project.id.0)
        .execute(repository.pool())
        .await
        .unwrap();
    let tampered_integrity = repository
        .verify_audit_integrity(&organization.id, &project.id)
        .await
        .unwrap();
    assert!(!tampered_integrity.valid);
    assert_eq!(tampered_integrity.first_invalid_position, Some(2));
    let page = repository
        .query_audit(
            &organization.id,
            &project.id,
            &AuditQueryFilter {
                action: Some("notion.page.get_markdown".into()),
                connection_id: Some(connection.connection_id.0),
                policy_version: Some(2),
                limit: 10,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(page.events.len(), 1);
    assert!(!page.has_more);
}
