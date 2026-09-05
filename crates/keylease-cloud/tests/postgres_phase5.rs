use chrono::{Duration, Utc};
use keylease_cloud::{CloudRepository, CredentialLeaseFilter};
use keylease_core::{
    AccountId, ConnectionHealth, ConnectionId, CredentialLeaseId, DeviceId, RotationId,
};
use leasegate_control::{CONTROL_CONTRACT_VERSION, ConnectionDescriptor, RevocationScope};
use leasegate_credentials::{
    CREDENTIAL_CONTRACT_VERSION, ConnectionPosture, ConnectionPostureStatus, CredentialKind,
    CredentialLeaseRecord, CredentialLeaseState, RotationRecord, RotationState, SenderConstraint,
};

#[tokio::test]
async fn phase5_lease_posture_rotation_and_revocation_are_tenant_bound() {
    let Some(database_url) = std::env::var("KEYLEASE_TEST_DATABASE_URL").ok() else {
        eprintln!("skipping PostgreSQL Phase 5 test; KEYLEASE_TEST_DATABASE_URL is unset");
        return;
    };
    let repository = CloudRepository::connect(&database_url, 5).await.unwrap();
    repository.migrate().await.unwrap();

    let account = AccountId::new();
    let (organization, project, membership) = repository
        .bootstrap_tenant(
            account.clone(),
            "Phase 5 integration organization",
            "dynamic-credentials",
            "https://issuer.phase5.test",
            &format!("subject-{}", account.0),
            "Phase 5 owner",
        )
        .await
        .unwrap();
    let agent = repository
        .register_agent(&organization.id, &project.id, "phase5-agent")
        .await
        .unwrap();
    let now = Utc::now();
    let connection = ConnectionDescriptor {
        schema_version: CONTROL_CONTRACT_VERSION,
        connection_id: ConnectionId::new(),
        organization_id: organization.id.clone(),
        project_id: project.id.clone(),
        provider: "ssh".into(),
        connector_version: "1-beta".into(),
        display_name: "Production SSH CA".into(),
        auth_method: "openssh_ca".into(),
        health: ConnectionHealth::Connected,
        health_reason: None,
        reauthorization_required: false,
        granted_permissions: vec!["credential:ssh:issue".into()],
        authorized_resources: vec!["credential:ssh/ssh-prod/deploy".into()],
        created_at: now,
        updated_at: now,
    };
    repository
        .upsert_connection_descriptor(&connection)
        .await
        .unwrap();
    let connection = repository
        .connection_descriptor(&organization.id, &project.id, &connection.connection_id)
        .await
        .unwrap();

    let device = DeviceId::new();
    repository
        .register_device_key(&account, &device, "phase5-device-key")
        .await
        .unwrap();
    let enrollment = repository
        .create_edge_enrollment(
            &organization.id,
            &project.id,
            "local credential gateway",
            Duration::minutes(5),
        )
        .await
        .unwrap();
    let edge = repository
        .enroll_edge(&enrollment.secret, device, "phase5-edge-key", "0.1.0")
        .await
        .unwrap();

    let lease_id = CredentialLeaseId::new();
    let mut lease = CredentialLeaseRecord {
        schema_version: CREDENTIAL_CONTRACT_VERSION,
        lease_id: lease_id.clone(),
        agent_id: agent.registration.agent_id.clone(),
        workload_id: Some("workload_phase5".into()),
        task_id: None,
        connection_id: connection.connection_id.clone(),
        backend_id: "ssh-prod".into(),
        kind: CredentialKind::SshCertificate,
        target: "deploy".into(),
        policy_version: 1,
        request_digest_sha256: "a".repeat(64),
        sender_constraint: SenderConstraint::SshPublicKeySha256 {
            thumbprint: "b".repeat(64),
        },
        state: CredentialLeaseState::Active,
        issued_at: now,
        expires_at: now + Duration::minutes(5),
        revoked_at: None,
        renewable: false,
        failure_code: None,
    };
    repository
        .report_credential_lease(&edge.edge.id, &lease)
        .await
        .unwrap();
    assert_eq!(
        repository
            .credential_leases(
                &organization.id,
                &project.id,
                &CredentialLeaseFilter {
                    agent_id: Some(agent.registration.agent_id.0.clone()),
                    state: Some(CredentialLeaseState::Active),
                    limit: 10,
                },
            )
            .await
            .unwrap(),
        vec![lease.clone()]
    );
    let mut rebound = lease.clone();
    rebound.target = "root".into();
    assert!(
        repository
            .report_credential_lease(&edge.edge.id, &rebound)
            .await
            .is_err()
    );

    let event = repository
        .revoke_credential_lease(
            &organization.id,
            &project.id,
            &lease_id,
            "operator revoked test lease",
        )
        .await
        .unwrap();
    assert!(matches!(
        event.kind,
        leasegate_control::ControlEventKind::Revocation(ref revocation)
            if revocation.scope == RevocationScope::Lease && revocation.target_id == lease_id.0
    ));
    lease.state = CredentialLeaseState::Revoked;
    lease.revoked_at = Some(Utc::now());
    repository
        .report_credential_lease(&edge.edge.id, &lease)
        .await
        .unwrap();

    let posture = ConnectionPosture {
        schema_version: CREDENTIAL_CONTRACT_VERSION,
        connection_id: connection.connection_id.clone(),
        status: ConnectionPostureStatus::Healthy,
        checked_at: Utc::now(),
        secret_expires_at: Some(Utc::now() + Duration::days(1)),
        rotation_due_at: None,
        last_rotated_at: None,
        reason_codes: vec!["local_gateway_issuance_succeeded".into()],
    };
    repository
        .report_connection_posture(&edge.edge.id, &posture)
        .await
        .unwrap();
    assert_eq!(
        repository
            .connection_postures(&organization.id, &project.id)
            .await
            .unwrap(),
        vec![posture]
    );
    assert!(
        repository
            .sweep_connection_posture(
                Utc::now(),
                Utc::now() - Duration::minutes(5),
                Utc::now() + Duration::days(7),
            )
            .await
            .unwrap()
            >= 1
    );
    assert_eq!(
        repository
            .connection_postures(&organization.id, &project.id)
            .await
            .unwrap()[0]
            .status,
        ConnectionPostureStatus::Expiring
    );

    let rotation = RotationRecord {
        schema_version: CREDENTIAL_CONTRACT_VERSION,
        rotation_id: RotationId::new(),
        connection_id: connection.connection_id,
        state: RotationState::Pending,
        requested_by: membership.human_id.0,
        reason: "scheduled rotation".into(),
        expected_connection_updated_at: connection.updated_at,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        completed_at: None,
        failure_code: None,
    };
    repository
        .create_rotation(&organization.id, &project.id, &rotation)
        .await
        .unwrap();
    let rotating = repository
        .transition_rotation(
            &organization.id,
            &project.id,
            &rotation.rotation_id,
            RotationState::Pending,
            RotationState::Rotating,
            None,
        )
        .await
        .unwrap();
    assert_eq!(rotating.state, RotationState::Rotating);
    assert!(
        repository
            .transition_rotation(
                &organization.id,
                &project.id,
                &rotation.rotation_id,
                RotationState::Pending,
                RotationState::Activated,
                None,
            )
            .await
            .is_err()
    );
}
