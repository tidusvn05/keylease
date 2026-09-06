use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use keylease_cloud::CloudRepository;
use keylease_core::{
    AccessReviewId, AccountId, DeviceId, KeyProviderId, OrganizationId, PolicyBundleId,
    SiemDestinationId, WorkloadIdentityId,
};
use leasegate_control::{
    AccessReview, AccessReviewDecision, AccessReviewState, CONTROL_CONTRACT_VERSION, KeyProvider,
    KeyProviderKind, MembershipRole, MobilePlatform, OfflineAuthorization, OidcProvider,
    OperatorDevice, PolicyBundlePayload, PolicyRelease, PolicyReleaseState, RetentionPolicy,
    SiemDestination, SiemFormat, WorkloadIdentityBinding,
};
use leasegate_policy_bundle::{ControlSigner, verify_operator_session};
use std::collections::BTreeMap;

#[tokio::test]
async fn phase6_enterprise_mobile_policy_and_ha_are_tenant_bound() {
    let Some(database_url) = std::env::var("KEYLEASE_TEST_DATABASE_URL").ok() else {
        eprintln!("skipping PostgreSQL Phase 6 test; KEYLEASE_TEST_DATABASE_URL is unset");
        return;
    };
    let repository = CloudRepository::connect(&database_url, 5).await.unwrap();
    repository.migrate().await.unwrap();
    let account = AccountId::new();
    let (organization, project, owner) = repository
        .bootstrap_tenant(
            account,
            "Phase 6 organization",
            "enterprise",
            "https://identity.phase6.test",
            &format!("owner-{}", OrganizationId::new().0),
            "Phase 6 owner",
        )
        .await
        .unwrap();
    let now = Utc::now();
    let provider = OidcProvider {
        schema_version: CONTROL_CONTRACT_VERSION,
        organization_id: organization.id.clone(),
        issuer: "https://identity.phase6.test".into(),
        audience: "leasegate".into(),
        jwks_uri: "https://identity.phase6.test/.well-known/jwks.json".into(),
        allowed_email_domains: vec!["example.test".into()],
        group_role_mapping: BTreeMap::from([("operators".into(), MembershipRole::Operator)]),
        enabled: true,
        created_at: now,
        updated_at: now,
    };
    repository.upsert_oidc_provider(&provider).await.unwrap();
    assert_eq!(
        repository.oidc_provider(&organization.id).await.unwrap(),
        Some(provider)
    );

    let scim = repository
        .create_scim_token(&organization.id, "test SCIM", Duration::hours(1))
        .await
        .unwrap();
    assert!(!format!("{scim:?}").contains(&scim.token));
    assert!(
        repository
            .authenticate_scim_token(
                &organization.id,
                "wrong-token-value-that-is-long-enough-000"
            )
            .await
            .is_err()
    );
    repository
        .authenticate_scim_token(&organization.id, &scim.token)
        .await
        .unwrap();
    let operator = repository
        .provision_scim_membership(
            &organization.id,
            "https://identity.phase6.test",
            "operator-1",
            "Operator One",
            MembershipRole::Operator,
        )
        .await
        .unwrap();
    assert!(
        repository
            .provision_scim_membership(
                &organization.id,
                "https://identity.phase6.test",
                "admin-1",
                "Unexpected Admin",
                MembershipRole::Admin,
            )
            .await
            .is_err()
    );

    let review = AccessReview {
        schema_version: CONTROL_CONTRACT_VERSION,
        review_id: AccessReviewId::new(),
        organization_id: organization.id.clone(),
        state: AccessReviewState::Open,
        created_by: owner.human_id.clone(),
        due_at: now + Duration::days(7),
        created_at: now,
        completed_at: None,
    };
    repository.create_access_review(&review).await.unwrap();
    repository
        .decide_access_review_entry(
            &organization.id,
            &review.review_id,
            &owner.id,
            AccessReviewDecision::Retain,
            &owner.human_id,
        )
        .await
        .unwrap();
    repository
        .decide_access_review_entry(
            &organization.id,
            &review.review_id,
            &operator.id,
            AccessReviewDecision::Revoke,
            &owner.human_id,
        )
        .await
        .unwrap();
    repository
        .complete_access_review(&organization.id, &review.review_id, &owner.human_id)
        .await
        .unwrap();
    let memberships = repository
        .organization_memberships(&organization.id)
        .await
        .unwrap();
    assert!(
        memberships
            .iter()
            .find(|item| item.id == operator.id)
            .unwrap()
            .revoked_at
            .is_some()
    );

    let device_key = SigningKey::from_bytes(&[11_u8; 32]);
    let device = OperatorDevice {
        schema_version: CONTROL_CONTRACT_VERSION,
        device_id: DeviceId::new(),
        organization_id: organization.id.clone(),
        human_id: owner.human_id.clone(),
        platform: MobilePlatform::Ios,
        display_name: "Owner iPhone".into(),
        verifying_key_base64: URL_SAFE_NO_PAD.encode(device_key.verifying_key().to_bytes()),
        push_token_digest_sha256: None,
        created_at: now,
        last_seen_at: None,
        revoked_at: None,
    };
    repository.register_operator_device(&device).await.unwrap();
    let challenge = repository
        .create_device_challenge(&organization.id, &device.device_id)
        .await
        .unwrap();
    let payload = serde_json_canonicalizer::to_vec(&challenge.signing_payload()).unwrap();
    let signature = URL_SAFE_NO_PAD.encode(device_key.sign(&payload).to_bytes());
    let claims = repository
        .verify_device_challenge(&organization.id, &challenge.challenge_id, &signature)
        .await
        .unwrap();
    assert_eq!(claims.role, MembershipRole::Owner);
    assert!(
        repository
            .verify_device_challenge(&organization.id, &challenge.challenge_id, &signature)
            .await
            .is_err()
    );
    let signer = ControlSigner::generate("phase6-test").unwrap();
    let session = signer.sign_operator_session(claims).unwrap();
    verify_operator_session(&session, &signer.verifying_key_base64(), Utc::now()).unwrap();

    let bundle = signer
        .sign_policy(PolicyBundlePayload {
            schema_version: CONTROL_CONTRACT_VERSION,
            bundle_id: PolicyBundleId::new(),
            organization_id: organization.id.clone(),
            project_id: project.id.clone(),
            version: 1,
            previous_bundle_digest: None,
            issued_at: now,
            not_before: now,
            expires_at: now + Duration::days(1),
            revocation_epoch: 0,
            minimum_edge_version: "0.1.0".into(),
            offline: OfflineAuthorization::default(),
            rules: vec![],
        })
        .unwrap();
    let mut release = PolicyRelease {
        schema_version: CONTROL_CONTRACT_VERSION,
        release_id: keylease_core::PolicyReleaseId::new(),
        organization_id: organization.id.clone(),
        project_id: project.id.clone(),
        source_revision: "git:0123456789abcdef".into(),
        source_digest_sha256: "a".repeat(64),
        state: PolicyReleaseState::Staged,
        canary_percent: 10,
        bundle,
        created_by: owner.human_id.clone(),
        created_at: now,
        updated_at: now,
        rollback_of: None,
    };
    repository.create_policy_release(&release).await.unwrap();
    release = repository
        .transition_policy_release(
            &organization.id,
            &project.id,
            &release.release_id,
            PolicyReleaseState::Staged,
            PolicyReleaseState::Canary,
        )
        .await
        .unwrap();
    assert_eq!(release.state, PolicyReleaseState::Canary);

    repository
        .upsert_retention_policy(&RetentionPolicy {
            schema_version: CONTROL_CONTRACT_VERSION,
            organization_id: organization.id.clone(),
            project_id: project.id.clone(),
            audit_days: 90,
            approval_days: 90,
            credential_metadata_days: 90,
            updated_by: owner.human_id.clone(),
            updated_at: now,
        })
        .await
        .unwrap();
    let evidence = repository
        .compliance_evidence(
            &organization.id,
            &project.id,
            now - Duration::minutes(1),
            now + Duration::seconds(1),
        )
        .await
        .unwrap();
    assert_eq!(evidence.controls["deployment"], "self_hosted/local_gateway");

    let destination = SiemDestination {
        schema_version: CONTROL_CONTRACT_VERSION,
        destination_id: SiemDestinationId::new(),
        organization_id: organization.id.clone(),
        project_id: project.id.clone(),
        display_name: "Primary SIEM".into(),
        format: SiemFormat::Json,
        endpoint: "https://siem.phase6.test/events".into(),
        secret_ref: "default".into(),
        enabled: true,
        created_at: now,
        updated_at: now,
    };
    repository
        .upsert_siem_destination(&destination)
        .await
        .unwrap();
    assert_eq!(
        repository
            .siem_destinations(&organization.id, &project.id)
            .await
            .unwrap(),
        vec![destination]
    );

    let agent = repository
        .register_agent(&organization.id, &project.id, "workload-agent")
        .await
        .unwrap();
    let binding = WorkloadIdentityBinding {
        schema_version: CONTROL_CONTRACT_VERSION,
        workload_identity_id: WorkloadIdentityId::new(),
        organization_id: organization.id.clone(),
        project_id: project.id.clone(),
        agent_id: agent.registration.agent_id,
        issuer: "https://spire.phase6.test".into(),
        subject: "spiffe://phase6.test/ns/default/sa/agent".into(),
        audience: "leasegate-gateway".into(),
        certificate_sha256: Some("b".repeat(64)),
        enabled: true,
        created_at: now,
        updated_at: now,
    };
    repository.upsert_workload_identity(&binding).await.unwrap();
    assert_eq!(
        repository
            .workload_identities(&organization.id, &project.id)
            .await
            .unwrap(),
        vec![binding]
    );
    let key_provider = KeyProvider {
        schema_version: CONTROL_CONTRACT_VERSION,
        key_provider_id: KeyProviderId::new(),
        organization_id: organization.id.clone(),
        kind: KeyProviderKind::Pkcs11,
        key_reference: "pkcs11:token=leasegate;object=control-signing".into(),
        public_key_fingerprint_sha256: "c".repeat(64),
        enabled: true,
        created_at: now,
        last_verified_at: Some(now),
    };
    repository.upsert_key_provider(&key_provider).await.unwrap();
    assert_eq!(
        repository.key_providers(&organization.id).await.unwrap(),
        vec![key_provider]
    );

    let worker_lease_name = format!("maintenance-test-{}", organization.id.0);
    assert!(
        repository
            .acquire_worker_lease(&worker_lease_name, "worker-a", now, Duration::seconds(30))
            .await
            .unwrap()
    );
    assert!(
        !repository
            .acquire_worker_lease(&worker_lease_name, "worker-b", now, Duration::seconds(30))
            .await
            .unwrap()
    );
    assert!(
        repository
            .acquire_worker_lease(
                &worker_lease_name,
                "worker-b",
                now + Duration::seconds(31),
                Duration::seconds(30)
            )
            .await
            .unwrap()
    );

    let foreign_org = OrganizationId::new();
    assert!(
        repository
            .oidc_provider(&foreign_org)
            .await
            .unwrap()
            .is_none()
    );
}
