use chrono::Utc;
use keylease_core::{ConnectionId, CredentialLeaseId};
use leasegate_credentials::{
    CREDENTIAL_CONTRACT_VERSION, CredentialBackend, CredentialKind, CredentialLeaseRequest,
    CredentialMaterial, SenderConstraint, SshCertificateBackend, SshCertificateConfig,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    process::Command,
};

#[tokio::test]
async fn ssh_certificate_is_key_bound_and_added_to_revocation_list() {
    if Command::new("ssh-keygen").arg("-V").output().is_err() {
        eprintln!("skipping SSH backend test; ssh-keygen is unavailable");
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let ca = directory.path().join("ca");
    let subject = directory.path().join("subject");
    assert!(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&ca)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&subject)
            .status()
            .unwrap()
            .success()
    );
    let public_key = std::fs::read_to_string(subject.with_extension("pub")).unwrap();
    let connection_id = ConnectionId("conn_ssh".into());
    let krl = directory.path().join("revoked.krl");
    let backend = SshCertificateBackend::new(SshCertificateConfig {
        backend_id: "ssh-test".into(),
        connection_id: connection_id.clone(),
        ca_private_key_file: ca,
        revoked_keys_file: krl.clone(),
        allowed_principals: BTreeSet::from(["deploy".into()]),
        maximum_ttl_seconds: 300,
    })
    .unwrap();
    let issue = backend
        .issue(
            &CredentialLeaseId::new(),
            &CredentialLeaseRequest {
                schema_version: CREDENTIAL_CONTRACT_VERSION,
                connection_id,
                backend_id: "ssh-test".into(),
                kind: CredentialKind::SshCertificate,
                target: "deploy".into(),
                requested_ttl_seconds: 120,
                idempotency_key: "ssh-test".into(),
                task_id: None,
                approval_id: None,
                claims: BTreeMap::from([
                    ("principal".into(), "deploy".into()),
                    ("public_key".into(), public_key),
                ]),
            },
            120,
            Utc::now(),
        )
        .await
        .unwrap();
    assert!(matches!(
        issue.sender_constraint,
        SenderConstraint::SshPublicKeySha256 { .. }
    ));
    let CredentialMaterial::SshCertificate { certificate } = &issue.credential else {
        panic!("expected SSH certificate")
    };
    let certificate_path = directory.path().join("issued-cert.pub");
    std::fs::write(&certificate_path, certificate).unwrap();
    let inspection = Command::new("ssh-keygen")
        .args(["-L", "-f"])
        .arg(&certificate_path)
        .output()
        .unwrap();
    assert!(inspection.status.success());
    assert!(String::from_utf8_lossy(&inspection.stdout).contains("deploy"));

    backend
        .revoke(issue.revocation_handle.as_deref())
        .await
        .unwrap();
    assert!(krl.exists());
    let query = Command::new("ssh-keygen")
        .args(["-Q", "-f"])
        .arg(&krl)
        .arg(&certificate_path)
        .output()
        .unwrap();
    assert!(!query.status.success());
    assert!(String::from_utf8_lossy(&query.stdout).contains("REVOKED"));
}
