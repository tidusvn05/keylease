//! Versioned, transport-independent KeyLease contracts.

mod action;
mod audit;
mod connection;
mod domain;
mod error;
mod identity;
mod policy;
pub mod relay;
mod template;
mod trust;

pub use action::*;
pub use audit::*;
pub use connection::*;
pub use domain::*;
pub use error::*;
pub use identity::*;
pub use policy::*;
pub use template::*;
pub use trust::*;

pub const CONTRACT_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[test]
    fn debug_output_redacts_secret_and_external_content() {
        let actor = ActorContext {
            agent_id: AgentId("agent_test".into()),
            workload_id: None,
            human_principal: None,
            on_behalf_of: None,
            client_session_id: "session".into(),
            purpose: None,
        };
        let request = ActionRequest {
            schema_version: CONTRACT_VERSION,
            request_id: RequestId::new(),
            subject: actor,
            task_id: None,
            connection_id: ConnectionId("conn_test".into()),
            resource: "fake:resource/1".into(),
            action: "fake.write".into(),
            arguments: serde_json::json!({"secret":"request-secret-fixture"}),
            idempotency_key: "idem".into(),
        };
        let lease = AccessLease {
            id: LeaseId::new(),
            token: "lease-token-fixture".into(),
            request_digest_hex: "digest".into(),
            policy_version: 1,
            action: "fake.write".into(),
            resource: "fake:resource/1".into(),
            audience: "fake".into(),
            expires_at: Utc::now() + Duration::minutes(1),
            max_uses: 1,
            remaining_uses: 1,
            budget: Default::default(),
            approval_id: None,
            session_id: "session".into(),
            revoked: false,
        };
        let field = FieldValue::Concealed("vault-secret-fixture".into());
        let output = format!("{request:?} {lease:?} {field:?}");
        for secret in [
            "request-secret-fixture",
            "lease-token-fixture",
            "vault-secret-fixture",
        ] {
            assert!(!output.contains(secret));
        }
        assert!(output.contains("[REDACTED]"));
    }
}
