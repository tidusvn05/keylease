//! Console approvals and node audit (ADR 0011): what a node and
//! keylease-server exchange so that a person can decide a node's pending
//! approvals in the KeyLease Console and read its audit there.
//!
//! The server only carries decisions. Each one is signed in the browser with
//! one of the account's passkeys over [`decision_challenge`] of the exact
//! payload text, and the node checks that signature against the passkeys it
//! pinned when the owner turned console approvals on. A server that is taken
//! over can show wrong data or drop decisions, but it cannot approve.

use crate::{ApprovalRecord, AuditEvent, TrustDecision};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separation for the challenge a passkey signs.
pub const DECISION_CONTEXT: &str = "KEYLEASE-CONSOLE-DECISION-V1";
/// A decision older than this is refused by the node.
pub const DECISION_MAX_AGE_SECONDS: i64 = 600;
/// Pending approvals one node report may carry.
pub const MAX_REPORTED_APPROVALS: usize = 200;
/// Audit events one upload may carry.
pub const MAX_AUDIT_UPLOAD: usize = 500;

/// What the person decided, as the browser signs it. The server builds it
/// from the node's latest report; the node checks every field again.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionPayload {
    /// Always 1.
    pub v: u32,
    pub account_id: String,
    /// The node's relay member id.
    pub node: String,
    pub approval_id: String,
    pub approve: bool,
    pub request_digest_hex: String,
    pub policy_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<TrustDecision>,
    pub issued_at: DateTime<Utc>,
    /// Random, so two decisions never share a challenge.
    pub nonce: String,
}

/// The 32 bytes the passkey signs as its WebAuthn challenge.
pub fn decision_challenge(payload_json: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DECISION_CONTEXT.as_bytes());
    hasher.update(b"\n");
    hasher.update(payload_json.as_bytes());
    hasher.finalize().into()
}

/// A WebAuthn assertion, every field base64url as the browser returns it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PasskeyAssertion {
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
}

/// A signed decision on its way to the node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsoleDecision {
    pub id: String,
    /// The exact [`DecisionPayload`] JSON that was signed.
    pub payload: String,
    pub assertion: PasskeyAssertion,
}

/// `PUT /v1/relay/console/report`: the node's pending approvals.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeReport {
    pub approvals: Vec<ApprovalRecord>,
}

/// The decisions waiting for the node that reported.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeReportResponse {
    pub decisions: Vec<ConsoleDecision>,
}

/// What the node did with one decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionResult {
    pub id: String,
    /// `approved`, `denied` or `rejected` (not applied; see `reason`).
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `POST /v1/relay/console/results`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionResults {
    pub results: Vec<DecisionResult>,
}

/// One audit event with the node's sequence number.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuditEntry {
    pub seq: i64,
    pub event: AuditEvent,
}

/// `POST /v1/relay/console/audit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditUpload {
    pub events: Vec<AuditEntry>,
}

/// A passkey of the account as the node pins it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PinnedPasskey {
    /// base64url, no padding.
    pub credential_id: String,
    /// Standard base64 of the SEC1 P-256 public key.
    pub public_key_b64: String,
    pub name: String,
}

/// `GET /v1/relay/console/passkeys`: where passkeys are bound and which
/// exist.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccountPasskeys {
    pub rp_id: String,
    pub origin: String,
    pub passkeys: Vec<PinnedPasskey>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_challenge_depends_on_every_byte_of_the_payload() {
        let a = decision_challenge(r#"{"v":1}"#);
        assert_eq!(a, decision_challenge(r#"{"v":1}"#));
        assert_ne!(a, decision_challenge(r#"{"v":1 }"#));
    }
}
