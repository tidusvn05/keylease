//! Managed nodes (ADR 0012): an organization's owners and admins write
//! policy rules on keylease-server, which signs them; every node that joined
//! the organization verifies the signature with the server key it pinned
//! when it joined, and adds the rules to its own policy.
//!
//! Managed rules only tighten: their effect is `deny` or `require_approval`.
//! A deny always wins on the node; a managed `require_approval` outranks the
//! node's own grants and trusts, so an organization can insist on a person's
//! approval for, say, production secrets.

use crate::{PolicyEffect, PolicyRule};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Domain separation for the server's signature.
pub const MANAGED_POLICY_CONTEXT: &str = "KEYLEASE-MANAGED-POLICY-V1";
/// Managed rules carry this plus the policy version as their rule version,
/// so they outrank a node's own rules (and trusts) for the same request.
pub const MANAGED_RULE_VERSION_BASE: u64 = 1 << 40;
/// Prefix of managed rule ids on the node.
pub const MANAGED_RULE_PREFIX: &str = "managed_";
/// Rules one managed policy may carry.
pub const MAX_MANAGED_RULES: usize = 500;

/// What the server signs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ManagedPolicy {
    /// Always 1.
    pub v: u32,
    pub org_id: String,
    pub version: u64,
    pub issued_at: DateTime<Utc>,
    /// The node stops trusting a copy older than this; the server re-signs
    /// well before.
    pub expires_at: DateTime<Utc>,
    pub rules: Vec<PolicyRule>,
}

impl ManagedPolicy {
    /// Whether every rule only tightens.
    pub fn only_tightens(&self) -> bool {
        self.rules.iter().all(|rule| {
            matches!(
                rule.effect,
                PolicyEffect::Deny | PolicyEffect::RequireApproval
            )
        })
    }
}

/// A signed managed policy, as the node receives it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedManagedPolicy {
    /// The exact [`ManagedPolicy`] JSON that was signed.
    pub payload: String,
    pub key_id: String,
    /// Ed25519 over [`managed_policy_signing_input`], unpadded base64.
    pub signature: String,
}

/// The bytes the server signs.
pub fn managed_policy_signing_input(payload: &str) -> Vec<u8> {
    format!("{MANAGED_POLICY_CONTEXT}\n{payload}").into_bytes()
}

/// `POST /v1/relay/org-nodes/join`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrgNodeJoin {
    pub code: String,
}

/// The organization a node joined and the key it pins.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OrgNodeJoined {
    pub org_id: String,
    pub org_name: String,
    pub key_id: String,
    /// The server's Ed25519 verifying key, unpadded base64.
    pub verifying_key: String,
}

/// `GET /v1/relay/org-policy`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrgPolicyAnswer {
    pub policy: Option<SignedManagedPolicy>,
}

/// `PUT /v1/relay/org-policy/applied`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedPolicy {
    pub version: u64,
}
