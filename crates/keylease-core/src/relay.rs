//! Wire contract of the cloud relay (ADR 0006), shared by the vault node and
//! the Cloud. The Cloud stores and forwards these records; every payload in
//! them is sealed to its recipient and signed by its sender, so the Cloud can
//! neither read nor forge one.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RELAY_VERSION: u32 = 1;
/// Domain separation for signed relay HTTP requests.
pub const RELAY_REQUEST_CONTEXT: &str = "KEYLEASE-RELAY-REQUEST-V1";
/// Domain separation for signed relay payloads (messages and backups).
pub const RELAY_PAYLOAD_CONTEXT: &str = "KEYLEASE-RELAY-PAYLOAD-V1";
/// Signed requests must be this fresh.
pub const RELAY_REQUEST_SKEW_SECONDS: i64 = 120;
/// Largest sealed payload the relay accepts, in bytes of JSON.
pub const RELAY_MAX_SEALED_BYTES: usize = 1024 * 1024;

pub const HEADER_MEMBER: &str = "x-keylease-member";
pub const HEADER_TIMESTAMP: &str = "x-keylease-timestamp";
pub const HEADER_SIGNATURE: &str = "x-keylease-signature";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 of `data`, lowercase hex.
pub fn relay_digest(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// The bytes a member signs for one HTTP request. `path` includes the query.
pub fn relay_request_signing_input(
    method: &str,
    path: &str,
    timestamp: i64,
    body: &[u8],
) -> Vec<u8> {
    format!(
        "{RELAY_REQUEST_CONTEXT}\n{method}\n{path}\n{timestamp}\n{}",
        relay_digest(body)
    )
    .into_bytes()
}

/// Everything a sealed payload is bound to: its AAD, and (with the ciphertext
/// digest) what its sender signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPayloadLabel<'a> {
    pub account_id: &'a str,
    pub from_member_id: &'a str,
    pub to_member_id: &'a str,
    pub kind: &'a str,
    pub object_id: &'a str,
    pub revision: u64,
}

impl RelayPayloadLabel<'_> {
    pub fn aad(&self) -> Vec<u8> {
        format!(
            "{RELAY_PAYLOAD_CONTEXT}\n{}\n{}\n{}\n{}\n{}\n{}",
            self.account_id,
            self.from_member_id,
            self.to_member_id,
            self.kind,
            self.object_id,
            self.revision
        )
        .into_bytes()
    }

    pub fn signing_input(&self, sealed_json: &str) -> Vec<u8> {
        let mut input = self.aad();
        input.extend_from_slice(b"\n");
        input.extend_from_slice(relay_digest(sealed_json.as_bytes()).as_bytes());
        input
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayRole {
    Owner,
    Node,
}

/// A member's public keys, base64 (standard, padded).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelayMemberKeys {
    pub sign_public_b64: String,
    pub box_public_b64: String,
}

impl RelayMemberKeys {
    /// The bytes an invite tag covers: the account and both keys.
    pub fn tag_material(&self, account_id: &str, role: RelayRole) -> Vec<u8> {
        format!(
            "keylease-relay-invite-v1\n{account_id}\n{role:?}\n{}\n{}",
            self.sign_public_b64, self.box_public_b64
        )
        .into_bytes()
    }

    /// A short fingerprint for people to compare.
    pub fn fingerprint(&self) -> String {
        let digest =
            relay_digest(format!("{}\n{}", self.sign_public_b64, self.box_public_b64).as_bytes());
        digest.as_bytes()[..16]
            .chunks(4)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect::<Vec<_>>()
            .join("-")
    }
}

/// `POST /v1/relay/accounts` (admin token): the owner's first device creates
/// the account.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRelayAccount {
    pub account_id: String,
    pub owner_name: String,
    pub owner: RelayMemberKeys,
    /// SHA-256 hex of the lookup value derived from the recovery code.
    pub recovery_lookup_hash: String,
    /// The owner keys, encrypted under the recovery code (opaque JSON).
    pub recovery_kit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayAccountCreated {
    pub account_id: String,
    pub owner_member_id: String,
}

/// `POST /v1/relay/recovery`: anyone holding the recovery code can fetch the
/// encrypted kit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchRecoveryKit {
    pub account_id: String,
    /// Hex of the lookup value (not its hash).
    pub lookup_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryKitResponse {
    pub account_id: String,
    pub owner_member_id: String,
    pub recovery_kit: String,
}

/// `POST /v1/relay/invites` (signed by the owner).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRelayInvite {
    /// SHA-256 hex of the code's lookup half.
    pub lookup_hash: String,
    pub name: String,
    pub expires_at: DateTime<Utc>,
    /// HMAC(secret half, owner keys), base64.
    pub owner_tag_b64: String,
}

/// `GET /v1/relay/invites/{lookup}`: what a joining node sees.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayInvite {
    pub account_id: String,
    pub owner_member_id: String,
    pub owner: RelayMemberKeys,
    pub name: String,
    pub owner_tag_b64: String,
    pub expires_at: DateTime<Utc>,
}

/// `POST /v1/relay/join`: a node registers its keys with an invite.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinRelay {
    pub lookup: String,
    pub keys: RelayMemberKeys,
    /// HMAC(secret half, node keys), base64.
    pub node_tag_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayJoined {
    pub account_id: String,
    pub member_id: String,
}

/// `GET /v1/relay/members` (signed).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelayMember {
    pub member_id: String,
    pub role: RelayRole,
    pub name: String,
    pub keys: RelayMemberKeys,
    pub node_tag_b64: Option<String>,
    pub invite_lookup_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Message kinds. The relay enforces direction: `share_request` goes from a
/// node to the owner; the others from the owner to a node.
pub mod kind {
    pub const SHARE: &str = "share";
    pub const UNSHARE: &str = "unshare";
    pub const RESTORE: &str = "restore";
    pub const SHARE_REQUEST: &str = "share_request";
    pub const REQUEST_DECISION: &str = "request_decision";
    pub const BACKUP: &str = "backup";

    pub const OWNER_TO_NODE: &[&str] = &[SHARE, UNSHARE, RESTORE, REQUEST_DECISION];
    pub const NODE_TO_OWNER: &[&str] = &[SHARE_REQUEST];
}

/// One mailbox message. `sealed_json` is a sealed box serialized as JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelayEnvelope {
    pub message_id: String,
    pub account_id: String,
    pub from_member_id: String,
    pub to_member_id: String,
    pub kind: String,
    pub object_id: String,
    pub revision: u64,
    pub sealed_json: String,
    pub signature_b64: String,
    pub created_at: DateTime<Utc>,
}

impl RelayEnvelope {
    pub fn label(&self) -> RelayPayloadLabel<'_> {
        RelayPayloadLabel {
            account_id: &self.account_id,
            from_member_id: &self.from_member_id,
            to_member_id: &self.to_member_id,
            kind: &self.kind,
            object_id: &self.object_id,
            revision: self.revision,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayInbox {
    pub messages: Vec<RelayEnvelope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayAck {
    pub message_ids: Vec<String>,
}

/// The latest backup of one object of one member, sealed to the owner. A
/// tombstone has `deleted` set and an empty `sealed_json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelayBackup {
    pub member_id: String,
    pub object_id: String,
    pub revision: u64,
    pub deleted: bool,
    pub sealed_json: String,
    pub signature_b64: String,
    pub updated_at: DateTime<Utc>,
}

impl RelayBackup {
    pub fn label<'a>(
        &'a self,
        account_id: &'a str,
        owner_member_id: &'a str,
    ) -> RelayPayloadLabel<'a> {
        RelayPayloadLabel {
            account_id,
            from_member_id: &self.member_id,
            to_member_id: owner_member_id,
            kind: if self.deleted {
                "backup_tombstone"
            } else {
                kind::BACKUP
            },
            object_id: &self.object_id,
            revision: self.revision,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayBackupList {
    pub backups: Vec<RelayBackup>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_inputs_are_frozen() {
        assert_eq!(
            String::from_utf8(relay_request_signing_input(
                "POST",
                "/v1/relay/messages",
                7,
                b"{}"
            ))
            .unwrap(),
            "KEYLEASE-RELAY-REQUEST-V1\nPOST\n/v1/relay/messages\n7\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
        let label = RelayPayloadLabel {
            account_id: "acct_a",
            from_member_id: "m_owner",
            to_member_id: "m_node",
            kind: kind::SHARE,
            object_id: "item_1",
            revision: 3,
        };
        assert_eq!(
            String::from_utf8(label.aad()).unwrap(),
            "KEYLEASE-RELAY-PAYLOAD-V1\nacct_a\nm_owner\nm_node\nshare\nitem_1\n3"
        );
        assert!(
            String::from_utf8(label.signing_input("{}"))
                .unwrap()
                .ends_with("\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a")
        );
    }

    #[test]
    fn fingerprints_are_short_and_stable() {
        let keys = RelayMemberKeys {
            sign_public_b64: "a".into(),
            box_public_b64: "b".into(),
        };
        let fingerprint = keys.fingerprint();
        assert_eq!(fingerprint.len(), 19);
        assert_eq!(fingerprint, keys.fingerprint());
    }
}
