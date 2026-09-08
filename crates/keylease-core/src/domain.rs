use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{FieldId, GroupId, ItemId, VaultId};

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretValue(pub String);

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretValue([REDACTED])")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    PublicMetadata,
    PrivateMetadata,
    Secret,
    HighlySensitive,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum FieldValue {
    Text(String),
    Concealed(String),
    Url(String),
    Email(String),
    Phone(String),
    Number(f64),
    Date(String),
    Boolean(bool),
    Totp(TotpConfig),
    KeyPair { public: String, private: String },
    Certificate(String),
    AttachmentRef(String),
    Reference(String),
}

impl std::fmt::Debug for FieldValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::Text(_) => "Text",
            Self::Concealed(_) => "Concealed",
            Self::Url(_) => "Url",
            Self::Email(_) => "Email",
            Self::Phone(_) => "Phone",
            Self::Number(_) => "Number",
            Self::Date(_) => "Date",
            Self::Boolean(_) => "Boolean",
            Self::Totp(_) => "Totp",
            Self::KeyPair { .. } => "KeyPair",
            Self::Certificate(_) => "Certificate",
            Self::AttachmentRef(_) => "AttachmentRef",
            Self::Reference(_) => "Reference",
        };
        write!(formatter, "{kind}([REDACTED])")
    }
}

#[derive(Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TotpConfig {
    pub secret_base32: String,
    pub issuer: Option<String>,
    pub account: Option<String>,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u64,
    pub source_representation: Option<String>,
}

impl std::fmt::Debug for TotpConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TotpConfig")
            .field("secret_base32", &"[REDACTED]")
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("source_representation", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum TotpAlgorithm {
    #[serde(rename = "sha1")]
    Sha1,
    #[serde(rename = "sha256")]
    Sha256,
    #[serde(rename = "sha512")]
    Sha512,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ItemField {
    pub id: FieldId,
    pub key: String,
    pub label: String,
    pub value: FieldValue,
    pub sensitivity: Sensitivity,
    pub protected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ItemSection {
    pub id: String,
    pub label: String,
    pub field_ids: Vec<FieldId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ItemUrl {
    pub label: Option<String>,
    pub url: String,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VaultItem {
    pub id: ItemId,
    pub vault_id: VaultId,
    pub group_id: GroupId,
    pub kind: String,
    pub title: String,
    pub sections: Vec<ItemSection>,
    pub fields: Vec<ItemField>,
    pub urls: Vec<ItemUrl>,
    pub tags: Vec<String>,
    pub attachments: Vec<String>,
    pub notes: Option<String>,
    pub schema_version: u32,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub secret_changed_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub rotation_interval_days: Option<u32>,
    pub issuer: Option<String>,
    pub environment: Option<String>,
    pub owner: Option<String>,
    pub status: ItemStatus,
    #[serde(default)]
    pub extensions: BTreeMap<String, serde_json::Value>,
}

impl std::fmt::Debug for VaultItem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VaultItem")
            .field("id", &self.id)
            .field("vault_id", &self.vault_id)
            .field("group_id", &self.group_id)
            .field("kind", &self.kind)
            .field("revision", &self.revision)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ItemStatus {
    Active,
    Expired,
    Revoked,
    Archived,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VaultGroup {
    pub id: GroupId,
    pub vault_id: VaultId,
    pub parent_id: Option<GroupId>,
    pub name: String,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ItemMetadata {
    pub id: ItemId,
    pub group_id: GroupId,
    pub kind: String,
    pub title: String,
    pub username: Option<String>,
    pub urls: Vec<String>,
    /// Whether the item contains a password field. The password remains
    /// excluded from metadata.
    pub has_password: bool,
    /// Whether the encrypted item contains non-empty notes. The note body
    /// remains excluded from list and metadata responses.
    pub has_notes: bool,
    /// Whether the item contains a valid typed TOTP configuration. The secret
    /// and current code remain excluded from metadata.
    pub has_totp: bool,
    pub revision: u64,
    pub updated_at: DateTime<Utc>,
}

impl VaultItem {
    pub fn metadata(&self) -> ItemMetadata {
        let username = self
            .fields
            .iter()
            .find(|f| f.key == "username")
            .and_then(|f| match &f.value {
                FieldValue::Text(v) => Some(v.clone()),
                _ => None,
            });
        let has_totp = self
            .fields
            .iter()
            .any(|field| field.key == "otp" && matches!(&field.value, FieldValue::Totp(_)));
        let has_password = self.fields.iter().any(|field| {
            field.key == "password"
                && matches!(
                    &field.value,
                    FieldValue::Text(value) | FieldValue::Concealed(value) if !value.is_empty()
                )
        });
        let has_notes = self
            .notes
            .as_deref()
            .is_some_and(|notes| !notes.trim().is_empty());
        ItemMetadata {
            id: self.id.clone(),
            group_id: self.group_id.clone(),
            kind: self.kind.clone(),
            title: self.title.clone(),
            username,
            urls: self.urls.iter().map(|u| u.url.clone()).collect(),
            has_password,
            has_notes,
            has_totp,
            revision: self.revision,
            updated_at: self.updated_at,
        }
    }

    pub fn secret_reference(&self, field: &ItemField) -> String {
        format!("kl://{}/{}/{}", self.vault_id.0, self.id.0, field.id.0)
    }
}
