use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{AgentId, FieldId, GroupId, ItemId, ProjectId, VaultId};

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
    MonthYear { month: u8, year: u16 },
    Address(AddressValue),
    Boolean(bool),
    Totp(TotpConfig),
    KeyPair { public: String, private: String },
    Certificate(String),
    AttachmentRef(String),
    Reference(String),
    OpaqueJson(serde_json::Value),
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
            Self::MonthYear { .. } => "MonthYear",
            Self::Address(_) => "Address",
            Self::Boolean(_) => "Boolean",
            Self::Totp(_) => "Totp",
            Self::KeyPair { .. } => "KeyPair",
            Self::Certificate(_) => "Certificate",
            Self::AttachmentRef(_) => "AttachmentRef",
            Self::Reference(_) => "Reference",
            Self::OpaqueJson(_) => "OpaqueJson",
        };
        write!(formatter, "{kind}([REDACTED])")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct AddressValue {
    pub street: String,
    pub city: String,
    pub state: String,
    pub postal_code: String,
    pub country: String,
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
    #[serde(default)]
    pub semantic_role: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ItemSection {
    pub id: String,
    pub label: String,
    pub field_ids: Vec<FieldId>,
    #[serde(default)]
    pub semantic_role: Option<String>,
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
    #[serde(default)]
    pub favorite: bool,
    pub attachments: Vec<String>,
    pub notes: Option<String>,
    #[serde(default = "default_template_version")]
    pub template_version: u32,
    #[serde(default)]
    pub project_id: Option<ProjectId>,
    #[serde(default)]
    pub agent_access: AgentAccess,
    #[serde(default)]
    pub content_metadata: Option<ContentMetadata>,
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

const fn default_template_version() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AgentAccess {
    #[default]
    None,
    Read,
    ReadWrite,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContentReviewState {
    Unreviewed,
    HumanReviewed,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContentMetadata {
    pub created_by: AgentId,
    pub last_modified_by: AgentId,
    pub review_state: ContentReviewState,
    pub reviewed_by: Option<String>,
    pub reviewed_at: Option<DateTime<Utc>>,
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
    #[serde(default)]
    pub purpose: GroupPurpose,
    /// User-defined order among groups with the same parent. Older vaults do
    /// not have an explicit order and are sorted deterministically by clients.
    #[serde(default)]
    pub sort_order: Option<u32>,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GroupPurpose {
    #[default]
    User,
    Knowledge,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VaultProject {
    pub id: ProjectId,
    pub vault_id: VaultId,
    pub slug: String,
    pub name: String,
    pub revision: u64,
    pub created_by: AgentId,
    pub updated_by: AgentId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub archived_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ItemMetadata {
    pub id: ItemId,
    pub group_id: GroupId,
    #[serde(default)]
    pub project_id: Option<ProjectId>,
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
    pub favorite: bool,
    pub revision: u64,
    pub updated_at: DateTime<Utc>,
}

impl VaultItem {
    pub fn metadata(&self) -> ItemMetadata {
        let favorite = self.favorite
            || self
                .extensions
                .get("onepux.favorite_index")
                .and_then(serde_json::Value::as_i64)
                .is_some_and(|index| index > 0);
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
            project_id: self.project_id.clone(),
            kind: self.kind.clone(),
            title: self.title.clone(),
            username,
            urls: self.urls.iter().map(|u| u.url.clone()).collect(),
            has_password,
            has_notes,
            has_totp,
            favorite,
            revision: self.revision,
            updated_at: self.updated_at,
        }
    }

    pub fn secret_reference(&self, field: &ItemField) -> String {
        format!("kl://{}/{}/{}", self.vault_id.0, self.id.0, field.id.0)
    }
}

/// Which local client holds owner authority over a vault, and how much of it.
///
/// The desktop and the phone are both "the human who owns this vault", but they
/// are not equally exposed. A phone is more easily lost and less easily
/// inspected, so it is given the authority needed to use and defend the vault
/// and not the authority to widen it: it may list, test, refresh, disconnect
/// and revoke connections, but not create or enrol new ones, run migrations, or
/// drive the agent workflows.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalOwnerRole {
    /// The desktop client. The full local surface.
    DesktopOwner,
    /// The mobile client.
    MobileOwner,
}

impl LocalOwnerRole {
    /// The value stored in `local_client_roles.role`.
    ///
    /// `desktop_owner` predates the mobile client and is what existing vaults
    /// already contain, so it must not be renamed.
    pub fn wire(self) -> &'static str {
        match self {
            LocalOwnerRole::DesktopOwner => "desktop_owner",
            LocalOwnerRole::MobileOwner => "mobile_owner",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "desktop_owner" => Some(LocalOwnerRole::DesktopOwner),
            "mobile_owner" => Some(LocalOwnerRole::MobileOwner),
            _ => None,
        }
    }

    /// Whether this role may run the agent new-item handoff.
    ///
    /// The workflow hands the user a CLI command to paste into a coding agent
    /// on the same machine, which a phone has no way to do.
    pub fn may_use_agent_handoff(self) -> bool {
        matches!(self, LocalOwnerRole::DesktopOwner)
    }

    /// Whether this role may apply or roll back vault migrations.
    ///
    /// Migrations rewrite the whole vault. That is a deliberate, reviewable
    /// operation for the machine that holds the backups.
    pub fn may_manage_migrations(self) -> bool {
        matches!(self, LocalOwnerRole::DesktopOwner)
    }
}
