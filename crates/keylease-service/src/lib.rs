//! The only production boundary allowed to mutate a vault or dispatch a connector.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use keylease_1pux::{
    ImportPreview as OnePuxImportPreview, MigrationReport as OnePuxMigrationReport, OnePuxAdapter,
    ZipOnePuxAdapter,
};
use keylease_connectors::{
    BuiltinConnector, CanonicalAction, Connector, ConnectorCredential, FakeConnector,
    OAuthCredential, a1_cell_count, enforce_response_budget, normalized_permissions,
    validate_connection_credential, validate_enrolled_resource,
};
use keylease_core::*;
use keylease_kdbx::{ImportPreview, KdbxAdapter, KeepassRsAdapter, MigrationReport};
use keylease_policy::RulePolicyEngine;
use keylease_store::{
    LeaseConsume, MutationContext, NativeStore, TaskBudgetContext, UnlockedVault,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{Arc, Mutex, RwLock},
    time::{Duration as StdDuration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use zeroize::{Zeroize, Zeroizing};

mod authorize;
mod backup;
mod bundle;
pub mod client_key;
mod cloud;
mod connections;
mod db;
mod environments;
mod http;
mod identity;
mod inject;
mod items;
mod leases;
mod owner_rules;
mod password;
mod remote;
mod remote_mcp;
mod ssh;
#[cfg(test)]
mod tests;
mod text_import;
mod trust;
mod vault;
pub use bundle::{
    BUNDLE_EXTENSION, BUNDLE_FORMAT, BundleImportReport, BundlePreview, BundleSelection,
    NodeIdentity,
};
pub use cloud::{
    CloudLink, CloudNode, CloudRole, CloudShare, CloudShareRequest, CloudStatus, InboxOutcome,
    InviteSetup, OwnerSetup, PendingBackup, RelaySignature, RequestStatus, RestoreReport,
    ShareScope,
};
pub use db::{DbTarget, ScramClientFinal};
use environments::*;
pub use http::{
    HTTP_EXTENSION, HttpBinding, HttpForwardRequest, HttpForwardResponse, MAX_HTTP_BODY_BYTES,
};
pub use inject::InjectRequest;
use items::*;
use owner_rules::*;
pub use password::*;
pub use remote::{APPROVER_SIGNATURE_CONTEXT, ApproverDevice, PairingCode, approver_signing_input};
pub use remote_mcp::{
    ACCESS_TOKEN_TTL_SECONDS, ConnectCode, GatewayConnection, OAuthClient, OAuthError, OAuthTokens,
    pkce_matches, valid_redirect_uri,
};
pub use ssh::{
    DEFAULT_CERT_TTL_SECONDS, MAX_CERT_TTL_SECONDS, MAX_SESSION_BINDS, SSH_AGENT_RSA_SHA2_256,
    SSH_AGENT_RSA_SHA2_512, SshCertificate, SshIdentity, SshSessionBind, SshSignature,
};
pub use text_import::{TextImportReport, parse_dotenv};
pub use trust::{ApprovalDecisionOutcome, EnrolledAgent};
use trust::{VAULT_CONNECTION_ID, project_alias, vault_action_risk};

const AUTH_FAILURE_LIMIT: usize = 10;
const AUTH_FAILURE_WINDOW: StdDuration = StdDuration::from_secs(60);
const AGENT_HANDOFF_TTL: StdDuration = StdDuration::from_secs(2 * 60 * 60);
const MAX_AGENT_HANDOFFS: usize = 64;
const MAX_AGENT_HANDOFF_BYTES: usize = 64 * 1024;
const MAX_AGENT_CONTEXT_BYTES: usize = 32 * 1024;
const MAX_AGENT_SOURCE_PATH_BYTES: usize = 4 * 1024;
const GOOGLE_OAUTH_FLOW_TTL: StdDuration = StdDuration::from_secs(10 * 60);
const GOOGLE_OAUTH_SCOPE: &str = "https://www.googleapis.com/auth/drive.file";
const MAX_OAUTH_HTTP_BYTES: usize = 16 * 1024;
const MAX_GOOGLE_TOKEN_RESPONSE_BYTES: usize = 1024 * 1024;

pub struct KeyLeaseService {
    store: Arc<NativeStore>,
    session: Mutex<Option<Session>>,
    policy: RwLock<RulePolicyEngine>,
    connectors: HashMap<String, Arc<dyn Connector>>,
    active_executions: Mutex<HashMap<String, u32>>,
    authentication_failures: Mutex<HashMap<String, VecDeque<Instant>>>,
    /// Nonces of recent signed client requests (`agent\nnonce` → timestamp),
    /// so a captured request cannot be replayed within its validity window.
    signature_nonces: Mutex<HashMap<String, i64>>,
    agent_handoffs: Mutex<HashMap<String, AgentNewItemHandoff>>,
    google_oauth_flows: Arc<Mutex<HashMap<String, GoogleOAuthFlow>>>,
    /// SQLite `data_version` when the in-memory policy was last built; a
    /// change means another process (the admin CLI) wrote the database.
    policy_data_version: std::sync::atomic::AtomicI64,
}
struct Session {
    vault: UnlockedVault,
    idle_timeout: Duration,
    last_activity: DateTime<Utc>,
}
struct ExecutionSlot<'a> {
    active: &'a Mutex<HashMap<String, u32>>,
    lease_id: String,
}

struct AgentNewItemHandoff {
    creator_agent_id: AgentId,
    vault_id: VaultId,
    input: AgentNewItemHandoffInput,
    expires_at: Instant,
    expires_at_utc: DateTime<Utc>,
}

impl Drop for AgentNewItemHandoff {
    fn drop(&mut self) {
        self.input.context.zeroize();
        self.input.source_path.zeroize();
    }
}

struct GoogleOAuthFlow {
    agent_id: AgentId,
    state: String,
    verifier: String,
    redirect_uri: String,
    client_id: String,
    client_secret: Option<String>,
    expires_at: Instant,
    callback: GoogleOAuthCallback,
}

enum GoogleOAuthCallback {
    Waiting,
    Received {
        code: String,
        picked_file_ids: Vec<String>,
        scope: String,
    },
    Failed(String),
}

impl Drop for GoogleOAuthFlow {
    fn drop(&mut self) {
        self.state.zeroize();
        self.verifier.zeroize();
        self.client_secret.zeroize();
        if let GoogleOAuthCallback::Received { code, .. } = &mut self.callback {
            code.zeroize();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoogleOAuthStart {
    pub flow_id: String,
    pub authorization_url: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GoogleTokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: u64,
    scope: String,
    token_type: String,
}

impl Drop for GoogleTokenResponse {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}
impl Drop for ExecutionSlot<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active.lock()
            && let Some(count) = active.get_mut(&self.lease_id)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                active.remove(&self.lease_id);
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NewEntryInput {
    pub group_id: GroupId,
    pub kind: String,
    pub title: String,
    #[serde(default)]
    pub project_slug: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub custom_fields: Vec<ItemField>,
    #[serde(default)]
    pub sections: Vec<ItemSection>,
    #[serde(default)]
    pub totp: Option<TotpConfig>,
    #[serde(default)]
    pub totp_uri: Option<String>,
    /// Deployment environment (a slug of the project's environments when it
    /// defines any). Protected environments raise the item's risk tier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// Put the item in the Personal area, invisible to agents (owner only).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub personal: bool,
}

impl std::fmt::Debug for NewEntryInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NewEntryInput")
            .field("group_id", &self.group_id)
            .field("kind", &self.kind)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, Default, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntryPatch {
    pub title: Option<String>,
    pub project_slug: Option<String>,
    #[serde(default)]
    pub clear_project: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub group_id: Option<GroupId>,
    pub totp: Option<TotpConfig>,
    pub totp_uri: Option<String>,
    pub custom_fields: Option<Vec<ItemField>>,
    #[serde(default)]
    pub field_updates: Vec<ItemField>,
    pub sections: Option<Vec<ItemSection>>,
    #[serde(default)]
    pub remove_field_ids: Vec<FieldId>,
    pub favorite: Option<bool>,
    /// New environment; an empty string clears it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// Move the item into or out of the Personal area (owner only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub personal: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FieldView {
    pub id: FieldId,
    pub key: String,
    pub label: String,
    pub semantic_role: Option<String>,
    pub value_type: String,
    pub sensitivity: Sensitivity,
    pub protected: bool,
    pub has_value: bool,
    pub value: Option<FieldValue>,
    pub display_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntryView {
    pub metadata: ItemMetadata,
    pub template_version: u32,
    pub project_id: Option<ProjectId>,
    pub tags: Vec<String>,
    pub sections: Vec<ItemSection>,
    pub fields: Vec<FieldView>,
    pub attachments: Vec<String>,
    pub has_notes: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContentCreateInput {
    pub kind: String,
    pub title: String,
    #[serde(default)]
    pub favorite: bool,
    pub body: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub project_slug: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContentPatch {
    pub title: Option<String>,
    pub body: Option<String>,
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub add_tags: Vec<String>,
    #[serde(default)]
    pub remove_tags: Vec<String>,
    pub project_slug: Option<String>,
    #[serde(default)]
    pub clear_project: bool,
    pub favorite: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContentSummary {
    pub id: ItemId,
    pub reference: String,
    pub kind: String,
    pub title: String,
    pub favorite: bool,
    pub tags: Vec<String>,
    pub project_id: Option<ProjectId>,
    pub project_slug: Option<String>,
    pub revision: u64,
    pub agent_access: AgentAccess,
    pub content_metadata: ContentMetadata,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContentDocument {
    pub summary: ContentSummary,
    pub body: String,
}

pub const AGENT_NEW_ITEM_PROTOCOL_VERSION: u32 = 1;

#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentNewItemHandoffInput {
    pub protocol_version: u32,
    pub expected_vault_id: VaultId,
    pub recipe_id: String,
    pub kind: String,
    pub group_id: Option<GroupId>,
    pub project_slug: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub agent_access: AgentAccess,
    pub source_path: Option<String>,
    pub context: Option<String>,
}

impl std::fmt::Debug for AgentNewItemHandoffInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentNewItemHandoffInput")
            .field("protocol_version", &self.protocol_version)
            .field("expected_vault_id", &self.expected_vault_id)
            .field("recipe_id", &self.recipe_id)
            .field("kind", &self.kind)
            .field("group_id", &self.group_id)
            .field("project_slug", &self.project_slug)
            .field("agent_access", &self.agent_access)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentNewItemHandoffReceipt {
    pub protocol_version: u32,
    pub handoff_id: String,
    pub command: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentNewItemRecipeView {
    pub id: String,
    pub title: String,
    pub instructions: String,
}

#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentNewItemGuide {
    pub protocol_version: u32,
    pub handoff_id: String,
    pub expires_at: DateTime<Utc>,
    pub vault_id: VaultId,
    pub recipe: AgentNewItemRecipeView,
    pub template: ItemKindDefinition,
    pub group_id: Option<GroupId>,
    pub group_name: Option<String>,
    pub project_slug: Option<String>,
    pub tags: Vec<String>,
    pub agent_access: AgentAccess,
    pub source_path: Option<String>,
    pub context: Option<String>,
    pub workflow: Vec<String>,
    pub kind_requirements: Vec<String>,
    pub safety_requirements: Vec<String>,
    pub waiting_message: String,
    pub success_prefix: String,
}

impl std::fmt::Debug for AgentNewItemGuide {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentNewItemGuide")
            .field("protocol_version", &self.protocol_version)
            .field("handoff_id", &self.handoff_id)
            .field("expires_at", &self.expires_at)
            .field("vault_id", &self.vault_id)
            .field("recipe", &self.recipe.id)
            .field("template", &self.template.kind)
            .field("group_id", &self.group_id)
            .field("project_slug", &self.project_slug)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

pub const MIGRATION_FRAMEWORK_VERSION: u32 = 1;
pub const KDBX_RECLASSIFY_MIGRATION_ID: &str = "kdbx-reclassify-v1";

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationProposal {
    pub item_id: ItemId,
    pub title: String,
    pub current_kind: String,
    pub proposed_kind: String,
    pub confidence: String,
    pub reasons: Vec<String>,
    pub expected_revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationPreview {
    pub migration_id: String,
    pub version: u32,
    pub title: String,
    pub migration_type: String,
    pub preview_digest: String,
    pub proposals: Vec<MigrationProposal>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationHistoryEntry {
    pub migration_id: String,
    pub version: u32,
    pub state: String,
    pub item_count: u64,
    pub applied_at: DateTime<Utc>,
    pub rolled_back_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationStatus {
    pub framework_version: u32,
    pub pending: Vec<MigrationPreview>,
    pub history: Vec<MigrationHistoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationApplyResult {
    pub migration_id: String,
    pub state: String,
    pub item_count: u64,
    pub checkpoint_available: bool,
}

impl std::fmt::Debug for ContentDocument {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContentDocument")
            .field("summary", &self.summary)
            .field("body", &"[REDACTED]")
            .finish()
    }
}

impl std::fmt::Debug for EntryPatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EntryPatch")
            .field("group_id", &self.group_id)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LeaseRequestOutcome {
    Issued { lease: Box<AccessLease> },
    ApprovalRequired { approval: Box<ApprovalRecord> },
}
