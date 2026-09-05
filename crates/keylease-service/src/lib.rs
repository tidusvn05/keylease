//! The only production boundary allowed to mutate a vault or dispatch a connector.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use keylease_1pux::{
    ImportPreview as OnePuxImportPreview, MigrationReport as OnePuxMigrationReport, OnePuxAdapter,
    ZipOnePuxAdapter,
};
use keylease_core::*;
use keylease_kdbx::{ImportPreview, KdbxAdapter, KeepassRsAdapter, MigrationReport};
use keylease_store::{LeaseConsume, MutationContext, NativeStore, UnlockedVault};
use leasegate_connectors::{
    BuiltinConnector, CanonicalAction, Connector, ConnectorCredential, FakeConnector,
    OAuthCredential, a1_cell_count, enforce_response_budget, validate_connection_credential,
    validate_enrolled_resource,
};
use leasegate_policy::RulePolicyEngine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, RwLock},
    time::{Duration as StdDuration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use zeroize::{Zeroize, Zeroizing};

const AUTH_FAILURE_LIMIT: usize = 10;
const AUTH_FAILURE_WINDOW: StdDuration = StdDuration::from_secs(60);
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
    google_oauth_flows: Arc<Mutex<HashMap<String, GoogleOAuthFlow>>>,
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
    pub totp: Option<TotpConfig>,
    #[serde(default)]
    pub totp_uri: Option<String>,
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
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub group_id: Option<GroupId>,
    pub totp: Option<TotpConfig>,
    pub totp_uri: Option<String>,
    pub custom_fields: Option<Vec<ItemField>>,
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
    ApprovalRequired { approval: ApprovalRecord },
}

impl KeyLeaseService {
    pub fn new(store: Arc<NativeStore>) -> Result<Self> {
        let rules = store.load_policy_rules()?;
        let mut connectors: HashMap<String, Arc<dyn Connector>> = HashMap::new();
        connectors.insert("fake".into(), Arc::new(FakeConnector::default()));
        connectors.insert(
            "google_workspace".into(),
            Arc::new(BuiltinConnector::google()),
        );
        connectors.insert("github".into(), Arc::new(BuiltinConnector::github()));
        connectors.insert("linear".into(), Arc::new(BuiltinConnector::linear()));
        connectors.insert("notion".into(), Arc::new(BuiltinConnector::notion()));
        Ok(Self {
            store,
            session: Mutex::new(None),
            policy: RwLock::new(RulePolicyEngine::new(rules)),
            connectors,
            active_executions: Mutex::new(HashMap::new()),
            authentication_failures: Mutex::new(HashMap::new()),
            google_oauth_flows: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    pub fn initialize(&self, password: &[u8], session_ttl: Duration) -> Result<VaultId> {
        validate_session_timeout(session_ttl)?;
        let vault = self.store.initialize(password)?;
        let id = vault.vault_id.clone();
        *self.session.lock().map_err(|_| KeyLeaseError::Storage)? = Some(Session {
            vault,
            idle_timeout: session_ttl,
            last_activity: Utc::now(),
        });
        Ok(id)
    }
    pub fn unlock(&self, password: &[u8], session_ttl: Duration) -> Result<VaultId> {
        validate_session_timeout(session_ttl)?;
        let vault = self.store.unlock(password)?;
        let id = vault.vault_id.clone();
        *self.session.lock().map_err(|_| KeyLeaseError::Storage)? = Some(Session {
            vault,
            idle_timeout: session_ttl,
            last_activity: Utc::now(),
        });
        Ok(id)
    }
    pub fn unlock_for_client(
        &self,
        agent_id: &AgentId,
        password: &[u8],
        session_ttl: Duration,
    ) -> Result<VaultId> {
        let bucket = format!("vault-unlock:{}", agent_id.0);
        let now = Instant::now();
        {
            let mut failures = self
                .authentication_failures
                .lock()
                .map_err(|_| KeyLeaseError::Storage)?;
            let attempts = failures.entry(bucket.clone()).or_default();
            attempts.retain(|attempt| now.duration_since(*attempt) < AUTH_FAILURE_WINDOW);
            if attempts.len() >= AUTH_FAILURE_LIMIT {
                return Err(KeyLeaseError::Denied {
                    reason: "vault unlock rate limit exceeded".into(),
                });
            }
        }
        match self.unlock(password, session_ttl) {
            Ok(vault_id) => {
                self.authentication_failures
                    .lock()
                    .map_err(|_| KeyLeaseError::Storage)?
                    .remove(&bucket);
                Ok(vault_id)
            }
            Err(error) => {
                self.authentication_failures
                    .lock()
                    .map_err(|_| KeyLeaseError::Storage)?
                    .entry(bucket)
                    .or_default()
                    .push_back(now);
                Err(error)
            }
        }
    }
    pub fn lock(&self) -> Result<()> {
        *self.session.lock().map_err(|_| KeyLeaseError::Storage)? = None;
        self.revoke_session_authority()
    }
    pub fn status(&self) -> Result<Value> {
        let mut guard = self.session.lock().map_err(|_| KeyLeaseError::Storage)?;
        let now = Utc::now();
        let expired = guard
            .as_ref()
            .is_some_and(|session| session.last_activity + session.idle_timeout <= now);
        if expired {
            *guard = None;
            drop(guard);
            self.revoke_session_authority()?;
            return Ok(serde_json::json!({"locked":true,"requires_user_action":true}));
        }
        Ok(match guard.as_ref() {
            Some(s) => {
                serde_json::json!({"locked":false,"vault_id":s.vault.vault_id,"idle_expires_at":s.last_activity+s.idle_timeout})
            }
            None => serde_json::json!({"locked":true,"requires_user_action":true}),
        })
    }

    pub fn register_client(&self, name: &str) -> Result<(AgentId, String)> {
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "client name must be ASCII letters, digits, '-' or '_'".into(),
            });
        }
        let id = AgentId(format!("agent_{name}"));
        let token = self.store.register_client(&id)?;
        Ok((id, token))
    }
    pub fn list_clients(&self) -> Result<Vec<AgentId>> {
        self.store.list_clients()
    }
    pub fn revoke_client(&self, agent_id: &AgentId) -> Result<()> {
        self.store.revoke_client(agent_id)
    }
    pub fn authenticate(
        &self,
        agent_id: &AgentId,
        token: &str,
        session_id: &str,
    ) -> Result<ActorContext> {
        let now = Instant::now();
        {
            let mut failures = self
                .authentication_failures
                .lock()
                .map_err(|_| KeyLeaseError::Storage)?;
            failures.retain(|_, attempts| {
                attempts.retain(|attempt| now.duration_since(*attempt) < AUTH_FAILURE_WINDOW);
                !attempts.is_empty()
            });
            if !failures.contains_key(&agent_id.0) && failures.len() >= 1024 {
                return Err(KeyLeaseError::Denied {
                    reason: "client authentication rate limit exceeded".into(),
                });
            }
            let attempts = failures.entry(agent_id.0.clone()).or_default();
            if attempts.len() >= AUTH_FAILURE_LIMIT {
                return Err(KeyLeaseError::Denied {
                    reason: "client authentication rate limit exceeded".into(),
                });
            }
        }
        if let Err(error) = self.store.authenticate_client(agent_id, token) {
            self.authentication_failures
                .lock()
                .map_err(|_| KeyLeaseError::Storage)?
                .entry(agent_id.0.clone())
                .or_default()
                .push_back(now);
            return Err(error);
        }
        self.authentication_failures
            .lock()
            .map_err(|_| KeyLeaseError::Storage)?
            .remove(&agent_id.0);
        Ok(ActorContext {
            agent_id: agent_id.clone(),
            workload_id: None,
            human_principal: None,
            on_behalf_of: None,
            client_session_id: session_id.into(),
        })
    }
    pub fn add_grant(&self, rule: PolicyRule) -> Result<()> {
        if rule.actions.is_empty()
            || rule.resource_prefix.trim().is_empty()
            || rule.max_lease_ttl_seconds == 0
            || rule.max_uses == 0
            || rule.expires_at.is_some_and(|expiry| expiry <= Utc::now())
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "grant scope, lifetime, actions and use limit must be non-empty".into(),
            });
        }
        self.store.save_policy_rule(&rule)?;
        let rules = self.store.load_policy_rules()?;
        *self.policy.write().map_err(|_| KeyLeaseError::Storage)? = RulePolicyEngine::new(rules);
        Ok(())
    }
    pub fn list_grants(&self) -> Result<Vec<PolicyRule>> {
        self.store.load_policy_rules()
    }
    pub fn revoke_grant(&self, id: &str) -> Result<()> {
        self.store.delete_policy_rule(id)?;
        let rules = self.store.load_policy_rules()?;
        *self.policy.write().map_err(|_| KeyLeaseError::Storage)? = RulePolicyEngine::new(rules);
        Ok(())
    }

    pub fn create_group(&self, name: &str, parent_id: Option<GroupId>) -> Result<VaultGroup> {
        self.with_vault(|vault| {
            validate_group(name, parent_id.as_ref(), &self.store.list_groups(vault)?)?;
            let now = Utc::now();
            let group = VaultGroup {
                id: GroupId::new(),
                vault_id: vault.vault_id.clone(),
                parent_id,
                name: name.into(),
                revision: 1,
                created_at: now,
                updated_at: now,
            };
            self.store.put_group(vault, &group, Some(0), None)?;
            Ok(group)
        })
    }
    pub fn list_groups(&self) -> Result<Vec<VaultGroup>> {
        self.with_vault(|vault| self.store.list_groups(vault))
    }
    pub fn create_group_authorized(
        &self,
        actor: &ActorContext,
        name: &str,
        parent_id: Option<GroupId>,
        idempotency_key: &str,
        dry_run: bool,
    ) -> Result<VaultGroup> {
        self.with_vault(|vault| {
            validate_group(name, None, &[])?;
            validate_idempotency_key(idempotency_key)?;
            let request_material = operation_material(&serde_json::json!({
                "operation":"group:create",
                "actor":actor.agent_id,
                "name":name,
                "parent_id":parent_id,
            }))?;
            self.authorize_vault(
                actor,
                "group:create",
                &format!("kl://{}/groups", vault.vault_id.0),
                serde_json::json!({"name":name,"parent_id":parent_id}),
            )?;
            if !dry_run
                && let Some(replay) =
                    self.store
                        .mutation_replay(vault, idempotency_key, &request_material)?
            {
                return self.store.get_group(vault, &GroupId(replay.item_id.0));
            }
            validate_group(name, parent_id.as_ref(), &self.store.list_groups(vault)?)?;
            let now = Utc::now();
            let group = VaultGroup {
                id: GroupId::new(),
                vault_id: vault.vault_id.clone(),
                parent_id,
                name: name.into(),
                revision: 1,
                created_at: now,
                updated_at: now,
            };
            if !dry_run {
                let audit = self.vault_audit_event(
                    actor,
                    "group:create",
                    &group.id.0,
                    "allow",
                    "success",
                    vec!["name".into()],
                );
                self.store.put_group(
                    vault,
                    &group,
                    Some(0),
                    Some(MutationContext {
                        actor: &actor.agent_id.0,
                        idempotency_key,
                        request_material: &request_material,
                        audit_event: Some(&audit),
                    }),
                )?;
            } else {
                self.audit_vault(
                    actor,
                    "group:create",
                    &group.id.0,
                    "allow",
                    "dry_run",
                    vec!["name".into()],
                )?;
            }
            Ok(group)
        })
    }
    pub fn list_groups_authorized(&self, actor: &ActorContext) -> Result<Vec<VaultGroup>> {
        self.with_vault(|vault| {
            self.authorize_vault(
                actor,
                "entry:search",
                &format!("kl://{}", vault.vault_id.0),
                Value::Object(Default::default()),
            )?;
            self.store.list_groups(vault)
        })
    }
    pub fn update_group(
        &self,
        id: &GroupId,
        name: &str,
        expected_revision: u64,
    ) -> Result<VaultGroup> {
        self.with_vault(|vault| {
            let groups = self.store.list_groups(vault)?;
            validate_group(name, None, &groups)?;
            let mut group = groups.into_iter().find(|g| &g.id == id).ok_or_else(|| {
                KeyLeaseError::NotFound {
                    resource: id.0.clone(),
                }
            })?;
            if group.revision != expected_revision {
                return Err(KeyLeaseError::RevisionConflict {
                    expected: expected_revision,
                    actual: group.revision,
                    retryable: false,
                });
            }
            group.name = name.into();
            group.revision += 1;
            group.updated_at = Utc::now();
            self.store
                .put_group(vault, &group, Some(expected_revision), None)?;
            Ok(group)
        })
    }
    pub fn delete_group(&self, id: &GroupId, expected_revision: u64) -> Result<()> {
        self.with_vault(|vault| {
            let groups = self.store.list_groups(vault)?;
            let group = groups.iter().find(|group| &group.id == id).ok_or_else(|| {
                KeyLeaseError::NotFound {
                    resource: id.0.clone(),
                }
            })?;
            if group.revision != expected_revision {
                return Err(KeyLeaseError::RevisionConflict {
                    expected: expected_revision,
                    actual: group.revision,
                    retryable: false,
                });
            }
            if groups
                .iter()
                .any(|group| group.parent_id.as_ref() == Some(id))
                || self
                    .store
                    .list_items(vault)?
                    .iter()
                    .any(|item| &item.group_id == id)
            {
                return Err(KeyLeaseError::Denied {
                    reason: "group must be empty before deletion".into(),
                });
            }
            self.store.delete_group(vault, id, expected_revision, None)
        })
    }
    pub fn update_group_authorized(
        &self,
        actor: &ActorContext,
        id: &GroupId,
        name: &str,
        expected_revision: u64,
        idempotency_key: &str,
        dry_run: bool,
    ) -> Result<VaultGroup> {
        self.with_vault(|vault| {
            validate_idempotency_key(idempotency_key)?;
            let request_material = operation_material(&serde_json::json!({
                "operation":"group:update",
                "actor":actor.agent_id,
                "id":id,
                "name":name,
                "expected_revision":expected_revision,
            }))?;
            let resource = format!("kl://{}/group/{}", vault.vault_id.0, id.0);
            self.authorize_vault(
                actor,
                "group:update",
                &resource,
                serde_json::json!({"name":name,"expected_revision":expected_revision}),
            )?;
            if !dry_run
                && let Some(replay) =
                    self.store
                        .mutation_replay(vault, idempotency_key, &request_material)?
            {
                return self.store.get_group(vault, &GroupId(replay.item_id.0));
            }
            let groups = self.store.list_groups(vault)?;
            validate_group(name, None, &groups)?;
            let mut group = groups
                .into_iter()
                .find(|group| &group.id == id)
                .ok_or_else(|| KeyLeaseError::NotFound {
                    resource: id.0.clone(),
                })?;
            if group.revision != expected_revision {
                return Err(KeyLeaseError::RevisionConflict {
                    expected: expected_revision,
                    actual: group.revision,
                    retryable: false,
                });
            }
            group.name = name.into();
            group.revision += 1;
            group.updated_at = Utc::now();
            if dry_run {
                self.audit_vault(
                    actor,
                    "group:update",
                    &resource,
                    "allow",
                    "dry_run",
                    vec!["name".into()],
                )?;
            } else {
                let audit = self.vault_audit_event(
                    actor,
                    "group:update",
                    &resource,
                    "allow",
                    "success",
                    vec!["name".into()],
                );
                self.store.put_group(
                    vault,
                    &group,
                    Some(expected_revision),
                    Some(MutationContext {
                        actor: &actor.agent_id.0,
                        idempotency_key,
                        request_material: &request_material,
                        audit_event: Some(&audit),
                    }),
                )?;
            }
            Ok(group)
        })
    }
    pub fn delete_group_authorized(
        &self,
        actor: &ActorContext,
        id: &GroupId,
        expected_revision: u64,
        idempotency_key: &str,
        dry_run: bool,
    ) -> Result<()> {
        self.with_vault(|vault| {
            validate_idempotency_key(idempotency_key)?;
            let request_material = operation_material(&serde_json::json!({
                "operation":"group:delete",
                "actor":actor.agent_id,
                "id":id,
                "expected_revision":expected_revision,
            }))?;
            let resource = format!("kl://{}/group/{}", vault.vault_id.0, id.0);
            self.authorize_vault(
                actor,
                "group:delete",
                &resource,
                serde_json::json!({"expected_revision":expected_revision}),
            )?;
            if !dry_run
                && self
                    .store
                    .mutation_replay(vault, idempotency_key, &request_material)?
                    .is_some()
            {
                return Ok(());
            }
            let groups = self.store.list_groups(vault)?;
            let group = groups.iter().find(|group| &group.id == id).ok_or_else(|| {
                KeyLeaseError::NotFound {
                    resource: id.0.clone(),
                }
            })?;
            if group.revision != expected_revision {
                return Err(KeyLeaseError::RevisionConflict {
                    expected: expected_revision,
                    actual: group.revision,
                    retryable: false,
                });
            }
            if groups
                .iter()
                .any(|group| group.parent_id.as_ref() == Some(id))
                || self
                    .store
                    .list_items(vault)?
                    .iter()
                    .any(|item| &item.group_id == id)
            {
                return Err(KeyLeaseError::Denied {
                    reason: "group must be empty before deletion".into(),
                });
            }
            if dry_run {
                self.audit_vault(actor, "group:delete", &resource, "allow", "dry_run", vec![])
            } else {
                let audit = self.vault_audit_event(
                    actor,
                    "group:delete",
                    &resource,
                    "allow",
                    "success",
                    vec![],
                );
                self.store.delete_group(
                    vault,
                    id,
                    expected_revision,
                    Some(MutationContext {
                        actor: &actor.agent_id.0,
                        idempotency_key,
                        request_material: &request_material,
                        audit_event: Some(&audit),
                    }),
                )
            }
        })
    }

    pub fn create_entry(
        &self,
        actor: &ActorContext,
        mut input: NewEntryInput,
        idempotency_key: &str,
        dry_run: bool,
    ) -> Result<ItemMetadata> {
        self.with_vault(|vault| {
            normalize_totp(&mut input.totp, &mut input.totp_uri)?;
            validate_custom_fields(&input.custom_fields)?;
            validate_item_title(&input.title)?;
            validate_idempotency_key(idempotency_key)?;
            let request_value = serde_json::to_value(&input).map_err(|_| KeyLeaseError::Storage)?;
            let request_material = operation_material(&serde_json::json!({
                "operation":"entry:create",
                "actor":actor.agent_id,
                "input":request_value,
            }))?;
            let resource = format!("kl://{}/group/{}", vault.vault_id.0, input.group_id.0);
            self.authorize_vault(actor, "entry:create", &resource, request_value)?;
            if input.password.is_some()
                || input.custom_fields.iter().any(|field| {
                    field.protected
                        || matches!(
                            field.sensitivity,
                            Sensitivity::Secret | Sensitivity::HighlySensitive
                        )
                })
            {
                self.authorize_vault(
                    actor,
                    "entry:update_protected_fields",
                    &resource,
                    serde_json::json!({"operation":"set_new_protected_fields"}),
                )?;
            }
            if input.totp.is_some() {
                self.authorize_vault(
                    actor,
                    "entry:update_totp",
                    &resource,
                    serde_json::json!({"operation":"set_new_totp"}),
                )?;
            }
            if !dry_run
                && let Some(replay) =
                    self.store
                        .mutation_replay(vault, idempotency_key, &request_material)?
            {
                return Ok(self
                    .store
                    .get_item_at_revision(vault, &replay.item_id, replay.result_revision)?
                    .metadata());
            }
            if !self
                .store
                .list_groups(vault)?
                .iter()
                .any(|group| group.id == input.group_id)
            {
                return Err(KeyLeaseError::NotFound {
                    resource: input.group_id.0.clone(),
                });
            }
            let now = Utc::now();
            let mut fields = input.custom_fields.clone();
            if let Some(v) = &input.username {
                fields.push(field(
                    "username",
                    "Username",
                    FieldValue::Text(v.clone()),
                    Sensitivity::PrivateMetadata,
                    false,
                ));
            }
            if let Some(v) = &input.password {
                fields.push(field(
                    "password",
                    "Password",
                    FieldValue::Concealed(v.clone()),
                    Sensitivity::Secret,
                    true,
                ));
            }
            if let Some(value) = &input.totp {
                fields.push(field(
                    "otp",
                    "One-time password",
                    FieldValue::Totp(value.clone()),
                    Sensitivity::Secret,
                    true,
                ));
            }
            let item = VaultItem {
                id: ItemId::new(),
                vault_id: vault.vault_id.clone(),
                group_id: input.group_id.clone(),
                kind: validate_kind(&input.kind)?,
                title: input.title.clone(),
                sections: vec![],
                fields,
                urls: input
                    .url
                    .iter()
                    .map(|url| ItemUrl {
                        label: None,
                        url: url.clone(),
                    })
                    .collect(),
                tags: vec![],
                attachments: vec![],
                notes: input.notes.clone(),
                schema_version: 1,
                revision: 1,
                created_at: now,
                updated_at: now,
                secret_changed_at: input.password.as_ref().map(|_| now),
                expires_at: None,
                rotation_interval_days: None,
                issuer: None,
                environment: None,
                owner: None,
                status: ItemStatus::Active,
                extensions: Default::default(),
            };
            if !dry_run {
                let audit = self.vault_audit_event(
                    actor,
                    "entry:create",
                    &item.id.0,
                    "allow",
                    "success",
                    vec!["item".into()],
                );
                self.store.put_item(
                    vault,
                    &item,
                    Some(0),
                    MutationContext {
                        actor: &actor.agent_id.0,
                        idempotency_key,
                        request_material: &request_material,
                        audit_event: Some(&audit),
                    },
                )?;
            } else {
                self.audit_vault(
                    actor,
                    "entry:create",
                    &item.id.0,
                    "allow",
                    "dry_run",
                    vec!["item".into()],
                )?;
            }
            Ok(item.metadata())
        })
    }

    pub fn update_entry(
        &self,
        actor: &ActorContext,
        id: &ItemId,
        mut patch: EntryPatch,
        expected_revision: u64,
        idempotency_key: &str,
        dry_run: bool,
    ) -> Result<ItemMetadata> {
        self.with_vault(|vault| {
            normalize_totp(&mut patch.totp, &mut patch.totp_uri)?;
            validate_idempotency_key(idempotency_key)?;
            if let Some(fields) = &patch.custom_fields {
                validate_custom_fields(fields)?;
            }
            if let Some(title) = &patch.title {
                validate_item_title(title)?;
            }
            let arguments = serde_json::to_value(&patch).map_err(|_| KeyLeaseError::Storage)?;
            let request_material = operation_material(&serde_json::json!({
                "operation":"entry:update",
                "actor":actor.agent_id,
                "item_id":id,
                "expected_revision":expected_revision,
                "patch":arguments,
            }))?;
            let resource = format!("kl://{}/{}", vault.vault_id.0, id.0);
            let has_standard_fields = patch.title.is_some()
                || patch.username.is_some()
                || patch.url.is_some()
                || patch.notes.is_some()
                || patch.custom_fields.as_ref().is_some_and(|fields| {
                    fields.iter().any(|field| !field_requires_protection(field))
                });
            let has_protected_fields = patch.password.is_some()
                || patch
                    .custom_fields
                    .as_ref()
                    .is_some_and(|fields| fields.iter().any(field_requires_protection));
            if !has_standard_fields
                && !has_protected_fields
                && patch.totp.is_none()
                && patch.group_id.is_none()
            {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "entry patch does not change any fields".into(),
                });
            }
            for required_capability in [
                has_standard_fields.then_some("entry:update_standard_fields"),
                has_protected_fields.then_some("entry:update_protected_fields"),
                patch.totp.is_some().then_some("entry:update_totp"),
                patch.group_id.is_some().then_some("entry:move"),
            ]
            .into_iter()
            .flatten()
            {
                self.authorize_vault(actor, required_capability, &resource, arguments.clone())?;
            }
            if !dry_run
                && let Some(replay) =
                    self.store
                        .mutation_replay(vault, idempotency_key, &request_material)?
            {
                if replay.item_id != *id {
                    return Err(KeyLeaseError::IdempotencyConflict);
                }
                return Ok(self
                    .store
                    .get_item_at_revision(vault, id, replay.result_revision)?
                    .metadata());
            }
            if let Some(group_id) = &patch.group_id
                && !self
                    .store
                    .list_groups(vault)?
                    .iter()
                    .any(|group| &group.id == group_id)
            {
                return Err(KeyLeaseError::NotFound {
                    resource: group_id.0.clone(),
                });
            }
            let mut item = self.store.get_item(vault, id)?;
            if item.revision != expected_revision {
                return Err(KeyLeaseError::RevisionConflict {
                    expected: expected_revision,
                    actual: item.revision,
                    retryable: false,
                });
            }
            let mut changed = vec![];
            if let Some(v) = patch.title {
                item.title = v;
                changed.push("title".into())
            }
            if let Some(v) = patch.username {
                upsert(
                    &mut item.fields,
                    "username",
                    FieldValue::Text(v),
                    Sensitivity::PrivateMetadata,
                    false,
                );
                changed.push("username".into())
            }
            if let Some(v) = patch.password {
                upsert(
                    &mut item.fields,
                    "password",
                    FieldValue::Concealed(v),
                    Sensitivity::Secret,
                    true,
                );
                item.secret_changed_at = Some(Utc::now());
                changed.push("password".into())
            }
            if let Some(v) = patch.url {
                item.urls = vec![ItemUrl {
                    label: None,
                    url: v,
                }];
                changed.push("url".into())
            }
            if let Some(v) = patch.notes {
                item.notes = Some(v);
                changed.push("notes".into())
            }
            if let Some(v) = patch.group_id {
                item.group_id = v;
                changed.push("group_id".into())
            }
            if let Some(v) = patch.totp {
                upsert(
                    &mut item.fields,
                    "otp",
                    FieldValue::Totp(v),
                    Sensitivity::Secret,
                    true,
                );
                changed.push("otp".into())
            }
            if let Some(fields) = patch.custom_fields {
                item.fields
                    .retain(|field| matches!(field.key.as_str(), "username" | "password" | "otp"));
                changed.extend(fields.iter().map(|field| field.key.clone()));
                item.fields.extend(fields);
            }
            item.revision += 1;
            item.updated_at = Utc::now();
            if !dry_run {
                let audit = self.vault_audit_event(
                    actor,
                    "entry:update",
                    &id.0,
                    "allow",
                    "success",
                    changed,
                );
                self.store.put_item(
                    vault,
                    &item,
                    Some(expected_revision),
                    MutationContext {
                        actor: &actor.agent_id.0,
                        idempotency_key,
                        request_material: &request_material,
                        audit_event: Some(&audit),
                    },
                )?;
            } else {
                self.audit_vault(actor, "entry:update", &id.0, "allow", "dry_run", changed)?;
            }
            Ok(item.metadata())
        })
    }

    pub fn search_entries(&self, actor: &ActorContext, query: &str) -> Result<Vec<ItemMetadata>> {
        self.with_vault(|vault| {
            self.authorize_vault(
                actor,
                "entry:search",
                &format!("kl://{}", vault.vault_id.0),
                serde_json::json!({"query":query}),
            )?;
            let q = query.to_lowercase();
            let result = self
                .store
                .list_items(vault)?
                .into_iter()
                .filter(|i| {
                    i.title.to_lowercase().contains(&q)
                        || i.metadata()
                            .username
                            .is_some_and(|u| u.to_lowercase().contains(&q))
                        || i.urls.iter().any(|u| u.url.to_lowercase().contains(&q))
                })
                .map(|i| i.metadata())
                .collect();
            self.audit_vault(
                actor,
                "entry:search",
                &vault.vault_id.0,
                "allow",
                "success",
                vec![],
            )?;
            Ok(result)
        })
    }
    pub fn get_entry_metadata(&self, actor: &ActorContext, id: &ItemId) -> Result<ItemMetadata> {
        self.with_vault(|vault| {
            self.authorize_vault(
                actor,
                "entry:read_metadata",
                &format!("kl://{}/{}", vault.vault_id.0, id.0),
                Value::Object(Default::default()),
            )?;
            let metadata = self.store.get_item(vault, id)?.metadata();
            self.audit_vault(
                actor,
                "entry:read_metadata",
                &id.0,
                "allow",
                "success",
                vec![],
            )?;
            Ok(metadata)
        })
    }
    pub fn reveal_field_for_human(&self, id: &ItemId, key: &str) -> Result<String> {
        self.with_vault(|vault| {
            let item = self.store.get_item(vault, id)?;
            item.fields
                .into_iter()
                .find(|field| field.key == key)
                .and_then(|field| match field.value {
                    FieldValue::Text(value)
                    | FieldValue::Concealed(value)
                    | FieldValue::Url(value)
                    | FieldValue::Email(value)
                    | FieldValue::Phone(value) => Some(value),
                    _ => None,
                })
                .ok_or_else(|| KeyLeaseError::NotFound {
                    resource: format!("{}/{}", id.0, key),
                })
        })
    }
    pub fn reveal_field_authorized(
        &self,
        actor: &ActorContext,
        id: &ItemId,
        key: &str,
    ) -> Result<String> {
        if key.is_empty()
            || key.len() > 128
            || key.chars().any(char::is_control)
            || matches!(key, "otp")
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "invalid reveal field".into(),
            });
        }
        self.with_vault(|vault| {
            let action = if key == "username" {
                "entry:read_username"
            } else {
                "entry:read_secret"
            };
            let resource = format!("kl://{}/{}", vault.vault_id.0, id.0);
            self.authorize_vault(actor, action, &resource, serde_json::json!({"field":key}))?;
            let item = self.store.get_item(vault, id)?;
            let value = item
                .fields
                .into_iter()
                .find(|field| field.key == key)
                .and_then(|field| match field.value {
                    FieldValue::Text(value)
                    | FieldValue::Concealed(value)
                    | FieldValue::Url(value)
                    | FieldValue::Email(value)
                    | FieldValue::Phone(value) => Some(value),
                    _ => None,
                })
                .ok_or_else(|| KeyLeaseError::NotFound {
                    resource: format!("{}/{}", id.0, key),
                })?;
            self.audit_vault(
                actor,
                action,
                &resource,
                "allow",
                "success",
                vec![key.into()],
            )?;
            Ok(value)
        })
    }
    pub fn totp_for_human(&self, id: &ItemId) -> Result<(String, u64)> {
        self.with_vault(|vault| {
            let item = self.store.get_item(vault, id)?;
            let config = item
                .fields
                .into_iter()
                .find(|field| field.key == "otp")
                .and_then(|field| match field.value {
                    FieldValue::Totp(value) => Some(value),
                    _ => None,
                })
                .ok_or_else(|| KeyLeaseError::NotFound {
                    resource: format!("{}/otp", id.0),
                })?;
            current_totp(&config)
        })
    }
    pub fn totp_authorized(&self, actor: &ActorContext, id: &ItemId) -> Result<(String, u64)> {
        self.with_vault(|vault| {
            let resource = format!("kl://{}/{}", vault.vault_id.0, id.0);
            self.authorize_vault(
                actor,
                "entry:read_secret",
                &resource,
                serde_json::json!({"field":"otp","representation":"current_code"}),
            )?;
            let item = self.store.get_item(vault, id)?;
            let config = item
                .fields
                .into_iter()
                .find(|field| field.key == "otp")
                .and_then(|field| match field.value {
                    FieldValue::Totp(value) => Some(value),
                    _ => None,
                })
                .ok_or_else(|| KeyLeaseError::NotFound {
                    resource: format!("{}/otp", id.0),
                })?;
            let result = current_totp(&config)?;
            self.audit_vault(
                actor,
                "entry:read_secret",
                &resource,
                "allow",
                "success",
                vec!["otp".into()],
            )?;
            Ok(result)
        })
    }
    pub fn entry_history_for_human(&self, id: &ItemId) -> Result<Vec<ItemMetadata>> {
        self.with_vault(|vault| {
            self.store
                .item_history(vault, id)
                .map(|items| items.into_iter().map(|item| item.metadata()).collect())
        })
    }
    pub fn entry_history_authorized(
        &self,
        actor: &ActorContext,
        id: &ItemId,
    ) -> Result<Vec<ItemMetadata>> {
        self.with_vault(|vault| {
            let resource = format!("kl://{}/{}", vault.vault_id.0, id.0);
            self.authorize_vault(
                actor,
                "entry:read_metadata",
                &resource,
                serde_json::json!({"view":"history"}),
            )?;
            let history = self
                .store
                .item_history(vault, id)?
                .into_iter()
                .map(|item| {
                    let mut metadata = item.metadata();
                    metadata.username = None;
                    metadata
                })
                .collect();
            self.audit_vault(
                actor,
                "entry:read_metadata",
                &resource,
                "allow",
                "success",
                vec!["history".into()],
            )?;
            Ok(history)
        })
    }
    pub fn delete_entry(
        &self,
        actor: &ActorContext,
        id: &ItemId,
        expected_revision: u64,
        idempotency_key: &str,
        dry_run: bool,
    ) -> Result<()> {
        self.with_vault(|vault| {
            validate_idempotency_key(idempotency_key)?;
            let request_material = operation_material(&serde_json::json!({
                "operation":"entry:delete",
                "actor":actor.agent_id,
                "item_id":id,
                "expected_revision":expected_revision,
            }))?;
            self.authorize_vault(
                actor,
                "entry:delete",
                &format!("kl://{}/{}", vault.vault_id.0, id.0),
                serde_json::json!({"expected_revision":expected_revision}),
            )?;
            if !dry_run
                && let Some(replay) =
                    self.store
                        .mutation_replay(vault, idempotency_key, &request_material)?
            {
                return if replay.item_id == *id {
                    Ok(())
                } else {
                    Err(KeyLeaseError::IdempotencyConflict)
                };
            }
            let item = self.store.get_item(vault, id)?;
            if item.revision != expected_revision {
                return Err(KeyLeaseError::RevisionConflict {
                    expected: expected_revision,
                    actual: item.revision,
                    retryable: false,
                });
            }
            if !dry_run {
                let audit = self.vault_audit_event(
                    actor,
                    "entry:delete",
                    &id.0,
                    "allow",
                    "success",
                    vec![],
                );
                self.store.delete_item(
                    vault,
                    id,
                    expected_revision,
                    MutationContext {
                        actor: &actor.agent_id.0,
                        idempotency_key,
                        request_material: &request_material,
                        audit_event: Some(&audit),
                    },
                )?;
            } else {
                self.audit_vault(actor, "entry:delete", &id.0, "allow", "dry_run", vec![])?;
            }
            Ok(())
        })
    }

    pub fn add_connection(
        &self,
        provider: &str,
        credential: String,
        authorized_resources: Vec<String>,
    ) -> Result<ConnectionRecord> {
        let connector =
            self.connectors
                .get(provider)
                .ok_or_else(|| KeyLeaseError::InvalidRequest {
                    reason: "unknown provider".into(),
                })?;
        let manifest = connector.manifest();
        validate_connection_credential(provider, &credential)?;
        let mut authorized_resources = authorized_resources
            .iter()
            .map(|resource| validate_enrolled_resource(&manifest, resource))
            .collect::<Result<Vec<_>>>()?;
        authorized_resources.sort();
        authorized_resources.dedup();
        self.with_vault(|vault| {
            let now = Utc::now();
            let item = VaultItem {
                id: ItemId::new(),
                vault_id: vault.vault_id.clone(),
                group_id: GroupId("group_connections".into()),
                kind: "core.api_credential".into(),
                title: format!("{} connection credential", provider),
                sections: vec![],
                fields: vec![field(
                    "credential",
                    "Credential",
                    FieldValue::Concealed(credential),
                    Sensitivity::HighlySensitive,
                    true,
                )],
                urls: vec![],
                tags: vec!["keylease.connection".into()],
                attachments: vec![],
                notes: None,
                schema_version: 1,
                revision: 1,
                created_at: now,
                updated_at: now,
                secret_changed_at: Some(now),
                expires_at: None,
                rotation_interval_days: None,
                issuer: Some(provider.into()),
                environment: None,
                owner: None,
                status: ItemStatus::Active,
                extensions: Default::default(),
            };
            self.store.put_item(
                vault,
                &item,
                Some(0),
                MutationContext {
                    actor: "local-human",
                    idempotency_key: &format!("connection-{}", item.id.0),
                    request_material: format!("connection-item:{}", item.id.0).as_bytes(),
                    audit_event: None,
                },
            )?;
            let record = ConnectionRecord {
                id: ConnectionId::new(),
                provider: provider.into(),
                connector_version: manifest.version,
                auth_method: manifest
                    .authentication_methods
                    .first()
                    .cloned()
                    .unwrap_or_default(),
                trust_mode: TrustMode::EdgeLocal,
                execution_location: "local".into(),
                credential_item_id: item.id.0,
                health: ConnectionHealth::Connected,
                authorized_resources,
                created_at: now,
                updated_at: now,
            };
            self.store.save_connection(&record)?;
            Ok(record)
        })
    }
    pub async fn test_connection(&self, id: &ConnectionId) -> Result<()> {
        let (record, credential) = self.connection_credential(id)?;
        self.connector(&record)?.test_connection(&credential).await
    }
    pub fn list_connections(&self) -> Result<Vec<ConnectionRecord>> {
        self.store.list_connections()
    }
    pub fn list_connections_authorized(
        &self,
        actor: &ActorContext,
    ) -> Result<Vec<ConnectionRecord>> {
        self.with_vault(|vault| {
            let resource = format!("kl://{}/connections", vault.vault_id.0);
            self.authorize_vault(
                actor,
                "connection:list",
                &resource,
                Value::Object(Default::default()),
            )?;
            let connections = self.store.list_connections()?;
            self.audit_vault(
                actor,
                "connection:list",
                &resource,
                "allow",
                "success",
                vec![],
            )?;
            Ok(connections)
        })
    }
    pub fn add_connection_authorized(
        &self,
        actor: &ActorContext,
        provider: &str,
        credential: String,
        authorized_resources: Vec<String>,
    ) -> Result<ConnectionRecord> {
        let resource = self.with_vault(|vault| {
            let resource = format!("kl://{}/connections", vault.vault_id.0);
            self.authorize_vault(
                actor,
                "connection:add",
                &resource,
                serde_json::json!({
                    "provider":provider,
                    "authorized_resources":authorized_resources,
                }),
            )?;
            Ok(resource)
        })?;
        let record = self.add_connection(provider, credential, authorized_resources)?;
        self.audit_vault(
            actor,
            "connection:add",
            &resource,
            "allow",
            "success",
            vec!["provider".into(), "authorized_resources".into()],
        )?;
        Ok(record)
    }
    pub async fn begin_google_oauth(
        &self,
        actor: &ActorContext,
        client_id: &str,
        client_secret: Option<String>,
    ) -> Result<GoogleOAuthStart> {
        if client_id.len() > 512
            || !client_id.ends_with(".apps.googleusercontent.com")
            || client_id.chars().any(char::is_control)
            || client_secret
                .as_ref()
                .is_some_and(|secret| secret.len() > 2048 || secret.chars().any(char::is_control))
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "invalid Google desktop OAuth client configuration".into(),
            });
        }
        self.with_vault(|vault| {
            self.authorize_vault(
                actor,
                "connection:add",
                &format!("kl://{}/connections", vault.vault_id.0),
                serde_json::json!({"provider":"google_workspace","flow":"oauth_picker"}),
            )
        })?;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        let port = listener
            .local_addr()
            .map_err(|_| KeyLeaseError::Storage)?
            .port();
        let redirect_uri = format!("http://127.0.0.1:{port}/oauth2/callback");
        let flow_id = random_token("google_oauth_");
        let state = random_token("state_");
        let verifier = random_token("pkce_");
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let mut authorization_url = url::Url::parse("https://accounts.google.com/o/oauth2/v2/auth")
            .map_err(|_| KeyLeaseError::Storage)?;
        authorization_url
            .query_pairs_mut()
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", GOOGLE_OAUTH_SCOPE)
            .append_pair("access_type", "offline")
            .append_pair("include_granted_scopes", "false")
            .append_pair("prompt", "consent")
            .append_pair("trigger_onepick", "true")
            .append_pair("allow_multiple", "true")
            .append_pair("allow_folder_selection", "true")
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", &state);
        let expires_at = Utc::now() + Duration::seconds(GOOGLE_OAUTH_FLOW_TTL.as_secs() as i64);
        {
            let mut flows = self
                .google_oauth_flows
                .lock()
                .map_err(|_| KeyLeaseError::Storage)?;
            let now = Instant::now();
            flows.retain(|_, flow| flow.expires_at > now);
            if flows.len() >= 64 {
                return Err(KeyLeaseError::Denied {
                    reason: "too many pending Google OAuth flows".into(),
                });
            }
            flows.insert(
                flow_id.clone(),
                GoogleOAuthFlow {
                    agent_id: actor.agent_id.clone(),
                    state,
                    verifier,
                    redirect_uri,
                    client_id: client_id.into(),
                    client_secret,
                    expires_at: Instant::now() + GOOGLE_OAUTH_FLOW_TTL,
                    callback: GoogleOAuthCallback::Waiting,
                },
            );
        }
        let flows = Arc::clone(&self.google_oauth_flows);
        let listener_flow_id = flow_id.clone();
        tokio::spawn(async move {
            capture_google_oauth_callback(listener, flows, listener_flow_id).await;
        });
        let flows = Arc::clone(&self.google_oauth_flows);
        let cleanup_flow_id = flow_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(GOOGLE_OAUTH_FLOW_TTL).await;
            if let Ok(mut flows) = flows.lock()
                && flows
                    .get(&cleanup_flow_id)
                    .is_some_and(|flow| flow.expires_at <= Instant::now())
            {
                flows.remove(&cleanup_flow_id);
            }
        });
        Ok(GoogleOAuthStart {
            flow_id,
            authorization_url: authorization_url.into(),
            expires_at,
        })
    }

    pub async fn complete_google_oauth(
        &self,
        actor: &ActorContext,
        flow_id: &str,
    ) -> Result<ConnectionRecord> {
        if flow_id.len() > 256 || !flow_id.starts_with("google_oauth_") {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "invalid Google OAuth flow ID".into(),
            });
        }
        {
            let mut flows = self
                .google_oauth_flows
                .lock()
                .map_err(|_| KeyLeaseError::Storage)?;
            let flow = flows.get(flow_id).ok_or_else(|| KeyLeaseError::NotFound {
                resource: flow_id.into(),
            })?;
            if flow.agent_id != actor.agent_id {
                return Err(KeyLeaseError::Denied {
                    reason: "Google OAuth flow belongs to another client".into(),
                });
            }
            if flow.expires_at <= Instant::now() {
                flows.remove(flow_id);
                return Err(KeyLeaseError::Denied {
                    reason: "Google OAuth flow expired".into(),
                });
            }
            match &flow.callback {
                GoogleOAuthCallback::Waiting => {
                    return Err(KeyLeaseError::InvalidRequest {
                        reason: "Google OAuth/Picker flow has not returned yet".into(),
                    });
                }
                GoogleOAuthCallback::Failed(reason) => {
                    let reason = reason.clone();
                    flows.remove(flow_id);
                    return Err(KeyLeaseError::Denied {
                        reason: format!("Google OAuth/Picker failed: {reason}"),
                    });
                }
                GoogleOAuthCallback::Received { .. } => {}
            }
        }
        let flow = self
            .google_oauth_flows
            .lock()
            .map_err(|_| KeyLeaseError::Storage)?
            .remove(flow_id)
            .ok_or_else(|| KeyLeaseError::NotFound {
                resource: flow_id.into(),
            })?;
        let GoogleOAuthCallback::Received {
            code,
            picked_file_ids,
            scope,
        } = &flow.callback
        else {
            return Err(KeyLeaseError::Storage);
        };
        if scope.split_whitespace().collect::<Vec<_>>() != [GOOGLE_OAUTH_SCOPE]
            || picked_file_ids.is_empty()
            || picked_file_ids.len() > 25
        {
            return Err(KeyLeaseError::Denied {
                reason: "Google returned an invalid scope or Picker selection".into(),
            });
        }
        let mut form = vec![
            ("client_id", flow.client_id.as_str()),
            ("code", code.as_str()),
            ("code_verifier", flow.verifier.as_str()),
            ("grant_type", "authorization_code"),
            ("redirect_uri", flow.redirect_uri.as_str()),
        ];
        if let Some(secret) = flow.client_secret.as_deref() {
            form.push(("client_secret", secret));
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(StdDuration::from_secs(10))
            .timeout(StdDuration::from_secs(30))
            .build()
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        let response = client
            .post("https://oauth2.googleapis.com/token")
            .form(&form)
            .send()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        if !response.status().is_success() {
            return Err(KeyLeaseError::Denied {
                reason: "Google OAuth token exchange was rejected".into(),
            });
        }
        let token_bytes = response
            .bytes()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        if token_bytes.len() > MAX_GOOGLE_TOKEN_RESPONSE_BYTES {
            return Err(KeyLeaseError::ConnectorUnavailable { retryable: false });
        }
        let token: GoogleTokenResponse = serde_json::from_slice(&token_bytes)
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: false })?;
        if token.token_type != "Bearer"
            || token.scope.split_whitespace().collect::<Vec<_>>() != [GOOGLE_OAUTH_SCOPE]
            || token.refresh_token.is_none()
            || !(1..=86_400).contains(&token.expires_in)
        {
            return Err(KeyLeaseError::Denied {
                reason: "Google did not return an offline drive.file credential".into(),
            });
        }
        let resources =
            resolve_google_picker_resources(&client, &token.access_token, picked_file_ids).await?;
        let credential = OAuthCredential {
            access_token: token.access_token.clone(),
            refresh_token: token.refresh_token.clone(),
            client_id: Some(flow.client_id.clone()),
            client_secret: flow.client_secret.clone(),
            expires_at: Some(Utc::now() + Duration::seconds(token.expires_in as i64)),
            scopes: vec![GOOGLE_OAUTH_SCOPE.into()],
        };
        let credential = serde_json::to_string(&credential).map_err(|_| KeyLeaseError::Crypto)?;
        self.add_connection_authorized(actor, "google_workspace", credential, resources)
    }
    pub fn enroll_connection_resource_authorized(
        &self,
        actor: &ActorContext,
        id: &ConnectionId,
        resource_to_enroll: &str,
    ) -> Result<ConnectionRecord> {
        let resource = self.authorize_connection_operation(
            actor,
            id,
            "connection:enroll",
            serde_json::json!({"resource":resource_to_enroll}),
        )?;
        let record = self.enroll_connection_resource(id, resource_to_enroll)?;
        self.audit_vault(
            actor,
            "connection:enroll",
            &resource,
            "allow",
            "success",
            vec!["authorized_resources".into()],
        )?;
        Ok(record)
    }
    pub fn unenroll_connection_resource_authorized(
        &self,
        actor: &ActorContext,
        id: &ConnectionId,
        resource_to_remove: &str,
    ) -> Result<ConnectionRecord> {
        let resource = self.authorize_connection_operation(
            actor,
            id,
            "connection:unenroll",
            serde_json::json!({"resource":resource_to_remove}),
        )?;
        let record = self.unenroll_connection_resource(id, resource_to_remove)?;
        self.audit_vault(
            actor,
            "connection:unenroll",
            &resource,
            "allow",
            "success",
            vec!["authorized_resources".into()],
        )?;
        Ok(record)
    }
    pub async fn test_connection_authorized(
        &self,
        actor: &ActorContext,
        id: &ConnectionId,
    ) -> Result<()> {
        let resource = self.authorize_connection_operation(
            actor,
            id,
            "connection:test",
            Value::Object(Default::default()),
        )?;
        self.test_connection(id).await?;
        self.audit_vault(
            actor,
            "connection:test",
            &resource,
            "allow",
            "success",
            vec![],
        )
    }
    pub async fn refresh_connection_authorized(
        &self,
        actor: &ActorContext,
        id: &ConnectionId,
    ) -> Result<ConnectionRecord> {
        let resource = self.authorize_connection_operation(
            actor,
            id,
            "connection:refresh",
            Value::Object(Default::default()),
        )?;
        let record = self.refresh_connection(id).await?;
        self.audit_vault(
            actor,
            "connection:refresh",
            &resource,
            "allow",
            "success",
            vec!["health".into()],
        )?;
        Ok(record)
    }
    pub fn disconnect_connection_authorized(
        &self,
        actor: &ActorContext,
        id: &ConnectionId,
    ) -> Result<ConnectionRecord> {
        let resource = self.authorize_connection_operation(
            actor,
            id,
            "connection:disconnect",
            Value::Object(Default::default()),
        )?;
        let record = self.disconnect_connection(id)?;
        self.audit_vault(
            actor,
            "connection:disconnect",
            &resource,
            "allow",
            "success",
            vec!["health".into()],
        )?;
        Ok(record)
    }
    pub async fn revoke_connection_authorized(
        &self,
        actor: &ActorContext,
        id: &ConnectionId,
    ) -> Result<ConnectionRecord> {
        let resource = self.authorize_connection_operation(
            actor,
            id,
            "connection:revoke",
            Value::Object(Default::default()),
        )?;
        let record = self.revoke_connection(id).await?;
        self.audit_vault(
            actor,
            "connection:revoke",
            &resource,
            "allow",
            "success",
            vec!["health".into()],
        )?;
        Ok(record)
    }
    pub fn enroll_connection_resource(
        &self,
        id: &ConnectionId,
        resource: &str,
    ) -> Result<ConnectionRecord> {
        let mut record = self.store.get_connection(id)?;
        let connector = self.connector(&record)?;
        let canonical = validate_enrolled_resource(&connector.manifest(), resource)?;
        if !record.authorized_resources.contains(&canonical) {
            record.authorized_resources.push(canonical);
            record.authorized_resources.sort();
        }
        record.updated_at = Utc::now();
        self.store.save_connection(&record)?;
        Ok(record)
    }
    pub fn unenroll_connection_resource(
        &self,
        id: &ConnectionId,
        resource: &str,
    ) -> Result<ConnectionRecord> {
        let mut record = self.store.get_connection(id)?;
        let canonical = validate_enrolled_resource(&self.connector(&record)?.manifest(), resource)?;
        let before = record.authorized_resources.len();
        record
            .authorized_resources
            .retain(|authorized| authorized != &canonical);
        if before == record.authorized_resources.len() {
            return Err(KeyLeaseError::NotFound {
                resource: canonical,
            });
        }
        record.updated_at = Utc::now();
        self.store.save_connection(&record)?;
        Ok(record)
    }
    pub async fn refresh_connection(&self, id: &ConnectionId) -> Result<ConnectionRecord> {
        let (mut record, credential) = self.connection_credential(id)?;
        let connector = self.connector(&record)?;
        if let Some(refreshed) = connector.refresh(&credential).await? {
            self.with_vault(|vault| {
                let item_id = ItemId(record.credential_item_id.clone());
                let mut item = self.store.get_item(vault, &item_id)?;
                upsert(
                    &mut item.fields,
                    "credential",
                    FieldValue::Concealed(refreshed.expose().to_owned()),
                    Sensitivity::HighlySensitive,
                    true,
                );
                let expected = item.revision;
                item.revision += 1;
                item.updated_at = Utc::now();
                item.secret_changed_at = Some(Utc::now());
                self.store.put_item(
                    vault,
                    &item,
                    Some(expected),
                    MutationContext {
                        actor: "local-human",
                        idempotency_key: &format!("refresh-{}-{expected}", record.id.0),
                        request_material: format!("connection-refresh:{}:{expected}", record.id.0)
                            .as_bytes(),
                        audit_event: None,
                    },
                )
            })?;
        }
        record.health = ConnectionHealth::Connected;
        record.updated_at = Utc::now();
        self.store.save_connection(&record)?;
        Ok(record)
    }
    pub fn disconnect_connection(&self, id: &ConnectionId) -> Result<ConnectionRecord> {
        let mut record = self.store.get_connection(id)?;
        record.health = ConnectionHealth::Disconnected;
        record.updated_at = Utc::now();
        self.store.save_connection(&record)?;
        Ok(record)
    }
    pub async fn revoke_connection(&self, id: &ConnectionId) -> Result<ConnectionRecord> {
        let (mut record, credential) = self.connection_credential(id)?;
        self.connector(&record)?.revoke(&credential).await?;
        record.health = ConnectionHealth::Revoked;
        record.updated_at = Utc::now();
        self.store.save_connection(&record)?;
        Ok(record)
    }

    pub fn preview_kdbx_import(&self, bytes: &[u8], password: &str) -> Result<ImportPreview> {
        self.with_vault(|vault| {
            let mut source = bytes;
            let mut preview =
                KeepassRsAdapter.preview_import(&mut source, password, &vault.vault_id)?;
            let existing_items = self
                .store
                .list_items(vault)?
                .into_iter()
                .map(|item| item.id)
                .collect::<std::collections::HashSet<_>>();
            let before = preview.items.len();
            preview.items.retain(|item| {
                let duplicate = existing_items.contains(&item.id);
                if duplicate {
                    preview.report.duplicate_decisions.push(format!(
                        "{}: skipped because the stable item ID already exists",
                        item.id.0
                    ));
                }
                !duplicate
            });
            let existing_groups = self
                .store
                .list_groups(vault)?
                .into_iter()
                .map(|group| group.id)
                .collect::<std::collections::HashSet<_>>();
            preview.groups.retain(|group| {
                let duplicate = existing_groups.contains(&group.id);
                if duplicate {
                    preview
                        .report
                        .duplicate_decisions
                        .push(format!("{}: reused existing group", group.id.0));
                }
                !duplicate
            });
            if before != preview.items.len() {
                preview.report.warnings.push(format!(
                    "{} duplicate items will be skipped",
                    before - preview.items.len()
                ));
            }
            preview.report.successful_items = preview.items.len() as u64;
            Ok(preview)
        })
    }
    pub fn commit_kdbx_import(&self, preview: &ImportPreview) -> Result<MigrationReport> {
        self.with_vault(|vault| {
            let checksum = preview
                .report
                .source_checksum_sha256
                .as_deref()
                .ok_or_else(|| KeyLeaseError::InvalidRequest {
                    reason: "import preview has no source checksum".into(),
                })?;
            self.store.import_batch(
                vault,
                &preview.groups,
                &preview.items,
                &format!("kdbx-import-{checksum}"),
            )?;
            Ok(preview.report.clone())
        })
    }
    pub fn preview_onepux_import(&self, bytes: &[u8]) -> Result<OnePuxImportPreview> {
        self.with_vault(|vault| {
            let mut source = bytes;
            let mut preview = ZipOnePuxAdapter.preview_import(&mut source, &vault.vault_id)?;
            let existing_items = self
                .store
                .list_items(vault)?
                .into_iter()
                .map(|item| item.id)
                .collect::<std::collections::HashSet<_>>();
            let item_count = preview.items.len();
            preview.items.retain(|item| {
                let duplicate = existing_items.contains(&item.id);
                if duplicate {
                    preview.report.duplicate_decisions.push(format!(
                        "{}: skipped because the stable item ID already exists",
                        item.id.0
                    ));
                }
                !duplicate
            });
            let existing_groups = self
                .store
                .list_groups(vault)?
                .into_iter()
                .map(|group| group.id)
                .collect::<std::collections::HashSet<_>>();
            preview.groups.retain(|group| {
                let duplicate = existing_groups.contains(&group.id);
                if duplicate {
                    preview
                        .report
                        .duplicate_decisions
                        .push(format!("{}: reused existing group", group.id.0));
                }
                !duplicate
            });
            if item_count != preview.items.len() {
                preview.report.warnings.push(format!(
                    "{} duplicate items will be skipped",
                    item_count - preview.items.len()
                ));
            }
            preview.report.successful_groups = preview.groups.len() as u64;
            preview.report.successful_items = preview.items.len() as u64;
            Ok(preview)
        })
    }
    pub fn commit_onepux_import(
        &self,
        preview: &OnePuxImportPreview,
    ) -> Result<OnePuxMigrationReport> {
        self.with_vault(|vault| {
            self.store.import_batch(
                vault,
                &preview.groups,
                &preview.items,
                &format!("onepux-import-{}", preview.report.source_checksum_sha256),
            )?;
            Ok(preview.report.clone())
        })
    }
    pub fn export_kdbx(
        &self,
        password: &str,
        selected_item_ids: &[ItemId],
    ) -> Result<(Vec<u8>, MigrationReport)> {
        self.with_vault(|vault| {
            let groups = self.store.list_groups(vault)?;
            let selected = selected_item_ids
                .iter()
                .collect::<std::collections::HashSet<_>>();
            let items = self
                .store
                .list_items(vault)?
                .into_iter()
                .filter(|item| !item.tags.iter().any(|tag| tag == "keylease.connection"))
                .filter(|item| selected.is_empty() || selected.contains(&item.id))
                .collect::<Vec<_>>();
            if !selected.is_empty() && items.len() != selected.len() {
                return Err(KeyLeaseError::NotFound {
                    resource: "one or more selected KDBX export items".into(),
                });
            }
            let mut output = vec![];
            let report = KeepassRsAdapter.export(&mut output, password, &groups, &items)?;
            Ok((output, report))
        })
    }
    pub fn export_native_backup(&self) -> Result<Vec<u8>> {
        self.with_vault(|vault| self.store.export_native_backup(vault))
    }
    pub fn restore_native_backup(
        &self,
        password: &[u8],
        bytes: &[u8],
        session_ttl: Duration,
    ) -> Result<VaultId> {
        validate_session_timeout(session_ttl)?;
        let vault = self.store.restore_native_backup(password, bytes)?;
        let id = vault.vault_id.clone();
        *self.session.lock().map_err(|_| KeyLeaseError::Storage)? = Some(Session {
            vault,
            idle_timeout: session_ttl,
            last_activity: Utc::now(),
        });
        Ok(id)
    }

    pub async fn request_lease(
        &self,
        actor: &ActorContext,
        request: ActionRequest,
        ttl_seconds: u64,
        max_uses: u64,
        approval_id: Option<&str>,
    ) -> Result<LeaseRequestOutcome> {
        if request.subject.agent_id != actor.agent_id {
            return Err(KeyLeaseError::Denied {
                reason: "request subject does not match authenticated client".into(),
            });
        }
        let vault_session_id = self.current_vault_session_id()?;
        let record = self.store.get_connection(&request.connection_id)?;
        let connector = self.connector(&record)?;
        let canonical = connector.canonicalize(&request).await?;
        if !is_local_authorized_listing(&canonical)
            && !record
                .authorized_resources
                .contains(&canonical.request.resource)
        {
            return Err(KeyLeaseError::Denied {
                reason: "resource was not enrolled in connection".into(),
            });
        }
        let decision = self
            .policy
            .read()
            .map_err(|_| KeyLeaseError::Storage)?
            .evaluate(&canonical.request, canonical.spec.risk.clone(), Utc::now());
        let (policy_version, allowed_ttl, allowed_uses, policy_budget, approval, approval_binding) =
            match decision {
                PolicyDecision::Deny { reason, .. } => {
                    self.audit_action(actor, &canonical, "deny", "denied", None, None)?;
                    return Err(KeyLeaseError::Denied { reason });
                }
                PolicyDecision::Allow {
                    policy_version,
                    max_ttl_seconds,
                    max_uses,
                    budget,
                    ..
                } => (
                    policy_version,
                    max_ttl_seconds,
                    max_uses,
                    budget,
                    None,
                    None,
                ),
                PolicyDecision::RequireApproval {
                    policy_version,
                    request_digest_hex,
                    risk: _,
                    max_ttl_seconds,
                    max_uses,
                    budget,
                    ..
                } => {
                    if let Some(id) = approval_id {
                        (
                            policy_version,
                            max_ttl_seconds,
                            max_uses,
                            budget,
                            Some(ApprovalId(id.into())),
                            Some((id.to_owned(), request_digest_hex)),
                        )
                    } else {
                        let now = Utc::now();
                        let approval = ApprovalRecord {
                            id: ApprovalId::new(),
                            request_digest_hex,
                            policy_version,
                            state: ApprovalState::Pending,
                            expires_at: now + Duration::minutes(10),
                            request_id: Some(canonical.request.request_id.clone()),
                            agent_id: Some(actor.agent_id.clone()),
                            connection_id: Some(canonical.request.connection_id.clone()),
                            action: Some(canonical.request.action.clone()),
                            resource: Some(canonical.request.resource.clone()),
                            created_at: Some(now),
                        };
                        let event = self.action_audit_event(
                            actor,
                            &canonical,
                            "require_approval",
                            "pending",
                            Some(policy_version),
                            None,
                        );
                        self.store.save_approval_with_audit(&approval, &event)?;
                        return Ok(LeaseRequestOutcome::ApprovalRequired { approval });
                    }
                }
            };
        if ttl_seconds == 0 || ttl_seconds > allowed_ttl || max_uses == 0 || max_uses > allowed_uses
        {
            return Err(KeyLeaseError::Denied {
                reason: "requested TTL or max_uses exceeds policy".into(),
            });
        }
        let budget = intersect_budget(&policy_budget, &canonical.spec.default_budget);
        let token = random_token("kl_live_");
        let digest = hex(&canonical.request.canonical_digest(policy_version));
        let lease = AccessLease {
            id: LeaseId::new(),
            token,
            request_digest_hex: digest,
            policy_version,
            action: canonical.request.action.clone(),
            resource: canonical.request.resource.clone(),
            audience: record.provider,
            expires_at: Utc::now() + Duration::seconds(ttl_seconds as i64),
            max_uses,
            remaining_uses: max_uses,
            budget,
            approval_id: approval,
            session_id: vault_session_id,
            revoked: false,
        };
        if let Some((approval_id, approval_digest)) = approval_binding {
            self.store.save_lease_consuming_approval(
                &lease,
                &approval_id,
                &approval_digest,
                policy_version,
                Utc::now(),
            )?;
        } else {
            self.store.save_lease(&lease)?;
        }
        Ok(LeaseRequestOutcome::Issued {
            lease: Box::new(lease),
        })
    }
    pub fn approve(&self, id: &str) -> Result<()> {
        self.with_vault(|vault| {
            let actor = ActorContext {
                agent_id: AgentId("local-human".into()),
                workload_id: None,
                human_principal: Some("local-human".into()),
                on_behalf_of: None,
                client_session_id: vault.session_id.clone(),
            };
            let resource = format!("kl://{}/approval/{id}", vault.vault_id.0);
            let event = self.vault_audit_event(
                &actor,
                "approval:decide",
                &resource,
                "allow",
                "approved",
                vec!["state".into()],
            );
            self.store.decide_pending_approval(
                id,
                ApprovalState::Approved,
                Utc::now(),
                Some(&event),
            )?;
            Ok(())
        })
    }
    pub fn list_pending_approvals_authorized(
        &self,
        actor: &ActorContext,
        limit: u32,
    ) -> Result<Vec<ApprovalRecord>> {
        self.with_vault(|vault| {
            let resource = format!("kl://{}/approvals", vault.vault_id.0);
            self.authorize_vault(
                actor,
                "approval:list",
                &resource,
                serde_json::json!({"limit":limit.min(1000)}),
            )?;
            let approvals = self.store.list_pending_approvals(limit, Utc::now())?;
            self.audit_vault(
                actor,
                "approval:list",
                &resource,
                "allow",
                "success",
                vec![],
            )?;
            Ok(approvals)
        })
    }
    pub fn decide_approval_authorized(
        &self,
        actor: &ActorContext,
        id: &str,
        approve: bool,
    ) -> Result<ApprovalRecord> {
        self.with_vault(|vault| {
            let resource = format!("kl://{}/approval/{id}", vault.vault_id.0);
            self.authorize_vault(
                actor,
                "approval:decide",
                &resource,
                serde_json::json!({"approve":approve}),
            )?;
            let event = self.vault_audit_event(
                actor,
                "approval:decide",
                &resource,
                "allow",
                if approve { "approved" } else { "denied" },
                vec!["state".into()],
            );
            self.store.decide_pending_approval(
                id,
                if approve {
                    ApprovalState::Approved
                } else {
                    ApprovalState::Denied
                },
                Utc::now(),
                Some(&event),
            )
        })
    }
    pub fn revoke_lease(&self, id: &str) -> Result<()> {
        self.store.revoke_lease(id)
    }
    pub fn kill_switch(&self, enabled: bool) -> Result<()> {
        self.store.set_kill_switch(enabled)
    }

    pub async fn execute(
        &self,
        actor: &ActorContext,
        token: &str,
        request: ActionRequest,
    ) -> Result<ActionResponse> {
        if request.subject.agent_id != actor.agent_id {
            return Err(KeyLeaseError::Denied {
                reason: "request subject does not match authenticated client".into(),
            });
        }
        let record = self.store.get_connection(&request.connection_id)?;
        if !matches!(
            record.health,
            ConnectionHealth::Connected | ConnectionHealth::Degraded
        ) {
            return Err(KeyLeaseError::Denied {
                reason: "connection is not active".into(),
            });
        }
        let connector = self.connector(&record)?;
        let canonical = connector.canonicalize(&request).await?;
        if !is_local_authorized_listing(&canonical)
            && !record
                .authorized_resources
                .contains(&canonical.request.resource)
        {
            return Err(KeyLeaseError::Denied {
                reason: "resource is no longer enrolled in connection".into(),
            });
        }
        let lease = self.store.lookup_lease(token)?;
        if lease.session_id != self.current_vault_session_id()?
            || lease.action != canonical.request.action
            || lease.resource != canonical.request.resource
        {
            return Err(KeyLeaseError::Denied {
                reason: "lease scope mismatch".into(),
            });
        }
        let digest = hex(&canonical.request.canonical_digest(lease.policy_version));
        let current = self
            .policy
            .read()
            .map_err(|_| KeyLeaseError::Storage)?
            .evaluate(&canonical.request, canonical.spec.risk.clone(), Utc::now());
        let current_version = match current {
            PolicyDecision::Deny { reason, .. } => return Err(KeyLeaseError::Denied { reason }),
            PolicyDecision::Allow { policy_version, .. } => policy_version,
            PolicyDecision::RequireApproval { policy_version, .. }
                if lease.approval_id.is_some() =>
            {
                policy_version
            }
            PolicyDecision::RequireApproval { .. } => {
                return Err(KeyLeaseError::Denied {
                    reason: "approval is required".into(),
                });
            }
        };
        if current_version != lease.policy_version {
            return Err(KeyLeaseError::Denied {
                reason: "lease policy version is stale".into(),
            });
        }
        validate_action_budget(&canonical, &lease.budget)?;
        let _execution_slot = self.acquire_execution_slot(&lease)?;
        match self
            .store
            .consume_lease(token, &digest, &request.idempotency_key, Utc::now())?
        {
            LeaseConsume::Replay {
                response_json: Some(raw),
            } => serde_json::from_str(&raw).map_err(|_| KeyLeaseError::Storage),
            LeaseConsume::Replay {
                response_json: None,
            } => Err(KeyLeaseError::ConnectorUnavailable { retryable: false }),
            LeaseConsume::Reserved { lease } => {
                let execution = if is_local_authorized_listing(&canonical) {
                    let prefix = if canonical.request.action == "google_drive.file.list_authorized"
                    {
                        "google:"
                    } else {
                        "notion:page/"
                    };
                    let resources = record
                        .authorized_resources
                        .iter()
                        .filter(|resource| resource.starts_with(prefix))
                        .cloned()
                        .collect::<Vec<_>>();
                    Ok(ActionResponse {
                        provider: record.provider.clone(),
                        connection_id: record.id.clone(),
                        canonical_resource: canonical.request.resource.clone(),
                        revision: None,
                        untrusted_content: true,
                        item_count: Some(resources.len() as u64),
                        cell_count: None,
                        body: serde_json::json!({"authorized_resources":resources}),
                    })
                } else {
                    let (_, credential) = self.connection_credential(&record.id)?;
                    connector.execute(&canonical, &credential).await
                };
                match execution
                    .and_then(|response| enforce_response_budget(response, &lease.budget))
                {
                    Ok(response) => {
                        if is_create_action(&canonical) {
                            let created = validate_enrolled_resource(
                                &connector.manifest(),
                                &response.canonical_resource,
                            )?;
                            let mut updated_record = record.clone();
                            if !updated_record.authorized_resources.contains(&created) {
                                updated_record.authorized_resources.push(created);
                                updated_record.authorized_resources.sort();
                                updated_record.updated_at = Utc::now();
                                self.store.save_connection(&updated_record)?;
                            }
                        }
                        let audit = self.action_audit_event(
                            actor,
                            &canonical,
                            "allow",
                            "success",
                            Some(lease.policy_version),
                            Some(&response),
                        );
                        self.store.complete_execution(
                            &request.idempotency_key,
                            &serde_json::to_string(&response)
                                .map_err(|_| KeyLeaseError::Storage)?,
                            Some(&audit),
                        )?;
                        Ok(response)
                    }
                    Err(error) => {
                        self.audit_action(
                            actor,
                            &canonical,
                            "allow",
                            "failure",
                            Some(lease.policy_version),
                            None,
                        )?;
                        Err(error)
                    }
                }
            }
        }
    }

    pub fn audit_query(&self, limit: u32) -> Result<Vec<AuditEvent>> {
        self.store.query_audit(limit.min(1000))
    }
    pub fn audit_query_authorized(
        &self,
        actor: &ActorContext,
        limit: u32,
    ) -> Result<Vec<AuditEvent>> {
        self.with_vault(|vault| {
            let resource = format!("kl://{}/audit", vault.vault_id.0);
            self.authorize_vault(
                actor,
                "audit:query",
                &resource,
                serde_json::json!({"limit":limit.min(1000)}),
            )?;
            self.audit_vault(actor, "audit:query", &resource, "allow", "success", vec![])?;
            self.store.query_audit(limit.min(1000))
        })
    }

    fn with_vault<T>(&self, f: impl FnOnce(&UnlockedVault) -> Result<T>) -> Result<T> {
        let mut guard = self.session.lock().map_err(|_| KeyLeaseError::Storage)?;
        let now = Utc::now();
        if guard
            .as_ref()
            .is_some_and(|session| session.last_activity + session.idle_timeout <= now)
        {
            *guard = None;
            drop(guard);
            self.revoke_session_authority()?;
            return Err(KeyLeaseError::VaultLocked {
                requires_user_action: true,
            });
        }
        let session = guard.as_ref().ok_or(KeyLeaseError::VaultLocked {
            requires_user_action: true,
        })?;
        let result = f(&session.vault);
        if result.is_ok()
            && let Some(session) = guard.as_mut()
        {
            session.last_activity = now;
        }
        result
    }
    fn current_vault_session_id(&self) -> Result<String> {
        self.with_vault(|vault| Ok(vault.session_id.clone()))
    }
    fn acquire_execution_slot(&self, lease: &AccessLease) -> Result<ExecutionSlot<'_>> {
        let maximum = lease.budget.max_concurrent.unwrap_or(u32::MAX);
        if maximum == 0 {
            return Err(KeyLeaseError::Denied {
                reason: "lease concurrency budget is zero".into(),
            });
        }
        let mut active = self
            .active_executions
            .lock()
            .map_err(|_| KeyLeaseError::Storage)?;
        let count = active.entry(lease.id.0.clone()).or_default();
        if *count >= maximum {
            return Err(KeyLeaseError::Denied {
                reason: "lease concurrency budget exceeded".into(),
            });
        }
        *count += 1;
        Ok(ExecutionSlot {
            active: &self.active_executions,
            lease_id: lease.id.0.clone(),
        })
    }
    fn revoke_session_authority(&self) -> Result<()> {
        self.store.revoke_session_authority()?;
        *self.policy.write().map_err(|_| KeyLeaseError::Storage)? =
            RulePolicyEngine::new(Vec::new());
        self.google_oauth_flows
            .lock()
            .map_err(|_| KeyLeaseError::Storage)?
            .clear();
        Ok(())
    }
    fn authorize_vault(
        &self,
        actor: &ActorContext,
        action: &str,
        resource: &str,
        arguments: Value,
    ) -> Result<()> {
        let request = ActionRequest {
            schema_version: CONTRACT_VERSION,
            request_id: RequestId::new(),
            subject: actor.clone(),
            task_id: None,
            connection_id: ConnectionId("conn_vault".into()),
            resource: resource.into(),
            action: action.into(),
            arguments,
            idempotency_key: "authorization-only".into(),
        };
        match self
            .policy
            .read()
            .map_err(|_| KeyLeaseError::Storage)?
            .evaluate(&request, RiskTier::R2, Utc::now())
        {
            PolicyDecision::Allow { .. } => Ok(()),
            PolicyDecision::RequireApproval { .. } => {
                self.audit_vault(
                    actor,
                    action,
                    resource,
                    "require_approval",
                    "denied",
                    vec![],
                )?;
                Err(KeyLeaseError::Denied {
                    reason: "vault command requires explicit approval flow".into(),
                })
            }
            PolicyDecision::Deny { reason, .. } => {
                self.audit_vault(actor, action, resource, "deny", "denied", vec![])?;
                Err(KeyLeaseError::Denied { reason })
            }
        }
    }
    fn connection_credential(
        &self,
        id: &ConnectionId,
    ) -> Result<(ConnectionRecord, ConnectorCredential)> {
        let record = self.store.get_connection(id)?;
        let item_id = ItemId(record.credential_item_id.clone());
        let value = self.with_vault(|vault| {
            let item = self.store.get_item(vault, &item_id)?;
            if item.group_id.0 != "group_connections"
                || item.kind != "core.api_credential"
                || !item.tags.iter().any(|tag| tag == "keylease.connection")
                || item.issuer.as_deref() != Some(record.provider.as_str())
                || item.status != ItemStatus::Active
            {
                return Err(KeyLeaseError::Crypto);
            }
            item.fields
                .into_iter()
                .find(|f| {
                    f.key == "credential"
                        && f.protected
                        && f.sensitivity == Sensitivity::HighlySensitive
                })
                .and_then(|f| match f.value {
                    FieldValue::Concealed(v) => Some(v),
                    _ => None,
                })
                .ok_or(KeyLeaseError::Crypto)
        })?;
        Ok((record, ConnectorCredential::new(value)))
    }
    fn connector(&self, record: &ConnectionRecord) -> Result<Arc<dyn Connector>> {
        if record.trust_mode != TrustMode::EdgeLocal {
            return Err(KeyLeaseError::Denied {
                reason: "managed gateway is not available in Phase 1".into(),
            });
        }
        self.connectors
            .get(&record.provider)
            .cloned()
            .ok_or_else(|| KeyLeaseError::NotFound {
                resource: record.provider.clone(),
            })
    }
    fn authorize_connection_operation(
        &self,
        actor: &ActorContext,
        id: &ConnectionId,
        action: &str,
        arguments: Value,
    ) -> Result<String> {
        self.with_vault(|vault| {
            let resource = format!("kl://{}/connection/{}", vault.vault_id.0, id.0);
            self.authorize_vault(actor, action, &resource, arguments)?;
            Ok(resource)
        })
    }
    fn audit_vault(
        &self,
        actor: &ActorContext,
        action: &str,
        resource: &str,
        decision: &str,
        outcome: &str,
        changed_fields: Vec<String>,
    ) -> Result<()> {
        self.store.append_audit(&self.vault_audit_event(
            actor,
            action,
            resource,
            decision,
            outcome,
            changed_fields,
        ))
    }
    fn vault_audit_event(
        &self,
        actor: &ActorContext,
        action: &str,
        resource: &str,
        decision: &str,
        outcome: &str,
        changed_fields: Vec<String>,
    ) -> AuditEvent {
        AuditEvent {
            schema_version: CONTRACT_VERSION,
            timestamp: Utc::now(),
            request_id: RequestId::new(),
            agent_id: actor.agent_id.clone(),
            workload_id: actor.workload_id.as_ref().map(|v| v.0.clone()),
            on_behalf_of: actor.on_behalf_of.clone(),
            action: action.into(),
            resource: resource.into(),
            connection_id: None,
            policy_version: None,
            decision: decision.into(),
            connector: None,
            outcome: outcome.into(),
            item_count: None,
            cell_count: None,
            byte_count: None,
            changed_fields,
        }
    }
    fn audit_action(
        &self,
        actor: &ActorContext,
        action: &CanonicalAction,
        decision: &str,
        outcome: &str,
        policy_version: Option<u64>,
        response: Option<&ActionResponse>,
    ) -> Result<()> {
        self.store.append_audit(&self.action_audit_event(
            actor,
            action,
            decision,
            outcome,
            policy_version,
            response,
        ))
    }
    fn action_audit_event(
        &self,
        actor: &ActorContext,
        action: &CanonicalAction,
        decision: &str,
        outcome: &str,
        policy_version: Option<u64>,
        response: Option<&ActionResponse>,
    ) -> AuditEvent {
        AuditEvent {
            schema_version: CONTRACT_VERSION,
            timestamp: Utc::now(),
            request_id: action.request.request_id.clone(),
            agent_id: actor.agent_id.clone(),
            workload_id: actor.workload_id.as_ref().map(|v| v.0.clone()),
            on_behalf_of: actor.on_behalf_of.clone(),
            action: action.request.action.clone(),
            resource: action.request.resource.clone(),
            connection_id: Some(action.request.connection_id.clone()),
            policy_version,
            decision: decision.into(),
            connector: Some(response.map_or_else(|| "unknown".into(), |r| r.provider.clone())),
            outcome: outcome.into(),
            item_count: response.and_then(|r| r.item_count),
            cell_count: response.and_then(|r| r.cell_count),
            byte_count: response
                .and_then(|r| serde_json::to_vec(&r.body).ok().map(|v| v.len() as u64)),
            changed_fields: vec![],
        }
    }
}

async fn capture_google_oauth_callback(
    listener: TcpListener,
    flows: Arc<Mutex<HashMap<String, GoogleOAuthFlow>>>,
    flow_id: String,
) {
    let capture = async {
        for _ in 0..16 {
            let (mut stream, peer) = listener.accept().await.map_err(|_| "listener failure")?;
            if !peer.ip().is_loopback() {
                let _ = write_oauth_http_response(&mut stream, 403, false).await;
                continue;
            }
            let target = match read_oauth_http_target(&mut stream).await {
                Ok(target) => target,
                Err(()) => {
                    let _ = write_oauth_http_response(&mut stream, 400, false).await;
                    continue;
                }
            };
            let Ok(url) = url::Url::parse(&format!("http://127.0.0.1{target}")) else {
                let _ = write_oauth_http_response(&mut stream, 400, false).await;
                continue;
            };
            if url.path() != "/oauth2/callback" {
                let _ = write_oauth_http_response(&mut stream, 404, false).await;
                continue;
            }
            let mut parameters = HashMap::new();
            let mut duplicate_parameter = false;
            for (key, value) in url.query_pairs().into_owned() {
                if parameters.insert(key, value).is_some() {
                    duplicate_parameter = true;
                    break;
                }
            }
            if duplicate_parameter {
                let _ = write_oauth_http_response(&mut stream, 400, false).await;
                continue;
            }
            let state_valid = flows
                .lock()
                .ok()
                .and_then(|flows| flows.get(&flow_id).map(|flow| flow.state.clone()))
                .is_some_and(|state| parameters.get("state") == Some(&state));
            if !state_valid {
                let _ = write_oauth_http_response(&mut stream, 403, false).await;
                continue;
            }
            let callback = if let Some(error) = parameters.get("error") {
                GoogleOAuthCallback::Failed(safe_oauth_error(error))
            } else {
                let Some(code) = parameters.get("code").filter(|code| code.len() <= 4096) else {
                    let _ = write_oauth_http_response(&mut stream, 400, false).await;
                    continue;
                };
                let picked_file_ids = parameters
                    .get("picked_file_ids")
                    .map(|ids| {
                        ids.split(',')
                            .filter(|id| valid_google_file_id(id))
                            .map(str::to_owned)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                GoogleOAuthCallback::Received {
                    code: code.clone(),
                    picked_file_ids,
                    scope: parameters.get("scope").cloned().unwrap_or_default(),
                }
            };
            let success = matches!(callback, GoogleOAuthCallback::Received { .. });
            if let Ok(mut flows) = flows.lock()
                && let Some(flow) = flows.get_mut(&flow_id)
            {
                flow.callback = callback;
            }
            let _ = write_oauth_http_response(&mut stream, 200, success).await;
            return Ok::<(), &'static str>(());
        }
        Err("too many invalid callback attempts")
    };
    let failure = match tokio::time::timeout(GOOGLE_OAUTH_FLOW_TTL, capture).await {
        Ok(Ok(())) => None,
        Ok(Err(reason)) => Some(reason),
        Err(_) => Some("callback timed out"),
    };
    if failure.is_some()
        && let Ok(mut flows) = flows.lock()
    {
        flows.remove(&flow_id);
    }
}

async fn read_oauth_http_target(
    stream: &mut tokio::net::TcpStream,
) -> std::result::Result<String, ()> {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    while request.len() <= MAX_OAUTH_HTTP_BYTES {
        let read = stream.read(&mut chunk).await.map_err(|_| ())?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    if request.len() > MAX_OAUTH_HTTP_BYTES {
        return Err(());
    }
    let request = std::str::from_utf8(&request).map_err(|_| ())?;
    let mut parts = request.lines().next().ok_or(())?.split_whitespace();
    if parts.next() != Some("GET") {
        return Err(());
    }
    let target = parts.next().ok_or(())?;
    if !target.starts_with('/') || target.len() > 12 * 1024 {
        return Err(());
    }
    Ok(target.into())
}

async fn write_oauth_http_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    success: bool,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Bad Request",
    };
    let body = if success {
        "<!doctype html><meta charset=utf-8><title>KeyLease</title><h1>Selection received</h1><p>Return to KeyLease to finish the connection.</p>"
    } else {
        "<!doctype html><meta charset=utf-8><title>KeyLease</title><h1>Request not accepted</h1><p>Return to KeyLease and retry the connection flow.</p>"
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'none'; style-src 'none'\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await
}

fn safe_oauth_error(error: &str) -> String {
    if error.len() <= 128
        && error
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        error.into()
    } else {
        "provider_error".into()
    }
}

fn valid_google_file_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

async fn resolve_google_picker_resources(
    client: &reqwest::Client,
    access_token: &str,
    picked_file_ids: &[String],
) -> Result<Vec<String>> {
    let mut resources = Vec::with_capacity(picked_file_ids.len());
    for file_id in picked_file_ids {
        if !valid_google_file_id(file_id) {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "Google Picker returned an invalid file ID".into(),
            });
        }
        let mut url = url::Url::parse("https://www.googleapis.com/drive/v3/files/")
            .map_err(|_| KeyLeaseError::Storage)?;
        url.path_segments_mut()
            .map_err(|_| KeyLeaseError::Storage)?
            .push(file_id);
        url.query_pairs_mut().append_pair("fields", "id,mimeType");
        let response = client
            .get(url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        if !response.status().is_success() {
            return Err(KeyLeaseError::Denied {
                reason: "Google denied metadata access to a Picker-selected file".into(),
            });
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        if bytes.len() > MAX_GOOGLE_TOKEN_RESPONSE_BYTES {
            return Err(KeyLeaseError::ConnectorUnavailable { retryable: false });
        }
        let metadata: Value = serde_json::from_slice(&bytes)
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: false })?;
        resources.push(canonical_google_picker_resource(file_id, &metadata)?);
    }
    resources.sort();
    resources.dedup();
    Ok(resources)
}

fn canonical_google_picker_resource(file_id: &str, metadata: &Value) -> Result<String> {
    if metadata.get("id").and_then(Value::as_str) != Some(file_id) {
        return Err(KeyLeaseError::Denied {
            reason: "Google returned mismatched file metadata".into(),
        });
    }
    let prefix = match metadata.get("mimeType").and_then(Value::as_str) {
        Some("application/vnd.google-apps.document") => "google:document/",
        Some("application/vnd.google-apps.spreadsheet") => "google:spreadsheet/",
        Some("application/vnd.google-apps.folder") => "google:folder/",
        Some(_) => "google:file/",
        None => return Err(KeyLeaseError::ConnectorUnavailable { retryable: false }),
    };
    Ok(format!("{prefix}{file_id}"))
}

fn is_local_authorized_listing(action: &CanonicalAction) -> bool {
    matches!(
        (
            action.request.action.as_str(),
            action.request.resource.as_str()
        ),
        ("google_drive.file.list_authorized", "google:file")
            | ("notion.page.search_authorized", "notion:page")
    )
}
fn is_create_action(action: &CanonicalAction) -> bool {
    matches!(
        action.request.action.as_str(),
        "google_docs.document.create" | "google_sheets.spreadsheet.create" | "notion.page.create"
    )
}

fn field(
    key: &str,
    label: &str,
    value: FieldValue,
    sensitivity: Sensitivity,
    protected: bool,
) -> ItemField {
    ItemField {
        id: FieldId::new(),
        key: key.into(),
        label: label.into(),
        value,
        sensitivity,
        protected,
    }
}
fn upsert(
    fields: &mut Vec<ItemField>,
    key: &str,
    value: FieldValue,
    sensitivity: Sensitivity,
    protected: bool,
) {
    if let Some(field) = fields.iter_mut().find(|f| f.key == key) {
        field.value = value;
        field.sensitivity = sensitivity;
        field.protected = protected
    } else {
        fields.push(field(key, key, value, sensitivity, protected))
    }
}
fn validate_kind(kind: &str) -> Result<String> {
    if matches!(
        kind,
        "core.login" | "core.api_credential" | "core.secure_note" | "core.generic"
    ) || kind.starts_with("user.custom.")
    {
        Ok(kind.into())
    } else {
        Err(KeyLeaseError::InvalidRequest {
            reason: "unsupported item kind".into(),
        })
    }
}
fn field_requires_protection(field: &ItemField) -> bool {
    field.protected
        || matches!(
            field.sensitivity,
            Sensitivity::Secret | Sensitivity::HighlySensitive
        )
}
fn validate_group(name: &str, parent_id: Option<&GroupId>, groups: &[VaultGroup]) -> Result<()> {
    if name.trim().is_empty() || name.chars().any(char::is_control) {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "group name must be non-empty and contain no control characters".into(),
        });
    }
    if let Some(parent_id) = parent_id
        && !groups.iter().any(|group| &group.id == parent_id)
    {
        return Err(KeyLeaseError::NotFound {
            resource: parent_id.0.clone(),
        });
    }
    Ok(())
}
fn validate_item_title(title: &str) -> Result<()> {
    if title.trim().is_empty() || title.chars().any(char::is_control) {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "entry title must be non-empty and contain no control characters".into(),
        });
    }
    Ok(())
}
fn validate_custom_fields(fields: &[ItemField]) -> Result<()> {
    let mut keys = std::collections::HashSet::new();
    let mut ids = std::collections::HashSet::new();
    for field in fields {
        if field.key.is_empty()
            || matches!(
                field.key.as_str(),
                "username" | "password" | "otp" | "credential"
            )
            || !keys.insert(field.key.clone())
            || !ids.insert(field.id.clone())
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "custom fields must have unique non-reserved keys and IDs".into(),
            });
        }
        if matches!(
            field.sensitivity,
            Sensitivity::Secret | Sensitivity::HighlySensitive
        ) && !field.protected
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "secret custom fields must be marked protected".into(),
            });
        }
    }
    Ok(())
}
fn normalize_totp(config: &mut Option<TotpConfig>, uri: &mut Option<String>) -> Result<()> {
    if config.is_some() && uri.is_some() {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "provide either a typed TOTP configuration or totp_uri, not both".into(),
        });
    }
    if let Some(source) = uri.take() {
        let parsed =
            totp_rs::TOTP::from_url(&source).map_err(|_| KeyLeaseError::InvalidRequest {
                reason: "invalid otpauth TOTP URI".into(),
            })?;
        let algorithm = match parsed.algorithm {
            totp_rs::Algorithm::SHA1 => TotpAlgorithm::Sha1,
            totp_rs::Algorithm::SHA256 => TotpAlgorithm::Sha256,
            totp_rs::Algorithm::SHA512 => TotpAlgorithm::Sha512,
        };
        *config = Some(TotpConfig {
            secret_base32: parsed.get_secret_base32(),
            issuer: parsed.issuer,
            account: Some(parsed.account_name),
            algorithm,
            digits: parsed.digits as u32,
            period: parsed.step,
            source_representation: Some(source),
        });
    }
    Ok(())
}
fn validate_session_timeout(timeout: Duration) -> Result<()> {
    if timeout <= Duration::zero() {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "session inactivity timeout must be positive".into(),
        });
    }
    Ok(())
}
fn validate_idempotency_key(key: &str) -> Result<()> {
    if key.is_empty() || key.len() > 256 || key.chars().any(char::is_control) {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "idempotency key must be 1..=256 characters without control characters".into(),
        });
    }
    Ok(())
}
fn operation_material(value: &Value) -> Result<Zeroizing<Vec<u8>>> {
    serde_json::to_vec(&keylease_core::canonical_json(value))
        .map(Zeroizing::new)
        .map_err(|_| KeyLeaseError::Storage)
}
fn random_token(prefix: &str) -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn intersect_budget(policy: &DataBudget, connector: &DataBudget) -> DataBudget {
    fn minimum<T: Ord + Copy>(a: Option<T>, b: Option<T>) -> Option<T> {
        match (a, b) {
            (Some(x), Some(y)) => Some(x.min(y)),
            (Some(x), None) => Some(x),
            (None, Some(y)) => Some(y),
            (None, None) => None,
        }
    }
    DataBudget {
        max_items: minimum(policy.max_items, connector.max_items),
        max_cells: minimum(policy.max_cells, connector.max_cells),
        max_response_bytes: minimum(policy.max_response_bytes, connector.max_response_bytes),
        max_rows_changed: minimum(policy.max_rows_changed, connector.max_rows_changed),
        max_concurrent: minimum(policy.max_concurrent, connector.max_concurrent),
    }
}
fn validate_action_budget(action: &CanonicalAction, budget: &DataBudget) -> Result<()> {
    if action.request.action == "google_sheets.rows.append"
        || action.request.action == "google_sheets.values.update"
    {
        let rows = action
            .request
            .arguments
            .get("values")
            .and_then(Value::as_array)
            .ok_or_else(|| KeyLeaseError::InvalidRequest {
                reason: "values must be an array".into(),
            })?;
        let cells = rows
            .iter()
            .map(|row| row.as_array().map_or(0, |values| values.len() as u64))
            .sum::<u64>();
        if budget
            .max_rows_changed
            .is_some_and(|max| rows.len() as u64 > max)
            || budget.max_cells.is_some_and(|max| cells > max)
        {
            return Err(KeyLeaseError::Denied {
                reason: "sheet write budget exceeded".into(),
            });
        }
    }
    if action.request.action == "google_sheets.values.read" {
        let cells = a1_cell_count(
            action
                .request
                .arguments
                .get("range")
                .and_then(Value::as_str)
                .ok_or_else(|| KeyLeaseError::InvalidRequest {
                    reason: "missing range".into(),
                })?,
        )?;
        if budget.max_cells.is_some_and(|max| cells > max) {
            return Err(KeyLeaseError::Denied {
                reason: "sheet read range exceeds cell budget".into(),
            });
        }
    }
    if action.request.action == "google_sheets.values.batch_read" {
        let total = action
            .request
            .arguments
            .get("ranges")
            .and_then(Value::as_array)
            .ok_or_else(|| KeyLeaseError::InvalidRequest {
                reason: "missing ranges".into(),
            })?
            .iter()
            .try_fold(0_u64, |sum, range| {
                Ok::<_, KeyLeaseError>(sum.saturating_add(
                    a1_cell_count(range.as_str().ok_or_else(|| {
                        KeyLeaseError::InvalidRequest {
                            reason: "range must be string".into(),
                        }
                    })?)?,
                ))
            })?;
        if budget.max_cells.is_some_and(|max| total > max) {
            return Err(KeyLeaseError::Denied {
                reason: "sheet batch ranges exceed cell budget".into(),
            });
        }
    }
    Ok(())
}

pub fn generate_password(length: usize) -> Result<String> {
    if !(16..=256).contains(&length) {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "password length must be 16..=256".into(),
        });
    }
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+";
    let mut random = vec![0_u8; length];
    rand::rng().fill_bytes(&mut random);
    Ok(random
        .into_iter()
        .map(|b| CHARS[b as usize % CHARS.len()] as char)
        .collect())
}
pub fn current_totp(config: &TotpConfig) -> Result<(String, u64)> {
    let algorithm = match config.algorithm {
        TotpAlgorithm::Sha1 => totp_rs::Algorithm::SHA1,
        TotpAlgorithm::Sha256 => totp_rs::Algorithm::SHA256,
        TotpAlgorithm::Sha512 => totp_rs::Algorithm::SHA512,
    };
    let secret = totp_rs::Secret::Encoded(config.secret_base32.clone())
        .to_bytes()
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid TOTP secret".into(),
        })?;
    let totp = totp_rs::TOTP::new(
        algorithm,
        config.digits as usize,
        1,
        config.period,
        secret,
        config.issuer.clone(),
        config.account.clone().unwrap_or_default(),
    )
    .map_err(|_| KeyLeaseError::InvalidRequest {
        reason: "invalid TOTP configuration".into(),
    })?;
    let now = Utc::now().timestamp() as u64;
    let code = totp.generate(now);
    Ok((code, config.period - (now % config.period)))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn service() -> (tempfile::TempDir, KeyLeaseService, ActorContext) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(NativeStore::open(dir.path().join("vault.sqlite")).unwrap());
        let service = KeyLeaseService::new(store).unwrap();
        let vault = service.initialize(b"password", Duration::hours(1)).unwrap();
        let (agent, token) = service.register_client("test").unwrap();
        let actor = service
            .authenticate(&agent, &token, "session-test")
            .unwrap();
        for (action, resource) in [
            ("entry:create", format!("kl://{}/group", vault.0)),
            ("entry:search", format!("kl://{}", vault.0)),
            ("entry:update_standard_fields", format!("kl://{}", vault.0)),
            ("entry:update_protected_fields", format!("kl://{}", vault.0)),
            ("group:create", format!("kl://{}", vault.0)),
            ("group:update", format!("kl://{}", vault.0)),
            ("group:delete", format!("kl://{}", vault.0)),
            ("connection:add", format!("kl://{}", vault.0)),
        ] {
            service
                .add_grant(PolicyRule {
                    id: action.into(),
                    version: 1,
                    effect: PolicyEffect::Allow,
                    agent_id: Some(agent.clone()),
                    connection_id: None,
                    resource_prefix: resource,
                    actions: vec![action.into()],
                    argument_equals: Default::default(),
                    not_before: None,
                    expires_at: None,
                    max_lease_ttl_seconds: 600,
                    max_uses: 10,
                    budget: Default::default(),
                })
                .unwrap();
        }
        (dir, service, actor)
    }
    #[test]
    fn agent_group_create_is_idempotent_and_audited() {
        let (_dir, service, actor) = service();
        let created = service
            .create_group_authorized(&actor, "Development", None, "group-task", false)
            .unwrap();
        let replay = service
            .create_group_authorized(&actor, "Development", None, "group-task", false)
            .unwrap();
        assert_eq!(created.id, replay.id);
        assert_eq!(service.list_groups().unwrap().len(), 1);
        assert!(matches!(
            service.create_group_authorized(&actor, "Different", None, "group-task", false),
            Err(KeyLeaseError::IdempotencyConflict)
        ));
        let updated = service
            .update_group_authorized(&actor, &created.id, "Engineering", 1, "group-update", false)
            .unwrap();
        assert_eq!(updated.revision, 2);
        assert_eq!(
            service
                .update_group_authorized(
                    &actor,
                    &created.id,
                    "Engineering",
                    1,
                    "group-update",
                    false,
                )
                .unwrap(),
            updated
        );
        service
            .delete_group_authorized(&actor, &created.id, 2, "group-delete", false)
            .unwrap();
        service
            .delete_group_authorized(&actor, &created.id, 2, "group-delete", false)
            .unwrap();
        assert!(service.list_groups().unwrap().is_empty());
        assert!(
            service
                .audit_query(10)
                .unwrap()
                .iter()
                .filter(|event| event.action.starts_with("group:"))
                .all(|event| event.outcome == "success")
        );
    }
    #[test]
    fn agent_write_search_and_revision_are_policy_enforced() {
        let (_dir, service, actor) = service();
        let group = service.create_group("Development", None).unwrap();
        let input = NewEntryInput {
            group_id: group.id,
            kind: "core.login".into(),
            title: "GitHub".into(),
            username: Some("bot".into()),
            password: Some("new-secret".into()),
            url: Some("https://github.com".into()),
            notes: None,
            custom_fields: vec![],
            totp: None,
            totp_uri: None,
        };
        let item = service
            .create_entry(&actor, input.clone(), "task-create", false)
            .unwrap();
        assert!(!serde_json::to_string(&item).unwrap().contains("new-secret"));
        assert!(matches!(
            service.reveal_field_authorized(&actor, &item.id, "password"),
            Err(KeyLeaseError::Denied { .. })
        ));
        for action in [
            "entry:read_metadata",
            "entry:read_username",
            "entry:read_secret",
        ] {
            service
                .add_grant(PolicyRule {
                    id: format!("desktop-{action}"),
                    version: 1,
                    effect: PolicyEffect::Allow,
                    agent_id: Some(actor.agent_id.clone()),
                    connection_id: None,
                    resource_prefix: format!("kl://{}", group.vault_id.0),
                    actions: vec![action.into()],
                    argument_equals: Default::default(),
                    not_before: None,
                    expires_at: None,
                    max_lease_ttl_seconds: 600,
                    max_uses: 10,
                    budget: Default::default(),
                })
                .unwrap();
        }
        assert_eq!(
            service
                .reveal_field_authorized(&actor, &item.id, "username")
                .unwrap(),
            "bot"
        );
        assert_eq!(
            service
                .reveal_field_authorized(&actor, &item.id, "password")
                .unwrap(),
            "new-secret"
        );
        assert!(
            service
                .entry_history_authorized(&actor, &item.id)
                .unwrap()
                .is_empty()
        );
        assert!(
            !serde_json::to_string(&service.audit_query(20).unwrap())
                .unwrap()
                .contains("new-secret")
        );
        assert_eq!(service.search_entries(&actor, "github").unwrap().len(), 1);
        let error = service
            .update_entry(
                &actor,
                &item.id,
                EntryPatch {
                    title: Some("Changed".into()),
                    ..Default::default()
                },
                0,
                "task-update",
                false,
            )
            .unwrap_err();
        assert!(matches!(error, KeyLeaseError::RevisionConflict { .. }));
        let update_patch = EntryPatch {
            title: Some("Changed".into()),
            ..Default::default()
        };
        let updated = service
            .update_entry(
                &actor,
                &item.id,
                update_patch.clone(),
                1,
                "task-update-success",
                false,
            )
            .unwrap();
        assert_eq!(updated.revision, 2);
        let repeated_update = service
            .update_entry(
                &actor,
                &item.id,
                update_patch,
                1,
                "task-update-success",
                false,
            )
            .unwrap();
        assert_eq!(repeated_update, updated);
        let repeated_create = service
            .create_entry(&actor, input, "task-create", false)
            .unwrap();
        assert_eq!(repeated_create.id, item.id);
        assert_eq!(repeated_create.revision, 1);
        let history = service.entry_history_for_human(&item.id).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].revision, 1);
        let authorized_history = service.entry_history_authorized(&actor, &item.id).unwrap();
        assert_eq!(authorized_history.len(), 1);
        assert_eq!(authorized_history[0].username, None);
        let destination = service.create_group("Other", None).unwrap();
        assert!(matches!(
            service.update_entry(
                &actor,
                &item.id,
                EntryPatch {
                    title: Some("Mixed".into()),
                    group_id: Some(destination.id),
                    ..Default::default()
                },
                2,
                "mixed-capability-update",
                false,
            ),
            Err(KeyLeaseError::Denied { .. })
        ));
        assert_eq!(service.entry_history_for_human(&item.id).unwrap().len(), 1);
        service
            .add_grant(PolicyRule {
                id: "entry-delete".into(),
                version: 1,
                effect: PolicyEffect::Allow,
                agent_id: Some(actor.agent_id.clone()),
                connection_id: None,
                resource_prefix: format!("kl://{}", group.vault_id.0),
                actions: vec!["entry:delete".into()],
                argument_equals: Default::default(),
                not_before: None,
                expires_at: None,
                max_lease_ttl_seconds: 60,
                max_uses: 1,
                budget: Default::default(),
            })
            .unwrap();
        service
            .delete_entry(&actor, &item.id, 2, "task-delete", false)
            .unwrap();
        service
            .delete_entry(&actor, &item.id, 2, "task-delete", false)
            .unwrap();
        let events = service.audit_query(10).unwrap();
        assert!(
            !serde_json::to_string(&events)
                .unwrap()
                .contains("new-secret")
        );
    }
    #[test]
    fn unknown_agent_has_no_vault_access() {
        let (_dir, service, _) = service();
        let actor = ActorContext {
            agent_id: AgentId("agent_unknown".into()),
            workload_id: None,
            human_principal: None,
            on_behalf_of: None,
            client_session_id: "s".into(),
        };
        assert!(matches!(
            service.search_entries(&actor, ""),
            Err(KeyLeaseError::Denied { .. })
        ));
    }
    #[test]
    fn locking_revokes_session_scoped_grants() {
        let (_dir, service, actor) = service();
        assert!(service.search_entries(&actor, "").is_ok());
        service.lock().unwrap();
        service.unlock(b"password", Duration::hours(1)).unwrap();
        assert!(matches!(
            service.search_entries(&actor, ""),
            Err(KeyLeaseError::Denied { .. })
        ));
    }
    #[test]
    fn lease_concurrency_slots_are_enforced_and_released() {
        let (_dir, service, _) = service();
        let lease = AccessLease {
            id: LeaseId::new(),
            token: "unused".into(),
            request_digest_hex: "unused".into(),
            policy_version: 1,
            action: "fake.resource.read".into(),
            resource: "fake:resource/1".into(),
            audience: "fake".into(),
            expires_at: Utc::now() + Duration::minutes(1),
            max_uses: 2,
            remaining_uses: 2,
            budget: DataBudget {
                max_concurrent: Some(1),
                ..Default::default()
            },
            approval_id: None,
            session_id: "session".into(),
            revoked: false,
        };
        let first = service.acquire_execution_slot(&lease).unwrap();
        assert!(matches!(
            service.acquire_execution_slot(&lease),
            Err(KeyLeaseError::Denied { .. })
        ));
        drop(first);
        assert!(service.acquire_execution_slot(&lease).is_ok());
    }
    #[test]
    fn repeated_client_authentication_failures_are_rate_limited() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(NativeStore::open(dir.path().join("auth.sqlite")).unwrap());
        let service = KeyLeaseService::new(store).unwrap();
        service.initialize(b"password", Duration::hours(1)).unwrap();
        let (agent, token) = service.register_client("limited").unwrap();
        for _ in 0..AUTH_FAILURE_LIMIT {
            assert!(service.authenticate(&agent, "wrong", "session").is_err());
        }
        let error = service.authenticate(&agent, &token, "session").unwrap_err();
        assert!(matches!(
            error,
            KeyLeaseError::Denied { reason } if reason.contains("rate limit")
        ));
    }
    #[test]
    fn password_generator_and_totp() {
        assert_eq!(generate_password(32).unwrap().len(), 32);
        let config = TotpConfig {
            secret_base32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            issuer: None,
            account: None,
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            source_representation: None,
        };
        let (code, left) = current_totp(&config).unwrap();
        assert_eq!(code.len(), 6);
        assert!((1..=30).contains(&left));
        let mut parsed = None;
        let mut uri = Some("otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA1&digits=6&period=30".into());
        normalize_totp(&mut parsed, &mut uri).unwrap();
        let parsed = parsed.unwrap();
        assert_eq!(parsed.issuer.as_deref(), Some("Example"));
        assert_eq!(parsed.account.as_deref(), Some("alice"));
        assert_eq!(parsed.period, 30);
    }
    #[tokio::test]
    async fn google_oauth_pkce_picker_callback_is_state_bound() {
        let (_dir, service, actor) = service();
        let start = service
            .begin_google_oauth(&actor, "123456789-example.apps.googleusercontent.com", None)
            .await
            .unwrap();
        let authorization = url::Url::parse(&start.authorization_url).unwrap();
        assert_eq!(authorization.host_str(), Some("accounts.google.com"));
        let parameters = authorization
            .query_pairs()
            .into_owned()
            .collect::<HashMap<_, _>>();
        assert_eq!(
            parameters.get("scope").map(String::as_str),
            Some(GOOGLE_OAUTH_SCOPE)
        );
        assert_eq!(
            parameters.get("trigger_onepick").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            parameters.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert!(parameters.contains_key("code_challenge"));
        assert!(!start.authorization_url.contains("pkce_"));
        let redirect = url::Url::parse(parameters.get("redirect_uri").unwrap()).unwrap();

        async fn callback(redirect: &url::Url, state: &str) -> String {
            let mut callback = redirect.clone();
            callback
                .query_pairs_mut()
                .append_pair("code", "authorization-code-secret")
                .append_pair("picked_file_ids", "file_1,file-2")
                .append_pair("scope", GOOGLE_OAUTH_SCOPE)
                .append_pair("state", state);
            let target = format!(
                "{}?{}",
                callback.path(),
                callback.query().unwrap_or_default()
            );
            let mut stream = tokio::net::TcpStream::connect((
                redirect.host_str().unwrap(),
                redirect.port().unwrap(),
            ))
            .await
            .unwrap();
            stream
                .write_all(format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            response
        }

        assert!(
            callback(&redirect, "wrong-state")
                .await
                .starts_with("HTTP/1.1 403")
        );
        assert!(
            callback(&redirect, parameters.get("state").unwrap())
                .await
                .starts_with("HTTP/1.1 200")
        );
        let flows = service.google_oauth_flows.lock().unwrap();
        let flow = flows.get(&start.flow_id).unwrap();
        let GoogleOAuthCallback::Received {
            code,
            picked_file_ids,
            scope,
        } = &flow.callback
        else {
            panic!("callback was not captured");
        };
        assert_eq!(code, "authorization-code-secret");
        assert_eq!(picked_file_ids, &["file_1", "file-2"]);
        assert_eq!(scope, GOOGLE_OAUTH_SCOPE);
        drop(flows);
        service.lock().unwrap();
        assert!(service.google_oauth_flows.lock().unwrap().is_empty());
    }
    #[test]
    fn google_picker_metadata_maps_to_exact_canonical_resources() {
        for (mime_type, expected) in [
            (
                "application/vnd.google-apps.document",
                "google:document/file_1",
            ),
            (
                "application/vnd.google-apps.spreadsheet",
                "google:spreadsheet/file_1",
            ),
            ("application/vnd.google-apps.folder", "google:folder/file_1"),
            ("application/pdf", "google:file/file_1"),
        ] {
            let metadata = serde_json::json!({"id":"file_1","mimeType":mime_type});
            assert_eq!(
                canonical_google_picker_resource("file_1", &metadata).unwrap(),
                expected
            );
        }
        let mismatched = serde_json::json!({
            "id":"file_2",
            "mimeType":"application/vnd.google-apps.document"
        });
        assert!(canonical_google_picker_resource("file_1", &mismatched).is_err());
    }
    #[tokio::test]
    async fn fake_connector_lease_replay_restart_and_budget_are_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("lease.sqlite");
        let store = Arc::new(NativeStore::open(&db).unwrap());
        let service = KeyLeaseService::new(store).unwrap();
        service.initialize(b"password", Duration::hours(1)).unwrap();
        let (agent, client_token) = service.register_client("connector").unwrap();
        let actor = service
            .authenticate(&agent, &client_token, "stable-session")
            .unwrap();
        let connection = service
            .add_connection(
                "fake",
                "upstream-fixture-secret".into(),
                vec!["fake:resource/1".into()],
            )
            .unwrap();
        service
            .add_grant(PolicyRule {
                id: "fake-write".into(),
                version: 7,
                effect: PolicyEffect::Allow,
                agent_id: Some(agent.clone()),
                connection_id: Some(connection.id.0.clone()),
                resource_prefix: "fake:resource/1".into(),
                actions: vec!["fake.resource.write".into()],
                argument_equals: Default::default(),
                not_before: None,
                expires_at: None,
                max_lease_ttl_seconds: 60,
                max_uses: 1,
                budget: DataBudget {
                    max_items: Some(2),
                    max_response_bytes: Some(1024),
                    ..Default::default()
                },
            })
            .unwrap();
        let request = ActionRequest {
            schema_version: 1,
            request_id: RequestId::new(),
            subject: actor.clone(),
            task_id: Some(TaskId("task-conformance".into())),
            connection_id: connection.id.clone(),
            resource: "fake:resource/1".into(),
            action: "fake.resource.write".into(),
            arguments: serde_json::json!({"value":"external-content-must-not-enter-audit"}),
            idempotency_key: "side-effect-1".into(),
        };
        let mut scope_alias = request.clone();
        scope_alias.resource = "fake:resource/1/other-object".into();
        assert!(matches!(
            service
                .request_lease(&actor, scope_alias, 60, 1, None)
                .await,
            Err(KeyLeaseError::Denied { .. })
        ));
        let lease = match service
            .request_lease(&actor, request.clone(), 60, 1, None)
            .await
            .unwrap()
        {
            LeaseRequestOutcome::Issued { lease } => lease,
            _ => panic!("unexpected approval"),
        };
        let first = service
            .execute(&actor, &lease.token, request.clone())
            .await
            .unwrap();
        assert_eq!(first.body, serde_json::json!({"written":true}));
        drop(service);
        let reopened = KeyLeaseService::new(Arc::new(NativeStore::open(&db).unwrap())).unwrap();
        reopened.unlock(b"password", Duration::hours(1)).unwrap();
        let actor = reopened
            .authenticate(&agent, &client_token, "stable-session")
            .unwrap();
        assert!(matches!(
            reopened
                .execute(&actor, &lease.token, request.clone())
                .await,
            Err(KeyLeaseError::Denied { .. })
        ));
        let mut second = request;
        second.idempotency_key = "side-effect-2".into();
        assert!(matches!(
            reopened.execute(&actor, &lease.token, second).await,
            Err(KeyLeaseError::Denied { .. })
        ));
        let audits = reopened.audit_query(50).unwrap();
        let raw = serde_json::to_string(&audits).unwrap();
        assert!(!raw.contains("upstream-fixture-secret"));
        assert!(!raw.contains("external-content-must-not-enter-audit"));
    }
    #[tokio::test]
    async fn connection_registry_cannot_repoint_to_an_invalid_credential_item() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(NativeStore::open(dir.path().join("connection.sqlite")).unwrap());
        let service = KeyLeaseService::new(store.clone()).unwrap();
        service.initialize(b"password", Duration::hours(1)).unwrap();
        let connection = service
            .add_connection("fake", "credential".into(), vec!["fake:resource/1".into()])
            .unwrap();

        let unlocked = store.unlock(b"password").unwrap();
        let item_id = ItemId(connection.credential_item_id);
        let mut item = store.get_item(&unlocked, &item_id).unwrap();
        item.issuer = Some("different-provider".into());
        item.revision += 1;
        store
            .put_item(
                &unlocked,
                &item,
                Some(1),
                MutationContext {
                    actor: "tamper-test",
                    idempotency_key: "tamper-credential",
                    request_material: b"tamper-credential",
                    audit_event: None,
                },
            )
            .unwrap();

        assert!(matches!(
            service.test_connection(&connection.id).await,
            Err(KeyLeaseError::Crypto)
        ));
    }
    #[tokio::test]
    async fn approval_is_consumable_only_for_the_exact_canonical_request() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(NativeStore::open(dir.path().join("approval.sqlite")).unwrap());
        let service = KeyLeaseService::new(store.clone()).unwrap();
        service.initialize(b"password", Duration::hours(1)).unwrap();
        let (agent, token) = service.register_client("approval").unwrap();
        let actor = service
            .authenticate(&agent, &token, "approval-session")
            .unwrap();
        let connection = service
            .add_connection("fake", "credential".into(), vec!["fake:resource/1".into()])
            .unwrap();
        service
            .add_grant(PolicyRule {
                id: "approved-write".into(),
                version: 2,
                effect: PolicyEffect::RequireApproval,
                agent_id: Some(agent),
                connection_id: Some(connection.id.0.clone()),
                resource_prefix: "fake:resource/1".into(),
                actions: vec!["fake.resource.write".into()],
                argument_equals: Default::default(),
                not_before: None,
                expires_at: None,
                max_lease_ttl_seconds: 60,
                max_uses: 1,
                budget: Default::default(),
            })
            .unwrap();
        let request = ActionRequest {
            schema_version: 1,
            request_id: RequestId::new(),
            subject: actor.clone(),
            task_id: None,
            connection_id: connection.id,
            resource: "fake:resource/1".into(),
            action: "fake.resource.write".into(),
            arguments: serde_json::json!({"value":"approved"}),
            idempotency_key: "approval-idem".into(),
        };
        let approval = match service
            .request_lease(&actor, request.clone(), 30, 1, None)
            .await
            .unwrap()
        {
            LeaseRequestOutcome::ApprovalRequired { approval } => approval,
            _ => panic!("approval expected"),
        };
        service.approve(&approval.id.0).unwrap();
        let mut changed = request.clone();
        changed.arguments = serde_json::json!({"value":"changed-after-approval"});
        assert!(matches!(
            service
                .request_lease(&actor, changed, 30, 1, Some(&approval.id.0))
                .await,
            Err(KeyLeaseError::Denied { .. })
        ));
        assert!(matches!(
            service
                .request_lease(&actor, request.clone(), 61, 1, Some(&approval.id.0))
                .await,
            Err(KeyLeaseError::Denied { .. })
        ));
        assert_eq!(
            store.get_approval(&approval.id.0).unwrap().state,
            ApprovalState::Approved
        );
        assert!(matches!(
            service
                .request_lease(&actor, request, 30, 1, Some(&approval.id.0))
                .await
                .unwrap(),
            LeaseRequestOutcome::Issued { .. }
        ));
        assert_eq!(
            store.get_approval(&approval.id.0).unwrap().state,
            ApprovalState::Consumed
        );
        let audit = service.audit_query(20).unwrap();
        assert!(
            audit.iter().any(|event| {
                event.decision == "require_approval" && event.outcome == "pending"
            })
        );
        assert!(
            audit
                .iter()
                .any(|event| { event.action == "approval:decide" && event.outcome == "approved" })
        );
    }
}
