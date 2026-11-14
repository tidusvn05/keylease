//! Initialization, unlock, sessions, clients and policy grants.

use super::*;

impl KeyLeaseService {
    pub fn new(store: Arc<NativeStore>) -> Result<Self> {
        let mut rules = store.load_policy_rules()?;
        rules.extend(trust::standing_rules(&store, Utc::now())?);
        let mut connectors: HashMap<String, Arc<dyn Connector>> = HashMap::new();
        connectors.insert("fake".into(), Arc::new(FakeConnector::default()));
        connectors.insert(
            "google_workspace".into(),
            Arc::new(BuiltinConnector::google()),
        );
        connectors.insert("github".into(), Arc::new(BuiltinConnector::github()));
        connectors.insert("linear".into(), Arc::new(BuiltinConnector::linear()));
        connectors.insert("notion".into(), Arc::new(BuiltinConnector::notion()));
        let data_version = store.data_version()?;
        Ok(Self {
            policy_data_version: std::sync::atomic::AtomicI64::new(data_version),
            store,
            session: Mutex::new(None),
            policy: RwLock::new(RulePolicyEngine::new(rules)),
            connectors,
            active_executions: Mutex::new(HashMap::new()),
            authentication_failures: Mutex::new(HashMap::new()),
            signature_nonces: Mutex::new(HashMap::new()),
            agent_handoffs: Mutex::new(HashMap::new()),
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
                self.reload_policy_for_client(agent_id, &vault_id)?;
                Ok(vault_id)
            }
            Err(error) => {
                self.authentication_failures
                    .lock()
                    .map_err(|_| KeyLeaseError::Storage)?
                    .entry(bucket)
                    .or_default()
                    .push_back(now);
                // Password-slot authentication deliberately exposes no crypto
                // details. At this boundary a crypto failure means the supplied
                // password could not unlock the vault (or the slot is unusable),
                // so callers should treat it as a rejected credential.
                match error {
                    KeyLeaseError::Crypto => Err(KeyLeaseError::Denied {
                        reason: "master password rejected".into(),
                    }),
                    other => Err(other),
                }
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
            return Ok(serde_json::json!({
                "locked":true,
                "requires_user_action":true,
                "service_version":env!("CARGO_PKG_VERSION"),
                "contract_version":CONTRACT_VERSION
            }));
        }
        Ok(match guard.as_ref() {
            Some(s) => {
                // A count, not records: polling it neither extends the idle
                // timeout nor writes audit, unlike `approvals_list`.
                let pending_approvals = self.store.count_pending_approvals(now)?;
                serde_json::json!({
                    "locked":false,
                    "vault_id":s.vault.vault_id,
                    "idle_expires_at":s.last_activity+s.idle_timeout,
                    "pending_approvals":pending_approvals,
                    "service_version":env!("CARGO_PKG_VERSION"),
                    "contract_version":CONTRACT_VERSION
                })
            }
            None => serde_json::json!({
                "locked":true,
                "requires_user_action":true,
                "service_version":env!("CARGO_PKG_VERSION"),
                "contract_version":CONTRACT_VERSION
            }),
        })
    }

    /// Registers a legacy bearer-token client; see
    /// [`Self::register_client_with_key`] for the signing kind.
    pub fn register_client(&self, name: &str) -> Result<(AgentId, String)> {
        let id = client_key::client_agent_id(name)?;
        let token = self.store.register_client(&id)?;
        Ok((id, token))
    }
    /// Creates or rotates the built-in desktop owner credential. This is
    /// deliberately distinct from registering an agent: the desktop's broad
    /// UI authority exists only while the vault is unlocked and is rebuilt
    /// after every successful desktop unlock.
    /// This device's stable identity for the open vault.
    ///
    /// See [`NativeStore::device_identity`] for why it is minted before sync
    /// exists.
    pub fn device_identity(&self, provenance: &str) -> Result<(String, String)> {
        self.store.device_identity(provenance)
    }

    /// Whether `agent_id` is a local owner client at all — desktop or phone.
    ///
    /// Use this where the question is "is this the human who owns the vault,
    /// rather than an agent", which is most places.
    pub(crate) fn is_local_owner(&self, agent_id: &AgentId) -> Result<bool> {
        Ok(self.store.local_owner_role(agent_id)?.is_some())
    }

    /// Whether `agent_id` is specifically the desktop owner.
    ///
    /// Use this only where the operation genuinely needs the desktop: the agent
    /// handoff and vault migrations.
    pub(crate) fn desktop_owner_only(&self, agent_id: &AgentId) -> Result<bool> {
        Ok(self.store.local_owner_role(agent_id)? == Some(LocalOwnerRole::DesktopOwner))
    }

    pub fn register_desktop_client(&self) -> Result<(AgentId, String)> {
        self.register_local_owner_client(LocalOwnerRole::DesktopOwner)
    }

    /// Registers (or rotates) the local owner credential for `role`.
    ///
    /// The agent id is derived from the role so a desktop and a phone opening
    /// the same vault file hold distinct credentials and distinct authority.
    pub fn register_local_owner_client(&self, role: LocalOwnerRole) -> Result<(AgentId, String)> {
        let id = match role {
            LocalOwnerRole::DesktopOwner => AgentId("agent_desktop".into()),
            LocalOwnerRole::MobileOwner => AgentId("agent_mobile".into()),
        };
        let token = self.store.register_local_owner_client(&id, role)?;
        Ok((id, token))
    }
    /// Whether the open database holds an initialised vault — the distinction
    /// between the onboarding and the locked phases on a client.
    pub fn is_initialized(&self) -> Result<bool> {
        self.store.is_initialized()
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
            purpose: None,
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
        self.install_policy(rules)
    }
    /// Atomically activates a complete signed-policy rule set at the local
    /// enforcement boundary and revokes leases issued under the old version.
    pub fn replace_policy_rules(&self, rules: Vec<PolicyRule>) -> Result<()> {
        self.store.replace_policy_rules(&rules)?;
        self.install_policy(rules)
    }
    pub fn list_grants(&self) -> Result<Vec<PolicyRule>> {
        self.store.load_policy_rules()
    }
    pub fn revoke_grant(&self, id: &str) -> Result<()> {
        self.store.delete_policy_rule(id)?;
        let rules = self.store.load_policy_rules()?;
        self.install_policy(rules)
    }
}
