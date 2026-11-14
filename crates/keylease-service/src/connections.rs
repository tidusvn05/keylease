//! Connector connections and enrolled resources.

use super::*;

impl KeyLeaseService {
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
        let granted_permissions = ConnectorCredential::new(credential.clone())
            .oauth()
            .map(|oauth| normalized_permissions(provider, &oauth.scopes))
            .unwrap_or_default();
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
                favorite: false,
                attachments: vec![],
                notes: None,
                template_version: 1,
                project_id: None,
                agent_access: AgentAccess::None,
                content_metadata: None,
                personal: false,
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
                health_reason: None,
                reauthorization_required: false,
                granted_permissions,
                last_checked_at: None,
                last_refreshed_at: None,
                authorized_resources,
                created_at: now,
                updated_at: now,
            };
            self.store.save_connection(&record)?;
            Ok(record)
        })
    }
    pub async fn test_connection(&self, id: &ConnectionId) -> Result<()> {
        let (mut record, credential) = self.connection_credential(id)?;
        let result = self.connector(&record)?.test_connection(&credential).await;
        record.last_checked_at = Some(Utc::now());
        record.updated_at = Utc::now();
        match &result {
            Ok(()) => {
                record.health = ConnectionHealth::Connected;
                record.health_reason = None;
            }
            Err(KeyLeaseError::Denied { .. }) => {
                record.health = ConnectionHealth::Expired;
                record.health_reason = Some("upstream authorization was rejected".into());
                record.reauthorization_required = true;
            }
            Err(_) => {
                record.health = ConnectionHealth::Degraded;
                record.health_reason = Some("upstream health check failed".into());
            }
        }
        self.store.save_connection(&record)?;
        result
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
                vault,
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
                vault,
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
                vault,
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
        let refreshed = match connector.refresh(&credential).await {
            Ok(value) => value,
            Err(error) => {
                record.health = if matches!(error, KeyLeaseError::Denied { .. }) {
                    ConnectionHealth::Expired
                } else {
                    ConnectionHealth::Degraded
                };
                record.health_reason = Some("credential refresh failed closed".into());
                record.reauthorization_required = matches!(error, KeyLeaseError::Denied { .. });
                record.updated_at = Utc::now();
                self.store.save_connection(&record)?;
                return Err(error);
            }
        };
        if let Some(refreshed) = refreshed {
            let refreshed_permissions = refreshed
                .oauth()
                .map(|oauth| normalized_permissions(&record.provider, &oauth.scopes))
                .unwrap_or_else(|| record.granted_permissions.clone());
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
            record.granted_permissions = refreshed_permissions;
        }
        record.health = ConnectionHealth::Connected;
        record.health_reason = None;
        record.reauthorization_required = false;
        record.last_refreshed_at = Some(Utc::now());
        record.updated_at = Utc::now();
        self.store.save_connection(&record)?;
        Ok(record)
    }
    pub fn disconnect_connection(&self, id: &ConnectionId) -> Result<ConnectionRecord> {
        let mut record = self.store.get_connection(id)?;
        record.health = ConnectionHealth::Disconnected;
        record.health_reason = Some("disconnected locally".into());
        record.updated_at = Utc::now();
        self.store.save_connection(&record)?;
        Ok(record)
    }
    pub async fn revoke_connection(&self, id: &ConnectionId) -> Result<ConnectionRecord> {
        let (mut record, credential) = self.connection_credential(id)?;
        // Revoke locally before contacting the provider. A provider outage must
        // never leave the gateway capable of using a connection the user has
        // revoked.
        record.health = ConnectionHealth::Revoked;
        record.health_reason = Some("revoked locally".into());
        record.reauthorization_required = false;
        record.updated_at = Utc::now();
        self.store.save_connection(&record)?;
        match self.connector(&record)?.revoke(&credential).await {
            Ok(()) => Ok(record),
            Err(error) => {
                record.health_reason =
                    Some("revoked locally; upstream revoke requires retry".into());
                record.updated_at = Utc::now();
                self.store.save_connection(&record)?;
                Err(error)
            }
        }
    }
}
