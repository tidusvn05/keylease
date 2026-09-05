use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use keylease_core::{
    AccountId, AgentId, ControlEventId, DeviceId, EdgeId, HumanId, KeyLeaseError, MembershipId,
    OrganizationId, ProjectId, Result, VaultId,
};
use leasegate_control::{
    AgentRegistration, ApprovalDecision, ApprovalRequest, AuditBatch, CONTROL_CONTRACT_VERSION,
    ControlEvent, ControlEventKind, EdgeEventBatch, EdgeHealth, EdgeHeartbeat, EdgeRecord,
    Membership, MembershipRole, Organization, Project, Revocation, RevocationScope,
    SignedApprovalReceipt, SignedPolicyBundle, SyncMutationEnvelope, SyncMutationResult,
    SyncMutationStatus, SyncPullResponse, SyncPushResponse,
};
use leasegate_policy_bundle::{BundleAcceptanceState, verify_sync_mutation_signature};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};

#[derive(Debug, Clone)]
pub struct CloudRepository {
    pool: PgPool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct EdgeEnrollmentSecret {
    pub secret: String,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for EdgeEnrollmentSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EdgeEnrollmentSecret")
            .field("secret", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AgentCredentialSecret {
    pub registration: AgentRegistration,
    /// Returned exactly once; PostgreSQL stores only its SHA-256 digest.
    pub credential: String,
}

impl std::fmt::Debug for AgentCredentialSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentCredentialSecret")
            .field("registration", &self.registration)
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
pub struct EnrolledEdgeSecret {
    pub edge: EdgeRecord,
    /// Returned exactly once. It is scoped to this Edge's control/audit paths.
    pub credential: String,
}

impl std::fmt::Debug for EnrolledEdgeSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnrolledEdgeSecret")
            .field("edge", &self.edge)
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

pub struct ApprovalDecisionBinding<'a> {
    pub approver_id: &'a HumanId,
    pub expected_digest: &'a str,
    pub expected_policy_version: u64,
}

impl CloudRepository {
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.max(1))
            .connect(database_url)
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        Ok(Self { pool })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|_| KeyLeaseError::Storage)
    }

    pub async fn bootstrap_tenant(
        &self,
        account_id: AccountId,
        organization_name: &str,
        project_name: &str,
        oidc_issuer: &str,
        oidc_subject: &str,
        human_name: &str,
    ) -> Result<(Organization, Project, Membership)> {
        for value in [
            organization_name,
            project_name,
            oidc_issuer,
            oidc_subject,
            human_name,
        ] {
            validate_text(value, 500)?;
        }
        let now = Utc::now();
        let organization = Organization {
            id: OrganizationId::new(),
            account_id: account_id.clone(),
            name: organization_name.into(),
            created_at: now,
        };
        let project = Project {
            id: ProjectId::new(),
            organization_id: organization.id.clone(),
            name: project_name.into(),
            created_at: now,
        };
        let human_id = HumanId::new();
        let membership = Membership {
            id: MembershipId::new(),
            organization_id: organization.id.clone(),
            human_id: human_id.clone(),
            role: MembershipRole::Owner,
            created_at: now,
            revoked_at: None,
        };
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        sqlx::query("INSERT INTO accounts(account_id,created_at) VALUES($1,$2) ON CONFLICT(account_id) DO NOTHING")
            .bind(&account_id.0).bind(now).execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        sqlx::query("INSERT INTO organizations(organization_id,account_id,name,created_at) VALUES($1,$2,$3,$4)")
            .bind(&organization.id.0).bind(&account_id.0).bind(&organization.name).bind(now)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, &organization.id).await?;
        sqlx::query(
            "INSERT INTO projects(project_id,organization_id,name,created_at) VALUES($1,$2,$3,$4)",
        )
        .bind(&project.id.0)
        .bind(&organization.id.0)
        .bind(&project.name)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| KeyLeaseError::Storage)?;
        sqlx::query("INSERT INTO human_principals(human_id,oidc_issuer,oidc_subject,display_name,created_at) VALUES($1,$2,$3,$4,$5)")
            .bind(&human_id.0).bind(oidc_issuer).bind(oidc_subject).bind(human_name).bind(now)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        sqlx::query("INSERT INTO memberships(membership_id,organization_id,human_id,role,created_at) VALUES($1,$2,$3,'owner',$4)")
            .bind(&membership.id.0).bind(&organization.id.0).bind(&human_id.0).bind(now)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        Ok((organization, project, membership))
    }

    pub async fn register_device_key(
        &self,
        account_id: &AccountId,
        device_id: &DeviceId,
        verifying_key_base64: &str,
    ) -> Result<()> {
        validate_text(verifying_key_base64, 256)?;
        sqlx::query(
            "INSERT INTO device_keys(device_id,account_id,verifying_key_base64) VALUES($1,$2,$3)",
        )
        .bind(&device_id.0)
        .bind(&account_id.0)
        .bind(verifying_key_base64)
        .execute(&self.pool)
        .await
        .map_err(|_| KeyLeaseError::Storage)?;
        Ok(())
    }

    pub async fn register_agent(
        &self,
        organization_id: &OrganizationId,
        project_id: &ProjectId,
        display_name: &str,
    ) -> Result<AgentCredentialSecret> {
        validate_text(display_name, 200)?;
        let mut random = [0_u8; 32];
        rand::rng().fill_bytes(&mut random);
        let credential = format!("kla_{}", URL_SAFE_NO_PAD.encode(random));
        random.fill(0);
        let now = Utc::now();
        let registration = AgentRegistration {
            agent_id: AgentId::new(),
            organization_id: organization_id.clone(),
            project_id: project_id.clone(),
            display_name: display_name.into(),
            credential_digest: digest(credential.as_bytes()),
            created_at: now,
            revoked_at: None,
        };
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        ensure_project(&mut tx, organization_id, project_id).await?;
        sqlx::query("INSERT INTO agents(agent_id,organization_id,project_id,display_name,credential_digest,created_at) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(&registration.agent_id.0).bind(&organization_id.0).bind(&project_id.0).bind(display_name).bind(&registration.credential_digest).bind(now)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        insert_outbox(
            &mut tx,
            "agent.registered",
            &registration.agent_id.0,
            &registration,
        )
        .await?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        Ok(AgentCredentialSecret {
            registration,
            credential,
        })
    }

    pub async fn revoke_agent(
        &self,
        organization_id: &OrganizationId,
        project_id: &ProjectId,
        agent_id: &AgentId,
        reason: &str,
    ) -> Result<ControlEvent> {
        validate_text(reason, 500)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        ensure_project(&mut tx, organization_id, project_id).await?;
        let changed = sqlx::query("UPDATE agents SET revoked_at=$1 WHERE agent_id=$2 AND organization_id=$3 AND project_id=$4 AND revoked_at IS NULL")
            .bind(Utc::now()).bind(&agent_id.0).bind(&organization_id.0).bind(&project_id.0)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?.rows_affected();
        if changed != 1 {
            return Err(KeyLeaseError::NotFound {
                resource: agent_id.0.clone(),
            });
        }
        let current: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(epoch),0) FROM revocations WHERE organization_id=$1",
        )
        .bind(&organization_id.0)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| KeyLeaseError::Storage)?;
        let revocation = Revocation {
            organization_id: organization_id.clone(),
            project_id: Some(project_id.clone()),
            epoch: current as u64 + 1,
            scope: RevocationScope::Agent,
            target_id: agent_id.0.clone(),
            reason: reason.into(),
            created_at: Utc::now(),
        };
        sqlx::query("INSERT INTO revocations(organization_id,epoch,project_id,scope,target_id,revocation_json,created_at) VALUES($1,$2,$3,'agent',$4,$5,$6)")
            .bind(&organization_id.0).bind(revocation.epoch as i64).bind(&project_id.0).bind(&agent_id.0)
            .bind(serde_json::to_value(&revocation).map_err(|_| KeyLeaseError::Storage)?).bind(revocation.created_at)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        let event = insert_control_event(
            &mut tx,
            organization_id,
            Some(project_id),
            None,
            ControlEventKind::Revocation(revocation),
        )
        .await?;
        insert_outbox(&mut tx, "control.revocation", &agent_id.0, &event).await?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        Ok(event)
    }

    pub async fn create_vault(
        &self,
        account_id: &AccountId,
        organization_id: Option<&OrganizationId>,
        vault_id: &VaultId,
        encrypted_header: &str,
    ) -> Result<()> {
        validate_text(encrypted_header, 1_048_576)?;
        sqlx::query("INSERT INTO vaults(vault_id,account_id,organization_id,encrypted_header) VALUES($1,$2,$3,$4)")
            .bind(&vault_id.0).bind(&account_id.0).bind(organization_id.map(|value| value.0.as_str())).bind(encrypted_header)
            .execute(&self.pool).await.map_err(|_| KeyLeaseError::Storage)?;
        Ok(())
    }

    pub async fn create_edge_enrollment(
        &self,
        organization_id: &OrganizationId,
        project_id: &ProjectId,
        name: &str,
        ttl: Duration,
    ) -> Result<EdgeEnrollmentSecret> {
        validate_text(name, 200)?;
        if ttl <= Duration::zero() || ttl > Duration::minutes(30) {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "edge enrollment TTL must be within 1..=30 minutes".into(),
            });
        }
        let mut random = [0_u8; 32];
        rand::rng().fill_bytes(&mut random);
        let secret = format!("lge_{}", URL_SAFE_NO_PAD.encode(random));
        let digest = digest(secret.as_bytes());
        let expires_at = Utc::now() + ttl;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        ensure_project(&mut tx, organization_id, project_id).await?;
        sqlx::query("INSERT INTO edge_enrollments(enrollment_digest,organization_id,project_id,name,expires_at) VALUES($1,$2,$3,$4,$5)")
            .bind(digest).bind(&organization_id.0).bind(&project_id.0).bind(name).bind(expires_at)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        Ok(EdgeEnrollmentSecret { secret, expires_at })
    }

    pub async fn enroll_edge(
        &self,
        enrollment_secret: &str,
        device_id: DeviceId,
        public_key_base64: &str,
        software_version: &str,
    ) -> Result<EnrolledEdgeSecret> {
        validate_text(public_key_base64, 256)?;
        validate_text(software_version, 100)?;
        let now = Utc::now();
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        let row = sqlx::query("SELECT organization_id,project_id,name,expires_at,consumed_at FROM edge_enrollments WHERE enrollment_digest=$1 FOR UPDATE")
            .bind(digest(enrollment_secret.as_bytes())).fetch_optional(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?
            .ok_or_else(|| KeyLeaseError::Denied { reason: "invalid edge enrollment secret".into() })?;
        let organization_id = OrganizationId(
            row.try_get("organization_id")
                .map_err(|_| KeyLeaseError::Storage)?,
        );
        let project_id = ProjectId(
            row.try_get("project_id")
                .map_err(|_| KeyLeaseError::Storage)?,
        );
        let expires_at: DateTime<Utc> = row
            .try_get("expires_at")
            .map_err(|_| KeyLeaseError::Storage)?;
        let consumed_at: Option<DateTime<Utc>> = row
            .try_get("consumed_at")
            .map_err(|_| KeyLeaseError::Storage)?;
        if expires_at <= now || consumed_at.is_some() {
            return Err(KeyLeaseError::Denied {
                reason: "edge enrollment secret expired or consumed".into(),
            });
        }
        set_tenant(&mut tx, &organization_id).await?;
        let mut credential_bytes = [0_u8; 32];
        rand::rng().fill_bytes(&mut credential_bytes);
        let credential = format!("kle_{}", URL_SAFE_NO_PAD.encode(credential_bytes));
        credential_bytes.fill(0);
        let credential_digest = digest(credential.as_bytes());
        let edge = EdgeRecord {
            id: EdgeId::new(),
            organization_id: organization_id.clone(),
            project_id,
            device_id,
            name: row.try_get("name").map_err(|_| KeyLeaseError::Storage)?,
            public_key_base64: public_key_base64.into(),
            certificate_fingerprint_sha256: None,
            health: EdgeHealth::Healthy,
            software_version: software_version.into(),
            last_seen_at: Some(now),
            created_at: now,
            revoked_at: None,
        };
        sqlx::query("UPDATE edge_enrollments SET consumed_at=$1 WHERE enrollment_digest=$2")
            .bind(now)
            .bind(digest(enrollment_secret.as_bytes()))
            .execute(&mut *tx)
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        sqlx::query("INSERT INTO edges(edge_id,organization_id,project_id,device_id,name,public_key_base64,credential_digest,health,software_version,last_seen_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,'healthy',$8,$9,$10)")
            .bind(&edge.id.0).bind(&edge.organization_id.0).bind(&edge.project_id.0).bind(&edge.device_id.0).bind(&edge.name).bind(public_key_base64).bind(credential_digest).bind(software_version).bind(now).bind(now)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        sqlx::query("INSERT INTO edge_event_acks(edge_id,sequence,updated_at) VALUES($1,0,$2)")
            .bind(&edge.id.0)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        Ok(EnrolledEdgeSecret { edge, credential })
    }

    pub async fn authenticate_edge(
        &self,
        edge_id: &EdgeId,
        credential: &str,
    ) -> Result<EdgeRecord> {
        if credential.len() < 32 || credential.len() > 1024 {
            return Err(KeyLeaseError::Denied {
                reason: "invalid Edge credential".into(),
            });
        }
        let authenticated: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM edges WHERE edge_id=$1 AND credential_digest=$2 AND revoked_at IS NULL)")
            .bind(&edge_id.0).bind(digest(credential.as_bytes())).fetch_one(&self.pool).await.map_err(|_| KeyLeaseError::Storage)?;
        if !authenticated {
            return Err(KeyLeaseError::Denied {
                reason: "invalid or revoked Edge credential".into(),
            });
        }
        self.edge(edge_id).await
    }

    pub async fn push_sync(
        &self,
        account_id: &AccountId,
        vault_id: &VaultId,
        mutations: Vec<SyncMutationEnvelope>,
    ) -> Result<SyncPushResponse> {
        if mutations.is_empty() || mutations.len() > 100 {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "sync push must contain 1..=100 mutations".into(),
            });
        }
        let mut results = Vec::with_capacity(mutations.len());
        let mut cursor = 0_u64;
        for mutation in mutations {
            let (result, applied_cursor) = self
                .apply_sync_mutation(account_id, vault_id, mutation)
                .await?;
            cursor = cursor.max(applied_cursor);
            results.push(result);
        }
        Ok(SyncPushResponse {
            schema_version: CONTROL_CONTRACT_VERSION,
            cursor,
            results,
        })
    }

    async fn apply_sync_mutation(
        &self,
        account_id: &AccountId,
        vault_id: &VaultId,
        mutation: SyncMutationEnvelope,
    ) -> Result<(SyncMutationResult, u64)> {
        mutation.validate_shape()?;
        if &mutation.account_id != account_id || &mutation.vault_id != vault_id {
            return Err(KeyLeaseError::Denied {
                reason: "sync tenant/vault binding mismatch".into(),
            });
        }
        if mutation.ciphertext.len() > 4 * 1024 * 1024 {
            return Err(KeyLeaseError::Denied {
                reason: "sync object exceeds four MiB; use encrypted attachment chunks".into(),
            });
        }
        let public: String = sqlx::query_scalar("SELECT verifying_key_base64 FROM device_keys WHERE device_id=$1 AND account_id=$2 AND revoked_at IS NULL")
            .bind(&mutation.device_id.0).bind(&account_id.0).fetch_optional(&self.pool).await.map_err(|_| KeyLeaseError::Storage)?
            .ok_or_else(|| KeyLeaseError::Denied { reason: "unknown or revoked sync device".into() })?;
        verify_sync_mutation_signature(&mutation, &public)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("{}:{}", vault_id.0, mutation.object_id))
            .execute(&mut *tx)
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        if let Some(row) = sqlx::query("SELECT cursor,ciphertext_digest FROM sync_mutations WHERE vault_id=$1 AND device_id=$2 AND idempotency_key=$3")
            .bind(&vault_id.0).bind(&mutation.device_id.0).bind(&mutation.idempotency_key)
            .fetch_optional(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?
        {
            let existing: String = row.try_get("ciphertext_digest").map_err(|_| KeyLeaseError::Storage)?;
            let replay_cursor: i64 = row.try_get("cursor").map_err(|_| KeyLeaseError::Storage)?;
            let different = existing != mutation.ciphertext_digest;
            let current = current_revision(&mut tx, vault_id, &mutation.object_id).await?;
            tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
            return Ok((SyncMutationResult {
                mutation_id: mutation.mutation_id,
                status: if different { SyncMutationStatus::Rejected } else { SyncMutationStatus::Replay },
                current_revision: current,
                reason: different.then(|| "idempotency key reused with different ciphertext".into()),
            }, replay_cursor as u64));
        }
        let current = current_revision(&mut tx, vault_id, &mutation.object_id).await?;
        if current != mutation.base_revision {
            tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
            return Ok((
                SyncMutationResult {
                    mutation_id: mutation.mutation_id,
                    status: SyncMutationStatus::Conflict,
                    current_revision: current,
                    reason: Some("base revision does not match cloud object".into()),
                },
                cursor_for_vault(&self.pool, vault_id).await?,
            ));
        }
        sqlx::query("INSERT INTO vault_objects(account_id,vault_id,object_id,revision,ciphertext,ciphertext_digest,tombstone,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(vault_id,object_id) DO UPDATE SET revision=excluded.revision,ciphertext=excluded.ciphertext,ciphertext_digest=excluded.ciphertext_digest,tombstone=excluded.tombstone,updated_at=excluded.updated_at")
            .bind(&account_id.0).bind(&vault_id.0).bind(&mutation.object_id).bind(mutation.result_revision as i64).bind(&mutation.ciphertext).bind(&mutation.ciphertext_digest).bind(mutation.tombstone).bind(mutation.created_at)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        let envelope = serde_json::to_value(&mutation).map_err(|_| KeyLeaseError::Storage)?;
        let applied_cursor: i64 = sqlx::query_scalar("INSERT INTO sync_mutations(mutation_id,account_id,vault_id,object_id,device_id,idempotency_key,ciphertext_digest,envelope_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING cursor")
            .bind(&mutation.mutation_id.0).bind(&account_id.0).bind(&vault_id.0).bind(&mutation.object_id).bind(&mutation.device_id.0).bind(&mutation.idempotency_key).bind(&mutation.ciphertext_digest).bind(envelope).bind(mutation.created_at)
            .fetch_one(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        Ok((
            SyncMutationResult {
                mutation_id: mutation.mutation_id,
                status: SyncMutationStatus::Applied,
                current_revision: mutation.result_revision,
                reason: None,
            },
            applied_cursor as u64,
        ))
    }

    pub async fn pull_sync(
        &self,
        account_id: &AccountId,
        vault_id: &VaultId,
        after_cursor: u64,
        limit: u32,
    ) -> Result<SyncPullResponse> {
        let limit = limit.clamp(1, 500);
        let rows = sqlx::query("SELECT cursor,envelope_json FROM sync_mutations WHERE account_id=$1 AND vault_id=$2 AND cursor>$3 ORDER BY cursor ASC LIMIT $4")
            .bind(&account_id.0).bind(&vault_id.0).bind(after_cursor as i64).bind((limit + 1) as i64)
            .fetch_all(&self.pool).await.map_err(|_| KeyLeaseError::Storage)?;
        let has_more = rows.len() > limit as usize;
        let mut cursor = after_cursor;
        let mut mutations = Vec::new();
        for row in rows.into_iter().take(limit as usize) {
            cursor = row
                .try_get::<i64, _>("cursor")
                .map_err(|_| KeyLeaseError::Storage)? as u64;
            let value: serde_json::Value = row
                .try_get("envelope_json")
                .map_err(|_| KeyLeaseError::Storage)?;
            mutations.push(serde_json::from_value(value).map_err(|_| KeyLeaseError::Storage)?);
        }
        Ok(SyncPullResponse {
            schema_version: CONTROL_CONTRACT_VERSION,
            cursor,
            has_more,
            mutations,
        })
    }

    pub async fn latest_policy_state(
        &self,
        organization_id: &OrganizationId,
        project_id: &ProjectId,
    ) -> Result<Option<BundleAcceptanceState>> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        let row = sqlx::query("SELECT version,payload_digest,bundle_json FROM policy_bundles WHERE project_id=$1 AND activated_at IS NOT NULL ORDER BY version DESC LIMIT 1")
            .bind(&project_id.0).fetch_optional(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        row.map(|row| {
            let bundle: SignedPolicyBundle = serde_json::from_value(
                row.try_get("bundle_json")
                    .map_err(|_| KeyLeaseError::Storage)?,
            )
            .map_err(|_| KeyLeaseError::Storage)?;
            Ok(BundleAcceptanceState {
                organization_id: organization_id.clone(),
                project_id: project_id.clone(),
                version: row
                    .try_get::<i64, _>("version")
                    .map_err(|_| KeyLeaseError::Storage)? as u64,
                payload_digest_sha256: row
                    .try_get("payload_digest")
                    .map_err(|_| KeyLeaseError::Storage)?,
                revocation_epoch: bundle.payload.revocation_epoch,
            })
        })
        .transpose()
    }

    pub async fn activate_policy(&self, bundle: &SignedPolicyBundle) -> Result<ControlEvent> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, &bundle.payload.organization_id).await?;
        ensure_project(
            &mut tx,
            &bundle.payload.organization_id,
            &bundle.payload.project_id,
        )
        .await?;
        let now = Utc::now();
        sqlx::query("INSERT INTO policy_bundles(bundle_id,organization_id,project_id,version,payload_digest,bundle_json,activated_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$7)")
            .bind(&bundle.payload.bundle_id.0).bind(&bundle.payload.organization_id.0).bind(&bundle.payload.project_id.0).bind(bundle.payload.version as i64).bind(&bundle.payload_digest_sha256).bind(serde_json::to_value(bundle).map_err(|_| KeyLeaseError::Storage)?).bind(now)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        let event = insert_control_event(
            &mut tx,
            &bundle.payload.organization_id,
            Some(&bundle.payload.project_id),
            Some(bundle.payload.expires_at),
            ControlEventKind::PolicyBundle(bundle.clone()),
        )
        .await?;
        insert_outbox(
            &mut tx,
            "control.policy",
            &bundle.payload.project_id.0,
            &event,
        )
        .await?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        Ok(event)
    }

    pub async fn create_approval(&self, approval: &ApprovalRequest) -> Result<()> {
        if approval.schema_version != CONTROL_CONTRACT_VERSION || approval.expires_at <= Utc::now()
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "invalid or expired approval request".into(),
            });
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, &approval.organization_id).await?;
        ensure_project(&mut tx, &approval.organization_id, &approval.project_id).await?;
        sqlx::query("INSERT INTO approval_requests(approval_id,organization_id,project_id,request_digest,policy_version,state,request_json,created_at,expires_at) VALUES($1,$2,$3,$4,$5,'pending',$6,$7,$8)")
            .bind(&approval.approval_id.0).bind(&approval.organization_id.0).bind(&approval.project_id.0).bind(&approval.request_digest_hex).bind(approval.policy_version as i64).bind(serde_json::to_value(approval).map_err(|_| KeyLeaseError::Storage)?).bind(approval.created_at).bind(approval.expires_at)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        insert_outbox(
            &mut tx,
            "approval.requested",
            &approval.approval_id.0,
            approval,
        )
        .await?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)
    }

    pub async fn approval_request(
        &self,
        organization_id: &OrganizationId,
        approval_id: &str,
    ) -> Result<ApprovalRequest> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        let value: serde_json::Value =
            sqlx::query_scalar("SELECT request_json FROM approval_requests WHERE approval_id=$1")
                .bind(approval_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| KeyLeaseError::Storage)?
                .ok_or_else(|| KeyLeaseError::NotFound {
                    resource: approval_id.into(),
                })?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        serde_json::from_value(value).map_err(|_| KeyLeaseError::Storage)
    }

    pub async fn pending_approvals(
        &self,
        organization_id: &OrganizationId,
        project_id: &ProjectId,
        limit: u32,
    ) -> Result<Vec<ApprovalRequest>> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        ensure_project(&mut tx, organization_id, project_id).await?;
        let rows: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT request_json FROM approval_requests WHERE organization_id=$1 AND project_id=$2 AND state='pending' AND expires_at>$3 ORDER BY created_at ASC LIMIT $4",
        )
        .bind(&organization_id.0)
        .bind(&project_id.0)
        .bind(Utc::now())
        .bind(limit.clamp(1, 500) as i64)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        rows.into_iter()
            .map(|value| serde_json::from_value(value).map_err(|_| KeyLeaseError::Storage))
            .collect()
    }

    pub async fn decide_approval(
        &self,
        organization_id: &OrganizationId,
        approval_id: &str,
        decision: ApprovalDecision,
        binding: ApprovalDecisionBinding<'_>,
        receipt: Option<&SignedApprovalReceipt>,
    ) -> Result<Option<ControlEvent>> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        let authorized: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM memberships WHERE organization_id=$1 AND human_id=$2 AND revoked_at IS NULL AND role IN ('owner','admin','approver'))")
            .bind(&organization_id.0).bind(&binding.approver_id.0).fetch_one(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        if !authorized {
            return Err(KeyLeaseError::Denied {
                reason: "human principal is not an active approver".into(),
            });
        }
        let row = sqlx::query("SELECT project_id,request_digest,policy_version,state,expires_at FROM approval_requests WHERE approval_id=$1 FOR UPDATE")
            .bind(approval_id).fetch_optional(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?
            .ok_or_else(|| KeyLeaseError::NotFound { resource: approval_id.into() })?;
        let state: String = row.try_get("state").map_err(|_| KeyLeaseError::Storage)?;
        let expires_at: DateTime<Utc> = row
            .try_get("expires_at")
            .map_err(|_| KeyLeaseError::Storage)?;
        let digest: String = row
            .try_get("request_digest")
            .map_err(|_| KeyLeaseError::Storage)?;
        let version: i64 = row
            .try_get("policy_version")
            .map_err(|_| KeyLeaseError::Storage)?;
        if state != "pending"
            || expires_at <= Utc::now()
            || digest != binding.expected_digest
            || version as u64 != binding.expected_policy_version
        {
            return Err(KeyLeaseError::Denied {
                reason: "approval state or exact request binding changed".into(),
            });
        }
        let next = match decision {
            ApprovalDecision::Approved => "approved",
            ApprovalDecision::Denied => "denied",
            ApprovalDecision::Revoked => "revoked",
        };
        if matches!(decision, ApprovalDecision::Approved) && receipt.is_none() {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "approved decision requires a signed receipt".into(),
            });
        }
        sqlx::query("UPDATE approval_requests SET state=$1,receipt_json=$2,decided_at=$3 WHERE approval_id=$4")
            .bind(next).bind(receipt.map(serde_json::to_value).transpose().map_err(|_| KeyLeaseError::Storage)?).bind(Utc::now()).bind(approval_id)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        let event = if let Some(receipt) = receipt {
            let project_id = ProjectId(
                row.try_get("project_id")
                    .map_err(|_| KeyLeaseError::Storage)?,
            );
            Some(
                insert_control_event(
                    &mut tx,
                    organization_id,
                    Some(&project_id),
                    Some(receipt.payload.expires_at),
                    ControlEventKind::ApprovalReceipt(receipt.clone()),
                )
                .await?,
            )
        } else {
            None
        };
        insert_outbox(
            &mut tx,
            "approval.decided",
            approval_id,
            &serde_json::json!({"decision":next}),
        )
        .await?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        Ok(event)
    }

    pub async fn append_revocation(&self, revocation: &Revocation) -> Result<ControlEvent> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, &revocation.organization_id).await?;
        let current: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(epoch),0) FROM revocations WHERE organization_id=$1",
        )
        .bind(&revocation.organization_id.0)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| KeyLeaseError::Storage)?;
        if revocation.epoch != current as u64 + 1 {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "revocation epoch must increase exactly by one".into(),
            });
        }
        sqlx::query("INSERT INTO revocations(organization_id,epoch,project_id,scope,target_id,revocation_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(&revocation.organization_id.0).bind(revocation.epoch as i64).bind(revocation.project_id.as_ref().map(|id| id.0.as_str())).bind(format!("{:?}", revocation.scope).to_lowercase()).bind(&revocation.target_id).bind(serde_json::to_value(revocation).map_err(|_| KeyLeaseError::Storage)?).bind(revocation.created_at)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        let event = insert_control_event(
            &mut tx,
            &revocation.organization_id,
            revocation.project_id.as_ref(),
            None,
            ControlEventKind::Revocation(revocation.clone()),
        )
        .await?;
        insert_outbox(
            &mut tx,
            "control.revocation",
            &revocation.organization_id.0,
            &event,
        )
        .await?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        Ok(event)
    }

    pub async fn edge_events(
        &self,
        edge_id: &EdgeId,
        after: u64,
        limit: u32,
    ) -> Result<EdgeEventBatch> {
        let edge = self.edge(edge_id).await?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, &edge.organization_id).await?;
        let limit = limit.clamp(1, 500);
        // Expired events remain in the feed so advancing a durable cursor can
        // never silently skip an approval/policy sequence. Edge discards an
        // expired approval while still recording the cursor.
        let rows = sqlx::query("SELECT sequence,event_json FROM control_events WHERE organization_id=$1 AND (project_id IS NULL OR project_id=$2) AND sequence>$3 ORDER BY sequence ASC LIMIT $4")
            .bind(&edge.organization_id.0).bind(&edge.project_id.0).bind(after as i64).bind((limit + 1) as i64)
            .fetch_all(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        let has_more = rows.len() > limit as usize;
        let mut cursor = after;
        let mut events = Vec::new();
        for row in rows.into_iter().take(limit as usize) {
            cursor = row
                .try_get::<i64, _>("sequence")
                .map_err(|_| KeyLeaseError::Storage)? as u64;
            events.push(
                serde_json::from_value(
                    row.try_get("event_json")
                        .map_err(|_| KeyLeaseError::Storage)?,
                )
                .map_err(|_| KeyLeaseError::Storage)?,
            );
        }
        Ok(EdgeEventBatch {
            schema_version: CONTROL_CONTRACT_VERSION,
            cursor,
            has_more,
            events,
        })
    }

    pub async fn acknowledge_edge_events(&self, edge_id: &EdgeId, cursor: u64) -> Result<()> {
        let edge = self.edge(edge_id).await?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, &edge.organization_id).await?;
        let current: i64 =
            sqlx::query_scalar("SELECT sequence FROM edge_event_acks WHERE edge_id=$1 FOR UPDATE")
                .bind(&edge_id.0)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| KeyLeaseError::Storage)?;
        if cursor < current as u64 {
            return Err(KeyLeaseError::Denied {
                reason: "edge control cursor rollback detected".into(),
            });
        }
        sqlx::query("UPDATE edge_event_acks SET sequence=$1,updated_at=$2 WHERE edge_id=$3")
            .bind(cursor as i64)
            .bind(Utc::now())
            .bind(&edge_id.0)
            .execute(&mut *tx)
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)
    }

    pub async fn record_heartbeat(&self, heartbeat: &EdgeHeartbeat) -> Result<()> {
        if heartbeat.schema_version != CONTROL_CONTRACT_VERSION {
            return Err(KeyLeaseError::UnsupportedVersion {
                version: heartbeat.schema_version,
            });
        }
        let edge = self.edge(&heartbeat.edge_id).await?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, &edge.organization_id).await?;
        sqlx::query("INSERT INTO edge_heartbeats(edge_id,heartbeat_json,observed_at) VALUES($1,$2,$3) ON CONFLICT(edge_id) DO UPDATE SET heartbeat_json=excluded.heartbeat_json,observed_at=excluded.observed_at")
            .bind(&heartbeat.edge_id.0).bind(serde_json::to_value(heartbeat).map_err(|_| KeyLeaseError::Storage)?).bind(heartbeat.observed_at)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        sqlx::query("UPDATE edges SET health='healthy',software_version=$1,last_seen_at=$2 WHERE edge_id=$3 AND revoked_at IS NULL")
            .bind(&heartbeat.software_version).bind(heartbeat.observed_at).bind(&heartbeat.edge_id.0)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)
    }

    pub async fn project_edges(
        &self,
        organization_id: &OrganizationId,
        project_id: &ProjectId,
    ) -> Result<Vec<EdgeRecord>> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        ensure_project(&mut tx, organization_id, project_id).await?;
        let rows = sqlx::query("SELECT edge_id,organization_id,project_id,device_id,name,public_key_base64,certificate_fingerprint_sha256,health,software_version,last_seen_at,created_at,revoked_at FROM edges WHERE organization_id=$1 AND project_id=$2 ORDER BY created_at")
            .bind(&organization_id.0).bind(&project_id.0).fetch_all(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        rows.into_iter().map(edge_from_row).collect()
    }

    pub async fn mark_stale_edges_offline(&self, before: DateTime<Utc>) -> Result<u64> {
        let changed = sqlx::query("UPDATE edges SET health='offline' WHERE revoked_at IS NULL AND (last_seen_at IS NULL OR last_seen_at<$1) AND health<>'offline'")
            .bind(before).execute(&self.pool).await.map_err(|_| KeyLeaseError::Storage)?.rows_affected();
        Ok(changed)
    }

    pub async fn expire_pending_approvals(&self, now: DateTime<Utc>) -> Result<u64> {
        Ok(sqlx::query("UPDATE approval_requests SET state='expired',decided_at=$1 WHERE state='pending' AND expires_at<=$1")
            .bind(now).execute(&self.pool).await.map_err(|_| KeyLeaseError::Storage)?.rows_affected())
    }

    /// Claims durable outbox records with `SKIP LOCKED`. Phase 3's baseline
    /// delivery is the control-event feed itself; marking here records that a
    /// worker observed the committed notification for metrics/webhooks.
    pub async fn dispatch_outbox_batch(&self, limit: u32) -> Result<u64> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        let ids: Vec<i64> = sqlx::query_scalar("SELECT outbox_id FROM event_outbox WHERE delivered_at IS NULL ORDER BY outbox_id FOR UPDATE SKIP LOCKED LIMIT $1")
            .bind(limit.clamp(1, 500) as i64).fetch_all(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        if !ids.is_empty() {
            sqlx::query("UPDATE event_outbox SET delivered_at=$1,attempts=attempts+1 WHERE outbox_id=ANY($2)")
                .bind(Utc::now()).bind(&ids).execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        }
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        Ok(ids.len() as u64)
    }

    pub async fn ingest_audit(
        &self,
        organization_id: &OrganizationId,
        project_id: &ProjectId,
        batch: &AuditBatch,
    ) -> Result<u64> {
        if batch.schema_version != CONTROL_CONTRACT_VERSION || batch.events.len() > 1000 {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "invalid audit batch".into(),
            });
        }
        let edge = self.edge(&batch.edge_id).await?;
        if &edge.organization_id != organization_id || &edge.project_id != project_id {
            return Err(KeyLeaseError::Denied {
                reason: "audit batch tenant binding mismatch".into(),
            });
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        for (offset, event) in batch.events.iter().enumerate() {
            let sequence = batch.first_sequence.saturating_add(offset as u64);
            sqlx::query("INSERT INTO audit_event_index(edge_id,edge_sequence,organization_id,project_id,timestamp,request_id,agent_id,action,resource,decision,outcome,event_json) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(edge_id,edge_sequence) DO NOTHING")
                .bind(&batch.edge_id.0).bind(sequence as i64).bind(&organization_id.0).bind(&project_id.0).bind(event.timestamp).bind(&event.request_id.0).bind(&event.agent_id.0).bind(&event.action).bind(&event.resource).bind(&event.decision).bind(&event.outcome).bind(serde_json::to_value(event).map_err(|_| KeyLeaseError::Storage)?)
                .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        }
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        Ok(batch
            .first_sequence
            .saturating_add(batch.events.len().saturating_sub(1) as u64))
    }

    async fn edge(&self, edge_id: &EdgeId) -> Result<EdgeRecord> {
        let row = sqlx::query("SELECT edge_id,organization_id,project_id,device_id,name,public_key_base64,certificate_fingerprint_sha256,health,software_version,last_seen_at,created_at,revoked_at FROM edges WHERE edge_id=$1")
            .bind(&edge_id.0).fetch_optional(&self.pool).await.map_err(|_| KeyLeaseError::Storage)?
            .ok_or_else(|| KeyLeaseError::NotFound { resource: edge_id.0.clone() })?;
        edge_from_row(row)
    }
}

fn edge_from_row(row: sqlx::postgres::PgRow) -> Result<EdgeRecord> {
    Ok(EdgeRecord {
        id: EdgeId(row.try_get("edge_id").map_err(|_| KeyLeaseError::Storage)?),
        organization_id: OrganizationId(
            row.try_get("organization_id")
                .map_err(|_| KeyLeaseError::Storage)?,
        ),
        project_id: ProjectId(
            row.try_get("project_id")
                .map_err(|_| KeyLeaseError::Storage)?,
        ),
        device_id: DeviceId(
            row.try_get("device_id")
                .map_err(|_| KeyLeaseError::Storage)?,
        ),
        name: row.try_get("name").map_err(|_| KeyLeaseError::Storage)?,
        public_key_base64: row
            .try_get("public_key_base64")
            .map_err(|_| KeyLeaseError::Storage)?,
        certificate_fingerprint_sha256: row
            .try_get("certificate_fingerprint_sha256")
            .map_err(|_| KeyLeaseError::Storage)?,
        health: match row
            .try_get::<String, _>("health")
            .map_err(|_| KeyLeaseError::Storage)?
            .as_str()
        {
            "enrolling" => EdgeHealth::Enrolling,
            "healthy" => EdgeHealth::Healthy,
            "degraded" => EdgeHealth::Degraded,
            "offline" => EdgeHealth::Offline,
            _ => EdgeHealth::Revoked,
        },
        software_version: row
            .try_get("software_version")
            .map_err(|_| KeyLeaseError::Storage)?,
        last_seen_at: row
            .try_get("last_seen_at")
            .map_err(|_| KeyLeaseError::Storage)?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| KeyLeaseError::Storage)?,
        revoked_at: row
            .try_get("revoked_at")
            .map_err(|_| KeyLeaseError::Storage)?,
    })
}

async fn set_tenant(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: &OrganizationId,
) -> Result<()> {
    sqlx::query("SELECT set_config('leasegate.organization_id',$1,true)")
        .bind(&organization_id.0)
        .execute(&mut **transaction)
        .await
        .map_err(|_| KeyLeaseError::Storage)?;
    Ok(())
}

async fn ensure_project(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: &OrganizationId,
    project_id: &ProjectId,
) -> Result<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM projects WHERE organization_id=$1 AND project_id=$2)",
    )
    .bind(&organization_id.0)
    .bind(&project_id.0)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| KeyLeaseError::Storage)?;
    if !exists {
        return Err(KeyLeaseError::Denied {
            reason: "project does not belong to organization".into(),
        });
    }
    Ok(())
}

async fn current_revision(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    vault_id: &VaultId,
    object_id: &str,
) -> Result<u64> {
    let revision: Option<i64> = sqlx::query_scalar(
        "SELECT revision FROM vault_objects WHERE vault_id=$1 AND object_id=$2 FOR UPDATE",
    )
    .bind(&vault_id.0)
    .bind(object_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| KeyLeaseError::Storage)?;
    Ok(revision.unwrap_or(0) as u64)
}

async fn cursor_for_vault(pool: &PgPool, vault_id: &VaultId) -> Result<u64> {
    let value: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(cursor),0) FROM sync_mutations WHERE vault_id=$1")
            .bind(&vault_id.0)
            .fetch_one(pool)
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
    Ok(value as u64)
}

async fn insert_control_event(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: &OrganizationId,
    project_id: Option<&ProjectId>,
    expires_at: Option<DateTime<Utc>>,
    kind: ControlEventKind,
) -> Result<ControlEvent> {
    let now = Utc::now();
    let id = ControlEventId::new();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("control:{}", organization_id.0))
        .execute(&mut **transaction)
        .await
        .map_err(|_| KeyLeaseError::Storage)?;
    let sequence: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(sequence),0)+1 FROM control_events WHERE organization_id=$1",
    )
    .bind(&organization_id.0)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| KeyLeaseError::Storage)?;
    sqlx::query("INSERT INTO control_events(event_id,organization_id,project_id,sequence,event_json,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(&id.0).bind(&organization_id.0).bind(project_id.map(|id| id.0.as_str())).bind(sequence).bind(serde_json::json!({"pending":true})).bind(now).bind(expires_at)
        .execute(&mut **transaction).await.map_err(|_| KeyLeaseError::Storage)?;
    let event = ControlEvent {
        schema_version: CONTROL_CONTRACT_VERSION,
        id,
        organization_id: organization_id.clone(),
        project_id: project_id.cloned(),
        sequence: sequence as u64,
        created_at: now,
        expires_at,
        kind,
    };
    sqlx::query(
        "UPDATE control_events SET event_json=$1 WHERE organization_id=$2 AND sequence=$3",
    )
        .bind(serde_json::to_value(&event).map_err(|_| KeyLeaseError::Storage)?)
        .bind(&organization_id.0)
        .bind(sequence)
        .execute(&mut **transaction)
        .await
        .map_err(|_| KeyLeaseError::Storage)?;
    Ok(event)
}

async fn insert_outbox<T: serde::Serialize>(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    topic: &str,
    aggregate_id: &str,
    payload: &T,
) -> Result<()> {
    sqlx::query("INSERT INTO event_outbox(topic,aggregate_id,payload_json) VALUES($1,$2,$3)")
        .bind(topic)
        .bind(aggregate_id)
        .bind(serde_json::to_value(payload).map_err(|_| KeyLeaseError::Storage)?)
        .execute(&mut **transaction)
        .await
        .map_err(|_| KeyLeaseError::Storage)?;
    Ok(())
}

fn validate_text(value: &str, maximum: usize) -> Result<()> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "text value is empty, too long or contains control characters".into(),
        });
    }
    Ok(())
}

fn digest(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
