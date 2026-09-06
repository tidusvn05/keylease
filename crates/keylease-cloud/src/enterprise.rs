use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use keylease_core::{
    AccessReviewId, DeviceChallengeId, DeviceId, HumanId, KeyLeaseError, MembershipId,
    OperatorSessionId, OrganizationId, PolicyReleaseId, ProjectId, Result, SecurityAlertId,
};
use leasegate_control::{
    AccessReview, AccessReviewDecision, AccessReviewEntry, AccessReviewState,
    CONTROL_CONTRACT_VERSION, ComplianceEvidence, DeviceChallenge, KeyProvider, Membership,
    MembershipRole, OidcProvider, OperatorDevice, OperatorSessionClaims, PolicyRelease,
    PolicyReleaseState, RetentionPolicy, SecurityAlert, SecurityAlertSeverity, SiemDestination,
    WorkloadIdentityBinding,
};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use subtle::ConstantTimeEq;

use crate::CloudRepository;

#[derive(Clone, PartialEq, Eq)]
pub struct ScimTokenSecret {
    pub token_id: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for ScimTokenSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScimTokenSecret")
            .field("token_id", &self.token_id)
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditExportBatch {
    pub destination_id: keylease_core::SiemDestinationId,
    pub after: u64,
    pub cursor: u64,
    pub events: Vec<keylease_core::AuditEvent>,
}

impl CloudRepository {
    pub async fn upsert_oidc_provider(&self, provider: &OidcProvider) -> Result<()> {
        provider.validate()?;
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, &provider.organization_id).await?;
        sqlx::query("INSERT INTO oidc_providers(organization_id,issuer,audience,jwks_uri,allowed_email_domains_json,group_role_mapping_json,enabled,provider_json,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(organization_id) DO UPDATE SET issuer=EXCLUDED.issuer,audience=EXCLUDED.audience,jwks_uri=EXCLUDED.jwks_uri,allowed_email_domains_json=EXCLUDED.allowed_email_domains_json,group_role_mapping_json=EXCLUDED.group_role_mapping_json,enabled=EXCLUDED.enabled,provider_json=EXCLUDED.provider_json,updated_at=EXCLUDED.updated_at")
            .bind(&provider.organization_id.0)
            .bind(&provider.issuer)
            .bind(&provider.audience)
            .bind(&provider.jwks_uri)
            .bind(json(&provider.allowed_email_domains)?)
            .bind(json(&provider.group_role_mapping)?)
            .bind(provider.enabled)
            .bind(json(provider)?)
            .bind(provider.created_at)
            .bind(provider.updated_at)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)
    }

    pub async fn oidc_provider(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Option<OidcProvider>> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        let value: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT provider_json FROM oidc_providers WHERE organization_id=$1")
                .bind(&organization_id.0)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        value.map(from_json).transpose()
    }

    pub async fn human_oidc_identity(
        &self,
        organization_id: &OrganizationId,
        human_id: &HumanId,
    ) -> Result<(String, String)> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        let row = sqlx::query("SELECT h.oidc_issuer,h.oidc_subject FROM human_principals h JOIN memberships m ON m.human_id=h.human_id WHERE m.organization_id=$1 AND h.human_id=$2 AND m.revoked_at IS NULL")
            .bind(&organization_id.0).bind(&human_id.0)
            .fetch_optional(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?
            .ok_or_else(|| denied("OIDC human membership is not active"))?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        Ok((
            row.try_get("oidc_issuer")
                .map_err(|_| KeyLeaseError::Storage)?,
            row.try_get("oidc_subject")
                .map_err(|_| KeyLeaseError::Storage)?,
        ))
    }

    pub async fn create_scim_token(
        &self,
        organization_id: &OrganizationId,
        display_name: &str,
        ttl: Duration,
    ) -> Result<ScimTokenSecret> {
        validate_text(display_name, 200)?;
        if ttl < Duration::minutes(5) || ttl > Duration::days(365) {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "SCIM token TTL must be 5 minutes..=365 days".into(),
            });
        }
        let mut random = [0_u8; 32];
        rand::rng().fill_bytes(&mut random);
        let token = format!("klscim_{}", URL_SAFE_NO_PAD.encode(random));
        random.fill(0);
        let token_id = format!("scim_token_{}", uuid::Uuid::now_v7().simple());
        let now = Utc::now();
        let expires_at = now + ttl;
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        sqlx::query("INSERT INTO scim_tokens(token_id,organization_id,token_digest_sha256,display_name,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(&token_id).bind(&organization_id.0).bind(digest(token.as_bytes()))
            .bind(display_name).bind(now).bind(expires_at)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        Ok(ScimTokenSecret {
            token_id,
            token,
            expires_at,
        })
    }

    pub async fn authenticate_scim_token(
        &self,
        organization_id: &OrganizationId,
        token: &str,
    ) -> Result<()> {
        if token.len() < 32 || token.len() > 1024 {
            return Err(denied("invalid SCIM bearer credential"));
        }
        let expected = digest(token.as_bytes());
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        let stored: Option<String> = sqlx::query_scalar("SELECT token_digest_sha256 FROM scim_tokens WHERE organization_id=$1 AND token_digest_sha256=$2 AND expires_at>$3 AND revoked_at IS NULL")
            .bind(&organization_id.0).bind(&expected).bind(Utc::now())
            .fetch_optional(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        if stored
            .as_ref()
            .is_none_or(|value| !bool::from(value.as_bytes().ct_eq(expected.as_bytes())))
        {
            return Err(denied("invalid or expired SCIM bearer credential"));
        }
        sqlx::query("UPDATE scim_tokens SET last_used_at=$1 WHERE organization_id=$2 AND token_digest_sha256=$3")
            .bind(Utc::now()).bind(&organization_id.0).bind(&expected)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)
    }

    pub async fn provision_scim_membership(
        &self,
        organization_id: &OrganizationId,
        issuer: &str,
        subject: &str,
        display_name: &str,
        role: MembershipRole,
    ) -> Result<Membership> {
        for value in [issuer, subject, display_name] {
            validate_text(value, 500)?;
        }
        if matches!(
            role,
            MembershipRole::Owner | MembershipRole::Admin | MembershipRole::SecurityAdmin
        ) {
            return Err(denied("SCIM cannot grant administrator roles"));
        }
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        let configured: Option<String> = sqlx::query_scalar(
            "SELECT issuer FROM oidc_providers WHERE organization_id=$1 AND enabled=TRUE",
        )
        .bind(&organization_id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| KeyLeaseError::Storage)?;
        if configured.as_deref() != Some(issuer) {
            return Err(denied(
                "SCIM issuer does not match the enabled OIDC provider",
            ));
        }
        let now = Utc::now();
        let human_id: String = sqlx::query_scalar("INSERT INTO human_principals(human_id,oidc_issuer,oidc_subject,display_name,created_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(oidc_issuer,oidc_subject) DO UPDATE SET display_name=EXCLUDED.display_name RETURNING human_id")
            .bind(HumanId::new().0).bind(issuer).bind(subject).bind(display_name).bind(now)
            .fetch_one(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        let proposed_membership_id = MembershipId::new();
        let row = sqlx::query("INSERT INTO memberships(membership_id,organization_id,human_id,role,created_at,revoked_at) VALUES($1,$2,$3,$4,$5,NULL) ON CONFLICT(organization_id,human_id) DO UPDATE SET role=EXCLUDED.role,revoked_at=NULL RETURNING membership_id,created_at")
            .bind(&proposed_membership_id.0).bind(&organization_id.0).bind(&human_id)
            .bind(enum_text(&role)?).bind(now).fetch_one(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        let membership = Membership {
            id: MembershipId(
                row.try_get("membership_id")
                    .map_err(|_| KeyLeaseError::Storage)?,
            ),
            organization_id: organization_id.clone(),
            human_id: HumanId(human_id),
            role,
            created_at: row
                .try_get("created_at")
                .map_err(|_| KeyLeaseError::Storage)?,
            revoked_at: None,
        };
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        Ok(membership)
    }

    pub async fn organization_memberships(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Vec<Membership>> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        let rows = sqlx::query("SELECT membership_id,human_id,role,created_at,revoked_at FROM memberships WHERE organization_id=$1 ORDER BY created_at")
            .bind(&organization_id.0).fetch_all(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        rows.into_iter()
            .map(|row| {
                Ok(Membership {
                    id: MembershipId(
                        row.try_get("membership_id")
                            .map_err(|_| KeyLeaseError::Storage)?,
                    ),
                    organization_id: organization_id.clone(),
                    human_id: HumanId(
                        row.try_get("human_id")
                            .map_err(|_| KeyLeaseError::Storage)?,
                    ),
                    role: parse_enum(row.try_get("role").map_err(|_| KeyLeaseError::Storage)?)?,
                    created_at: row
                        .try_get("created_at")
                        .map_err(|_| KeyLeaseError::Storage)?,
                    revoked_at: row
                        .try_get("revoked_at")
                        .map_err(|_| KeyLeaseError::Storage)?,
                })
            })
            .collect()
    }

    pub async fn deprovision_scim_membership(
        &self,
        organization_id: &OrganizationId,
        issuer: &str,
        subject: &str,
    ) -> Result<()> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        let changed = sqlx::query("UPDATE memberships SET revoked_at=$1 WHERE organization_id=$2 AND human_id=(SELECT human_id FROM human_principals WHERE oidc_issuer=$3 AND oidc_subject=$4) AND role<>'owner' AND revoked_at IS NULL")
            .bind(Utc::now()).bind(&organization_id.0).bind(issuer).bind(subject)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?.rows_affected();
        if changed != 1 {
            return Err(KeyLeaseError::NotFound {
                resource: "SCIM membership".into(),
            });
        }
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)
    }

    pub async fn create_access_review(&self, review: &AccessReview) -> Result<()> {
        if review.schema_version != CONTROL_CONTRACT_VERSION
            || review.state != AccessReviewState::Open
            || review.due_at <= review.created_at
            || review.due_at > review.created_at + Duration::days(90)
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "invalid access review".into(),
            });
        }
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, &review.organization_id).await?;
        require_role(
            &mut tx,
            &review.organization_id,
            &review.created_by,
            &["owner", "security_admin"],
        )
        .await?;
        sqlx::query("INSERT INTO access_reviews(review_id,organization_id,state,created_by,due_at,created_at) VALUES($1,$2,'open',$3,$4,$5)")
            .bind(&review.review_id.0).bind(&review.organization_id.0).bind(&review.created_by.0)
            .bind(review.due_at).bind(review.created_at).execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        sqlx::query("INSERT INTO access_review_entries(review_id,organization_id,membership_id,human_id,role) SELECT $1,organization_id,membership_id,human_id,role FROM memberships WHERE organization_id=$2 AND revoked_at IS NULL")
            .bind(&review.review_id.0).bind(&review.organization_id.0)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)
    }

    pub async fn decide_access_review_entry(
        &self,
        organization_id: &OrganizationId,
        review_id: &AccessReviewId,
        membership_id: &MembershipId,
        decision: AccessReviewDecision,
        actor: &HumanId,
    ) -> Result<()> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        require_role(
            &mut tx,
            organization_id,
            actor,
            &["owner", "security_admin"],
        )
        .await?;
        let now = Utc::now();
        let changed = sqlx::query("UPDATE access_review_entries e SET decision=$1,decided_by=$2,decided_at=$3 FROM access_reviews r WHERE e.review_id=r.review_id AND e.organization_id=$4 AND e.review_id=$5 AND e.membership_id=$6 AND e.decision IS NULL AND r.state='open' AND r.due_at>$3")
            .bind(enum_text(&decision)?).bind(&actor.0).bind(now).bind(&organization_id.0)
            .bind(&review_id.0).bind(&membership_id.0).execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?.rows_affected();
        if changed != 1 {
            return Err(denied("access review entry is not pending"));
        }
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)
    }

    pub async fn complete_access_review(
        &self,
        organization_id: &OrganizationId,
        review_id: &AccessReviewId,
        actor: &HumanId,
    ) -> Result<()> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        require_role(
            &mut tx,
            organization_id,
            actor,
            &["owner", "security_admin"],
        )
        .await?;
        let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM access_review_entries WHERE organization_id=$1 AND review_id=$2 AND decision IS NULL")
            .bind(&organization_id.0).bind(&review_id.0).fetch_one(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        if pending != 0 {
            return Err(denied("all access review entries must be decided"));
        }
        let now = Utc::now();
        sqlx::query("UPDATE memberships m SET revoked_at=$1 FROM access_review_entries e WHERE e.review_id=$2 AND e.organization_id=$3 AND e.membership_id=m.membership_id AND e.decision='revoke' AND m.role<>'owner'")
            .bind(now).bind(&review_id.0).bind(&organization_id.0).execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        let changed = sqlx::query("UPDATE access_reviews SET state='completed',completed_at=$1 WHERE organization_id=$2 AND review_id=$3 AND state='open'")
            .bind(now).bind(&organization_id.0).bind(&review_id.0).execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?.rows_affected();
        if changed != 1 {
            return Err(denied("access review is not open"));
        }
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)
    }

    pub async fn access_reviews(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Vec<(AccessReview, Vec<AccessReviewEntry>)>> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        let reviews = sqlx::query("SELECT review_id,state,created_by,due_at,created_at,completed_at FROM access_reviews WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 100")
            .bind(&organization_id.0).fetch_all(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        let mut output = Vec::with_capacity(reviews.len());
        for row in reviews {
            let review_id = AccessReviewId(
                row.try_get("review_id")
                    .map_err(|_| KeyLeaseError::Storage)?,
            );
            let entry_rows = sqlx::query("SELECT membership_id,human_id,role,decision,decided_by,decided_at FROM access_review_entries WHERE organization_id=$1 AND review_id=$2 ORDER BY membership_id")
                .bind(&organization_id.0).bind(&review_id.0).fetch_all(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
            let mut entries = Vec::with_capacity(entry_rows.len());
            for entry in entry_rows {
                entries.push(AccessReviewEntry {
                    review_id: review_id.clone(),
                    membership_id: MembershipId(
                        entry
                            .try_get("membership_id")
                            .map_err(|_| KeyLeaseError::Storage)?,
                    ),
                    human_id: HumanId(
                        entry
                            .try_get("human_id")
                            .map_err(|_| KeyLeaseError::Storage)?,
                    ),
                    role: parse_enum(entry.try_get("role").map_err(|_| KeyLeaseError::Storage)?)?,
                    decision: entry
                        .try_get::<Option<String>, _>("decision")
                        .map_err(|_| KeyLeaseError::Storage)?
                        .map(parse_enum)
                        .transpose()?,
                    decided_by: entry
                        .try_get::<Option<String>, _>("decided_by")
                        .map_err(|_| KeyLeaseError::Storage)?
                        .map(HumanId),
                    decided_at: entry
                        .try_get("decided_at")
                        .map_err(|_| KeyLeaseError::Storage)?,
                });
            }
            output.push((
                AccessReview {
                    schema_version: CONTROL_CONTRACT_VERSION,
                    review_id,
                    organization_id: organization_id.clone(),
                    state: parse_enum(row.try_get("state").map_err(|_| KeyLeaseError::Storage)?)?,
                    created_by: HumanId(
                        row.try_get("created_by")
                            .map_err(|_| KeyLeaseError::Storage)?,
                    ),
                    due_at: row.try_get("due_at").map_err(|_| KeyLeaseError::Storage)?,
                    created_at: row
                        .try_get("created_at")
                        .map_err(|_| KeyLeaseError::Storage)?,
                    completed_at: row
                        .try_get("completed_at")
                        .map_err(|_| KeyLeaseError::Storage)?,
                },
                entries,
            ));
        }
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        Ok(output)
    }

    pub async fn register_operator_device(&self, device: &OperatorDevice) -> Result<()> {
        if device.schema_version != CONTROL_CONTRACT_VERSION
            || device.display_name.is_empty()
            || device.display_name.len() > 200
            || device.revoked_at.is_some()
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "invalid operator device".into(),
            });
        }
        decode_verifying_key(&device.verifying_key_base64)?;
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, &device.organization_id).await?;
        require_role(
            &mut tx,
            &device.organization_id,
            &device.human_id,
            &[
                "owner",
                "admin",
                "security_admin",
                "operator",
                "approver",
                "auditor",
            ],
        )
        .await?;
        sqlx::query("INSERT INTO operator_devices(device_id,organization_id,human_id,platform,display_name,verifying_key_base64,push_token_digest_sha256,created_at,last_seen_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(&device.device_id.0).bind(&device.organization_id.0).bind(&device.human_id.0)
            .bind(enum_text(&device.platform)?).bind(&device.display_name).bind(&device.verifying_key_base64)
            .bind(&device.push_token_digest_sha256).bind(device.created_at).bind(device.last_seen_at)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)
    }

    pub async fn create_device_challenge(
        &self,
        organization_id: &OrganizationId,
        device_id: &DeviceId,
    ) -> Result<DeviceChallenge> {
        let now = Utc::now();
        let mut nonce = [0_u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        let challenge = DeviceChallenge {
            schema_version: CONTROL_CONTRACT_VERSION,
            challenge_id: DeviceChallengeId::new(),
            organization_id: organization_id.clone(),
            device_id: device_id.clone(),
            nonce_base64: URL_SAFE_NO_PAD.encode(nonce),
            created_at: now,
            expires_at: now + Duration::minutes(2),
        };
        nonce.fill(0);
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM operator_devices WHERE organization_id=$1 AND device_id=$2 AND revoked_at IS NULL)")
            .bind(&organization_id.0).bind(&device_id.0).fetch_one(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        if !active {
            return Err(denied("operator device is not active"));
        }
        sqlx::query("INSERT INTO device_challenges(challenge_id,organization_id,device_id,challenge_json,expires_at) VALUES($1,$2,$3,$4,$5)")
            .bind(&challenge.challenge_id.0).bind(&organization_id.0).bind(&device_id.0)
            .bind(json(&challenge)?).bind(challenge.expires_at).execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        Ok(challenge)
    }

    pub async fn verify_device_challenge(
        &self,
        organization_id: &OrganizationId,
        challenge_id: &DeviceChallengeId,
        signature_base64: &str,
    ) -> Result<OperatorSessionClaims> {
        let now = Utc::now();
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        let row = sqlx::query("SELECT c.challenge_json,d.device_id,d.human_id,d.verifying_key_base64,m.role FROM device_challenges c JOIN operator_devices d ON d.device_id=c.device_id JOIN memberships m ON m.organization_id=d.organization_id AND m.human_id=d.human_id WHERE c.organization_id=$1 AND c.challenge_id=$2 AND c.used_at IS NULL AND c.expires_at>$3 AND d.revoked_at IS NULL AND m.revoked_at IS NULL FOR UPDATE OF c")
            .bind(&organization_id.0).bind(&challenge_id.0).bind(now)
            .fetch_optional(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?
            .ok_or_else(|| denied("device challenge is invalid, used, or expired"))?;
        let challenge: DeviceChallenge = from_json(
            row.try_get("challenge_json")
                .map_err(|_| KeyLeaseError::Storage)?,
        )?;
        let verifying_key = decode_verifying_key(
            row.try_get("verifying_key_base64")
                .map_err(|_| KeyLeaseError::Storage)?,
        )?;
        let signature_bytes: [u8; 64] = URL_SAFE_NO_PAD
            .decode(signature_base64)
            .map_err(|_| KeyLeaseError::InvalidRequest {
                reason: "invalid device signature encoding".into(),
            })?
            .try_into()
            .map_err(|_| KeyLeaseError::InvalidRequest {
                reason: "invalid device signature length".into(),
            })?;
        let canonical = serde_json_canonicalizer::to_vec(&challenge.signing_payload())
            .map_err(|_| KeyLeaseError::Storage)?;
        verifying_key
            .verify(&canonical, &Signature::from_bytes(&signature_bytes))
            .map_err(|_| denied("invalid device proof"))?;
        sqlx::query("UPDATE device_challenges SET used_at=$1 WHERE challenge_id=$2")
            .bind(now)
            .bind(&challenge_id.0)
            .execute(&mut *tx)
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        let device_id = DeviceId(
            row.try_get("device_id")
                .map_err(|_| KeyLeaseError::Storage)?,
        );
        sqlx::query("UPDATE operator_devices SET last_seen_at=$1 WHERE device_id=$2")
            .bind(now)
            .bind(&device_id.0)
            .execute(&mut *tx)
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        let claims = OperatorSessionClaims {
            schema_version: CONTROL_CONTRACT_VERSION,
            session_id: OperatorSessionId::new(),
            organization_id: organization_id.clone(),
            human_id: HumanId(
                row.try_get("human_id")
                    .map_err(|_| KeyLeaseError::Storage)?,
            ),
            device_id,
            role: parse_enum(row.try_get("role").map_err(|_| KeyLeaseError::Storage)?)?,
            issued_at: now,
            expires_at: now + Duration::minutes(5),
        };
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        Ok(claims)
    }

    pub async fn create_policy_release(&self, release: &PolicyRelease) -> Result<()> {
        release.validate()?;
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, &release.organization_id).await?;
        require_role(
            &mut tx,
            &release.organization_id,
            &release.created_by,
            &["owner", "security_admin"],
        )
        .await?;
        sqlx::query("INSERT INTO policy_releases(release_id,organization_id,project_id,source_revision,source_digest_sha256,state,canary_percent,bundle_version,bundle_digest_sha256,release_json,created_by,created_at,updated_at,rollback_of) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)")
            .bind(&release.release_id.0).bind(&release.organization_id.0).bind(&release.project_id.0)
            .bind(&release.source_revision).bind(&release.source_digest_sha256).bind(enum_text(&release.state)?)
            .bind(release.canary_percent as i16).bind(release.bundle.payload.version as i64)
            .bind(&release.bundle.payload_digest_sha256).bind(json(release)?).bind(&release.created_by.0)
            .bind(release.created_at).bind(release.updated_at).bind(release.rollback_of.as_ref().map(|id| id.0.as_str()))
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)
    }

    pub async fn transition_policy_release(
        &self,
        organization_id: &OrganizationId,
        project_id: &ProjectId,
        release_id: &PolicyReleaseId,
        expected: PolicyReleaseState,
        next: PolicyReleaseState,
    ) -> Result<PolicyRelease> {
        if !valid_release_transition(&expected, &next) {
            return Err(denied("invalid policy release transition"));
        }
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        let value: serde_json::Value = sqlx::query_scalar("SELECT release_json FROM policy_releases WHERE organization_id=$1 AND project_id=$2 AND release_id=$3 FOR UPDATE")
            .bind(&organization_id.0).bind(&project_id.0).bind(&release_id.0)
            .fetch_optional(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?
            .ok_or_else(|| KeyLeaseError::NotFound { resource: release_id.0.clone() })?;
        let mut release: PolicyRelease = from_json(value)?;
        if release.state != expected {
            return Err(denied("policy release changed concurrently"));
        }
        release.state = next;
        release.updated_at = Utc::now();
        sqlx::query(
            "UPDATE policy_releases SET state=$1,release_json=$2,updated_at=$3 WHERE release_id=$4",
        )
        .bind(enum_text(&release.state)?)
        .bind(json(&release)?)
        .bind(release.updated_at)
        .bind(&release_id.0)
        .execute(&mut *tx)
        .await
        .map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        Ok(release)
    }

    pub async fn policy_releases(
        &self,
        organization_id: &OrganizationId,
        project_id: &ProjectId,
    ) -> Result<Vec<PolicyRelease>> {
        project_json_list(self, organization_id, project_id, "SELECT release_json FROM policy_releases WHERE organization_id=$1 AND project_id=$2 ORDER BY created_at DESC LIMIT 100").await
    }

    pub async fn upsert_retention_policy(&self, policy: &RetentionPolicy) -> Result<()> {
        policy.validate()?;
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, &policy.organization_id).await?;
        require_role(
            &mut tx,
            &policy.organization_id,
            &policy.updated_by,
            &["owner", "security_admin"],
        )
        .await?;
        sqlx::query("INSERT INTO retention_policies(project_id,organization_id,audit_days,approval_days,credential_metadata_days,policy_json,updated_by,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(project_id) DO UPDATE SET audit_days=EXCLUDED.audit_days,approval_days=EXCLUDED.approval_days,credential_metadata_days=EXCLUDED.credential_metadata_days,policy_json=EXCLUDED.policy_json,updated_by=EXCLUDED.updated_by,updated_at=EXCLUDED.updated_at")
            .bind(&policy.project_id.0).bind(&policy.organization_id.0).bind(policy.audit_days as i32)
            .bind(policy.approval_days as i32).bind(policy.credential_metadata_days as i32)
            .bind(json(policy)?).bind(&policy.updated_by.0).bind(policy.updated_at)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)
    }

    pub async fn sweep_retention(&self, now: DateTime<Utc>) -> Result<u64> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        let audit = sqlx::query("DELETE FROM audit_event_index a USING retention_policies r WHERE a.project_id=r.project_id AND a.timestamp < $1 - make_interval(days => r.audit_days)")
            .bind(now).execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?.rows_affected();
        let approvals = sqlx::query("DELETE FROM approval_requests a USING retention_policies r WHERE a.project_id=r.project_id AND a.created_at < $1 - make_interval(days => r.approval_days) AND a.state<>'pending'")
            .bind(now).execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?.rows_affected();
        let credentials = sqlx::query("DELETE FROM credential_lease_index c USING retention_policies r WHERE c.project_id=r.project_id AND c.observed_at < $1 - make_interval(days => r.credential_metadata_days) AND c.state IN ('revoked','expired','failed')")
            .bind(now).execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?.rows_affected();
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        Ok(audit + approvals + credentials)
    }

    pub async fn compliance_evidence(
        &self,
        organization_id: &OrganizationId,
        project_id: &ProjectId,
        from: DateTime<Utc>,
        until: DateTime<Utc>,
    ) -> Result<ComplianceEvidence> {
        if from >= until
            || until > Utc::now() + Duration::minutes(1)
            || until - from > Duration::days(366)
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "invalid compliance period".into(),
            });
        }
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        let audit_event_count = count(&mut tx, "SELECT count(*) FROM audit_event_index WHERE organization_id=$1 AND project_id=$2 AND timestamp >= $3 AND timestamp < $4", organization_id, project_id, from, until).await?;
        let approval_count = count(&mut tx, "SELECT count(*) FROM approval_requests WHERE organization_id=$1 AND project_id=$2 AND created_at >= $3 AND created_at < $4", organization_id, project_id, from, until).await?;
        let denied_count = count(&mut tx, "SELECT count(*) FROM audit_event_index WHERE organization_id=$1 AND project_id=$2 AND timestamp >= $3 AND timestamp < $4 AND decision='deny'", organization_id, project_id, from, until).await?;
        let active_membership_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM memberships WHERE organization_id=$1 AND revoked_at IS NULL",
        )
        .bind(&organization_id.0)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| KeyLeaseError::Storage)?;
        let head: Option<String> = sqlx::query_scalar("SELECT chain_digest_sha256 FROM audit_integrity_heads WHERE organization_id=$1 AND project_id=$2")
            .bind(&organization_id.0).bind(&project_id.0).fetch_optional(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        Ok(ComplianceEvidence {
            schema_version: CONTROL_CONTRACT_VERSION,
            organization_id: organization_id.clone(),
            project_id: project_id.clone(),
            period_start: from,
            period_end: until,
            generated_at: Utc::now(),
            audit_event_count: audit_event_count as u64,
            approval_count: approval_count as u64,
            denied_count: denied_count as u64,
            active_membership_count: active_membership_count as u64,
            audit_chain_head_sha256: head,
            controls: [
                ("deployment".into(), "self_hosted/local_gateway".into()),
                ("tenant_rls".into(), "enabled".into()),
                (
                    "credential_material_in_control_plane".into(),
                    "prohibited".into(),
                ),
            ]
            .into_iter()
            .collect(),
        })
    }

    pub async fn upsert_siem_destination(&self, destination: &SiemDestination) -> Result<()> {
        if destination.schema_version != CONTROL_CONTRACT_VERSION
            || !destination.endpoint.starts_with("https://")
            || destination.display_name.is_empty()
            || destination.secret_ref.is_empty()
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "invalid SIEM destination".into(),
            });
        }
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, &destination.organization_id).await?;
        sqlx::query("INSERT INTO siem_destinations(destination_id,organization_id,project_id,display_name,format,endpoint,secret_ref,enabled,destination_json,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(destination_id) DO UPDATE SET display_name=EXCLUDED.display_name,format=EXCLUDED.format,endpoint=EXCLUDED.endpoint,secret_ref=EXCLUDED.secret_ref,enabled=EXCLUDED.enabled,destination_json=EXCLUDED.destination_json,updated_at=EXCLUDED.updated_at")
            .bind(&destination.destination_id.0).bind(&destination.organization_id.0).bind(&destination.project_id.0)
            .bind(&destination.display_name).bind(enum_text(&destination.format)?).bind(&destination.endpoint)
            .bind(&destination.secret_ref).bind(destination.enabled).bind(json(destination)?)
            .bind(destination.created_at).bind(destination.updated_at).execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)
    }

    pub async fn siem_destinations(
        &self,
        organization_id: &OrganizationId,
        project_id: &ProjectId,
    ) -> Result<Vec<SiemDestination>> {
        project_json_list(self, organization_id, project_id, "SELECT destination_json FROM siem_destinations WHERE organization_id=$1 AND project_id=$2 ORDER BY created_at").await
    }

    pub async fn all_enabled_siem_destinations(&self) -> Result<Vec<SiemDestination>> {
        let values: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT destination_json FROM siem_destinations WHERE enabled=TRUE ORDER BY destination_id",
        )
        .fetch_all(self.pool())
        .await
        .map_err(|_| KeyLeaseError::Storage)?;
        values.into_iter().map(from_json).collect()
    }

    pub async fn pending_siem_batch(
        &self,
        destination: &SiemDestination,
        limit: u32,
    ) -> Result<AuditExportBatch> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, &destination.organization_id).await?;
        let after: i64 = sqlx::query_scalar("SELECT cursor FROM siem_destinations WHERE organization_id=$1 AND project_id=$2 AND destination_id=$3 AND enabled=TRUE")
            .bind(&destination.organization_id.0).bind(&destination.project_id.0).bind(&destination.destination_id.0)
            .fetch_optional(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?
            .ok_or_else(|| denied("SIEM destination is disabled"))?;
        let rows = sqlx::query("SELECT audit_event_row_id,event_json FROM audit_event_index WHERE organization_id=$1 AND project_id=$2 AND audit_event_row_id>$3 ORDER BY audit_event_row_id LIMIT $4")
            .bind(&destination.organization_id.0).bind(&destination.project_id.0).bind(after)
            .bind(limit.clamp(1, 500) as i64).fetch_all(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        let mut cursor = after;
        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            cursor = row
                .try_get("audit_event_row_id")
                .map_err(|_| KeyLeaseError::Storage)?;
            events.push(from_json(
                row.try_get("event_json")
                    .map_err(|_| KeyLeaseError::Storage)?,
            )?);
        }
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        Ok(AuditExportBatch {
            destination_id: destination.destination_id.clone(),
            after: after as u64,
            cursor: cursor as u64,
            events,
        })
    }

    pub async fn acknowledge_siem_batch(
        &self,
        destination_id: &keylease_core::SiemDestinationId,
        expected_after: u64,
        cursor: u64,
    ) -> Result<()> {
        let changed = sqlx::query("UPDATE siem_destinations SET cursor=$1,last_success_at=$2,last_error_code=NULL WHERE destination_id=$3 AND cursor=$4")
            .bind(cursor as i64).bind(Utc::now()).bind(&destination_id.0).bind(expected_after as i64)
            .execute(self.pool()).await.map_err(|_| KeyLeaseError::Storage)?.rows_affected();
        if changed != 1 {
            return Err(KeyLeaseError::IdempotencyConflict);
        }
        Ok(())
    }

    pub async fn acquire_worker_lease(
        &self,
        lease_name: &str,
        holder_id: &str,
        now: DateTime<Utc>,
        ttl: Duration,
    ) -> Result<bool> {
        validate_text(lease_name, 128)?;
        validate_text(holder_id, 256)?;
        if ttl < Duration::seconds(5) || ttl > Duration::minutes(5) {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "invalid worker lease TTL".into(),
            });
        }
        Ok(sqlx::query_scalar::<_, bool>("INSERT INTO worker_leases(lease_name,holder_id,lease_until,updated_at) VALUES($1,$2,$3,$4) ON CONFLICT(lease_name) DO UPDATE SET holder_id=EXCLUDED.holder_id,lease_until=EXCLUDED.lease_until,updated_at=EXCLUDED.updated_at WHERE worker_leases.lease_until<=$4 OR worker_leases.holder_id=$2 RETURNING TRUE")
            .bind(lease_name).bind(holder_id).bind(now + ttl).bind(now)
            .fetch_optional(self.pool()).await.map_err(|_| KeyLeaseError::Storage)?.unwrap_or(false))
    }

    pub async fn expire_access_reviews(&self, now: DateTime<Utc>) -> Result<u64> {
        Ok(sqlx::query(
            "UPDATE access_reviews SET state='expired' WHERE state='open' AND due_at<=$1",
        )
        .bind(now)
        .execute(self.pool())
        .await
        .map_err(|_| KeyLeaseError::Storage)?
        .rows_affected())
    }

    pub async fn sweep_security_alerts(&self, now: DateTime<Utc>) -> Result<u64> {
        let rows = sqlx::query("SELECT organization_id,project_id,connection_id,status,reason_codes_json FROM connection_posture WHERE status IN ('expiring','rotation_due','stale','misconfigured','revoked')")
            .fetch_all(self.pool()).await.map_err(|_| KeyLeaseError::Storage)?;
        let mut inserted = 0;
        for row in rows {
            let organization_id = OrganizationId(
                row.try_get("organization_id")
                    .map_err(|_| KeyLeaseError::Storage)?,
            );
            let project_id = ProjectId(
                row.try_get("project_id")
                    .map_err(|_| KeyLeaseError::Storage)?,
            );
            let aggregate_id: String = row
                .try_get("connection_id")
                .map_err(|_| KeyLeaseError::Storage)?;
            let status: String = row.try_get("status").map_err(|_| KeyLeaseError::Storage)?;
            let reason_codes: Vec<String> = serde_json::from_value(
                row.try_get("reason_codes_json")
                    .map_err(|_| KeyLeaseError::Storage)?,
            )
            .map_err(|_| KeyLeaseError::Storage)?;
            let code = format!("connection_posture_{status}");
            let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM security_alerts WHERE organization_id=$1 AND project_id=$2 AND code=$3 AND aggregate_id=$4 AND acknowledged_at IS NULL)")
                .bind(&organization_id.0).bind(&project_id.0).bind(&code).bind(&aggregate_id)
                .fetch_one(self.pool()).await.map_err(|_| KeyLeaseError::Storage)?;
            if exists {
                continue;
            }
            let alert = SecurityAlert {
                schema_version: CONTROL_CONTRACT_VERSION,
                alert_id: SecurityAlertId::new(),
                organization_id: organization_id.clone(),
                project_id: project_id.clone(),
                severity: if matches!(status.as_str(), "misconfigured" | "revoked") {
                    SecurityAlertSeverity::Critical
                } else {
                    SecurityAlertSeverity::Warning
                },
                code,
                aggregate_id,
                details: [
                    ("status".into(), status),
                    ("reason_codes".into(), reason_codes.join(",")),
                ]
                .into_iter()
                .collect(),
                created_at: now,
                acknowledged_by: None,
                acknowledged_at: None,
            };
            sqlx::query("INSERT INTO security_alerts(alert_id,organization_id,project_id,severity,code,aggregate_id,alert_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
                .bind(&alert.alert_id.0).bind(&organization_id.0).bind(&project_id.0).bind(enum_text(&alert.severity)?)
                .bind(&alert.code).bind(&alert.aggregate_id).bind(json(&alert)?).bind(now)
                .execute(self.pool()).await.map_err(|_| KeyLeaseError::Storage)?;
            inserted += 1;
        }
        Ok(inserted)
    }

    pub async fn security_alerts(
        &self,
        organization_id: &OrganizationId,
        project_id: &ProjectId,
        limit: u32,
    ) -> Result<Vec<SecurityAlert>> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        let values: Vec<serde_json::Value> = sqlx::query_scalar("SELECT alert_json FROM security_alerts WHERE organization_id=$1 AND project_id=$2 ORDER BY created_at DESC LIMIT $3")
            .bind(&organization_id.0).bind(&project_id.0).bind(limit.clamp(1, 500) as i64)
            .fetch_all(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        values.into_iter().map(from_json).collect()
    }

    pub async fn acknowledge_security_alert(
        &self,
        organization_id: &OrganizationId,
        project_id: &ProjectId,
        alert_id: &SecurityAlertId,
        actor: &HumanId,
    ) -> Result<()> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        require_role(
            &mut tx,
            organization_id,
            actor,
            &["owner", "security_admin", "operator"],
        )
        .await?;
        let value: serde_json::Value = sqlx::query_scalar("SELECT alert_json FROM security_alerts WHERE organization_id=$1 AND project_id=$2 AND alert_id=$3 FOR UPDATE")
            .bind(&organization_id.0).bind(&project_id.0).bind(&alert_id.0)
            .fetch_optional(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?
            .ok_or_else(|| KeyLeaseError::NotFound { resource: alert_id.0.clone() })?;
        let mut alert: SecurityAlert = from_json(value)?;
        if alert.acknowledged_at.is_some() {
            return Err(denied("security alert already acknowledged"));
        }
        let now = Utc::now();
        alert.acknowledged_by = Some(actor.clone());
        alert.acknowledged_at = Some(now);
        sqlx::query("UPDATE security_alerts SET acknowledged_by=$1,acknowledged_at=$2,alert_json=$3 WHERE alert_id=$4 AND acknowledged_at IS NULL")
            .bind(&actor.0).bind(now).bind(json(&alert)?).bind(&alert_id.0)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)
    }

    pub async fn upsert_workload_identity(&self, binding: &WorkloadIdentityBinding) -> Result<()> {
        if binding.schema_version != CONTROL_CONTRACT_VERSION
            || !binding.issuer.starts_with("https://")
            || binding.subject.is_empty()
            || binding.audience.is_empty()
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "invalid workload identity binding".into(),
            });
        }
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, &binding.organization_id).await?;
        sqlx::query("INSERT INTO workload_identities(workload_identity_id,organization_id,project_id,agent_id,issuer,subject,audience,certificate_sha256,enabled,binding_json,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(workload_identity_id) DO UPDATE SET issuer=EXCLUDED.issuer,subject=EXCLUDED.subject,audience=EXCLUDED.audience,certificate_sha256=EXCLUDED.certificate_sha256,enabled=EXCLUDED.enabled,binding_json=EXCLUDED.binding_json,updated_at=EXCLUDED.updated_at")
            .bind(&binding.workload_identity_id.0).bind(&binding.organization_id.0).bind(&binding.project_id.0)
            .bind(&binding.agent_id.0).bind(&binding.issuer).bind(&binding.subject).bind(&binding.audience)
            .bind(&binding.certificate_sha256).bind(binding.enabled).bind(json(binding)?)
            .bind(binding.created_at).bind(binding.updated_at).execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)
    }

    pub async fn workload_identities(
        &self,
        organization_id: &OrganizationId,
        project_id: &ProjectId,
    ) -> Result<Vec<WorkloadIdentityBinding>> {
        project_json_list(self, organization_id, project_id, "SELECT binding_json FROM workload_identities WHERE organization_id=$1 AND project_id=$2 ORDER BY created_at").await
    }

    pub async fn upsert_key_provider(&self, provider: &KeyProvider) -> Result<()> {
        if provider.schema_version != CONTROL_CONTRACT_VERSION
            || provider.key_reference.is_empty()
            || provider.public_key_fingerprint_sha256.len() != 64
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "invalid BYOK provider metadata".into(),
            });
        }
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, &provider.organization_id).await?;
        sqlx::query("INSERT INTO key_providers(key_provider_id,organization_id,kind,key_reference,public_key_fingerprint_sha256,enabled,provider_json,created_at,last_verified_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(key_provider_id) DO UPDATE SET key_reference=EXCLUDED.key_reference,public_key_fingerprint_sha256=EXCLUDED.public_key_fingerprint_sha256,enabled=EXCLUDED.enabled,provider_json=EXCLUDED.provider_json,last_verified_at=EXCLUDED.last_verified_at")
            .bind(&provider.key_provider_id.0).bind(&provider.organization_id.0).bind(enum_text(&provider.kind)?)
            .bind(&provider.key_reference).bind(&provider.public_key_fingerprint_sha256).bind(provider.enabled)
            .bind(json(provider)?).bind(provider.created_at).bind(provider.last_verified_at)
            .execute(&mut *tx).await.map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)
    }

    pub async fn key_providers(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Vec<KeyProvider>> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        set_tenant(&mut tx, organization_id).await?;
        let values: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT provider_json FROM key_providers WHERE organization_id=$1 ORDER BY created_at",
        )
        .bind(&organization_id.0)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| KeyLeaseError::Storage)?;
        tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
        values.into_iter().map(from_json).collect()
    }
}

async fn project_json_list<T: serde::de::DeserializeOwned>(
    repository: &CloudRepository,
    organization_id: &OrganizationId,
    project_id: &ProjectId,
    sql: &'static str,
) -> Result<Vec<T>> {
    let mut tx = repository
        .pool()
        .begin()
        .await
        .map_err(|_| KeyLeaseError::Storage)?;
    set_tenant(&mut tx, organization_id).await?;
    let values: Vec<serde_json::Value> = sqlx::query_scalar(sql)
        .bind(&organization_id.0)
        .bind(&project_id.0)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| KeyLeaseError::Storage)?;
    tx.commit().await.map_err(|_| KeyLeaseError::Storage)?;
    values.into_iter().map(from_json).collect()
}

async fn count(
    tx: &mut Transaction<'_, Postgres>,
    sql: &'static str,
    organization_id: &OrganizationId,
    project_id: &ProjectId,
    from: DateTime<Utc>,
    until: DateTime<Utc>,
) -> Result<i64> {
    sqlx::query_scalar(sql)
        .bind(&organization_id.0)
        .bind(&project_id.0)
        .bind(from)
        .bind(until)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| KeyLeaseError::Storage)
}

async fn set_tenant(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: &OrganizationId,
) -> Result<()> {
    sqlx::query("SELECT set_config('leasegate.organization_id',$1,true)")
        .bind(&organization_id.0)
        .execute(&mut **tx)
        .await
        .map_err(|_| KeyLeaseError::Storage)?;
    Ok(())
}

async fn require_role(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: &OrganizationId,
    human_id: &HumanId,
    roles: &[&str],
) -> Result<()> {
    let allowed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM memberships WHERE organization_id=$1 AND human_id=$2 AND role=ANY($3) AND revoked_at IS NULL)")
        .bind(&organization_id.0).bind(&human_id.0).bind(roles)
        .fetch_one(&mut **tx).await.map_err(|_| KeyLeaseError::Storage)?;
    if !allowed {
        return Err(denied("enterprise role does not permit this operation"));
    }
    Ok(())
}

fn decode_verifying_key(encoded: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid device verifying key encoding".into(),
        })?
        .try_into()
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid device verifying key length".into(),
        })?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| KeyLeaseError::InvalidRequest {
        reason: "invalid Ed25519 device key".into(),
    })
}

fn valid_release_transition(from: &PolicyReleaseState, to: &PolicyReleaseState) -> bool {
    matches!(
        (from, to),
        (
            PolicyReleaseState::Staged,
            PolicyReleaseState::Canary | PolicyReleaseState::Active | PolicyReleaseState::Failed
        ) | (
            PolicyReleaseState::Canary,
            PolicyReleaseState::Active
                | PolicyReleaseState::RolledBack
                | PolicyReleaseState::Failed
        ) | (PolicyReleaseState::Active, PolicyReleaseState::RolledBack)
            | (PolicyReleaseState::Failed, PolicyReleaseState::RolledBack)
    )
}

fn enum_text<T: Serialize>(value: &T) -> Result<String> {
    json(value)?
        .as_str()
        .map(str::to_owned)
        .ok_or(KeyLeaseError::Storage)
}

fn parse_enum<T: serde::de::DeserializeOwned>(value: String) -> Result<T> {
    from_json(serde_json::Value::String(value))
}

fn json<T: Serialize>(value: &T) -> Result<serde_json::Value> {
    serde_json::to_value(value).map_err(|_| KeyLeaseError::Storage)
}

fn from_json<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> Result<T> {
    serde_json::from_value(value).map_err(|_| KeyLeaseError::Storage)
}

fn validate_text(value: &str, maximum: usize) -> Result<()> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "invalid text value".into(),
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

fn denied(reason: &str) -> KeyLeaseError {
    KeyLeaseError::Denied {
        reason: reason.into(),
    }
}
