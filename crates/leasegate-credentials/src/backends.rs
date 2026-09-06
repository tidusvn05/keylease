use crate::{
    BackendIssue, CredentialBackend, CredentialKind, CredentialLeaseRequest, CredentialMaterial,
    SenderConstraint, hex, validate_text,
};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use keylease_core::{CredentialLeaseId, KeyLeaseError, Result};
use rand::RngCore;
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::Duration as StdDuration,
};
use tempfile::tempdir;
use tokio::{process::Command, time::timeout};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone)]
pub struct AwsStsWebIdentityConfig {
    pub backend_id: String,
    pub connection_id: keylease_core::ConnectionId,
    pub endpoint: Url,
    pub role_arn: String,
    pub web_identity_token_file: PathBuf,
    pub minimum_ttl_seconds: u64,
    pub maximum_ttl_seconds: u64,
}

pub struct AwsStsWebIdentityBackend {
    config: AwsStsWebIdentityConfig,
    http: Client,
}

impl std::fmt::Debug for AwsStsWebIdentityBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AwsStsWebIdentityBackend")
            .field("backend_id", &self.config.backend_id)
            .field("endpoint", &self.config.endpoint)
            .field("role_arn", &self.config.role_arn)
            .field("web_identity_token", &"[REDACTED FILE]")
            .finish_non_exhaustive()
    }
}

impl AwsStsWebIdentityBackend {
    pub fn new(config: AwsStsWebIdentityConfig) -> Result<Self> {
        validate_backend_id(&config.backend_id)?;
        validate_text(&config.connection_id.0, 200)?;
        validate_https_or_loopback(&config.endpoint)?;
        validate_text(&config.role_arn, 2_048)?;
        if config.minimum_ttl_seconds < 900
            || config.maximum_ttl_seconds < config.minimum_ttl_seconds
            || config.maximum_ttl_seconds > 3_600
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "AWS STS TTL must be within 900..=3600 seconds".into(),
            });
        }
        validate_secret_file(&config.web_identity_token_file, 256 * 1024)?;
        let http = Client::builder()
            .connect_timeout(StdDuration::from_secs(5))
            .timeout(StdDuration::from_secs(15))
            .https_only(config.endpoint.scheme() == "https")
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| KeyLeaseError::InvalidRequest {
                reason: "cannot construct AWS STS client".into(),
            })?;
        Ok(Self { config, http })
    }
}

#[async_trait]
impl CredentialBackend for AwsStsWebIdentityBackend {
    fn id(&self) -> &str {
        &self.config.backend_id
    }

    fn kind(&self) -> CredentialKind {
        CredentialKind::AwsSts
    }

    fn connection_id(&self) -> &keylease_core::ConnectionId {
        &self.config.connection_id
    }

    async fn issue(
        &self,
        lease_id: &CredentialLeaseId,
        request: &CredentialLeaseRequest,
        effective_ttl_seconds: u64,
        now: DateTime<Utc>,
    ) -> Result<BackendIssue> {
        if request.target != self.config.role_arn
            || effective_ttl_seconds < self.config.minimum_ttl_seconds
            || effective_ttl_seconds > self.config.maximum_ttl_seconds
        {
            return Err(KeyLeaseError::Denied {
                reason: "AWS role or TTL is outside the fixed local backend configuration".into(),
            });
        }
        let token = read_secret_file(&self.config.web_identity_token_file, 256 * 1024)?;
        let session_name = aws_session_name(lease_id);
        let ttl = effective_ttl_seconds.to_string();
        let form = [
            ("Action", "AssumeRoleWithWebIdentity"),
            ("Version", "2011-06-15"),
            ("RoleArn", self.config.role_arn.as_str()),
            ("RoleSessionName", session_name.as_str()),
            ("WebIdentityToken", token.as_str()),
            ("DurationSeconds", ttl.as_str()),
        ];
        let response = self
            .http
            .post(self.config.endpoint.clone())
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(form_body(form.iter().copied()))
            .send()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        if !response.status().is_success() {
            return Err(KeyLeaseError::ConnectorUnavailable {
                retryable: response.status().is_server_error(),
            });
        }
        let body = response
            .bytes()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        if body.len() > 256 * 1024 {
            return Err(KeyLeaseError::Denied {
                reason: "AWS STS response exceeded the local response ceiling".into(),
            });
        }
        let parsed: AssumeRoleWithWebIdentityResponse =
            quick_xml::de::from_reader(body.as_ref())
                .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: false })?;
        let credentials = parsed.result.credentials;
        if credentials.expiration <= now
            || credentials.expiration
                > now + chrono::Duration::seconds(effective_ttl_seconds as i64 + 5)
        {
            return Err(KeyLeaseError::Denied {
                reason: "AWS STS returned an expiry outside the requested lease".into(),
            });
        }
        Ok(BackendIssue {
            credential: CredentialMaterial::Aws {
                access_key_id: credentials.access_key_id,
                secret_access_key: credentials.secret_access_key,
                session_token: credentials.session_token,
            },
            revocation_handle: None,
            expires_at: credentials.expiration,
            sender_constraint: SenderConstraint::None,
            renewable: false,
        })
    }

    async fn revoke(&self, _revocation_handle: Option<&str>) -> Result<()> {
        // STS sessions cannot be individually deleted. The fixed IAM role and
        // short upstream expiration are the revocation boundary.
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResponse {
    #[serde(rename = "AssumeRoleWithWebIdentityResult")]
    result: AssumeRoleWithWebIdentityResult,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResult {
    credentials: AwsCredentials,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AwsCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct OAuthTokenExchangeConfig {
    pub backend_id: String,
    pub connection_id: keylease_core::ConnectionId,
    pub token_endpoint: Url,
    pub subject_token_file: PathBuf,
    pub subject_token_type: String,
    pub client_id: String,
    pub client_secret_file: Option<PathBuf>,
    pub allowed_audiences: BTreeSet<String>,
    pub allowed_scopes: BTreeSet<String>,
    pub maximum_ttl_seconds: u64,
}

pub struct OAuthTokenExchangeBackend {
    config: OAuthTokenExchangeConfig,
    http: Client,
    dpop_replay: tokio::sync::Mutex<BTreeMap<String, i64>>,
}

impl std::fmt::Debug for OAuthTokenExchangeBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthTokenExchangeBackend")
            .field("backend_id", &self.config.backend_id)
            .field("token_endpoint", &self.config.token_endpoint)
            .field("subject_token", &"[REDACTED FILE]")
            .field("client_id", &self.config.client_id)
            .field("client_secret", &"[REDACTED FILE]")
            .finish_non_exhaustive()
    }
}

impl OAuthTokenExchangeBackend {
    pub fn new(config: OAuthTokenExchangeConfig) -> Result<Self> {
        validate_backend_id(&config.backend_id)?;
        validate_text(&config.connection_id.0, 200)?;
        validate_https_or_loopback(&config.token_endpoint)?;
        validate_secret_file(&config.subject_token_file, 256 * 1024)?;
        if let Some(path) = &config.client_secret_file {
            validate_secret_file(path, 64 * 1024)?;
        }
        validate_text(&config.subject_token_type, 512)?;
        validate_text(&config.client_id, 512)?;
        if config.maximum_ttl_seconds == 0 || config.maximum_ttl_seconds > 3_600 {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "OAuth exchange TTL is outside the local ceiling".into(),
            });
        }
        for value in config
            .allowed_audiences
            .iter()
            .chain(config.allowed_scopes.iter())
        {
            validate_text(value, 1_024)?;
        }
        let http = Client::builder()
            .connect_timeout(StdDuration::from_secs(5))
            .timeout(StdDuration::from_secs(15))
            .https_only(config.token_endpoint.scheme() == "https")
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| KeyLeaseError::InvalidRequest {
                reason: "cannot construct OAuth token client".into(),
            })?;
        Ok(Self {
            config,
            http,
            dpop_replay: tokio::sync::Mutex::new(BTreeMap::new()),
        })
    }
}

#[async_trait]
impl CredentialBackend for OAuthTokenExchangeBackend {
    fn id(&self) -> &str {
        &self.config.backend_id
    }

    fn kind(&self) -> CredentialKind {
        CredentialKind::OAuthTokenExchange
    }

    fn connection_id(&self) -> &keylease_core::ConnectionId {
        &self.config.connection_id
    }

    async fn issue(
        &self,
        _lease_id: &CredentialLeaseId,
        request: &CredentialLeaseRequest,
        effective_ttl_seconds: u64,
        now: DateTime<Utc>,
    ) -> Result<BackendIssue> {
        if effective_ttl_seconds > self.config.maximum_ttl_seconds {
            return Err(KeyLeaseError::Denied {
                reason: "OAuth exchange TTL exceeds the backend ceiling".into(),
            });
        }
        let audience =
            request
                .claims
                .get("audience")
                .ok_or_else(|| KeyLeaseError::InvalidRequest {
                    reason: "OAuth token exchange requires an audience claim".into(),
                })?;
        if request.target != *audience || !self.config.allowed_audiences.contains(audience) {
            return Err(KeyLeaseError::Denied {
                reason: "OAuth audience is not fixed by the local backend allowlist".into(),
            });
        }
        let scopes = request
            .claims
            .get("scope")
            .map(|value| value.split_ascii_whitespace().collect::<Vec<_>>())
            .unwrap_or_default();
        if scopes
            .iter()
            .any(|scope| !self.config.allowed_scopes.contains(*scope))
        {
            return Err(KeyLeaseError::Denied {
                reason: "OAuth scope exceeds the local backend allowlist".into(),
            });
        }
        if request.claims.contains_key("dpop_jkt") || request.claims.contains_key("mtls_thumbprint")
        {
            return Err(KeyLeaseError::Denied {
                reason: "sender binding cannot be asserted with an unverified thumbprint".into(),
            });
        }
        let dpop = request
            .claims
            .get("dpop_proof")
            .map(|proof| verify_dpop_proof(proof, &self.config.token_endpoint, now))
            .transpose()?;
        if let Some(binding) = &dpop {
            let replay_key = format!("{}:{}", binding.jkt, binding.jti);
            let mut cache = self.dpop_replay.lock().await;
            cache.retain(|_, observed_at| *observed_at >= now.timestamp() - 120);
            if cache.len() >= 4096 || cache.insert(replay_key, binding.iat).is_some() {
                return Err(KeyLeaseError::Denied {
                    reason: "DPoP proof replay detected".into(),
                });
            }
        }
        let subject_token = read_secret_file(&self.config.subject_token_file, 256 * 1024)?;
        let mut form = vec![
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange".to_owned(),
            ),
            ("subject_token", subject_token.to_string()),
            ("subject_token_type", self.config.subject_token_type.clone()),
            ("audience", audience.clone()),
            ("client_id", self.config.client_id.clone()),
        ];
        if !scopes.is_empty() {
            form.push(("scope", scopes.join(" ")));
        }
        let client_secret = if let Some(path) = &self.config.client_secret_file {
            Some(read_secret_file(path, 64 * 1024)?)
        } else {
            None
        };
        if let Some(secret) = &client_secret {
            form.push(("client_secret", secret.to_string()));
        }
        let mut outbound = self
            .http
            .post(self.config.token_endpoint.clone())
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(form_body(
                form.iter().map(|(key, value)| (*key, value.as_str())),
            ));
        if let Some(proof) = request.claims.get("dpop_proof") {
            outbound = outbound.header("DPoP", proof);
        }
        let response = outbound
            .send()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        if !response.status().is_success() {
            return Err(KeyLeaseError::ConnectorUnavailable {
                retryable: response.status().is_server_error(),
            });
        }
        let body = response
            .bytes()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        if body.len() > 256 * 1024 {
            return Err(KeyLeaseError::Denied {
                reason: "OAuth response exceeded the local response ceiling".into(),
            });
        }
        let token: TokenExchangeResponse = serde_json::from_slice(&body)
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: false })?;
        let expires_in = token
            .expires_in
            .unwrap_or(effective_ttl_seconds)
            .min(effective_ttl_seconds);
        if expires_in == 0 {
            return Err(KeyLeaseError::Denied {
                reason: "OAuth provider returned an already-expired token".into(),
            });
        }
        if let Some(expected) = &dpop {
            if token
                .cnf
                .as_ref()
                .map(|confirmation| confirmation.jkt.as_str())
                != Some(expected.jkt.as_str())
                || !token.token_type.eq_ignore_ascii_case("dpop")
            {
                return Err(KeyLeaseError::Denied {
                    reason: "OAuth provider did not confirm the verified DPoP key".into(),
                });
            }
        } else if token.cnf.is_some() {
            return Err(KeyLeaseError::Denied {
                reason: "OAuth provider returned an unexpected sender constraint".into(),
            });
        }
        Ok(BackendIssue {
            credential: CredentialMaterial::OAuth {
                access_token: token.access_token,
                token_type: token.token_type,
                issued_token_type: token.issued_token_type,
                scope: token.scope,
            },
            revocation_handle: None,
            expires_at: now + chrono::Duration::seconds(expires_in as i64),
            sender_constraint: dpop
                .map(|binding| SenderConstraint::Dpop { jkt: binding.jkt })
                .unwrap_or(SenderConstraint::None),
            renewable: false,
        })
    }

    async fn revoke(&self, _revocation_handle: Option<&str>) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct TokenExchangeResponse {
    access_token: String,
    token_type: String,
    issued_token_type: Option<String>,
    expires_in: Option<u64>,
    scope: Option<String>,
    cnf: Option<TokenConfirmation>,
}

#[derive(Debug, Deserialize)]
struct TokenConfirmation {
    jkt: String,
}

#[derive(Debug, Deserialize)]
struct DpopHeader {
    typ: String,
    alg: String,
    jwk: DpopJwk,
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct DpopJwk {
    kty: String,
    crv: String,
    x: String,
}

#[derive(Debug, Deserialize)]
struct DpopClaims {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
}

struct VerifiedDpop {
    jkt: String,
    jti: String,
    iat: i64,
}

fn verify_dpop_proof(proof: &str, endpoint: &Url, now: DateTime<Utc>) -> Result<VerifiedDpop> {
    if proof.len() > 16 * 1024 {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "DPoP proof is too large".into(),
        });
    }
    let parts = proof.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "invalid DPoP compact JWS".into(),
        });
    }
    let header: DpopHeader =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).map_err(|_| {
            KeyLeaseError::InvalidRequest {
                reason: "invalid DPoP header".into(),
            }
        })?)
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid DPoP header".into(),
        })?;
    let claims: DpopClaims =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| {
            KeyLeaseError::InvalidRequest {
                reason: "invalid DPoP claims".into(),
            }
        })?)
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid DPoP claims".into(),
        })?;
    if header.typ != "dpop+jwt"
        || header.alg != "EdDSA"
        || header.jwk.kty != "OKP"
        || header.jwk.crv != "Ed25519"
        || !claims.htm.eq_ignore_ascii_case("POST")
        || claims.htu != endpoint.as_str()
        || (claims.iat - now.timestamp()).abs() > 60
        || claims.jti.is_empty()
        || claims.jti.len() > 256
    {
        return Err(KeyLeaseError::Denied {
            reason: "DPoP proof binding is invalid".into(),
        });
    }
    let public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&header.jwk.x)
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid DPoP public key".into(),
        })?
        .try_into()
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid DPoP public key length".into(),
        })?;
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid DPoP signature".into(),
        })?
        .try_into()
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid DPoP signature length".into(),
        })?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    VerifyingKey::from_bytes(&public)
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid DPoP public key".into(),
        })?
        .verify(signing_input.as_bytes(), &Signature::from_bytes(&signature))
        .map_err(|_| KeyLeaseError::Denied {
            reason: "DPoP signature verification failed".into(),
        })?;
    let canonical =
        serde_json_canonicalizer::to_vec(&header.jwk).map_err(|_| KeyLeaseError::Storage)?;
    Ok(VerifiedDpop {
        jkt: URL_SAFE_NO_PAD.encode(Sha256::digest(canonical)),
        jti: claims.jti,
        iat: claims.iat,
    })
}

#[derive(Debug, Clone)]
pub struct SshCertificateConfig {
    pub backend_id: String,
    pub connection_id: keylease_core::ConnectionId,
    pub ca_private_key_file: PathBuf,
    pub revoked_keys_file: PathBuf,
    pub allowed_principals: BTreeSet<String>,
    pub maximum_ttl_seconds: u64,
}

pub struct SshCertificateBackend {
    config: SshCertificateConfig,
    mutation_lock: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for SshCertificateBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SshCertificateBackend")
            .field("backend_id", &self.config.backend_id)
            .field("ca_private_key", &"[REDACTED FILE]")
            .field("revoked_keys_file", &self.config.revoked_keys_file)
            .field("allowed_principals", &self.config.allowed_principals)
            .finish_non_exhaustive()
    }
}

impl SshCertificateBackend {
    pub fn new(config: SshCertificateConfig) -> Result<Self> {
        validate_backend_id(&config.backend_id)?;
        validate_text(&config.connection_id.0, 200)?;
        validate_secret_file(&config.ca_private_key_file, 64 * 1024)?;
        if config.allowed_principals.is_empty()
            || config.maximum_ttl_seconds == 0
            || config.maximum_ttl_seconds > 3_600
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "SSH backend needs principals and a bounded TTL".into(),
            });
        }
        for principal in &config.allowed_principals {
            validate_identifier(principal, 128)?;
        }
        Ok(Self {
            config,
            mutation_lock: tokio::sync::Mutex::new(()),
        })
    }
}

#[async_trait]
impl CredentialBackend for SshCertificateBackend {
    fn id(&self) -> &str {
        &self.config.backend_id
    }

    fn kind(&self) -> CredentialKind {
        CredentialKind::SshCertificate
    }

    fn connection_id(&self) -> &keylease_core::ConnectionId {
        &self.config.connection_id
    }

    async fn issue(
        &self,
        lease_id: &CredentialLeaseId,
        request: &CredentialLeaseRequest,
        effective_ttl_seconds: u64,
        now: DateTime<Utc>,
    ) -> Result<BackendIssue> {
        let principal =
            request
                .claims
                .get("principal")
                .ok_or_else(|| KeyLeaseError::InvalidRequest {
                    reason: "SSH certificate requires a principal claim".into(),
                })?;
        let public_key =
            request
                .claims
                .get("public_key")
                .ok_or_else(|| KeyLeaseError::InvalidRequest {
                    reason: "SSH certificate requires a public_key claim".into(),
                })?;
        if request.target != *principal
            || !self.config.allowed_principals.contains(principal)
            || effective_ttl_seconds > self.config.maximum_ttl_seconds
        {
            return Err(KeyLeaseError::Denied {
                reason: "SSH principal or TTL exceeds the fixed backend configuration".into(),
            });
        }
        validate_openssh_public_key(public_key)?;
        let directory = tempdir().map_err(|_| KeyLeaseError::Storage)?;
        let public_key_path = directory.path().join("subject.pub");
        fs::write(&public_key_path, public_key).map_err(|_| KeyLeaseError::Storage)?;
        let validity = format!("-5s:+{effective_ttl_seconds}s");
        let output = timeout(
            StdDuration::from_secs(15),
            Command::new("ssh-keygen")
                .arg("-q")
                .arg("-s")
                .arg(&self.config.ca_private_key_file)
                .arg("-I")
                .arg(&lease_id.0)
                .arg("-n")
                .arg(principal)
                .arg("-V")
                .arg(validity)
                .arg(&public_key_path)
                .output(),
        )
        .await
        .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?
        .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: false })?;
        if !output.status.success() {
            return Err(KeyLeaseError::ConnectorUnavailable { retryable: false });
        }
        let certificate_path = directory.path().join("subject-cert.pub");
        let certificate = fs::read_to_string(&certificate_path)
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: false })?;
        if certificate.len() > 64 * 1024 {
            return Err(KeyLeaseError::Denied {
                reason: "SSH certificate exceeded the local response ceiling".into(),
            });
        }
        let thumbprint = hex(&Sha256::digest(public_key.as_bytes()));
        Ok(BackendIssue {
            credential: CredentialMaterial::SshCertificate {
                certificate: certificate.clone(),
            },
            revocation_handle: Some(certificate),
            expires_at: now + chrono::Duration::seconds(effective_ttl_seconds as i64),
            sender_constraint: SenderConstraint::SshPublicKeySha256 { thumbprint },
            renewable: false,
        })
    }

    async fn revoke(&self, revocation_handle: Option<&str>) -> Result<()> {
        let Some(certificate) = revocation_handle else {
            return Ok(());
        };
        // Keep KRL mutations serialized. `spawn_blocking` owns the guard so no
        // non-Send lock is held across an async suspension point.
        let ca = self.config.ca_private_key_file.clone();
        let krl = self.config.revoked_keys_file.clone();
        let certificate = certificate.to_owned();
        let _guard = self.mutation_lock.lock().await;
        let directory = tempdir().map_err(|_| KeyLeaseError::Storage)?;
        let certificate_path = directory.path().join("revoked-cert.pub");
        fs::write(&certificate_path, certificate).map_err(|_| KeyLeaseError::Storage)?;
        let mut command = Command::new("ssh-keygen");
        command.arg("-q").arg("-k");
        if krl.exists() {
            command.arg("-u");
        }
        let output = timeout(
            StdDuration::from_secs(15),
            command
                .arg("-f")
                .arg(krl)
                .arg("-s")
                .arg(ca)
                .arg(certificate_path)
                .output(),
        )
        .await
        .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?
        .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: false })?;
        if !output.status.success() {
            return Err(KeyLeaseError::ConnectorUnavailable { retryable: false });
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct PostgresRoleConfig {
    pub backend_id: String,
    pub connection_id: keylease_core::ConnectionId,
    pub database_url_file: PathBuf,
    pub advertised_host: String,
    pub advertised_port: u16,
    pub advertised_database: String,
    pub grant_role: String,
    pub role_prefix: String,
    pub maximum_ttl_seconds: u64,
    pub tls_required: bool,
}

impl std::fmt::Debug for PostgresRoleConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresRoleConfig")
            .field("backend_id", &self.backend_id)
            .field("connection_id", &self.connection_id)
            .field("database_url", &"[REDACTED FILE]")
            .field("advertised_host", &self.advertised_host)
            .field("advertised_port", &self.advertised_port)
            .field("advertised_database", &self.advertised_database)
            .field("grant_role", &self.grant_role)
            .field("role_prefix", &self.role_prefix)
            .field("maximum_ttl_seconds", &self.maximum_ttl_seconds)
            .field("tls_required", &self.tls_required)
            .finish()
    }
}

pub struct PostgresRoleBackend {
    config: PostgresRoleConfig,
    pool: PgPool,
}

impl std::fmt::Debug for PostgresRoleBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresRoleBackend")
            .field("backend_id", &self.config.backend_id)
            .field("database_url", &"[REDACTED]")
            .field("advertised_host", &self.config.advertised_host)
            .field("advertised_database", &self.config.advertised_database)
            .field("grant_role", &self.config.grant_role)
            .finish_non_exhaustive()
    }
}

impl PostgresRoleBackend {
    pub async fn connect(config: PostgresRoleConfig) -> Result<Self> {
        validate_backend_id(&config.backend_id)?;
        validate_text(&config.connection_id.0, 200)?;
        validate_secret_file(&config.database_url_file, 4096)?;
        validate_text(&config.advertised_host, 512)?;
        validate_text(&config.advertised_database, 128)?;
        validate_identifier(&config.grant_role, 63)?;
        validate_identifier(&config.role_prefix, 24)?;
        if config.advertised_port == 0
            || config.maximum_ttl_seconds == 0
            || config.maximum_ttl_seconds > 3_600
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "PostgreSQL backend has an invalid port or TTL".into(),
            });
        }
        let database_url = read_secret_file(&config.database_url_file, 4096)?;
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(database_url.as_str())
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        Ok(Self { config, pool })
    }

    #[cfg(test)]
    pub fn from_pool(config: PostgresRoleConfig, pool: PgPool) -> Result<Self> {
        validate_backend_id(&config.backend_id)?;
        validate_text(&config.connection_id.0, 200)?;
        Ok(Self { config, pool })
    }
}

#[async_trait]
impl CredentialBackend for PostgresRoleBackend {
    fn id(&self) -> &str {
        &self.config.backend_id
    }

    fn kind(&self) -> CredentialKind {
        CredentialKind::PostgresqlRole
    }

    fn connection_id(&self) -> &keylease_core::ConnectionId {
        &self.config.connection_id
    }

    async fn issue(
        &self,
        lease_id: &CredentialLeaseId,
        request: &CredentialLeaseRequest,
        effective_ttl_seconds: u64,
        now: DateTime<Utc>,
    ) -> Result<BackendIssue> {
        if request.target != self.config.advertised_database
            || effective_ttl_seconds > self.config.maximum_ttl_seconds
        {
            return Err(KeyLeaseError::Denied {
                reason: "database target or TTL exceeds the fixed backend configuration".into(),
            });
        }
        let suffix: String = lease_id
            .0
            .chars()
            .filter(|character| character.is_ascii_alphanumeric())
            .rev()
            .take(20)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        let username = format!("{}_{}", self.config.role_prefix, suffix).to_ascii_lowercase();
        validate_identifier(&username, 63)?;
        let password = random_secret("lgdb_");
        let expires_at = now + chrono::Duration::seconds(effective_ttl_seconds as i64);
        let statement = format!(
            "CREATE ROLE {} LOGIN PASSWORD {} VALID UNTIL {}; GRANT {} TO {}",
            quote_identifier(&username),
            quote_literal(&password),
            quote_literal(&expires_at.to_rfc3339_opts(SecondsFormat::Secs, true)),
            quote_identifier(&self.config.grant_role),
            quote_identifier(&username),
        );
        // Values are generated locally or pass the strict identifier validator
        // above; SQL literals are escaped by `quote_literal`.
        sqlx::raw_sql(sqlx::AssertSqlSafe(statement))
            .execute(&self.pool)
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: false })?;
        Ok(BackendIssue {
            credential: CredentialMaterial::Postgresql {
                username: username.clone(),
                password,
                host: self.config.advertised_host.clone(),
                port: self.config.advertised_port,
                database: self.config.advertised_database.clone(),
                tls_required: self.config.tls_required,
            },
            revocation_handle: Some(username),
            expires_at,
            sender_constraint: SenderConstraint::None,
            renewable: false,
        })
    }

    async fn revoke(&self, revocation_handle: Option<&str>) -> Result<()> {
        let Some(username) = revocation_handle else {
            return Ok(());
        };
        validate_identifier(username, 63)?;
        let role_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)")
                .bind(username)
                .fetch_one(&self.pool)
                .await
                .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        if !role_exists {
            return Ok(());
        }
        let disable = format!("ALTER ROLE {} NOLOGIN", quote_identifier(username));
        sqlx::raw_sql(sqlx::AssertSqlSafe(disable))
            .execute(&self.pool)
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        // Termination is best effort because a narrowly-scoped issuer role may
        // intentionally lack pg_signal_backend. NOLOGIN still blocks reuse.
        let _ = sqlx::query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename=$1 AND pid<>pg_backend_pid()",
        )
        .bind(username)
        .fetch_all(&self.pool)
        .await;
        Ok(())
    }
}

fn validate_backend_id(value: &str) -> Result<()> {
    validate_identifier(value, 200)
}

fn validate_identifier(value: &str, maximum: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'@'))
    {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "local backend identifier is invalid".into(),
        });
    }
    Ok(())
}

fn validate_https_or_loopback(url: &Url) -> Result<()> {
    let secure = url.scheme() == "https";
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if !secure && !loopback {
        return Err(KeyLeaseError::Denied {
            reason: "credential provider endpoint must use HTTPS or loopback".into(),
        });
    }
    Ok(())
}

fn validate_secret_file(path: &Path, maximum: u64) -> Result<()> {
    let metadata = fs::metadata(path).map_err(|_| KeyLeaseError::InvalidRequest {
        reason: "credential backend secret file is unavailable".into(),
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(KeyLeaseError::Denied {
                reason: "credential backend secret file must have mode 0600".into(),
            });
        }
    }
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "credential backend secret path is not a bounded regular file".into(),
        });
    }
    Ok(())
}

fn read_secret_file(path: &Path, maximum: u64) -> Result<Zeroizing<String>> {
    validate_secret_file(path, maximum)?;
    let mut value = fs::read_to_string(path).map_err(|_| KeyLeaseError::Storage)?;
    let trimmed = value.trim().to_owned();
    value.zeroize();
    if trimmed.is_empty() {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "credential backend secret file is empty".into(),
        });
    }
    Ok(Zeroizing::new(trimmed))
}

fn aws_session_name(lease_id: &CredentialLeaseId) -> String {
    lease_id
        .0
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        .take(64)
        .collect()
}

fn validate_openssh_public_key(value: &str) -> Result<()> {
    let mut fields = value.split_ascii_whitespace();
    let kind = fields.next().unwrap_or_default();
    let encoded = fields.next().unwrap_or_default();
    if !matches!(kind, "ssh-ed25519" | "ecdsa-sha2-nistp256" | "ssh-rsa")
        || encoded.is_empty()
        || encoded.len() > 16 * 1024
        || fields.next().is_some_and(|comment| comment.len() > 512)
    {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "SSH public key is not a bounded supported OpenSSH key".into(),
        });
    }
    Ok(())
}

fn random_secret(prefix: &str) -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes))
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn form_body<'a>(values: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(values)
        .finish()
}
