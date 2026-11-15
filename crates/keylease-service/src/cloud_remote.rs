//! The HTTPS side of the cloud link: the relay client and the operations an
//! owner runs against keylease-server (console sign-in, console approvals,
//! managed nodes). The service builds and checks every signed payload; this
//! module only carries them. Shared by the `keylease` CLI and the local RPC,
//! so the desktop app reaches the same code without a terminal.

use super::*;
use keylease_core::console::AccountPasskeys;
use keylease_core::managed::{AppliedPolicy, OrgNodeJoin, OrgNodeJoined, OrgPolicyAnswer};
use keylease_core::relay::{HEADER_MEMBER, HEADER_SIGNATURE, HEADER_TIMESTAMP};
use reqwest::Method;

/// Carries relay requests; signed ones are signed by the service.
pub struct CloudRelay<'a> {
    service: &'a KeyLeaseService,
    base: String,
    http: reqwest::Client,
}

fn relay_error(context: &str, status: reqwest::StatusCode, body: &str) -> KeyLeaseError {
    let detail: String = body.chars().take(200).collect();
    match status.as_u16() {
        401 | 403 => KeyLeaseError::Denied {
            reason: format!("{context}: the cloud refused ({status}) {detail}"),
        },
        404 => KeyLeaseError::NotFound {
            resource: format!("{context} ({detail})"),
        },
        _ => KeyLeaseError::ConnectorUnavailable { retryable: true },
    }
}

impl<'a> CloudRelay<'a> {
    pub fn new(service: &'a KeyLeaseService, url: &str) -> Result<Self> {
        Ok(Self {
            service,
            base: url.trim_end_matches('/').to_owned(),
            http: reqwest::Client::builder()
                // Under the desktop app's 30 s RPC response timeout.
                .timeout(StdDuration::from_secs(25))
                .user_agent(concat!("keylease/", env!("CARGO_PKG_VERSION")))
                .build()
                .map_err(|_| KeyLeaseError::Storage)?,
        })
    }

    pub async fn send<T: serde::de::DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        signed: bool,
        bearer: Option<&str>,
    ) -> Result<T> {
        let mut request = self
            .http
            .request(method.clone(), format!("{}{path}", self.base));
        let bytes = body.unwrap_or_default();
        if signed {
            let signature = self
                .service
                .cloud_sign_request(method.as_str(), path, &bytes)?;
            request = request
                .header(HEADER_MEMBER, signature.member_id)
                .header(HEADER_TIMESTAMP, signature.timestamp.to_string())
                .header(HEADER_SIGNATURE, signature.signature_b64);
        }
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        if !bytes.is_empty() {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(bytes);
        }
        let response = request
            .send()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(relay_error(path, status, &text));
        }
        serde_json::from_str(&text).map_err(|_| KeyLeaseError::InvalidRequest {
            reason: format!("{path}: unexpected cloud response"),
        })
    }

    pub async fn post<B: Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        signed: bool,
    ) -> Result<T> {
        let bytes = serde_json::to_vec(body).map_err(|_| KeyLeaseError::Storage)?;
        self.send(Method::POST, path, Some(bytes), signed, None)
            .await
    }
}

/// A one-time link that signs the owner in to the KeyLease Console.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsoleSignInLink {
    pub url: String,
    pub expires_at: DateTime<Utc>,
}

/// The vault after joining an organization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrgJoinOutcome {
    pub org_id: String,
    pub org_name: String,
    pub key_id: String,
    /// The policy version in force, when the organization has one yet.
    pub policy_version: Option<u64>,
}

/// What the desktop app shows on its Server page: the link, console
/// approvals and the organization, in one read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudOverview {
    pub linked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<CloudRole>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sync_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub nodes: usize,
    pub active_shares: usize,
    pub pending_requests: usize,
    pub console_approvals: ConsoleApprovalsOverview,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<OrgOverview>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConsoleApprovalsOverview {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    pub passkeys: Vec<String>,
    pub share_audit: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgOverview {
    pub org_id: String,
    pub org_name: String,
    pub key_id: String,
    pub joined_at: DateTime<Utc>,
    pub policy_version: Option<u64>,
}

impl ConsoleApprovalsOverview {
    pub fn from_config(config: Option<&ConsoleApprovalsConfig>) -> Self {
        match config {
            Some(config) => Self {
                enabled: true,
                origin: Some(config.origin.clone()),
                passkeys: config.passkeys.iter().map(|p| p.name.clone()).collect(),
                share_audit: config.share_audit,
                enabled_at: Some(config.enabled_at),
            },
            None => Self::default(),
        }
    }
}

const NOT_LINKED: &str = "this vault is not linked to a cloud (keylease cloud init / join)";

impl KeyLeaseService {
    /// The confirmed cloud link, or an error naming how to make one.
    pub fn cloud_require_link(&self) -> Result<CloudLink> {
        self.cloud_link()?
            .filter(|link| !link.member_id.is_empty())
            .ok_or_else(|| KeyLeaseError::InvalidRequest {
                reason: NOT_LINKED.into(),
            })
    }

    pub fn cloud_overview(&self) -> Result<CloudOverview> {
        let status = self.cloud_status()?;
        let link = status.link.filter(|link| !link.member_id.is_empty());
        let org = match self.org_membership()? {
            Some(membership) => Some(OrgOverview {
                org_id: membership.org_id,
                org_name: membership.org_name,
                key_id: membership.key_id,
                joined_at: membership.joined_at,
                policy_version: self.org_policy_version()?,
            }),
            None => None,
        };
        Ok(CloudOverview {
            linked: link.is_some(),
            fingerprint: link.as_ref().map(CloudLink::fingerprint),
            url: link.as_ref().map(|l| l.url.clone()),
            role: link.as_ref().map(|l| l.role),
            name: link.as_ref().map(|l| l.name.clone()),
            last_sync_at: link.as_ref().and_then(|l| l.last_sync_at),
            last_error: link.as_ref().and_then(|l| l.last_error.clone()),
            nodes: status.nodes,
            active_shares: status.active_shares,
            pending_requests: status.pending_requests,
            console_approvals: ConsoleApprovalsOverview::from_config(
                self.console_approvals_config()?.as_ref(),
            ),
            org,
        })
    }

    /// Owner: registers a one-time sign-in link (15 minutes) with the server.
    pub async fn cloud_console_sign_in(
        &self,
        console_url: Option<String>,
    ) -> Result<ConsoleSignInLink> {
        let link = self.cloud_require_link()?;
        if link.role != CloudRole::Owner {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "only the owner device signs in to the console".into(),
            });
        }
        let mut bytes = [0_u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut bytes);
        let token = URL_SAFE_NO_PAD.encode(bytes);
        let lookup_hash: String = Sha256::digest(token.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let expires_at = Utc::now() + Duration::minutes(15);
        CloudRelay::new(self, &link.url)?
            .post::<_, Value>(
                "/v1/relay/console-links",
                &serde_json::json!({"lookup_hash": lookup_hash, "expires_at": expires_at}),
                true,
            )
            .await?;
        let base =
            console_url.unwrap_or_else(|| format!("{}/console/", link.url.trim_end_matches('/')));
        Ok(ConsoleSignInLink {
            url: format!("{base}#login={token}"),
            expires_at,
        })
    }

    /// Fetches the account's passkeys from the server and turns console
    /// approvals on with them.
    pub async fn console_approvals_enable_remote(
        &self,
        share_audit: bool,
    ) -> Result<ConsoleApprovalsConfig> {
        let link = self.cloud_require_link()?;
        let passkeys: AccountPasskeys = CloudRelay::new(self, &link.url)?
            .send(Method::GET, "/v1/relay/console/passkeys", None, true, None)
            .await?;
        self.console_approvals_enable(passkeys, share_audit)
    }

    /// Joins an organization with an enrollment code and applies its policy
    /// when it has one.
    pub async fn org_join_remote(&self, code: &str) -> Result<OrgJoinOutcome> {
        let link = self.cloud_require_link()?;
        let joined: OrgNodeJoined = CloudRelay::new(self, &link.url)?
            .post(
                "/v1/relay/org-nodes/join",
                &OrgNodeJoin {
                    code: code.trim().to_owned(),
                },
                true,
            )
            .await?;
        let membership = self.org_join_commit(&joined)?;
        // Best effort: the serve loop applies it within a minute otherwise.
        let policy_version = tokio::time::timeout(
            StdDuration::from_secs(4),
            self.org_policy_refresh(&link.url),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .flatten();
        Ok(OrgJoinOutcome {
            org_id: membership.org_id,
            org_name: membership.org_name,
            key_id: membership.key_id,
            policy_version,
        })
    }

    /// Fetches, checks and applies the organization's policy, then reports the
    /// version in force.
    pub async fn org_policy_refresh(&self, url: &str) -> Result<Option<u64>> {
        let relay = CloudRelay::new(self, url)?;
        let answer: OrgPolicyAnswer = relay
            .send(Method::GET, "/v1/relay/org-policy", None, true, None)
            .await?;
        let Some(signed) = answer.policy else {
            return Ok(None);
        };
        let version = self.org_apply_policy(&signed)?;
        relay
            .send::<Value>(
                Method::PUT,
                "/v1/relay/org-policy/applied",
                Some(
                    serde_json::to_vec(&AppliedPolicy { version })
                        .map_err(|_| KeyLeaseError::Storage)?,
                ),
                true,
                None,
            )
            .await?;
        Ok(Some(version))
    }

    // ---- the local RPC surface (the desktop owner) --------------------------

    /// Only the desktop owner client manages the link. An agent is refused
    /// outright rather than queuing an approval the owner might wave through.
    fn authorize_cloud(&self, actor: &ActorContext, operation: &str) -> Result<()> {
        if self.store.local_owner_role(&actor.agent_id)? != Some(LocalOwnerRole::DesktopOwner) {
            return Err(KeyLeaseError::Denied {
                reason: "only the KeyLease app on the owner's computer manages the cloud link"
                    .into(),
            });
        }
        self.with_vault(|vault| {
            self.authorize_vault(
                vault,
                actor,
                "cloud:manage",
                &format!("kl://{}/cloud", vault.vault_id.0),
                serde_json::json!({"operation": operation}),
            )
        })
    }

    pub fn cloud_overview_authorized(&self, actor: &ActorContext) -> Result<CloudOverview> {
        self.authorize_cloud(actor, "overview")?;
        self.cloud_overview()
    }

    pub async fn cloud_console_sign_in_authorized(
        &self,
        actor: &ActorContext,
    ) -> Result<ConsoleSignInLink> {
        self.authorize_cloud(actor, "console_sign_in")?;
        self.cloud_console_sign_in(None).await
    }

    pub async fn console_approvals_enable_authorized(
        &self,
        actor: &ActorContext,
        share_audit: bool,
    ) -> Result<ConsoleApprovalsOverview> {
        self.authorize_cloud(actor, "console_approvals_enable")?;
        let config = self.console_approvals_enable_remote(share_audit).await?;
        Ok(ConsoleApprovalsOverview::from_config(Some(&config)))
    }

    pub fn console_approvals_disable_authorized(&self, actor: &ActorContext) -> Result<bool> {
        self.authorize_cloud(actor, "console_approvals_disable")?;
        self.console_approvals_disable()
    }

    pub async fn org_join_authorized(
        &self,
        actor: &ActorContext,
        code: &str,
    ) -> Result<OrgJoinOutcome> {
        self.authorize_cloud(actor, "org_join")?;
        self.org_join_remote(code).await
    }

    pub fn org_leave_authorized(&self, actor: &ActorContext) -> Result<bool> {
        self.authorize_cloud(actor, "org_leave")?;
        self.org_leave()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text)
            .unwrap()
            .with_timezone(&Utc)
    }

    /// `test-vectors/rpc/cloud/overview.json` is what the Swift client
    /// decodes in `CloudModelsTests`; this pins the Rust side of it.
    #[test]
    fn overview_wire_matches_the_shared_vector() {
        let overview = CloudOverview {
            linked: true,
            url: Some("https://keys.example.com".into()),
            role: Some(CloudRole::Owner),
            name: Some("owner".into()),
            fingerprint: Some("ab12-cd34".into()),
            last_sync_at: Some(at("2026-11-15T08:30:00.123456Z")),
            last_error: None,
            nodes: 2,
            active_shares: 3,
            pending_requests: 1,
            console_approvals: ConsoleApprovalsOverview {
                enabled: true,
                origin: Some("https://keys.example.com".into()),
                passkeys: vec!["MacBook Touch ID".into()],
                share_audit: true,
                enabled_at: Some(at("2026-11-15T08:00:00Z")),
            },
            org: Some(OrgOverview {
                org_id: "org_1".into(),
                org_name: "Acme".into(),
                key_id: "k1".into(),
                joined_at: at("2026-11-15T07:00:00Z"),
                policy_version: None,
            }),
        };
        let vector: Value = serde_json::from_str(include_str!(
            "../../../test-vectors/rpc/cloud/overview.json"
        ))
        .unwrap();
        assert_eq!(serde_json::to_value(&overview).unwrap(), vector);
    }
}
