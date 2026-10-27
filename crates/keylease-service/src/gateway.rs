//! The self-hosted MCP gateway's authorization server (OAuth 2.1).
//!
//! Web assistants (ChatGPT, claude.ai) reach a remote MCP server over HTTPS
//! and sign in with OAuth: they register themselves (RFC 7591), send the user
//! to `/authorize` with PKCE, and exchange the code for tokens. KeyLease has no
//! user accounts, so the person proves they own the vault with a one-time
//! **connect code** printed on the node (`keylease gateway connect-code`).
//!
//! Each successful authorization creates a new agent identity with the
//! least-privilege baseline, so a web assistant is just another agent: secret
//! use and writes wait for approval, every call is audited under its id, and
//! revoking the connection ends its tokens and its trusts at once.
//!
//! Only SHA-256 hashes of codes and tokens are stored.

use super::*;
use crate::remote::data_encoding_base32;
use keylease_store::OAuthTokenRow;

const CONNECT_CODE_TTL_MINUTES: i64 = 10;
const AUTHORIZATION_CODE_TTL_SECONDS: i64 = 300;
pub const ACCESS_TOKEN_TTL_SECONDS: i64 = 3600;
const REFRESH_TOKEN_TTL_DAYS: i64 = 30;
/// Registrations kept; dynamic registration is unauthenticated by design.
const MAX_OAUTH_CLIENTS: usize = 500;
const MAX_REDIRECT_URIS: usize = 8;

/// A dynamically registered OAuth client (a public client: no secret).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// What an authorization code stands for until it is exchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthorizationCode {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    agent_id: String,
    resource: Option<String>,
}

/// One web assistant connected through the gateway.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayConnection {
    pub agent_id: AgentId,
    pub name: String,
    pub client_name: String,
    pub created_at: DateTime<Utc>,
}

/// A one-time connect code shown to the operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectCode {
    pub code: String,
    pub name: String,
    pub expires_at: DateTime<Utc>,
}

/// The token endpoint's response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokens {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: String,
}

/// OAuth `error` codes (RFC 6749 section 5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthError {
    InvalidRequest(&'static str),
    InvalidClient,
    InvalidGrant,
    UnsupportedGrantType,
    AccessDenied(&'static str),
    Server,
}

impl OAuthError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::AccessDenied(_) => "access_denied",
            Self::Server => "server_error",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::InvalidRequest(reason) | Self::AccessDenied(reason) => reason,
            Self::InvalidClient => "unknown client",
            Self::InvalidGrant => "the code or token is invalid, expired or already used",
            Self::UnsupportedGrantType => "use authorization_code or refresh_token",
            Self::Server => "internal error",
        }
    }
}

impl From<KeyLeaseError> for OAuthError {
    fn from(_: KeyLeaseError) -> Self {
        Self::Server
    }
}

fn digest(value: &str) -> String {
    hex(&Sha256::digest(value.as_bytes()))
}

fn random_token(prefix: &str) -> String {
    let mut raw = [0_u8; 32];
    rand::rng().fill_bytes(&mut raw);
    format!(
        "{prefix}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
    )
}

/// Connection names become part of an agent id.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// `https`, or `http` on a loopback host (local development clients).
pub fn valid_redirect_uri(uri: &str) -> bool {
    let Ok(url) = url::Url::parse(uri) else {
        return false;
    };
    if url.fragment().is_some() || uri.len() > 2048 {
        return false;
    }
    match url.scheme() {
        "https" => url.host_str().is_some(),
        "http" => matches!(
            url.host(),
            Some(url::Host::Domain("localhost"))
                | Some(url::Host::Ipv4(std::net::Ipv4Addr::LOCALHOST))
                | Some(url::Host::Ipv6(std::net::Ipv6Addr::LOCALHOST))
        ),
        _ => false,
    }
}

/// RFC 7636 S256: `BASE64URL(SHA256(verifier)) == challenge`.
pub fn pkce_matches(verifier: &str, challenge: &str) -> bool {
    let valid_verifier = (43..=128).contains(&verifier.len())
        && verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c));
    valid_verifier
        && base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()))
            == challenge
}

impl KeyLeaseService {
    fn gateway_audit(&self, agent_id: &str, action: &str, outcome: &str) -> Result<()> {
        let actor = ActorContext {
            agent_id: AgentId(agent_id.into()),
            workload_id: None,
            human_principal: None,
            on_behalf_of: None,
            client_session_id: "gateway".into(),
            purpose: None,
        };
        self.store.append_audit(&self.vault_audit_event(
            &actor,
            action,
            "kl://gateway",
            "allow",
            outcome,
            vec![],
        ))
    }

    /// Creates a one-time code that authorizes one new web connection named
    /// `name`. Requires the unlocked vault, like a pairing code.
    pub fn create_gateway_connect_code(&self, name: &str) -> Result<ConnectCode> {
        if !valid_name(name) {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "connection name must be 1..=32 ASCII letters, digits, '-' or '_'".into(),
            });
        }
        self.with_vault(|_| {
            let mut raw = [0_u8; 10];
            rand::rng().fill_bytes(&mut raw);
            let code = data_encoding_base32(&raw);
            let expires_at = Utc::now() + Duration::minutes(CONNECT_CODE_TTL_MINUTES);
            self.store.save_gateway_connect_code(
                &digest(&normalize_code(&code)),
                name,
                expires_at,
            )?;
            Ok(ConnectCode {
                code,
                name: name.into(),
                expires_at,
            })
        })
    }

    /// RFC 7591 dynamic client registration.
    pub fn register_oauth_client(
        &self,
        client_name: Option<&str>,
        redirect_uris: &[String],
    ) -> std::result::Result<OAuthClient, OAuthError> {
        if redirect_uris.is_empty()
            || redirect_uris.len() > MAX_REDIRECT_URIS
            || !redirect_uris.iter().all(|uri| valid_redirect_uri(uri))
        {
            return Err(OAuthError::InvalidRequest(
                "redirect_uris must be 1..=8 https URLs (http only for localhost)",
            ));
        }
        let client_name: String = client_name
            .unwrap_or("MCP client")
            .chars()
            .filter(|c| !c.is_control())
            .take(80)
            .collect();
        let client = OAuthClient {
            client_id: format!("mcpclient_{}", uuid::Uuid::now_v7().simple()),
            client_name: if client_name.trim().is_empty() {
                "MCP client".into()
            } else {
                client_name
            },
            redirect_uris: redirect_uris.to_vec(),
            created_at: Utc::now(),
        };
        self.store
            .save_oauth_client(&client.client_id, &client, MAX_OAUTH_CLIENTS)?;
        Ok(client)
    }

    pub fn oauth_client(&self, client_id: &str) -> Result<Option<OAuthClient>> {
        self.store.get_oauth_client(client_id)
    }

    /// The user submitted the consent form with a connect code. Creates the
    /// connection's agent and returns an authorization code.
    pub fn authorize_gateway_connection(
        &self,
        client_id: &str,
        redirect_uri: &str,
        code_challenge: &str,
        resource: Option<&str>,
        connect_code: &str,
    ) -> std::result::Result<String, OAuthError> {
        let client = self
            .store
            .get_oauth_client::<OAuthClient>(client_id)?
            .ok_or(OAuthError::InvalidClient)?;
        if !client.redirect_uris.iter().any(|uri| uri == redirect_uri) {
            return Err(OAuthError::InvalidRequest("redirect_uri is not registered"));
        }
        if code_challenge.len() != 43 {
            return Err(OAuthError::InvalidRequest(
                "a PKCE S256 code_challenge is required",
            ));
        }
        // Checked before the code is used up, so a locked vault does not
        // waste it.
        let vault_id = self.current_vault_id().map_err(|_| {
            OAuthError::AccessDenied("the vault is locked; unlock it and try again")
        })?;
        let name = self
            .store
            .consume_gateway_connect_code(&digest(&normalize_code(connect_code)), Utc::now())?
            .ok_or(OAuthError::AccessDenied(
                "the connect code is wrong or expired; create a new one with \
                 `keylease gateway connect-code`",
            ))?;
        let suffix = &uuid::Uuid::now_v7().simple().to_string()[24..];
        let (agent_id, _token) = self.register_client(&format!("gw_{name}_{suffix}"))?;
        if let Err(error) = self.install_agent_baseline(&agent_id, &vault_id) {
            let _ = self.store.revoke_client(&agent_id);
            return Err(error.into());
        }
        let connection = GatewayConnection {
            agent_id: agent_id.clone(),
            name,
            client_name: client.client_name.clone(),
            created_at: Utc::now(),
        };
        self.store
            .save_gateway_connection(&agent_id.0, &connection)?;
        let code = random_token("klcode_");
        self.store.save_oauth_code(
            &digest(&code),
            &AuthorizationCode {
                client_id: client_id.into(),
                redirect_uri: redirect_uri.into(),
                code_challenge: code_challenge.into(),
                agent_id: agent_id.0.clone(),
                resource: resource.map(str::to_owned),
            },
            Utc::now() + Duration::seconds(AUTHORIZATION_CODE_TTL_SECONDS),
        )?;
        self.gateway_audit(&agent_id.0, "gateway:connect", "authorized")?;
        Ok(code)
    }

    fn issue_tokens(
        &self,
        agent_id: &str,
        client_id: &str,
        family_id: &str,
    ) -> std::result::Result<OAuthTokens, OAuthError> {
        let access = random_token("klat_");
        let refresh = random_token("klrt_");
        let now = Utc::now();
        for (token, kind, expires_at) in [
            (
                &access,
                "access",
                now + Duration::seconds(ACCESS_TOKEN_TTL_SECONDS),
            ),
            (
                &refresh,
                "refresh",
                now + Duration::days(REFRESH_TOKEN_TTL_DAYS),
            ),
        ] {
            self.store.save_oauth_token(&OAuthTokenRow {
                token_hash: digest(token),
                kind: kind.into(),
                family_id: family_id.into(),
                agent_id: agent_id.into(),
                client_id: client_id.into(),
                expires_at,
            })?;
        }
        Ok(OAuthTokens {
            access_token: access,
            token_type: "Bearer".into(),
            expires_in: ACCESS_TOKEN_TTL_SECONDS,
            refresh_token: refresh,
        })
    }

    /// `grant_type=authorization_code` with PKCE.
    pub fn exchange_authorization_code(
        &self,
        code: &str,
        client_id: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> std::result::Result<OAuthTokens, OAuthError> {
        let grant: AuthorizationCode = self
            .store
            .take_oauth_code(&digest(code), Utc::now())?
            .ok_or(OAuthError::InvalidGrant)?;
        if grant.client_id != client_id
            || grant.redirect_uri != redirect_uri
            || !pkce_matches(code_verifier, &grant.code_challenge)
        {
            return Err(OAuthError::InvalidGrant);
        }
        if !self.store.gateway_connection_active(&grant.agent_id)? {
            return Err(OAuthError::InvalidGrant);
        }
        let family = format!("family_{}", uuid::Uuid::now_v7().simple());
        self.issue_tokens(&grant.agent_id, client_id, &family)
    }

    /// `grant_type=refresh_token`, rotating the refresh token.
    pub fn refresh_gateway_tokens(
        &self,
        refresh_token: &str,
        client_id: &str,
    ) -> std::result::Result<OAuthTokens, OAuthError> {
        let row = self
            .store
            .use_refresh_token(&digest(refresh_token), Utc::now())?
            .ok_or(OAuthError::InvalidGrant)?;
        if row.client_id != client_id || !self.store.gateway_connection_active(&row.agent_id)? {
            return Err(OAuthError::InvalidGrant);
        }
        self.issue_tokens(&row.agent_id, client_id, &row.family_id)
    }

    /// Resolves a bearer access token to the agent it acts as.
    pub fn gateway_actor(&self, access_token: &str) -> Result<Option<ActorContext>> {
        let Some(row) = self
            .store
            .get_oauth_token(&digest(access_token), "access", Utc::now())?
        else {
            return Ok(None);
        };
        if !self.store.gateway_connection_active(&row.agent_id)? {
            return Ok(None);
        }
        Ok(Some(ActorContext {
            agent_id: AgentId(row.agent_id),
            workload_id: None,
            human_principal: None,
            on_behalf_of: None,
            client_session_id: row.family_id,
            purpose: None,
        }))
    }

    /// Whether a gateway connection (and its agent client) is still live.
    pub fn gateway_connection_active(&self, agent_id: &str) -> Result<bool> {
        self.store.gateway_connection_active(agent_id)
    }

    pub fn list_gateway_connections(&self) -> Result<Vec<GatewayConnection>> {
        self.store.list_gateway_connections()
    }

    /// Ends a connection: tokens, the agent client, its baseline and trusts.
    pub fn revoke_gateway_connection(&self, agent_id: &str) -> Result<()> {
        if !self
            .list_gateway_connections()?
            .iter()
            .any(|connection| connection.agent_id.0 == agent_id)
        {
            return Err(KeyLeaseError::NotFound {
                resource: format!("gateway connection {agent_id}"),
            });
        }
        // The client first: once it is revoked the connection's tokens are
        // dead (`gateway_connection_active` requires both), whatever happens
        // next.
        self.store.revoke_client(&AgentId(agent_id.into()))?;
        self.store.revoke_gateway_connection(agent_id)?;
        self.gateway_audit(agent_id, "gateway:revoke", "revoked")
    }
}

/// Codes are shown grouped and read aloud; compare them case- and
/// separator-insensitively.
fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> (tempfile::TempDir, KeyLeaseService) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(NativeStore::open(dir.path().join("vault.sqlite")).unwrap());
        let service = KeyLeaseService::new(store).unwrap();
        service.initialize(b"password", Duration::hours(1)).unwrap();
        (dir, service)
    }

    fn challenge(verifier: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
    }

    #[test]
    fn redirect_uris_and_pkce_are_strict() {
        assert!(valid_redirect_uri(
            "https://chatgpt.com/connector_platform_oauth_redirect"
        ));
        assert!(valid_redirect_uri("http://localhost:6274/callback"));
        assert!(valid_redirect_uri("http://127.0.0.1:33418/cb"));
        for bad in [
            "http://evil.example/cb",
            "javascript:alert(1)",
            "https://x.example/cb#frag",
            "custom://cb",
            "not a url",
        ] {
            assert!(!valid_redirect_uri(bad), "{bad}");
        }
        let verifier = "a".repeat(43);
        assert!(pkce_matches(&verifier, &challenge(&verifier)));
        assert!(!pkce_matches(&verifier, &challenge("b")));
        assert!(!pkce_matches("short", &challenge("short")));
    }

    #[test]
    fn a_connect_code_authorizes_one_agent_with_rotating_tokens() {
        let (_dir, service) = service();
        let redirect = "https://client.example/callback".to_owned();
        let client = service
            .register_oauth_client(Some("ChatGPT"), std::slice::from_ref(&redirect))
            .unwrap();
        let verifier = "v".repeat(64);
        let connect = service.create_gateway_connect_code("chatgpt").unwrap();

        assert_eq!(
            service.authorize_gateway_connection(
                &client.client_id,
                &redirect,
                &challenge(&verifier),
                None,
                "WRONGCODE"
            ),
            Err(OAuthError::AccessDenied(
                "the connect code is wrong or expired; create a new one with \
                 `keylease gateway connect-code`"
            ))
        );
        assert_eq!(
            service.authorize_gateway_connection(
                &client.client_id,
                "https://evil.example/cb",
                &challenge(&verifier),
                None,
                &connect.code
            ),
            Err(OAuthError::InvalidRequest("redirect_uri is not registered"))
        );
        let code = service
            .authorize_gateway_connection(
                &client.client_id,
                &redirect,
                &challenge(&verifier),
                Some("https://vault.example/mcp"),
                &connect.code.to_lowercase(),
            )
            .unwrap();
        assert!(
            service
                .authorize_gateway_connection(
                    &client.client_id,
                    &redirect,
                    &challenge(&verifier),
                    None,
                    &connect.code
                )
                .is_err(),
            "a connect code is single-use"
        );
        assert_eq!(
            service
                .exchange_authorization_code(&code, &client.client_id, &redirect, &"x".repeat(64))
                .unwrap_err(),
            OAuthError::InvalidGrant,
            "a wrong verifier burns the code"
        );

        let connect = service.create_gateway_connect_code("chatgpt").unwrap();
        let code = service
            .authorize_gateway_connection(
                &client.client_id,
                &redirect,
                &challenge(&verifier),
                None,
                &connect.code,
            )
            .unwrap();
        let tokens = service
            .exchange_authorization_code(&code, &client.client_id, &redirect, &verifier)
            .unwrap();
        assert!(
            service
                .exchange_authorization_code(&code, &client.client_id, &redirect, &verifier)
                .is_err()
        );
        let actor = service
            .gateway_actor(&tokens.access_token)
            .unwrap()
            .unwrap();
        assert!(actor.agent_id.0.starts_with("agent_gw_chatgpt_"));
        // Baseline: metadata yes, secrets wait for approval.
        assert!(service.search_entries(&actor, "").is_ok());

        let rotated = service
            .refresh_gateway_tokens(&tokens.refresh_token, &client.client_id)
            .unwrap();
        assert!(
            service
                .gateway_actor(&rotated.access_token)
                .unwrap()
                .is_some()
        );
        assert!(
            service
                .refresh_gateway_tokens(&tokens.refresh_token, &client.client_id)
                .is_err(),
            "a reused refresh token is refused"
        );
        assert!(
            service
                .gateway_actor(&rotated.access_token)
                .unwrap()
                .is_none(),
            "and revokes its whole family"
        );

        let connections = service.list_gateway_connections().unwrap();
        assert_eq!(connections.len(), 2);
        let connect = service.create_gateway_connect_code("chatgpt").unwrap();
        let code = service
            .authorize_gateway_connection(
                &client.client_id,
                &redirect,
                &challenge(&verifier),
                None,
                &connect.code,
            )
            .unwrap();
        let tokens = service
            .exchange_authorization_code(&code, &client.client_id, &redirect, &verifier)
            .unwrap();
        let actor = service
            .gateway_actor(&tokens.access_token)
            .unwrap()
            .unwrap();
        service
            .revoke_gateway_connection(&actor.agent_id.0)
            .unwrap();
        assert!(
            service
                .gateway_actor(&tokens.access_token)
                .unwrap()
                .is_none()
        );
        assert!(
            service
                .refresh_gateway_tokens(&tokens.refresh_token, &client.client_id)
                .is_err()
        );
    }
}
