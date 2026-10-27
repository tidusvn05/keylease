//! The self-hosted MCP gateway: KeyLease's vault tools for web assistants
//! (ChatGPT, claude.ai) over HTTPS, with OAuth 2.1 sign-in.
//!
//! `keylease serve --gateway-url https://vault.example.com --gateway-listen
//! 127.0.0.1:8787` serves, behind a TLS reverse proxy:
//!
//! | Path | |
//! |---|---|
//! | `/mcp` | Streamable HTTP MCP, bearer token required |
//! | `/.well-known/oauth-protected-resource` | RFC 9728 metadata |
//! | `/.well-known/oauth-authorization-server` | RFC 8414 metadata |
//! | `/register` | RFC 7591 dynamic client registration |
//! | `/authorize` | consent page: the user enters a one-time connect code |
//! | `/token` | authorization code (PKCE S256) and refresh grants |
//! | `/v1/…` | the paired-approver API (`approver.rs`) |
//!
//! The MCP tools are the same as `keylease mcp` (`mcp.rs`); each call runs in
//! this process as the agent the token belongs to.

use super::*;
use crate::backend::Backend;
use crate::mcp::{ToolOptions, VaultMcp};
use axum::{
    Form, Json, Router,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use keylease_service::OAuthError;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use std::time::Duration as StdDuration;

#[derive(Clone)]
pub(crate) struct GatewayConfig {
    /// Public base URL, without a trailing slash: the OAuth issuer.
    pub(crate) base_url: String,
    pub(crate) listen: std::net::SocketAddr,
    pub(crate) tools: ToolOptions,
    pub(crate) approval_wait: StdDuration,
}

impl GatewayConfig {
    pub(crate) fn new(
        base_url: &str,
        listen: std::net::SocketAddr,
        tools: ToolOptions,
        approval_wait: StdDuration,
    ) -> Result<Self> {
        let parsed = reqwest::Url::parse(base_url).map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "--gateway-url must be a URL like https://vault.example.com".into(),
        })?;
        let loopback = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback) {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "--gateway-url must use https (http only for localhost)".into(),
            });
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "--gateway-url must not have a query or fragment".into(),
            });
        }
        if !listen.ip().is_loopback() {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "--gateway-listen must be a loopback address; publish it through a TLS \
                         reverse proxy such as Caddy"
                    .into(),
            });
        }
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            listen,
            tools,
            approval_wait,
        })
    }

    fn host(&self) -> String {
        reqwest::Url::parse(&self.base_url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .unwrap_or_default()
    }

    fn resource(&self) -> String {
        format!("{}/mcp", self.base_url)
    }

    fn resource_metadata_url(&self) -> String {
        format!("{}/.well-known/oauth-protected-resource", self.base_url)
    }
}

#[derive(Clone)]
struct Gateway {
    service: Arc<KeyLeaseService>,
    config: GatewayConfig,
}

pub(crate) async fn serve_gateway(
    service: Arc<KeyLeaseService>,
    config: GatewayConfig,
) -> Result<()> {
    let listen = config.listen;
    let base = config.base_url.clone();
    let router = router(service, config);
    let listener =
        tokio::net::TcpListener::bind(listen)
            .await
            .map_err(|_| KeyLeaseError::InvalidRequest {
                reason: format!("cannot listen on {listen}"),
            })?;
    eprintln!("KeyLease gateway on http://{listen} for {base}/mcp");
    axum::serve(listener, router)
        .await
        .map_err(|_| KeyLeaseError::Storage)
}

pub(crate) fn router(service: Arc<KeyLeaseService>, config: GatewayConfig) -> Router {
    let state = Gateway {
        service: service.clone(),
        config: config.clone(),
    };
    let mut hosts = vec![config.host()];
    hosts.extend(["localhost".to_owned(), "127.0.0.1".to_owned()]);
    let mcp = VaultMcp::per_request(config.tools.clone());
    let mcp_service: StreamableHttpService<VaultMcp, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(mcp.clone()),
            Default::default(),
            StreamableHttpServerConfig::default()
                .with_allowed_hosts(hosts)
                .with_sse_keep_alive(Some(StdDuration::from_secs(15))),
        );
    let mcp_routes =
        Router::new()
            .nest_service("/mcp", mcp_service)
            .layer(middleware::from_fn_with_state(
                state.clone(),
                require_bearer,
            ));
    Router::new()
        .route("/", get(home))
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server),
        )
        .route(
            "/.well-known/oauth-authorization-server/mcp",
            get(authorization_server),
        )
        .route(
            "/.well-known/openid-configuration",
            get(authorization_server),
        )
        .route("/register", post(register))
        .route("/authorize", get(authorize_page).post(authorize_submit))
        .route("/token", post(token))
        .with_state(state)
        .merge(mcp_routes)
        .merge(approver::approver_routes().with_state(service))
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024))
        .layer(middleware::from_fn(security_headers))
}

/// Browsers ignore `frame-ancestors` in a `<meta>` policy, so the consent
/// page's protection against framing must travel as headers.
async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

// ---------------------------------------------------------------- bearer

async fn require_bearer(
    State(gateway): State<Gateway>,
    mut request: Request,
    next: Next,
) -> Response {
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty());
    let actor = match token.map(|token| gateway.service.gateway_actor(token)) {
        Some(Ok(Some(actor))) => actor,
        Some(Err(_)) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        _ => {
            let challenge = format!(
                "Bearer resource_metadata=\"{}\"",
                gateway.config.resource_metadata_url()
            );
            let mut response =
                (StatusCode::UNAUTHORIZED, "authentication required").into_response();
            if let Ok(value) = HeaderValue::from_str(&challenge) {
                response
                    .headers_mut()
                    .insert(header::WWW_AUTHENTICATE, value);
            }
            return response;
        }
    };
    request.extensions_mut().insert(Backend::in_process(
        gateway.service.clone(),
        actor,
        gateway.config.approval_wait,
    ));
    next.run(request).await
}

// -------------------------------------------------------------- metadata

async fn home(State(gateway): State<Gateway>) -> Html<String> {
    Html(page(
        "KeyLease gateway",
        &format!(
            "<p>This is a KeyLease MCP gateway. Add <code>{}</code> as a remote MCP server (custom \
             connector) in your assistant, then sign in with a connect code from \
             <code>keylease gateway connect-code NAME</code> on this server.</p>",
            escape(&gateway.config.resource())
        ),
    ))
}

async fn protected_resource(State(gateway): State<Gateway>) -> Response {
    no_store(Json(json!({
        "resource": gateway.config.resource(),
        "authorization_servers": [gateway.config.base_url],
        "bearer_methods_supported": ["header"],
        "resource_name": "KeyLease",
    })))
}

async fn authorization_server(State(gateway): State<Gateway>) -> Response {
    let base = &gateway.config.base_url;
    no_store(Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "registration_endpoint": format!("{base}/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["vault"],
    })))
}

fn no_store(body: impl IntoResponse) -> Response {
    let mut response = body.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn oauth_error(status: StatusCode, error: &OAuthError) -> Response {
    no_store((
        status,
        Json(json!({"error": error.code(), "error_description": error.description()})),
    ))
}

// ----------------------------------------------------------- registration

#[derive(Deserialize)]
struct RegistrationRequest {
    #[serde(default)]
    redirect_uris: Vec<String>,
    client_name: Option<String>,
}

async fn register(
    State(gateway): State<Gateway>,
    Json(body): Json<RegistrationRequest>,
) -> Response {
    match gateway
        .service
        .register_oauth_client(body.client_name.as_deref(), &body.redirect_uris)
    {
        Ok(client) => no_store((
            StatusCode::CREATED,
            Json(json!({
                "client_id": client.client_id,
                "client_id_issued_at": client.created_at.timestamp(),
                "client_name": client.client_name,
                "redirect_uris": client.redirect_uris,
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            })),
        )),
        Err(OAuthError::InvalidRequest(reason)) => no_store((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_redirect_uri", "error_description": reason})),
        )),
        Err(error) => oauth_error(StatusCode::INTERNAL_SERVER_ERROR, &error),
    }
}

// --------------------------------------------------------------- consent

#[derive(Deserialize, Default)]
struct AuthorizeParams {
    #[serde(default)]
    response_type: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    redirect_uri: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    code_challenge: String,
    #[serde(default)]
    code_challenge_method: String,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    /// Form submission only.
    #[serde(default)]
    connect_code: Option<String>,
    #[serde(default)]
    decision: Option<String>,
}

/// Checks everything that must hold before the user is ever redirected back
/// to `redirect_uri`; failures here render an error page instead.
fn checked_client(
    gateway: &Gateway,
    params: &AuthorizeParams,
) -> std::result::Result<keylease_service::OAuthClient, String> {
    let client = gateway
        .service
        .oauth_client(&params.client_id)
        .ok()
        .flatten()
        .ok_or("Unknown client. Remove the connector and add it again.")?;
    if !client.redirect_uris.contains(&params.redirect_uri) {
        return Err("This redirect address is not registered for the client.".into());
    }
    Ok(client)
}

/// Errors the client should hear about, returned through the redirect.
fn protocol_error(gateway: &Gateway, params: &AuthorizeParams) -> Option<&'static str> {
    if params.response_type != "code" {
        return Some("unsupported_response_type");
    }
    if params.code_challenge_method != "S256" || params.code_challenge.len() != 43 {
        return Some("invalid_request");
    }
    let resource_ok = params.resource.as_deref().is_none_or(|resource| {
        let resource = resource.trim_end_matches('/');
        resource == gateway.config.resource() || resource == gateway.config.base_url
    });
    (!resource_ok).then_some("invalid_target")
}

fn redirect_with(gateway: &Gateway, params: &AuthorizeParams, pairs: &[(&str, &str)]) -> Response {
    let Ok(mut url) = reqwest::Url::parse(&params.redirect_uri) else {
        return error_page("The redirect address is invalid.");
    };
    {
        let mut query = url.query_pairs_mut();
        for (key, value) in pairs {
            query.append_pair(key, value);
        }
        if let Some(state) = &params.state {
            query.append_pair("state", state);
        }
        query.append_pair("iss", &gateway.config.base_url);
    }
    Redirect::to(url.as_str()).into_response()
}

async fn authorize_page(
    State(gateway): State<Gateway>,
    axum::extract::Query(params): axum::extract::Query<AuthorizeParams>,
) -> Response {
    let client = match checked_client(&gateway, &params) {
        Ok(client) => client,
        Err(message) => return error_page(&message),
    };
    if let Some(error) = protocol_error(&gateway, &params) {
        return redirect_with(&gateway, &params, &[("error", error)]);
    }
    consent_page(&params, &client, None)
}

async fn authorize_submit(
    State(gateway): State<Gateway>,
    Form(params): Form<AuthorizeParams>,
) -> Response {
    let client = match checked_client(&gateway, &params) {
        Ok(client) => client,
        Err(message) => return error_page(&message),
    };
    if let Some(error) = protocol_error(&gateway, &params) {
        return redirect_with(&gateway, &params, &[("error", error)]);
    }
    if params.decision.as_deref() != Some("allow") {
        return redirect_with(&gateway, &params, &[("error", "access_denied")]);
    }
    let code = params.connect_code.clone().unwrap_or_default();
    match gateway.service.authorize_gateway_connection(
        &params.client_id,
        &params.redirect_uri,
        &params.code_challenge,
        params.resource.as_deref(),
        &code,
    ) {
        Ok(code) => redirect_with(&gateway, &params, &[("code", &code)]),
        Err(OAuthError::AccessDenied(reason)) => consent_page(&params, &client, Some(reason)),
        Err(error) => redirect_with(&gateway, &params, &[("error", error.code())]),
    }
}

fn consent_page(
    params: &AuthorizeParams,
    client: &keylease_service::OAuthClient,
    problem: Option<&str>,
) -> Response {
    let redirect_host = reqwest::Url::parse(&params.redirect_uri)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_default();
    let hidden = [
        ("response_type", Some(params.response_type.as_str())),
        ("client_id", Some(params.client_id.as_str())),
        ("redirect_uri", Some(params.redirect_uri.as_str())),
        ("state", params.state.as_deref()),
        ("code_challenge", Some(params.code_challenge.as_str())),
        (
            "code_challenge_method",
            Some(params.code_challenge_method.as_str()),
        ),
        ("resource", params.resource.as_deref()),
        ("scope", params.scope.as_deref()),
    ]
    .iter()
    .filter_map(|(name, value)| {
        value.map(|value| {
            format!(
                "<input type=\"hidden\" name=\"{name}\" value=\"{}\">",
                escape(value)
            )
        })
    })
    .collect::<String>();
    let problem = problem
        .map(|problem| format!("<p class=\"error\">{}</p>", escape(problem)))
        .unwrap_or_default();
    Html(page(
        "Connect to KeyLease",
        &format!(
            "<p><strong>{name}</strong> wants to use this KeyLease vault. It will return to \
             <code>{host}</code>.</p>\
             <p>It gets its own agent identity: it can search item names and use SSH keys and \
             databases without seeing them, and every secret use waits for your approval in \
             KeyLease. Revoke it any time with <code>keylease gateway revoke</code>.</p>\
             {problem}\
             <form method=\"post\" action=\"/authorize\">{hidden}\
             <label>Connect code<br><input name=\"connect_code\" autocomplete=\"off\" \
             autocapitalize=\"characters\" spellcheck=\"false\" autofocus required></label>\
             <p class=\"hint\">On the server, run <code>keylease gateway connect-code NAME</code>.</p>\
             <button name=\"decision\" value=\"allow\">Connect</button> \
             <button name=\"decision\" value=\"deny\" class=\"secondary\" formnovalidate>Cancel</button>\
             </form>",
            name = escape(&client.client_name),
            host = escape(&redirect_host),
        ),
    ))
    .into_response()
}

fn error_page(message: &str) -> Response {
    let mut response = Html(page(
        "Cannot connect",
        &format!("<p class=\"error\">{}</p>", escape(message)),
    ))
    .into_response();
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response
}

/// A self-contained page that cannot be framed or load anything external.
fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'\">\
         <title>{title}</title><style>\
         body{{font:16px/1.5 system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;color:#1d2433;background:#fff}}\
         h1{{font-size:1.4rem}}code{{background:#f1f3f7;padding:0 .25rem;border-radius:4px}}\
         input{{font:inherit;font-family:ui-monospace,monospace;letter-spacing:.08em;width:100%;padding:.5rem;margin:.25rem 0;box-sizing:border-box}}\
         button{{font:inherit;padding:.5rem 1rem;border:0;border-radius:6px;background:#2357d8;color:#fff;cursor:pointer}}\
         .secondary{{background:#e6e9f0;color:#1d2433}}.error{{color:#b3261e}}.hint{{color:#5b6475;font-size:.9rem}}\
         @media (prefers-color-scheme:dark){{body{{background:#14171f;color:#e6e9f0}}code{{background:#232837}}.hint{{color:#9aa3b5}}.secondary{{background:#2a3040;color:#e6e9f0}}}}\
         </style></head><body><h1>{title}</h1>{body}</body></html>"
    )
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

// ----------------------------------------------------------------- token

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    client_id: Option<String>,
}

async fn token(
    State(gateway): State<Gateway>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let form = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/x-www-form-urlencoded"));
    let request: Option<TokenRequest> = if form {
        serde_urlencoded::from_bytes(&body).ok()
    } else {
        serde_json::from_slice(&body).ok()
    };
    let Some(request) = request else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            &OAuthError::InvalidRequest("malformed token request"),
        );
    };
    let client_id = request.client_id.unwrap_or_default();
    let outcome = match request.grant_type.as_str() {
        "authorization_code" => gateway.service.exchange_authorization_code(
            request.code.as_deref().unwrap_or_default(),
            &client_id,
            request.redirect_uri.as_deref().unwrap_or_default(),
            request.code_verifier.as_deref().unwrap_or_default(),
        ),
        "refresh_token" => gateway.service.refresh_gateway_tokens(
            request.refresh_token.as_deref().unwrap_or_default(),
            &client_id,
        ),
        _ => Err(OAuthError::UnsupportedGrantType),
    };
    match outcome {
        Ok(tokens) => no_store(Json(json!({
            "access_token": tokens.access_token,
            "token_type": tokens.token_type,
            "expires_in": tokens.expires_in,
            "refresh_token": tokens.refresh_token,
            "scope": "vault",
        }))),
        Err(error @ OAuthError::Server) => oauth_error(StatusCode::INTERNAL_SERVER_ERROR, &error),
        Err(error) => oauth_error(StatusCode::BAD_REQUEST, &error),
    }
}

// ----------------------------------------------------------------- admin

#[derive(Subcommand)]
pub(crate) enum GatewayCommand {
    /// Print a one-time code (10 minutes) that connects one web assistant.
    ConnectCode {
        /// A name for the connection, e.g. chatgpt or claude-web.
        name: String,
    },
    /// List connected web assistants.
    Connections,
    /// Disconnect one: its tokens, approvals baseline and trusts end now.
    Revoke { agent_id: String },
}

pub(crate) fn gateway_command(db: &Path, command: GatewayCommand) -> Result<()> {
    let service = admin_service(db)?;
    match command {
        GatewayCommand::ConnectCode { name } => {
            let code = service.create_gateway_connect_code(&name)?;
            print_json(&json!({
                "code": code.code,
                "name": code.name,
                "expires_at": code.expires_at,
                "next": "Add https://YOUR-HOST/mcp as a custom connector in your assistant and enter this code when asked.",
            }))
        }
        GatewayCommand::Connections => print_json(&service.list_gateway_connections()?),
        GatewayCommand::Revoke { agent_id } => {
            service.revoke_gateway_connection(&agent_id)?;
            print_json(&json!({"revoked": agent_id}))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use tower::ServiceExt;

    async fn send(
        router: &Router,
        request: axum::http::Request<Body>,
    ) -> (StatusCode, HeaderMap, String) {
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, headers, String::from_utf8_lossy(&body).into_owned())
    }

    fn get(path: &str) -> axum::http::Request<Body> {
        axum::http::Request::get(path)
            .header(header::HOST, "localhost:8787")
            .body(Body::empty())
            .unwrap()
    }

    fn post(path: &str, content_type: &str, body: String) -> axum::http::Request<Body> {
        axum::http::Request::post(path)
            .header(header::HOST, "localhost:8787")
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn a_web_client_signs_in_and_reaches_the_tools() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(NativeStore::open(dir.path().join("vault.sqlite")).unwrap());
        let service = Arc::new(KeyLeaseService::new(store).unwrap());
        service.initialize(b"password", Duration::hours(1)).unwrap();
        let config = GatewayConfig::new(
            "http://localhost:8787/",
            "127.0.0.1:8787".parse().unwrap(),
            ToolOptions::default(),
            StdDuration::from_secs(1),
        )
        .unwrap();
        assert!(
            GatewayConfig::new(
                "http://vault.example.com",
                "127.0.0.1:8787".parse().unwrap(),
                ToolOptions::default(),
                StdDuration::from_secs(1)
            )
            .is_err(),
            "plain http is only for localhost"
        );
        let router = router(service.clone(), config);

        let (status, headers, _) =
            send(&router, post("/mcp", "application/json", "{}".into())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            headers[header::WWW_AUTHENTICATE],
            "Bearer resource_metadata=\"http://localhost:8787/.well-known/oauth-protected-resource\""
        );
        let (_, _, body) = send(&router, get("/.well-known/oauth-protected-resource")).await;
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap()["resource"],
            "http://localhost:8787/mcp"
        );
        let (_, _, body) = send(&router, get("/.well-known/oauth-authorization-server")).await;
        let metadata: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(metadata["code_challenge_methods_supported"][0], "S256");

        let redirect = "https://client.example/cb";
        let (status, _, body) = send(
            &router,
            post(
                "/register",
                "application/json",
                json!({"client_name": "<b>Evil</b>", "redirect_uris": [redirect]}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let client_id = serde_json::from_str::<Value>(&body).unwrap()["client_id"]
            .as_str()
            .unwrap()
            .to_owned();

        let verifier = "k".repeat(50);
        let challenge = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            sha2_digest(verifier.as_bytes()),
        );
        let query = serde_urlencoded::to_string([
            ("response_type", "code"),
            ("client_id", client_id.as_str()),
            ("redirect_uri", redirect),
            ("state", "s1"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ])
        .unwrap();
        let (status, headers, page) = send(&router, get(&format!("/authorize?{query}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(page.contains("&lt;b&gt;Evil&lt;/b&gt;") && !page.contains("<b>Evil"));
        assert!(headers.get(header::LOCATION).is_none());
        assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
        assert!(
            headers[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'")
        );

        let connect = service.create_gateway_connect_code("test").unwrap();
        let (status, headers, _) = send(
            &router,
            post(
                "/authorize",
                "application/x-www-form-urlencoded",
                format!("{query}&decision=allow&connect_code={}", connect.code),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let location = reqwest::Url::parse(headers[header::LOCATION].to_str().unwrap()).unwrap();
        let pairs: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
        assert_eq!(pairs["state"], "s1");
        assert_eq!(pairs["iss"], "http://localhost:8787");

        let (status, _, body) = send(
            &router,
            post(
                "/token",
                "application/x-www-form-urlencoded",
                serde_urlencoded::to_string([
                    ("grant_type", "authorization_code"),
                    ("code", pairs["code"].as_str()),
                    ("redirect_uri", redirect),
                    ("client_id", client_id.as_str()),
                    ("code_verifier", verifier.as_str()),
                ])
                .unwrap(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let access = serde_json::from_str::<Value>(&body).unwrap()["access_token"]
            .as_str()
            .unwrap()
            .to_owned();

        let initialize = json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}
        });
        let request = axum::http::Request::post("/mcp")
            .header(header::HOST, "localhost:8787")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header(header::AUTHORIZATION, format!("Bearer {access}"))
            .body(Body::from(initialize.to_string()))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // Streamable HTTP answers with an SSE stream that stays open; read
        // frames until the initialize result arrives.
        let mut body = response.into_body();
        let mut text = String::new();
        while !text.contains("\"result\"") {
            let frame = http_body_util::BodyExt::frame(&mut body)
                .await
                .unwrap()
                .unwrap();
            if let Ok(data) = frame.into_data() {
                text.push_str(&String::from_utf8_lossy(&data));
            }
        }
        assert!(text.contains("\"keylease\""), "{text}");
    }

    fn sha2_digest(bytes: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        sha2::Sha256::digest(bytes).to_vec()
    }
}
