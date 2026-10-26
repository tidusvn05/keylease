//! Remote approval for a headless vault node (ADR 0005 mode B).
//!
//! The node (`keylease serve --approver-listen`) exposes a small HTTP API with
//! no vault access: pair a device with a one-time code, then list and decide
//! approvals and revoke trusts with requests signed by that device's Ed25519
//! key. The approver side (`keylease remote …`, and later the macOS app) keeps
//! the key under `~/.keylease/remotes/`.

use super::*;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path as UrlPath, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use keylease_service::{ApproverDevice, approver_signing_input};
use std::{net::SocketAddr, os::unix::fs::DirBuilderExt, os::unix::fs::OpenOptionsExt};

const DEVICE_HEADER: &str = "x-keylease-device";
const TIMESTAMP_HEADER: &str = "x-keylease-timestamp";
const SIGNATURE_HEADER: &str = "x-keylease-signature";
const MAX_BODY_BYTES: usize = 64 * 1024;

// ---------------------------------------------------------------- node side

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairBody {
    code: String,
    name: String,
    public_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecideBody {
    approve: bool,
    request_digest_hex: String,
    policy_version: u64,
    #[serde(default)]
    trust: Option<TrustDecision>,
}

struct ApiError(KeyLeaseError);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self.0 {
            KeyLeaseError::Denied { .. } => StatusCode::FORBIDDEN,
            KeyLeaseError::NotFound { .. } => StatusCode::NOT_FOUND,
            KeyLeaseError::InvalidRequest { .. } => StatusCode::BAD_REQUEST,
            KeyLeaseError::VaultLocked { .. } => StatusCode::LOCKED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(self.0)).into_response()
    }
}

impl From<KeyLeaseError> for ApiError {
    fn from(error: KeyLeaseError) -> Self {
        Self(error)
    }
}

type ApiResult<T> = std::result::Result<Json<T>, ApiError>;

fn signed_device(
    service: &KeyLeaseService,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> std::result::Result<ApproverDevice, ApiError> {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| {
                ApiError(KeyLeaseError::Denied {
                    reason: "approver request is not signed".into(),
                })
            })
    };
    let timestamp = header(TIMESTAMP_HEADER)?.parse::<i64>().map_err(|_| {
        ApiError(KeyLeaseError::Denied {
            reason: "approver request is not signed".into(),
        })
    })?;
    Ok(service.verify_approver_request(
        header(DEVICE_HEADER)?,
        method.as_str(),
        uri.path(),
        timestamp,
        body,
        header(SIGNATURE_HEADER)?,
    )?)
}

async fn pair(
    State(service): State<Arc<KeyLeaseService>>,
    Json(body): Json<PairBody>,
) -> ApiResult<ApproverDevice> {
    Ok(Json(service.pair_approver(
        &body.code,
        &body.name,
        &body.public_key,
    )?))
}

async fn approvals(
    State(service): State<Arc<KeyLeaseService>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Vec<ApprovalRecord>> {
    let device = signed_device(&service, &method, &uri, &headers, &body)?;
    Ok(Json(service.remote_list_approvals(&device)?))
}

async fn decide(
    State(service): State<Arc<KeyLeaseService>>,
    UrlPath(id): UrlPath<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Value> {
    let device = signed_device(&service, &method, &uri, &headers, &body)?;
    let decision: DecideBody = serde_json::from_slice(&body).map_err(|_| {
        ApiError(KeyLeaseError::InvalidRequest {
            reason: "invalid decision body".into(),
        })
    })?;
    let outcome = service.remote_decide(
        &device,
        &id,
        decision.approve,
        &decision.request_digest_hex,
        decision.policy_version,
        decision.trust,
    )?;
    Ok(Json(
        serde_json::to_value(outcome).map_err(|_| ApiError(KeyLeaseError::Storage))?,
    ))
}

async fn trusts(
    State(service): State<Arc<KeyLeaseService>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Vec<TrustRecord>> {
    let device = signed_device(&service, &method, &uri, &headers, &body)?;
    Ok(Json(service.remote_list_trusts(&device)?))
}

async fn revoke_trust(
    State(service): State<Arc<KeyLeaseService>>,
    UrlPath(id): UrlPath<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Value> {
    let device = signed_device(&service, &method, &uri, &headers, &body)?;
    service.remote_revoke_trust(&device, &id)?;
    Ok(Json(json!({"revoked": id})))
}

/// Serves the approver API. Binding beyond loopback needs an explicit opt-in:
/// put it behind a TLS reverse proxy (Caddy) or a private network instead.
pub(crate) async fn serve_approver(
    service: Arc<KeyLeaseService>,
    address: SocketAddr,
    allow_public: bool,
) -> Result<()> {
    if !address.ip().is_loopback() && !allow_public {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "--approver-listen must be a loopback address; expose it through a TLS \
                     reverse proxy, or pass --approver-listen-public"
                .into(),
        });
    }
    let router = Router::new()
        .route("/v1/pair", post(pair))
        .route("/v1/approvals", get(approvals))
        .route("/v1/approvals/{id}/decide", post(decide))
        .route("/v1/trusts", get(trusts))
        .route("/v1/trusts/{id}/revoke", post(revoke_trust))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(service);
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|_| KeyLeaseError::Storage)?;
    eprintln!("KeyLease approver API listening on http://{address}");
    axum::serve(listener, router)
        .await
        .map_err(|_| KeyLeaseError::Storage)
}

// ------------------------------------------------------------ approver side

#[derive(Subcommand)]
pub(crate) enum RemoteCommand {
    /// On the node: print a one-time pairing code (master password).
    PairingCode,
    /// On the node: list paired approver devices (master password).
    Devices,
    /// On the node: revoke a paired device (master password).
    RevokeDevice { id: String },
    /// On the approver: pair with a node using its pairing code.
    Add {
        name: String,
        #[arg(long)]
        url: String,
        #[arg(long)]
        code: String,
        /// How this device appears on the node.
        #[arg(long, default_value = "keylease-cli")]
        device_name: String,
    },
    /// On the approver: list pending approvals on a node.
    Approvals { name: String },
    /// On the approver: decide an approval on a node.
    Decide {
        name: String,
        id: String,
        #[arg(long, conflicts_with = "deny", required_unless_present = "deny")]
        approve: bool,
        #[arg(long)]
        deny: bool,
        #[arg(long, value_parser = ["once", "30m", "1h", "6h", "1d", "3d", "7d"], requires = "approve")]
        trust: Option<String>,
        #[arg(long, default_value = "resource", value_parser = ["resource", "item"])]
        scope: String,
    },
    /// On the approver: list active trusts on a node.
    Trusts { name: String },
    /// On the approver: revoke a trust on a node.
    RevokeTrust { name: String, id: String },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteProfile {
    url: String,
    device_id: String,
}

fn remotes_dir() -> Result<PathBuf> {
    let directory = managed_home()
        .ok_or(KeyLeaseError::Storage)?
        .join("remotes");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&directory)
        .map_err(|_| KeyLeaseError::Storage)?;
    Ok(directory)
}

fn valid_profile_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "remote name must be ASCII letters, digits, '-' or '_'".into(),
        });
    }
    Ok(())
}

fn validate_url(url: &str) -> Result<reqwest::Url> {
    let parsed = reqwest::Url::parse(url).map_err(|_| KeyLeaseError::InvalidRequest {
        reason: "invalid node URL".into(),
    })?;
    let loopback = parsed.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
            || host == "[::1]"
    });
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback) {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "node URL must use https (http is allowed only for loopback)".into(),
        });
    }
    Ok(parsed)
}

fn load_profile(name: &str) -> Result<(RemoteProfile, SigningKey)> {
    valid_profile_name(name)?;
    let directory = remotes_dir()?;
    let profile: RemoteProfile = serde_json::from_slice(
        &fs::read(directory.join(format!("{name}.json"))).map_err(|_| KeyLeaseError::NotFound {
            resource: format!("remote {name}"),
        })?,
    )
    .map_err(|_| KeyLeaseError::Storage)?;
    let seed = read_secret_file(&directory.join(format!("{name}.key")), "approver key")?;
    let seed: [u8; 32] = STANDARD
        .decode(seed.trim())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(KeyLeaseError::Crypto)?;
    Ok((profile, SigningKey::from_bytes(&seed)))
}

async fn signed_request(
    name: &str,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value> {
    let (profile, key) = load_profile(name)?;
    let url = validate_url(&profile.url)?
        .join(path)
        .map_err(|_| KeyLeaseError::Storage)?;
    let body = body
        .map(|value| serde_json::to_vec(&value).map_err(|_| KeyLeaseError::Storage))
        .transpose()?
        .unwrap_or_default();
    let timestamp = Utc::now().timestamp();
    let signature = STANDARD.encode(
        key.sign(&approver_signing_input(
            method.as_str(),
            url.path(),
            timestamp,
            &body,
        ))
        .to_bytes(),
    );
    let mut request = reqwest::Client::new()
        .request(method, url)
        .header(DEVICE_HEADER, &profile.device_id)
        .header(TIMESTAMP_HEADER, timestamp.to_string())
        .header(SIGNATURE_HEADER, signature);
    if !body.is_empty() {
        request = request
            .header("content-type", "application/json")
            .body(body);
    }
    response_json(request.send().await).await
}

async fn response_json(
    response: std::result::Result<reqwest::Response, reqwest::Error>,
) -> Result<Value> {
    let response = response.map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
    let ok = response.status().is_success();
    let value: Value = response
        .json()
        .await
        .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
    if ok {
        Ok(value)
    } else {
        Err(serde_json::from_value(value).unwrap_or(KeyLeaseError::Storage))
    }
}

pub(crate) async fn remote_command(cli: &Cli, command: RemoteCommand) -> Result<()> {
    match command {
        RemoteCommand::PairingCode => {
            let service = admin_service(&cli.db)?;
            let code = service.create_pairing_code()?;
            print_json(&json!({
                "code": code.code,
                "expires_at": code.expires_at,
                "next": "On the approver: keylease remote add NAME --url https://THIS-HOST --code CODE"
            }))
        }
        RemoteCommand::Devices => print_json(&admin_service(&cli.db)?.list_approver_devices()?),
        RemoteCommand::RevokeDevice { id } => {
            admin_service(&cli.db)?.revoke_approver_device(&id)?;
            print_json(&json!({"revoked": id}))
        }
        RemoteCommand::Add {
            name,
            url,
            code,
            device_name,
        } => {
            valid_profile_name(&name)?;
            let base = validate_url(&url)?;
            let directory = remotes_dir()?;
            let key_path = directory.join(format!("{name}.key"));
            if key_path.exists() {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "a remote with this name already exists".into(),
                });
            }
            let mut seed = Zeroizing::new([0_u8; 32]);
            rand::RngCore::fill_bytes(&mut rand::rng(), seed.as_mut());
            let key = SigningKey::from_bytes(&seed);
            let device = response_json(
                reqwest::Client::new()
                    .post(base.join("/v1/pair").map_err(|_| KeyLeaseError::Storage)?)
                    .json(&json!({
                        "code": code,
                        "name": device_name,
                        "public_key": STANDARD.encode(key.verifying_key().to_bytes()),
                    }))
                    .send()
                    .await,
            )
            .await?;
            let device_id = device
                .get("id")
                .and_then(Value::as_str)
                .ok_or(KeyLeaseError::Storage)?
                .to_owned();
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&key_path)
                .map_err(|_| KeyLeaseError::Storage)?;
            file.write_all(STANDARD.encode(seed.as_ref()).as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|_| KeyLeaseError::Storage)?;
            write_atomic(
                &directory.join(format!("{name}.json")),
                &serde_json::to_vec(&RemoteProfile {
                    url: base.to_string(),
                    device_id: device_id.clone(),
                })
                .map_err(|_| KeyLeaseError::Storage)?,
            )?;
            print_json(&json!({"remote": name, "device_id": device_id}))
        }
        RemoteCommand::Approvals { name } => {
            print_json(&signed_request(&name, reqwest::Method::GET, "/v1/approvals", None).await?)
        }
        RemoteCommand::Decide {
            name,
            id,
            approve,
            deny: _,
            trust,
            scope,
        } => {
            // Re-read the pending request and bind the decision to it, so a
            // request that changed since it was listed cannot be approved.
            let pending =
                signed_request(&name, reqwest::Method::GET, "/v1/approvals", None).await?;
            let record = pending
                .as_array()
                .and_then(|list| {
                    list.iter()
                        .find(|record| record.get("id").and_then(Value::as_str) == Some(&id))
                })
                .ok_or_else(|| KeyLeaseError::NotFound {
                    resource: "pending approval".into(),
                })?;
            let trust = trust
                .as_deref()
                .and_then(TrustDuration::parse)
                .map(|duration| TrustDecision {
                    scope: if scope == "item" {
                        TrustScope::Item
                    } else {
                        TrustScope::Resource
                    },
                    duration,
                });
            let body = DecideBody {
                approve,
                request_digest_hex: record
                    .get("request_digest_hex")
                    .and_then(Value::as_str)
                    .ok_or(KeyLeaseError::Storage)?
                    .to_owned(),
                policy_version: record
                    .get("policy_version")
                    .and_then(Value::as_u64)
                    .ok_or(KeyLeaseError::Storage)?,
                trust,
            };
            print_json(
                &signed_request(
                    &name,
                    reqwest::Method::POST,
                    &format!("/v1/approvals/{id}/decide"),
                    Some(serde_json::to_value(body).map_err(|_| KeyLeaseError::Storage)?),
                )
                .await?,
            )
        }
        RemoteCommand::Trusts { name } => {
            print_json(&signed_request(&name, reqwest::Method::GET, "/v1/trusts", None).await?)
        }
        RemoteCommand::RevokeTrust { name, id } => print_json(
            &signed_request(
                &name,
                reqwest::Method::POST,
                &format!("/v1/trusts/{id}/revoke"),
                None,
            )
            .await?,
        ),
    }
}
