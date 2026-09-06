use anyhow::{Context, Result, bail};
use axum::{Json, Router, http::StatusCode, response::IntoResponse, routing::get};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chrono::{Duration, Utc};
use keylease_core::{AgentId, EdgeId, OrganizationId, ProjectId, WorkloadId};
use keylease_service::KeyLeaseService;
use keylease_store::NativeStore;
use leasegate_edge::{
    CloudControlClient, EdgeConfig, EdgeControlStore, EdgeCredentialAuthorizer,
    EdgeEnforcedExecutor, EdgeToolDiscovery, credential_api_router, credential_gateway_from_config,
};
use leasegate_mcp::{
    AgentEndpointIdentity, CanonicalActionExecutor, EndpointSecurity, LocalServiceExecutor,
    agent_router_with_discovery,
};
use std::{
    collections::BTreeMap,
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration as StdDuration,
};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> Result<()> {
    if env::args().nth(1).as_deref() == Some("healthcheck") {
        return local_healthcheck().await;
    }
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .json()
        .init();

    if required_env("LEASEGATE_DEPLOYMENT_MODE")? != "self_hosted"
        || required_env("LEASEGATE_EXECUTION_MODE")? != "local_gateway"
    {
        bail!("this binary only supports self_hosted/local_gateway execution")
    }

    let edge_id = EdgeId(required_env("LEASEGATE_EDGE_ID")?);
    let organization_id = OrganizationId(required_env("LEASEGATE_ORGANIZATION_ID")?);
    let project_id = ProjectId(required_env("LEASEGATE_PROJECT_ID")?);
    let agent_id = AgentId(required_env("LEASEGATE_AGENT_ID")?);
    let listen: SocketAddr = env::var("LEASEGATE_EDGE_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8090".into())
        .parse()
        .context("invalid LEASEGATE_EDGE_LISTEN")?;
    let state_path = PathBuf::from(required_env("LEASEGATE_EDGE_STATE")?);
    let vault_path = PathBuf::from(required_env("LEASEGATE_VAULT_DB")?);
    let storage_key =
        read_base64_key(Path::new(&required_env("LEASEGATE_EDGE_STORAGE_KEY_FILE")?))?;
    let edge_credential = read_secret_text(
        Path::new(&required_env("LEASEGATE_EDGE_CREDENTIAL_FILE")?),
        4096,
    )?;
    let agent_credential = read_secret_text(
        Path::new(&required_env("LEASEGATE_AGENT_CREDENTIAL_FILE")?),
        4096,
    )?;
    let vault_password = read_secret_text(
        Path::new(&required_env("LEASEGATE_VAULT_PASSWORD_FILE")?),
        4096,
    )?;
    let verifying_key = required_env("LEASEGATE_CONTROL_VERIFYING_KEY")?;
    let cloud_url = required_env("LEASEGATE_CLOUD_URL")?;

    let edge_store = Arc::new(
        EdgeControlStore::open(
            state_path,
            storage_key,
            EdgeConfig {
                edge_id: edge_id.clone(),
                organization_id: organization_id.clone(),
                project_id: project_id.clone(),
                software_version: env!("CARGO_PKG_VERSION").into(),
                control_verifying_key_base64: verifying_key,
                maximum_offline_seconds: 900,
                maximum_revocation_staleness_seconds: 300,
                maximum_audit_spool_bytes: 64 * 1024 * 1024,
            },
        )
        .map_err(|error| anyhow::anyhow!(error.to_string()))?,
    );
    let native_store = Arc::new(
        NativeStore::open(vault_path).map_err(|error| anyhow::anyhow!(error.to_string()))?,
    );
    let keylease = Arc::new(
        KeyLeaseService::new(native_store).map_err(|error| anyhow::anyhow!(error.to_string()))?,
    );
    keylease
        .unlock(vault_password.trim().as_bytes(), Duration::hours(24))
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;

    let cloud = Arc::new(
        CloudControlClient::new(
            &cloud_url,
            edge_id,
            organization_id.clone(),
            project_id.clone(),
            edge_credential.trim().to_owned(),
        )
        .map_err(|error| anyhow::anyhow!(error.to_string()))?,
    );
    let cloud_connected = Arc::new(AtomicBool::new(false));
    match cloud
        .poll_control(&edge_store, &keylease, 500, Utc::now())
        .await
    {
        Ok(_) => cloud_connected.store(true, Ordering::Release),
        Err(error) if edge_store.active_policy().ok().flatten().is_some() => {
            warn!(error = %error, "Cloud unavailable; starting under bounded cached policy")
        }
        Err(error) => {
            bail!("initial control synchronization failed without cached policy: {error}")
        }
    }

    let credential_authorizer = Arc::new(EdgeCredentialAuthorizer::new(
        edge_store.clone(),
        cloud.clone(),
        cloud_connected.clone(),
    ));
    let credential_gateway = credential_gateway_from_config(
        Path::new(&required_env("LEASEGATE_CREDENTIAL_BACKENDS_FILE")?),
        edge_store.clone(),
        credential_authorizer,
    )
    .await
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;

    let loop_store = edge_store.clone();
    let loop_service = keylease.clone();
    let loop_cloud = cloud.clone();
    let loop_connected = cloud_connected.clone();
    let loop_credentials = credential_gateway.clone();
    let loop_agent_id = agent_id.clone();
    tokio::spawn(async move {
        loop {
            match loop_cloud
                .poll_control(&loop_store, &loop_service, 500, Utc::now())
                .await
            {
                Ok(_) => {
                    loop_connected.store(true, Ordering::Release);
                    if let Ok(heartbeat) = loop_store.heartbeat(BTreeMap::new(), Utc::now())
                        && let Err(error) = loop_cloud.send_heartbeat(&heartbeat).await
                    {
                        warn!(error = %error, "heartbeat upload failed");
                    }
                    if let Err(error) = loop_cloud.flush_audit(&loop_store, 500).await {
                        warn!(error = %error, "audit upload failed");
                    }
                    match loop_credentials.reap(Utc::now()).await {
                        Ok(records) => {
                            for record in records {
                                if let Err(error) =
                                    loop_cloud.report_credential_lease(&record).await
                                {
                                    warn!(error = %error, lease_id = %record.lease_id, "credential terminal metadata report deferred");
                                }
                            }
                        }
                        Err(error) => {
                            warn!(error = %error, "dynamic credential expiry/revocation sweep failed");
                        }
                    }
                    match loop_credentials.list_for_agent(&loop_agent_id) {
                        Ok(records) => {
                            for record in records {
                                if let Err(error) =
                                    loop_cloud.report_credential_lease(&record).await
                                {
                                    warn!(error = %error, lease_id = %record.lease_id, "credential metadata retry deferred");
                                }
                            }
                        }
                        Err(error) => {
                            warn!(error = %error, "credential metadata retry scan failed");
                        }
                    }
                }
                Err(error) => {
                    loop_connected.store(false, Ordering::Release);
                    warn!(error = %error, "control poll failed; offline limits now apply");
                }
            }
            tokio::time::sleep(StdDuration::from_secs(2)).await;
        }
    });

    let local: Arc<dyn CanonicalActionExecutor> =
        Arc::new(LocalServiceExecutor::new(keylease.clone()));
    let enforced: Arc<dyn CanonicalActionExecutor> = Arc::new(EdgeEnforcedExecutor::new(
        local,
        edge_store.clone(),
        cloud.clone(),
        cloud_connected.clone(),
        organization_id,
        project_id,
    ));
    let hosts = env::var("LEASEGATE_MCP_ALLOWED_HOSTS")
        .unwrap_or_else(|_| listen.to_string())
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect();
    let origins = env::var("LEASEGATE_MCP_ALLOWED_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect();
    let security = EndpointSecurity::new(agent_credential.trim().to_owned(), hosts, origins)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let discovery = Arc::new(EdgeToolDiscovery::built_in(edge_store.clone()));
    let identity = AgentEndpointIdentity {
        agent_id,
        workload_id: env::var("LEASEGATE_WORKLOAD_ID").ok().map(WorkloadId),
        on_behalf_of: env::var("LEASEGATE_ON_BEHALF_OF").ok(),
        client_session_id: format!("gateway-{}", std::process::id()),
    };
    let health_store = edge_store.clone();
    let health_connected = cloud_connected.clone();
    let health_router = Router::new()
        .route(
            "/healthz",
            get(|| async {
                Json(serde_json::json!({
                    "ok": true,
                    "service": leasegate_edge::SERVICE_NAME
                }))
            }),
        )
        .route(
            "/readyz",
            get(move || {
                let store = health_store.clone();
                let connected = health_connected.clone();
                async move { edge_readiness(store, connected).await }
            }),
        );
    let router = health_router
        .merge(agent_router_with_discovery(
            "/mcp",
            identity.clone(),
            enforced,
            discovery,
            security.clone(),
        ))
        .merge(credential_api_router(
            credential_gateway,
            identity,
            edge_store,
            cloud,
            security,
        ));
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .context("bind Edge MCP listener")?;
    info!(%listen, "LeaseGate self-hosted local Gateway listening");
    axum::serve(listener, router)
        .await
        .context("serve Edge MCP")
}

async fn edge_readiness(
    store: Arc<EdgeControlStore>,
    cloud_connected: Arc<AtomicBool>,
) -> impl IntoResponse {
    let policy = store.active_policy();
    let spool = store.audit_spool_status();
    let ready = policy.as_ref().is_ok_and(Option::is_some)
        && spool
            .as_ref()
            .is_ok_and(|status| status.encrypted_bytes < status.maximum_bytes);
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let policy_version = policy.ok().flatten().map(|bundle| bundle.payload.version);
    let (audit_spool_bytes, audit_spool_maximum_bytes) = spool
        .map(|value| (Some(value.encrypted_bytes), Some(value.maximum_bytes)))
        .unwrap_or((None, None));
    (
        status,
        Json(serde_json::json!({
            "ok": ready,
            "service": leasegate_edge::SERVICE_NAME,
            "control_connected": cloud_connected.load(Ordering::Acquire),
            "policy_version": policy_version,
            "audit_spool_bytes": audit_spool_bytes,
            "audit_spool_maximum_bytes": audit_spool_maximum_bytes
        })),
    )
}

async fn local_healthcheck() -> Result<()> {
    let listen: SocketAddr = env::var("LEASEGATE_EDGE_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8090".into())
        .parse()
        .context("invalid LEASEGATE_EDGE_LISTEN")?;
    let response = reqwest::Client::builder()
        .connect_timeout(StdDuration::from_secs(2))
        .timeout(StdDuration::from_secs(4))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build healthcheck client")?
        .get(format!("http://127.0.0.1:{}/readyz", listen.port()))
        .send()
        .await
        .context("request Gateway readiness")?;
    if !response.status().is_success() {
        bail!("Gateway is not ready")
    }
    Ok(())
}

fn required_env(name: &str) -> Result<String> {
    let value = env::var(name).with_context(|| format!("{name} is required"))?;
    if value.is_empty() {
        bail!("{name} must not be empty")
    }
    Ok(value)
}

fn read_base64_key(path: &Path) -> Result<[u8; 32]> {
    let encoded = read_secret_text(path, 1024)?;
    STANDARD_NO_PAD
        .decode(encoded.trim())
        .context("storage key must be unpadded base64")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("storage key must decode to 32 bytes"))
}

fn read_secret_text(path: &Path, maximum: u64) -> Result<Zeroizing<String>> {
    let metadata = fs::metadata(path).context("read secret-file metadata")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("secret file must not be group/world accessible")
        }
    }
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        bail!("secret path must be a bounded non-empty regular file")
    }
    Ok(Zeroizing::new(
        fs::read_to_string(path).context("read secret file")?,
    ))
}
