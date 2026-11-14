use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use keylease_protocol::ControlSigner;
use keylease_server::{CloudApiConfig, CloudApiState, CloudRepository, router};
use std::{env, fs, net::SocketAddr, path::Path};
use tracing::info;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> Result<()> {
    if env::args().nth(1).as_deref() == Some("healthcheck") {
        return local_healthcheck().await;
    }
    if env::args().nth(1).as_deref() == Some("migrate") {
        return migrate_only().await;
    }
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .json()
        .init();
    let database_url = read_secret_text(
        Path::new(&required_env("KEYLEASE_DATABASE_URL_FILE")?),
        4096,
    )?;
    let admin_token =
        read_secret_text(Path::new(&required_env("KEYLEASE_ADMIN_TOKEN_FILE")?), 4096)?;
    let signing_key_path = required_env("KEYLEASE_CONTROL_SIGNING_KEY_FILE")?;
    let listen: SocketAddr = env::var("KEYLEASE_SERVER_LISTEN")
        .or_else(|_| env::var("KEYLEASE_CLOUD_LISTEN"))
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()
        .context("invalid KEYLEASE_CLOUD_LISTEN")?;
    let key = read_signing_key(Path::new(&signing_key_path))?;
    let signer = ControlSigner::from_bytes("cloud-control-v1", key.as_slice())
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let repository = CloudRepository::connect(database_url.trim(), 20)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    repository
        .migrate()
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let state = CloudApiState::new(
        repository,
        signer,
        CloudApiConfig {
            admin_token: admin_token.trim().to_owned(),
            maximum_body_bytes: 4 * 1024 * 1024,
            operations_status_file: env::var("KEYLEASE_OPERATIONS_STATUS_FILE")
                .ok()
                .filter(|value| !value.is_empty())
                .map(Into::into),
            public_url: env::var("KEYLEASE_SERVER_PUBLIC_URL")
                .ok()
                .filter(|value| !value.is_empty()),
            kms_root_key: match env::var("KEYLEASE_KMS_ROOT_KEY_FILE") {
                Ok(path) if !path.is_empty() => {
                    let key =
                        read_signing_key(Path::new(&path)).context("read the KMS root key")?;
                    Some(
                        key.as_slice()
                            .try_into()
                            .context("the KMS root key must be 32 bytes")?,
                    )
                }
                _ => None,
            },
            oidc: match env::var("KEYLEASE_OIDC_ISSUER") {
                Ok(issuer) if !issuer.is_empty() => Some(keylease_server::ConsoleOidc {
                    issuer,
                    client_id: required_env("KEYLEASE_OIDC_CLIENT_ID")?,
                    client_secret: match env::var("KEYLEASE_OIDC_CLIENT_SECRET_FILE") {
                        Ok(path) if !path.is_empty() => {
                            Some(read_secret_text(Path::new(&path), 4096)?.trim().to_owned())
                        }
                        _ => None,
                    },
                    allowed_email_domains: env::var("KEYLEASE_OIDC_ALLOWED_DOMAINS")
                        .unwrap_or_default()
                        .split(',')
                        .map(str::trim)
                        .filter(|domain| !domain.is_empty())
                        .map(str::to_owned)
                        .collect(),
                }),
                _ => None,
            },
        },
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .context("bind cloud listener")?;
    info!(%listen, "KeyLease Cloud listening");
    axum::serve(listener, router(state))
        .await
        .context("serve cloud API")
}

async fn migrate_only() -> Result<()> {
    let database_url = read_secret_text(
        Path::new(&required_env("KEYLEASE_DATABASE_URL_FILE")?),
        4096,
    )?;
    let repository = CloudRepository::connect(database_url.trim(), 2)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    repository
        .migrate()
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    repository
        .readiness()
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

async fn local_healthcheck() -> Result<()> {
    let listen: SocketAddr = env::var("KEYLEASE_SERVER_LISTEN")
        .or_else(|_| env::var("KEYLEASE_CLOUD_LISTEN"))
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()
        .context("invalid KEYLEASE_CLOUD_LISTEN")?;
    let response = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(4))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build healthcheck client")?
        .get(format!("http://127.0.0.1:{}/readyz", listen.port()))
        .send()
        .await
        .context("request Control Plane readiness")?;
    if !response.status().is_success() {
        bail!("Control Plane is not ready")
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

fn read_signing_key(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let metadata = fs::metadata(path).context("read signing-key metadata")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("control signing-key file must not be group/world accessible")
        }
    }
    if !metadata.is_file() || metadata.len() > 1024 {
        bail!("control signing-key path must be a small regular file")
    }
    let encoded = Zeroizing::new(fs::read_to_string(path).context("read control signing key")?);
    let decoded = STANDARD_NO_PAD
        .decode(encoded.trim())
        .context("control signing key must be unpadded base64")?;
    if decoded.len() != 32 {
        bail!("control signing key must decode to exactly 32 bytes")
    }
    Ok(Zeroizing::new(decoded))
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
