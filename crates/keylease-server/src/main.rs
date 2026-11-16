use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use keylease_protocol::ControlSigner;
use keylease_server::{CloudApiConfig, CloudApiState, CloudRepository, router};
use std::{env, fs, net::SocketAddr, path::Path};
use tracing::info;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

mod expose;
mod setup;
mod wizard;

fn main() -> Result<()> {
    // Before the runtime starts any thread: setup's server.env becomes the
    // environment unless it is already set.
    if !matches!(
        env::args().nth(1).as_deref(),
        Some("setup" | "status" | "uninstall" | "owner-code" | "-h" | "--help" | "help")
    ) {
        setup::load_env_file()?;
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("start the async runtime")?
        .block_on(async_main())
}

async fn async_main() -> Result<()> {
    match env::args().nth(1).as_deref() {
        Some("setup") => return setup::run(env::args().skip(2).collect()).await,
        Some("status") => return setup::status(env::args().skip(2).collect()).await,
        Some("uninstall") => return setup::uninstall(env::args().skip(2).collect()),
        Some("owner-code") => return setup::owner_code(env::args().skip(2).collect()),
        Some("-h" | "--help" | "help") => {
            println!(
                "keylease-server — the self-hosted KeyLease server\n\n\
                 \x20 keylease-server setup       install: secrets, a private PostgreSQL, a service\n\
                 \x20 keylease-server status      is it running, and where\n\
                 \x20 keylease-server uninstall   stop and remove the service (data is kept)\n\
                 \x20 keylease-server owner-code  a one-time code to link your laptop's vault\n\
                 \x20 keylease-server             run in the foreground (what the service runs)\n\
                 \x20 keylease-server migrate | healthcheck | kms …\n\n\
                 Docs: https://github.com/tidusvn05/keylease/blob/main/docs/server-quick-install.md"
            );
            return Ok(());
        }
        _ => {}
    }
    if env::args().nth(1).as_deref() == Some("healthcheck") {
        return local_healthcheck().await;
    }
    if env::args().nth(1).as_deref() == Some("migrate") {
        return migrate_only().await;
    }
    if env::args().nth(1).as_deref() == Some("kms") {
        return kms_command(env::args().skip(2).collect()).await;
    }
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .json()
        .init();
    setup::ensure_postgres()?;
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
            kms_root_key: match keylease_server::kms_root::settings_from_env()? {
                Some(settings) => {
                    let key = keylease_server::kms_root::load_root_key(&settings)
                        .await
                        .context("load the KMS root key")?;
                    info!(
                        fingerprint = keylease_server::kms_root::fingerprint(&key),
                        "KMS root key loaded"
                    );
                    Some(*key)
                }
                None => None,
            },
            allow_private_network: env::var("KEYLEASE_GATEWAY_ALLOW_PRIVATE")
                .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true")),
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
    keylease_server::spawn_reaper(state.clone());
    keylease_server::spawn_audit_push(state.clone());
    axum::serve(listener, router(state))
        .await
        .context("serve cloud API")
}

async fn migrate_only() -> Result<()> {
    setup::ensure_postgres()?;
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

/// `keylease-server kms init|wrap FILE|check`: manage the wrapped KMS root
/// key with the provider from the environment (docs/enterprise.md).
async fn kms_command(args: Vec<String>) -> Result<()> {
    use keylease_server::kms_root;
    let settings = kms_root::settings_from_env()?
        .context("set KEYLEASE_KMS_PROVIDER (aws, gcp or pkcs11) and its settings")?;
    let wrapped_path = || {
        settings
            .wrapped_file
            .clone()
            .context("set KEYLEASE_KMS_WRAPPED_ROOT_KEY_FILE")
    };
    let write_new = |path: &Path, wrapped: &str| -> Result<()> {
        use std::io::Write;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(path)
            .with_context(|| format!("create {} (it must not exist yet)", path.display()))?;
        writeln!(file, "{wrapped}").context("write the wrapped root key")
    };
    match args.first().map(String::as_str) {
        Some("init") => {
            use rand::RngCore;
            let path = wrapped_path()?;
            if path.exists() {
                bail!(
                    "{} exists already; init never replaces a root key",
                    path.display()
                );
            }
            let mut key = Zeroizing::new([0_u8; 32]);
            rand::rng().fill_bytes(key.as_mut_slice());
            let wrapped = kms_root::wrap_root_key(&settings, &key).await?;
            write_new(&path, &wrapped)?;
            // Check that the provider gives the key back.
            let loaded = kms_root::load_root_key(&settings).await?;
            if *loaded != *key {
                bail!(
                    "the provider did not give the same key back; {} is unusable",
                    path.display()
                );
            }
            println!(
                "Wrote a new wrapped root key to {} (fingerprint {}).",
                path.display(),
                kms_root::fingerprint(&key)
            );
            Ok(())
        }
        Some("wrap") => {
            let source = args
                .get(1)
                .context("usage: keylease-server kms wrap ROOT_KEY_FILE")?;
            let key = kms_root::read_root_key_file(Path::new(source))?;
            let path = wrapped_path()?;
            write_new(&path, &kms_root::wrap_root_key(&settings, &key).await?)?;
            let loaded = kms_root::load_root_key(&settings).await?;
            if *loaded != *key {
                bail!(
                    "the provider did not give the same key back; {} is unusable",
                    path.display()
                );
            }
            println!(
                "Wrapped {} into {} (fingerprint {}). Switch the server to the provider, check it starts, then delete {} and its backups only if another copy of the key is kept offline.",
                source,
                path.display(),
                kms_root::fingerprint(&key),
                source
            );
            Ok(())
        }
        Some("check") => {
            let key = kms_root::load_root_key(&settings).await?;
            println!(
                "The root key loads (fingerprint {}).",
                kms_root::fingerprint(&key)
            );
            Ok(())
        }
        _ => bail!("usage: keylease-server kms init | wrap ROOT_KEY_FILE | check"),
    }
}
