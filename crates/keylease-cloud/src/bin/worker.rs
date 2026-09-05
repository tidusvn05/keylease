use anyhow::{Context, Result, bail};
use chrono::{Duration, Utc};
use keylease_cloud::CloudRepository;
use std::{env, fs, path::Path, time::Duration as StdDuration};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .json()
        .init();
    let path =
        env::var("KEYLEASE_DATABASE_URL_FILE").context("KEYLEASE_DATABASE_URL_FILE is required")?;
    let database_url = read_secret_text(Path::new(&path), 4096)?;
    let repository = CloudRepository::connect(database_url.trim(), 5)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    repository
        .migrate()
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let interval = env::var("KEYLEASE_WORKER_INTERVAL_SECONDS")
        .unwrap_or_else(|_| "5".into())
        .parse::<u64>()
        .context("invalid worker interval")?
        .clamp(1, 300);
    info!(interval, "KeyLease Cloud worker started");
    loop {
        let now = Utc::now();
        match repository
            .mark_stale_edges_offline(now - Duration::minutes(2))
            .await
        {
            Ok(changed) if changed > 0 => info!(changed, "marked stale Edges offline"),
            Err(error) => warn!(error = %error, "Edge health sweep failed"),
            _ => {}
        }
        if let Err(error) = repository.expire_pending_approvals(now).await {
            warn!(error = %error, "approval expiry sweep failed");
        }
        if let Err(error) = repository.expire_pending_policy_proposals(now).await {
            warn!(error = %error, "policy proposal expiry sweep failed");
        }
        if let Err(error) = repository.expire_credential_lease_index(now).await {
            warn!(error = %error, "credential lease index expiry sweep failed");
        }
        if let Err(error) = repository
            .sweep_connection_posture(now, now - Duration::minutes(5), now + Duration::days(7))
            .await
        {
            warn!(error = %error, "connection posture/expiry alert sweep failed");
        }
        if let Err(error) = repository.dispatch_outbox_batch(100).await {
            warn!(error = %error, "outbox dispatch failed");
        }
        tokio::time::sleep(StdDuration::from_secs(interval)).await;
    }
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
