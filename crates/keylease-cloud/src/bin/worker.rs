use anyhow::{Context, Result, bail};
use chrono::{Duration, Utc};
use keylease_cloud::{CloudRepository, SiemExporter};
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
    let holder_id = env::var("LEASEGATE_INSTANCE_ID")
        .unwrap_or_else(|_| format!("worker-{}", uuid::Uuid::now_v7().simple()));
    let siem_exporter = env::var("KEYLEASE_SIEM_SECRETS_FILE")
        .ok()
        .filter(|path| !path.trim().is_empty())
        .map(|path| SiemExporter::from_file(Path::new(&path)))
        .transpose()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    info!(interval, %holder_id, siem_enabled = siem_exporter.is_some(), "KeyLease Cloud worker started");
    loop {
        let now = Utc::now();
        let leader = repository
            .acquire_worker_lease(
                "control-plane-maintenance",
                &holder_id,
                now,
                Duration::seconds((interval.saturating_mul(3)).clamp(15, 300) as i64),
            )
            .await
            .unwrap_or(false);
        if !leader {
            tokio::time::sleep(StdDuration::from_secs(interval)).await;
            continue;
        }
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
        if let Err(error) = repository.expire_access_reviews(now).await {
            warn!(error = %error, "access review expiry sweep failed");
        }
        if let Err(error) = repository.sweep_retention(now).await {
            warn!(error = %error, "retention sweep failed");
        }
        if let Err(error) = repository.sweep_security_alerts(now).await {
            warn!(error = %error, "security alert projection failed");
        }
        if let Some(exporter) = &siem_exporter {
            match repository.all_enabled_siem_destinations().await {
                Ok(destinations) => {
                    for destination in destinations {
                        let batch = match repository.pending_siem_batch(&destination, 250).await {
                            Ok(batch) => batch,
                            Err(error) => {
                                warn!(destination_id = %destination.destination_id, error = %error, "SIEM batch query failed");
                                continue;
                            }
                        };
                        if batch.events.is_empty() {
                            continue;
                        }
                        match exporter.export(&destination, &batch).await {
                            Ok(()) => {
                                if let Err(error) = repository
                                    .acknowledge_siem_batch(
                                        &destination.destination_id,
                                        batch.after,
                                        batch.cursor,
                                    )
                                    .await
                                {
                                    warn!(destination_id = %destination.destination_id, error = %error, "SIEM cursor acknowledgement failed");
                                }
                            }
                            Err(error) => {
                                warn!(destination_id = %destination.destination_id, error = %error, "SIEM delivery failed")
                            }
                        }
                    }
                }
                Err(error) => warn!(error = %error, "SIEM destination query failed"),
            }
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
