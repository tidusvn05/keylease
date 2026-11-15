//! `keylease cloud console-approvals …` and the loop of `keylease serve` that
//! reports pending approvals to the KeyLease Console, applies the decisions
//! signed there, and uploads the audit (ADR 0011). The service checks every
//! decision; this module only carries them over HTTPS.

use super::*;
use crate::cloud::Relay;
use keylease_core::console::{
    AccountPasskeys, AuditUpload, DecisionResults, MAX_AUDIT_UPLOAD, NodeReport, NodeReportResponse,
};
use reqwest::Method;

/// How often a node with console approvals on reports and fetches decisions.
const REPORT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
/// Audit is uploaded every this many reports (about once a minute).
const AUDIT_EVERY: u32 = 12;
/// Upload batches per audit round, so a large backlog is spread out.
const AUDIT_BATCHES_PER_ROUND: usize = 20;

#[derive(Debug, Subcommand)]
pub(crate) enum ConsoleApprovalsCommand {
    /// Pin the account's passkeys and turn console approvals on. Register the
    /// passkeys in the console first; run this again after adding one.
    Enable {
        /// Do not upload this vault's audit events to the server.
        #[arg(long)]
        no_audit: bool,
    },
    /// Turn console approvals (and the audit upload) off.
    Disable,
    /// Show the pinned passkeys.
    Status,
}

pub(crate) async fn command(
    service: &KeyLeaseService,
    command: ConsoleApprovalsCommand,
) -> Result<()> {
    match command {
        ConsoleApprovalsCommand::Enable { no_audit } => {
            let link = service
                .cloud_link()?
                .filter(|link| !link.member_id.is_empty())
                .ok_or_else(|| KeyLeaseError::InvalidRequest {
                    reason: "this vault is not linked to a cloud (keylease cloud init / join)"
                        .into(),
                })?;
            let relay = Relay::new(service, &link.url)?;
            let passkeys: AccountPasskeys = relay
                .send(Method::GET, "/v1/relay/console/passkeys", None, true, None)
                .await?;
            let config = service.console_approvals_enable(passkeys, !no_audit)?;
            println!(
                "Console approvals are on. Decisions must be signed at {} with one of:",
                config.origin
            );
            for passkey in &config.passkeys {
                println!("  {}", passkey.name);
            }
            if config.share_audit {
                println!("This vault's audit events are uploaded so the console can list them.");
            }
            println!("`keylease serve` checks for decisions every few seconds.");
            Ok(())
        }
        ConsoleApprovalsCommand::Disable => {
            if service.console_approvals_disable()? {
                println!("Console approvals are off.");
            } else {
                println!("Console approvals were not on.");
            }
            Ok(())
        }
        ConsoleApprovalsCommand::Status => match service.console_approvals_config()? {
            Some(config) => print_json(&json!({
                "enabled": true,
                "origin": config.origin,
                "passkeys": config.passkeys.iter().map(|p| &p.name).collect::<Vec<_>>(),
                "share_audit": config.share_audit,
                "enabled_at": config.enabled_at,
            })),
            None => print_json(&json!({"enabled": false})),
        },
    }
}

/// Reports pending approvals and applies the decisions that came back.
/// Returns how many decisions were handled.
pub(crate) async fn report_once(service: &KeyLeaseService, url: &str) -> Result<usize> {
    let approvals = service.console_pending_approvals()?;
    let relay = Relay::new(service, url)?;
    let body = serde_json::to_vec(&NodeReport { approvals }).map_err(|_| KeyLeaseError::Storage)?;
    let response: NodeReportResponse = relay
        .send(
            Method::PUT,
            "/v1/relay/console/report",
            Some(body),
            true,
            None,
        )
        .await?;
    if response.decisions.is_empty() {
        return Ok(0);
    }
    let results: Vec<_> = response
        .decisions
        .iter()
        .map(|decision| service.console_apply_decision(decision))
        .collect();
    let handled = results.len();
    relay
        .post::<_, Value>(
            "/v1/relay/console/results",
            &DecisionResults { results },
            true,
        )
        .await?;
    Ok(handled)
}

/// Uploads the audit events the server does not have yet.
pub(crate) async fn audit_once(service: &KeyLeaseService, url: &str) -> Result<usize> {
    let relay = Relay::new(service, url)?;
    let cursor: Value = relay
        .send(Method::GET, "/v1/relay/console/audit", None, true, None)
        .await?;
    let mut last = cursor["last_seq"].as_i64().unwrap_or(0);
    let mut uploaded = 0;
    for _ in 0..AUDIT_BATCHES_PER_ROUND {
        let events = service.console_audit_after(last, MAX_AUDIT_UPLOAD as u32)?;
        let Some(newest) = events.last().map(|entry| entry.seq) else {
            break;
        };
        uploaded += events.len();
        relay
            .post::<_, Value>("/v1/relay/console/audit", &AuditUpload { events }, true)
            .await?;
        last = newest;
    }
    Ok(uploaded)
}

/// The console loop of `keylease serve`. Quiet while console approvals are
/// off, the vault is unlinked or locked; a failure is printed once until it
/// changes.
pub(crate) fn spawn_loop(service: Arc<KeyLeaseService>) {
    tokio::spawn(async move {
        let mut round: u32 = 0;
        let mut last_problem = String::new();
        loop {
            tokio::time::sleep(REPORT_INTERVAL).await;
            let Ok(Some(config)) = service.console_approvals_config() else {
                continue;
            };
            let Ok(Some(link)) = service.cloud_link() else {
                continue;
            };
            if link.member_id.is_empty() {
                continue;
            }
            let mut outcome = report_once(&service, &link.url).await.map(|_| ());
            if outcome.is_ok() && config.share_audit && round.is_multiple_of(AUDIT_EVERY) {
                outcome = audit_once(&service, &link.url).await.map(|_| ());
            }
            round = round.wrapping_add(1);
            let problem = match outcome {
                Ok(()) | Err(KeyLeaseError::VaultLocked { .. }) => String::new(),
                Err(error) => format!("{error:?}"),
            };
            if problem != last_problem && !problem.is_empty() {
                eprintln!("KeyLease console approvals: {problem}");
            }
            last_problem = problem;
        }
    });
}
