//! `keylease cloud org …` and the loop of `keylease serve` that keeps the
//! organization's signed policy current on a managed node (ADR 0012). The
//! service checks every policy; this module only carries it over HTTPS.

use super::*;
use crate::cloud::Relay;
use keylease_core::managed::{AppliedPolicy, OrgNodeJoin, OrgNodeJoined, OrgPolicyAnswer};
use reqwest::Method;

/// How often a managed node fetches its organization's policy.
const POLICY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Debug, Subcommand)]
pub(crate) enum OrgCommand {
    /// Join an organization with an enrollment code from its console
    /// (Organization → Managed nodes). Its rules then apply to this vault.
    Join {
        /// The code. Prefer leaving it out to be asked.
        #[arg(long)]
        code: Option<String>,
    },
    /// Leave the organization: its rules stop applying.
    Leave,
    /// The organization and the policy version in force.
    Status,
}

fn linked_url(service: &KeyLeaseService) -> Result<String> {
    service
        .cloud_link()?
        .filter(|link| !link.member_id.is_empty())
        .map(|link| link.url)
        .ok_or_else(|| KeyLeaseError::InvalidRequest {
            reason: "this vault is not linked to a cloud (keylease cloud init / join)".into(),
        })
}

pub(crate) async fn command(service: &KeyLeaseService, command: OrgCommand) -> Result<()> {
    match command {
        OrgCommand::Join { code } => {
            let code = match code {
                Some(code) => Zeroizing::new(code),
                None => prompt("Enrollment code: ")?,
            };
            let url = linked_url(service)?;
            let relay = Relay::new(service, &url)?;
            let joined: OrgNodeJoined = relay
                .post(
                    "/v1/relay/org-nodes/join",
                    &OrgNodeJoin {
                        code: code.trim().to_owned(),
                    },
                    true,
                )
                .await?;
            let membership = service.org_join_commit(&joined)?;
            let version = policy_once(service, &url).await.ok();
            println!(
                "This vault is a managed node of {} ({}). Server key {} pinned.",
                membership.org_name, membership.org_id, membership.key_id
            );
            match version {
                Some(Some(version)) => println!("Organization policy version {version} applies."),
                _ => println!(
                    "The organization has no policy yet; `keylease serve` checks every minute."
                ),
            }
            Ok(())
        }
        OrgCommand::Leave => {
            if service.org_leave()? {
                println!("Left the organization; its rules no longer apply.");
            } else {
                println!("This vault is not a managed node.");
            }
            Ok(())
        }
        OrgCommand::Status => match service.org_membership()? {
            Some(membership) => print_json(&json!({
                "org_id": membership.org_id,
                "org_name": membership.org_name,
                "key_id": membership.key_id,
                "joined_at": membership.joined_at,
                "policy_version": service.org_policy_version()?,
            })),
            None => print_json(&json!({"member": false})),
        },
    }
}

/// Fetches, checks and applies the organization's policy, then reports the
/// version in force.
pub(crate) async fn policy_once(service: &KeyLeaseService, url: &str) -> Result<Option<u64>> {
    let relay = Relay::new(service, url)?;
    let answer: OrgPolicyAnswer = relay
        .send(Method::GET, "/v1/relay/org-policy", None, true, None)
        .await?;
    let Some(signed) = answer.policy else {
        return Ok(None);
    };
    let version = service.org_apply_policy(&signed)?;
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

/// The managed-node loop of `keylease serve`; quiet unless the vault joined
/// an organization. A failure is printed once until it changes.
pub(crate) fn spawn_loop(service: Arc<KeyLeaseService>) {
    tokio::spawn(async move {
        let mut last_problem = String::new();
        loop {
            tokio::time::sleep(POLICY_INTERVAL).await;
            if !matches!(service.org_membership(), Ok(Some(_))) {
                continue;
            }
            let Ok(url) = linked_url(&service) else {
                continue;
            };
            let problem = match policy_once(&service, &url).await {
                Ok(_) | Err(KeyLeaseError::VaultLocked { .. }) => String::new(),
                Err(error) => format!("{error:?}"),
            };
            if problem != last_problem && !problem.is_empty() {
                eprintln!("KeyLease organization policy: {problem}");
            }
            last_problem = problem;
        }
    });
}
