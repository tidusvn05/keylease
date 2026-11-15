//! `keylease cloud org …` and the loop of `keylease serve` that keeps the
//! organization's signed policy current on a managed node (ADR 0012). The
//! service checks every policy; this module only carries it over HTTPS.

use super::*;

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
    service.cloud_require_link().map(|link| link.url)
}

pub(crate) async fn command(service: &KeyLeaseService, command: OrgCommand) -> Result<()> {
    match command {
        OrgCommand::Join { code } => {
            let code = match code {
                Some(code) => Zeroizing::new(code),
                None => prompt("Enrollment code: ")?,
            };
            let joined = service.org_join_remote(&code).await?;
            println!(
                "This vault is a managed node of {} ({}). Server key {} pinned.",
                joined.org_name, joined.org_id, joined.key_id
            );
            match joined.policy_version {
                Some(version) => println!("Organization policy version {version} applies."),
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
            let problem = match service.org_policy_refresh(&url).await {
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
