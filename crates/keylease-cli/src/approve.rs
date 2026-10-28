//! `keylease approve`: decide agent requests one by one at a terminal.
//!
//! It asks for the master password once, then shows each pending request and
//! keeps waiting for more, so an agent working through several steps needs no
//! copied approval IDs. The suggested answer is a one-hour trust as wide as the
//! request allows (its project, else its item); a secret reveal is only ever
//! approved once.

use super::*;
use std::collections::HashSet;
use std::io::{BufRead, Write};

/// How often an idle `keylease approve` looks for new requests.
const POLL: std::time::Duration = std::time::Duration::from_secs(2);

#[derive(Args)]
pub(crate) struct ApproveArgs {
    /// Exit once nothing is pending instead of waiting for new requests.
    #[arg(long)]
    no_wait: bool,
}

/// The answer offered on Enter for a request.
fn suggested(approval: &ApprovalRecord) -> Option<TrustDecision> {
    let ceiling = max_trust_seconds(approval.risk.as_ref().unwrap_or(&RiskTier::R4))?;
    if ceiling < TrustDuration::Hour1.seconds() {
        return None;
    }
    let on_item = approval
        .resource
        .as_deref()
        .and_then(|resource| resource.split('/').nth(3))
        .is_some_and(|segment| segment.starts_with("item_"));
    let scope = if approval.project_id.is_some() {
        TrustScope::Project
    } else if on_item {
        TrustScope::Item
    } else {
        TrustScope::Resource
    };
    Some(TrustDecision {
        scope,
        duration: TrustDuration::Hour1,
    })
}

fn describe(decision: Option<TrustDecision>, project: Option<&str>) -> String {
    match decision.map(|decision| decision.scope) {
        None => "approve this once".into(),
        Some(TrustScope::Project) => format!(
            "trust everyday work in project {} for 1h",
            project.unwrap_or("?")
        ),
        Some(TrustScope::Item) => "trust this on the whole item for 1h".into(),
        Some(TrustScope::Resource) => "trust this for 1h".into(),
    }
}

pub(crate) fn approve(db: &Path, args: ApproveArgs) -> Result<()> {
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "`keylease approve` is interactive; use `keylease approval approve ID` in \
                     scripts"
                .into(),
        });
    }
    let service = admin_service(db)?;
    let mut seen = HashSet::new();
    let mut waiting = false;
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    loop {
        let fresh: Vec<_> = service
            .list_pending_approvals_admin(100)?
            .into_iter()
            .filter(|approval| !seen.contains(&approval.id.0))
            .collect();
        if fresh.is_empty() {
            if args.no_wait {
                return Ok(());
            }
            if !waiting {
                eprintln!("Waiting for agent requests… (Ctrl-C to stop)");
                waiting = true;
            }
            std::thread::sleep(POLL);
            continue;
        }
        waiting = false;
        for approval in fresh {
            seen.insert(approval.id.0.clone());
            let (title, project) = service.approval_target_admin(&approval)?;
            let agent = approval
                .agent_id
                .as_ref()
                .map(|id| id.0.trim_start_matches("agent_").to_owned())
                .unwrap_or_else(|| "?".into());
            let risk = approval.risk.as_ref().unwrap_or(&RiskTier::R4);
            eprintln!();
            eprintln!(
                "{agent} wants {} on {}{}  [{}]",
                approval.action.as_deref().unwrap_or("?"),
                title.as_deref().map_or_else(
                    || approval.resource.clone().unwrap_or_default(),
                    |title| format!("\"{title}\"")
                ),
                project
                    .as_deref()
                    .map(|project| format!(" in {project}"))
                    .unwrap_or_default(),
                serde_json::to_value(risk)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_uppercase))
                    .unwrap_or_default(),
            );
            if let Some(purpose) = &approval.purpose {
                eprintln!("  purpose (from the agent): {purpose}");
            }
            let suggestion = suggested(&approval);
            loop {
                eprint!(
                    "  [Enter] {}{}  [d] deny  [s] skip  [q] quit: ",
                    describe(suggestion, project.as_deref()),
                    if suggestion.is_some() {
                        "  [o] once"
                    } else {
                        ""
                    }
                );
                let _ = std::io::stderr().flush();
                let Some(Ok(answer)) = lines.next() else {
                    return Ok(());
                };
                let (approve, trust) = match answer.trim() {
                    "" => (true, suggestion),
                    "o" if suggestion.is_some() => (true, None),
                    "d" => (false, None),
                    "s" => break,
                    "q" => return Ok(()),
                    _ => continue,
                };
                match service.decide_approval_admin(&approval.id.0, approve, trust) {
                    Ok(outcome) => {
                        let done = match (&outcome.trust, approve) {
                            (Some(trust), _) => format!(
                                "trusted until {}",
                                trust
                                    .expires_at
                                    .with_timezone(&chrono::Local)
                                    .format("%H:%M")
                            ),
                            (None, true) => "approved once".into(),
                            (None, false) => "denied".into(),
                        };
                        eprintln!("  ✓ {done}");
                    }
                    // Expired or decided elsewhere meanwhile: say so and move on.
                    Err(error) => eprintln!(
                        "  ! {}",
                        serde_json::to_string(&error).unwrap_or_else(|_| "failed".into())
                    ),
                }
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approval(resource: &str, risk: RiskTier, project: bool) -> ApprovalRecord {
        ApprovalRecord {
            id: ApprovalId::new(),
            request_digest_hex: String::new(),
            policy_version: 1,
            state: ApprovalState::Pending,
            expires_at: Utc::now(),
            request_id: None,
            agent_id: None,
            connection_id: None,
            action: None,
            resource: Some(resource.into()),
            created_at: None,
            task_id: None,
            risk: Some(risk),
            semantic_summary: None,
            purpose: None,
            project_id: project.then(ProjectId::new),
        }
    }

    #[test]
    fn enter_suggests_the_widest_hour_the_request_allows() {
        let scope = |approval: ApprovalRecord| suggested(&approval).map(|d| d.scope);
        assert_eq!(
            scope(approval("kl://vault_a/item_b/password", RiskTier::R2, true)),
            Some(TrustScope::Project)
        );
        assert_eq!(
            scope(approval(
                "kl://vault_a/item_b/password",
                RiskTier::R3,
                false
            )),
            Some(TrustScope::Item)
        );
        assert_eq!(
            scope(approval("kl://vault_a/group/group_c", RiskTier::R1, false)),
            Some(TrustScope::Resource)
        );
        // A reveal is approved once, whatever the project.
        assert_eq!(
            scope(approval("kl://vault_a/item_b/password", RiskTier::R4, true)),
            None
        );
    }
}
