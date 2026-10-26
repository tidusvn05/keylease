//! Approval decisions, time-boxed trusts and agent enrollment (ADR 0005).

use super::*;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

#[derive(Subcommand)]
pub(crate) enum TrustCommand {
    /// List active trusts.
    List,
    /// Revoke one trust immediately.
    Revoke { id: String },
}

#[derive(Args)]
pub(crate) struct DecideArgs {
    id: String,
    #[arg(long, conflicts_with = "deny", required_unless_present = "deny")]
    approve: bool,
    #[arg(long)]
    deny: bool,
    /// Trust this agent for a window instead of one use.
    #[arg(long, value_parser = ["once", "30m", "1h", "6h", "1d", "3d", "7d"], requires = "approve")]
    trust: Option<String>,
    /// What the trust covers: the exact resource, or every field of its item.
    #[arg(long, default_value = "resource", value_parser = ["resource", "item"])]
    scope: String,
}

pub(crate) async fn decide(cli: &Cli, socket: &Path, args: DecideArgs) -> Result<()> {
    let trust = args
        .trust
        .as_deref()
        .and_then(TrustDuration::parse)
        .map(|duration| TrustDecision {
            scope: if args.scope == "item" {
                TrustScope::Item
            } else {
                TrustScope::Resource
            },
            duration,
        });
    print_rpc(
        socket,
        RpcRequest::ApprovalDecide {
            auth: auth(cli)?,
            id: args.id,
            approve: args.approve,
            trust,
        },
    )
    .await
}

pub(crate) async fn trust_command(cli: &Cli, socket: &Path, command: TrustCommand) -> Result<()> {
    match command {
        TrustCommand::List => print_rpc(socket, RpcRequest::TrustsList { auth: auth(cli)? }).await,
        TrustCommand::Revoke { id } => {
            print_rpc(
                socket,
                RpcRequest::TrustRevoke {
                    auth: auth(cli)?,
                    id,
                },
            )
            .await
        }
    }
}

/// Enrolls an agent and writes its token to a new mode-0600 file.
///
/// The token is never printed: an agent reading this command's output must
/// not learn a credential, and a human pasting it into a chat would leak one.
pub(crate) async fn enroll_agent(
    cli: &Cli,
    socket: &Path,
    name: &str,
    token_file: Option<PathBuf>,
) -> Result<()> {
    let path = match token_file {
        Some(path) => path,
        None => {
            let directory = managed_home()
                .ok_or(KeyLeaseError::Storage)?
                .join("clients");
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&directory)
                .map_err(|_| KeyLeaseError::Storage)?;
            directory.join(format!("agent_{name}.token"))
        }
    };
    if path.exists() {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "token file already exists; choose another --token-file".into(),
        });
    }
    let value = rpc(
        socket,
        RpcRequest::AgentEnroll {
            auth: auth(cli)?,
            name: name.into(),
        },
    )
    .await?;
    let agent_id = value
        .get("agent_id")
        .and_then(Value::as_str)
        .ok_or(KeyLeaseError::Storage)?
        .to_owned();
    let token = Zeroizing::new(
        value
            .get("token")
            .and_then(Value::as_str)
            .ok_or(KeyLeaseError::Storage)?
            .to_owned(),
    );
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|_| KeyLeaseError::Storage)?;
    file.write_all(token.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| KeyLeaseError::Storage)?;
    print_json(&json!({
        "agent_id": agent_id,
        "token_file": path,
        "baseline_rule_ids": value.get("baseline_rule_ids"),
        "env": {
            "KEYLEASE_AGENT_ID": agent_id,
            "KEYLEASE_CLIENT_TOKEN_FILE": path,
        },
        "next": "Set these variables in the agent's environment. Secret reads and \
                 writes now queue an approval; pass --wait-approval 120 to wait for it."
    }))
}
