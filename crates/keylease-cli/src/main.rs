use chrono::{Duration, Utc};
use clap::{Args, Parser, Subcommand};
use keylease_core::*;
use keylease_service::{EntryPatch, KeyLeaseService, NewEntryInput};
use keylease_store::NativeStore;
use leasegate_connectors::Connector;
use leasegate_policy::{PolicyTemplateInput, PolicyTemplateKind, materialize_provider_template};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};
use zeroize::Zeroizing;

const MAX_LOCAL_JSON_BYTES: usize = 4 * 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "keylease",
    version,
    about = "Local-first encrypted vault and LeaseGate agent gateway"
)]
struct Cli {
    #[arg(long, global = true, default_value = "keylease.sqlite")]
    db: PathBuf,
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    #[arg(long, global = true)]
    agent_id: Option<String>,
    #[arg(long, global = true)]
    client_token_file: Option<PathBuf>,
    #[arg(long, global = true, default_value = "default")]
    client_session: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long, default_value_t = 28800)]
        session_ttl_seconds: i64,
        #[arg(long)]
        start_locked: bool,
    },
    Status,
    Unlock {
        #[arg(long, default_value_t = 28800)]
        session_ttl_seconds: i64,
    },
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
    Client {
        #[command(subcommand)]
        command: ClientCommand,
    },
    Grant {
        #[command(subcommand)]
        command: GrantCommand,
    },
    Groups {
        #[command(subcommand)]
        command: GroupCommand,
    },
    Entries {
        #[command(subcommand)]
        command: EntryCommand,
    },
    Connection {
        #[command(subcommand)]
        command: ConnectionCommand,
    },
    Lease {
        #[command(subcommand)]
        command: LeaseCommand,
    },
    Approval {
        #[command(subcommand)]
        command: ApprovalCommand,
    },
    Gate {
        #[command(subcommand)]
        command: GateCommand,
    },
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    KillSwitch {
        #[arg(value_parser=["on","off"])]
        state: String,
    },
    Lock,
    GeneratePassword {
        #[arg(long, default_value_t = 32)]
        length: usize,
    },
    Contracts,
}
#[derive(Subcommand)]
enum VaultCommand {
    Init,
    ChangePassword,
    ImportKdbx {
        path: PathBuf,
        #[arg(long)]
        commit: bool,
    },
    ImportOnepux {
        path: PathBuf,
        #[arg(long)]
        commit: bool,
        #[arg(long)]
        acknowledge_plaintext: bool,
    },
    ExportKdbx {
        path: PathBuf,
        #[arg(long)]
        force: bool,
        #[arg(long = "item-id")]
        item_ids: Vec<String>,
    },
    Backup {
        path: PathBuf,
        #[arg(long)]
        force: bool,
    },
    Restore {
        path: PathBuf,
    },
}
#[derive(Subcommand)]
enum ClientCommand {
    Register { name: String },
    List,
    Revoke { id: String },
}
#[derive(Subcommand)]
enum GrantCommand {
    Create(GrantArgs),
    Template(GrantTemplateArgs),
    List,
    Revoke { id: String },
}
#[derive(Args)]
struct GrantTemplateArgs {
    #[arg(long)]
    client: String,
    #[arg(long)]
    connection_id: String,
    #[arg(long)]
    provider: String,
    #[arg(long)]
    resource: String,
    #[arg(long, default_value = "read_only", value_parser = ["read_only", "contributor"])]
    profile: String,
    #[arg(long, default_value_t = 28800)]
    ttl_seconds: u64,
}
#[derive(Args)]
struct GrantArgs {
    #[arg(long)]
    client: String,
    #[arg(long)]
    resource: String,
    #[arg(long)]
    connection_id: Option<String>,
    #[arg(long, value_delimiter = ',')]
    allow: Vec<String>,
    #[arg(long)]
    argument_equals_json: Option<String>,
    #[arg(long,default_value="allow",value_parser=["allow","deny","require_approval"])]
    effect: String,
    #[arg(long, default_value_t = 28800)]
    ttl_seconds: u64,
    #[arg(long, default_value_t = 600)]
    max_lease_ttl_seconds: u64,
    #[arg(long, default_value_t = 100)]
    max_uses: u64,
    #[arg(long, default_value_t = 100)]
    max_items: u64,
    #[arg(long, default_value_t = 10000)]
    max_cells: u64,
    #[arg(long, default_value_t = 1048576)]
    max_response_bytes: u64,
    #[arg(long, default_value_t = 1000)]
    max_rows_changed: u64,
    #[arg(long, default_value_t = 1)]
    max_concurrent: u32,
    #[arg(long)]
    max_task_requests: Option<u64>,
    #[arg(long)]
    max_task_items: Option<u64>,
    #[arg(long)]
    max_task_cells: Option<u64>,
    #[arg(long)]
    max_task_response_bytes: Option<u64>,
    #[arg(long)]
    max_task_rows_changed: Option<u64>,
}
#[derive(Subcommand)]
enum GroupCommand {
    Create {
        name: String,
        #[arg(long)]
        parent_id: Option<String>,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        dry_run: bool,
    },
    List,
    Rename {
        id: String,
        name: String,
        #[arg(long)]
        if_revision: u64,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        dry_run: bool,
    },
    Delete {
        id: String,
        #[arg(long)]
        if_revision: u64,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        dry_run: bool,
    },
}
#[derive(Subcommand)]
enum EntryCommand {
    Search {
        query: String,
    },
    Get {
        id: String,
    },
    Create {
        #[arg(long, default_value = "-")]
        input_json: String,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        dry_run: bool,
    },
    Update {
        id: String,
        #[arg(long, default_value = "-")]
        patch_json: String,
        #[arg(long)]
        if_revision: u64,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        dry_run: bool,
    },
    Delete {
        id: String,
        #[arg(long)]
        if_revision: u64,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        dry_run: bool,
    },
    Reveal {
        id: String,
        #[arg(long)]
        field: String,
    },
    Totp {
        id: String,
    },
    History {
        id: String,
    },
}
#[derive(Subcommand)]
enum ConnectionCommand {
    GoogleOauthBegin {
        #[arg(long, default_value = "-")]
        input_json: String,
    },
    GoogleOauthComplete {
        flow_id: String,
    },
    Add {
        provider: String,
        #[arg(long, default_value = "-")]
        input_json: String,
    },
    List,
    Enroll {
        id: String,
        resource: String,
    },
    Unenroll {
        id: String,
        resource: String,
    },
    Test {
        id: String,
    },
    Refresh {
        id: String,
    },
    Disconnect {
        id: String,
    },
    Revoke {
        id: String,
    },
}
#[derive(Subcommand)]
enum LeaseCommand {
    Request {
        #[arg(long, default_value = "-")]
        input_json: String,
        #[arg(long, default_value_t = 600)]
        ttl_seconds: u64,
        #[arg(long, default_value_t = 1)]
        max_uses: u64,
        #[arg(long)]
        approval_id: Option<String>,
    },
    Revoke {
        id: String,
    },
}
#[derive(Subcommand)]
enum ApprovalCommand {
    Approve { id: String },
}
#[derive(Subcommand)]
enum GateCommand {
    Execute {
        #[arg(long, default_value = "-")]
        input_json: String,
        #[arg(long)]
        lease_token_file: PathBuf,
    },
}
#[derive(Subcommand)]
enum AuditCommand {
    Query {
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    Recovery {
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RpcAuth {
    agent_id: AgentId,
    token: SecretValue,
    session_id: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum RpcRequest {
    Status,
    Unlock {
        auth: RpcAuth,
        password: SecretValue,
        session_ttl_seconds: i64,
    },
    GroupsList {
        auth: RpcAuth,
    },
    GroupsCreate {
        auth: RpcAuth,
        name: String,
        parent_id: Option<GroupId>,
        idempotency_key: String,
        dry_run: bool,
    },
    GroupsUpdate {
        auth: RpcAuth,
        id: GroupId,
        name: String,
        if_revision: u64,
        idempotency_key: String,
        dry_run: bool,
    },
    GroupsDelete {
        auth: RpcAuth,
        id: GroupId,
        if_revision: u64,
        idempotency_key: String,
        dry_run: bool,
    },
    EntriesSearch {
        auth: RpcAuth,
        query: String,
    },
    EntriesGet {
        auth: RpcAuth,
        id: ItemId,
    },
    EntriesCreate {
        auth: RpcAuth,
        input: NewEntryInput,
        idempotency_key: String,
        dry_run: bool,
    },
    EntriesUpdate {
        auth: RpcAuth,
        id: ItemId,
        patch: EntryPatch,
        if_revision: u64,
        idempotency_key: String,
        dry_run: bool,
    },
    EntriesDelete {
        auth: RpcAuth,
        id: ItemId,
        if_revision: u64,
        idempotency_key: String,
        dry_run: bool,
    },
    EntriesReveal {
        auth: RpcAuth,
        id: ItemId,
        field: String,
    },
    EntriesTotp {
        auth: RpcAuth,
        id: ItemId,
    },
    EntriesHistory {
        auth: RpcAuth,
        id: ItemId,
    },
    GeneratePassword {
        auth: RpcAuth,
        length: usize,
    },
    ConnectionsList {
        auth: RpcAuth,
    },
    ConnectionAdd {
        auth: RpcAuth,
        provider: String,
        credential: SecretValue,
        authorized_resources: Vec<String>,
    },
    ConnectionEnroll {
        auth: RpcAuth,
        id: ConnectionId,
        resource: String,
    },
    ConnectionUnenroll {
        auth: RpcAuth,
        id: ConnectionId,
        resource: String,
    },
    ConnectionTest {
        auth: RpcAuth,
        id: ConnectionId,
    },
    ConnectionRefresh {
        auth: RpcAuth,
        id: ConnectionId,
    },
    ConnectionDisconnect {
        auth: RpcAuth,
        id: ConnectionId,
    },
    ConnectionRevoke {
        auth: RpcAuth,
        id: ConnectionId,
    },
    ConnectionGoogleOauthBegin {
        auth: RpcAuth,
        client_id: String,
        client_secret: Option<SecretValue>,
    },
    ConnectionGoogleOauthComplete {
        auth: RpcAuth,
        flow_id: String,
    },
    ApprovalsList {
        auth: RpcAuth,
        limit: u32,
    },
    ApprovalDecide {
        auth: RpcAuth,
        id: String,
        approve: bool,
    },
    AuditQuery {
        auth: RpcAuth,
        limit: u32,
    },
    LeaseRequest {
        auth: RpcAuth,
        request: ActionRequest,
        ttl_seconds: u64,
        max_uses: u64,
        approval_id: Option<String>,
    },
    GateExecute {
        auth: RpcAuth,
        lease_token: SecretValue,
        request: ActionRequest,
    },
    Lock {
        auth: RpcAuth,
    },
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        let payload = serde_json::to_string(&error)
            .unwrap_or_else(|_| json!({"error":"internal"}).to_string());
        println!("{payload}");
        std::process::exit(exit_code(&error));
    }
}

async fn run() -> Result<()> {
    let mut cli = Cli::parse();
    let socket = cli.socket.clone().unwrap_or_else(default_socket);
    let command = std::mem::replace(&mut cli.command, Command::Status);
    match command {
        Command::Serve {
            session_ttl_seconds,
            start_locked,
        } => serve(&cli.db, &socket, session_ttl_seconds, start_locked).await,
        Command::Status => print_rpc(&socket, RpcRequest::Status).await,
        Command::Unlock {
            session_ttl_seconds,
        } => {
            let password = prompt("Master password: ")?;
            print_rpc(
                &socket,
                RpcRequest::Unlock {
                    auth: auth(&cli)?,
                    password: SecretValue(password.to_string()),
                    session_ttl_seconds,
                },
            )
            .await
        }
        Command::Vault { command } => vault_command(&cli.db, command),
        Command::Client { command } => client_command(&cli.db, command),
        Command::Grant { command } => grant_command(&cli.db, command),
        Command::Groups { command } => match command {
            GroupCommand::Create {
                name,
                parent_id,
                idempotency_key,
                dry_run,
            } => {
                let auth = auth(&cli)?;
                print_rpc(
                    &socket,
                    RpcRequest::GroupsCreate {
                        auth,
                        name,
                        parent_id: parent_id.map(GroupId),
                        idempotency_key,
                        dry_run,
                    },
                )
                .await
            }
            GroupCommand::List => {
                print_rpc(&socket, RpcRequest::GroupsList { auth: auth(&cli)? }).await
            }
            GroupCommand::Rename {
                id,
                name,
                if_revision,
                idempotency_key,
                dry_run,
            } => {
                print_rpc(
                    &socket,
                    RpcRequest::GroupsUpdate {
                        auth: auth(&cli)?,
                        id: GroupId(id),
                        name,
                        if_revision,
                        idempotency_key,
                        dry_run,
                    },
                )
                .await
            }
            GroupCommand::Delete {
                id,
                if_revision,
                idempotency_key,
                dry_run,
            } => {
                print_rpc(
                    &socket,
                    RpcRequest::GroupsDelete {
                        auth: auth(&cli)?,
                        id: GroupId(id),
                        if_revision,
                        idempotency_key,
                        dry_run,
                    },
                )
                .await
            }
        },
        Command::Entries { command } => entry_command(&cli, &socket, command).await,
        Command::Connection { command } => connection_command(&cli, &socket, command).await,
        Command::Lease { command } => lease_command(&cli, &socket, command).await,
        Command::Approval { command } => approval_command(&cli.db, command),
        Command::Gate { command } => gate_command(&cli, &socket, command).await,
        Command::Audit { command } => {
            let service = admin_service(&cli.db)?;
            match command {
                AuditCommand::Query { limit } => print_json(&service.audit_query(limit)?),
                AuditCommand::Recovery { limit } => {
                    print_json(&service.list_execution_recovery(limit)?)
                }
            }
        }
        Command::KillSwitch { state } => {
            let service = admin_service(&cli.db)?;
            service.kill_switch(state == "on")?;
            print_json(&json!({"kill_switch":state}))
        }
        Command::Lock => print_rpc(&socket, RpcRequest::Lock { auth: auth(&cli)? }).await,
        Command::GeneratePassword { length } => {
            print_json(&json!({"password":keylease_service::generate_password(length)?}))
        }
        Command::Contracts => print_json(&json!({
            "contract_version":CONTRACT_VERSION,
            "schemas":{
                "action_request":schemars::schema_for!(ActionRequest),
                "new_entry_input":schemars::schema_for!(NewEntryInput),
                "entry_patch":schemars::schema_for!(EntryPatch),
                "actor_context":schemars::schema_for!(ActorContext),
                "item_metadata":schemars::schema_for!(ItemMetadata),
                "vault_group":schemars::schema_for!(VaultGroup),
                "policy_rule":schemars::schema_for!(PolicyRule),
                "policy_decision":schemars::schema_for!(PolicyDecision),
                "audit_event":schemars::schema_for!(AuditEvent),
                "approval_record":schemars::schema_for!(ApprovalRecord),
                "access_lease":schemars::schema_for!(AccessLease),
                "connection_record":schemars::schema_for!(ConnectionRecord),
                "action_response":schemars::schema_for!(ActionResponse)
            },
            "connectors":[
                leasegate_connectors::FakeConnector::default().manifest(),
                leasegate_connectors::google_manifest(),
                leasegate_connectors::github_manifest(),
                leasegate_connectors::linear_manifest(),
                leasegate_connectors::notion_manifest()
            ]
        })),
    }
}

fn vault_command(db: &Path, command: VaultCommand) -> Result<()> {
    match command {
        VaultCommand::Init => {
            let first = prompt("New master password: ")?;
            let second = prompt("Confirm master password: ")?;
            if first != second || first.len() < 10 {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "passwords differ or are shorter than 10 characters".into(),
                });
            }
            let service = service(db)?;
            let vault_id = service.initialize(first.as_bytes(), Duration::minutes(5))?;
            print_json(&json!({"vault_id":vault_id,"initialized":true}))
        }
        VaultCommand::ChangePassword => {
            let current = prompt("Master password: ")?;
            let service = service(db)?;
            service.unlock(current.as_bytes(), Duration::minutes(5))?;
            let next = prompt("New master password: ")?;
            if next.len() < 10 {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "new password must contain at least 10 characters".into(),
                });
            }
            let store = NativeStore::open(db)?;
            let unlocked = store.unlock(current.as_bytes())?;
            store.change_password(&unlocked, next.as_bytes())?;
            print_json(&json!({"changed":true}))
        }
        VaultCommand::ImportKdbx { path, commit } => {
            let service = admin_service(db)?;
            let kdbx_password = prompt("KDBX password: ")?;
            let bytes = fs::read(path).map_err(|_| KeyLeaseError::Storage)?;
            let preview = service.preview_kdbx_import(&bytes, &kdbx_password)?;
            if commit {
                let report = service.commit_kdbx_import(&preview)?;
                print_json(&report)
            } else {
                print_json(&json!({"preview":preview.report,"commit_required":true}))
            }
        }
        VaultCommand::ImportOnepux {
            path,
            commit,
            acknowledge_plaintext,
        } => {
            if !acknowledge_plaintext {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "1PUX contains plaintext secrets; pass --acknowledge-plaintext after excluding it from backups and indexes"
                        .into(),
                });
            }
            let service = admin_service(db)?;
            let bytes = read_onepux_source(&path)?;
            let preview = service.preview_onepux_import(&bytes)?;
            if commit {
                let report = service.commit_onepux_import(&preview)?;
                print_json(&report)
            } else {
                print_json(&json!({"preview":preview.report,"commit_required":true}))
            }
        }
        VaultCommand::ExportKdbx {
            path,
            force,
            item_ids,
        } => {
            if path.exists() && !force {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "destination exists; pass --force to replace it".into(),
                });
            }
            let service = admin_service(db)?;
            let password = prompt("New KDBX export password: ")?;
            let selected = item_ids.into_iter().map(ItemId).collect::<Vec<_>>();
            let (bytes, report) = service.export_kdbx(&password, &selected)?;
            let parent = path.parent().unwrap_or_else(|| Path::new("."));
            let mut temp =
                tempfile::NamedTempFile::new_in(parent).map_err(|_| KeyLeaseError::Storage)?;
            temp.as_file_mut()
                .set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|_| KeyLeaseError::Storage)?;
            temp.write_all(&bytes).map_err(|_| KeyLeaseError::Storage)?;
            temp.as_file_mut()
                .sync_all()
                .map_err(|_| KeyLeaseError::Storage)?;
            temp.persist(&path).map_err(|_| KeyLeaseError::Storage)?;
            print_json(&report)
        }
        VaultCommand::Backup { path, force } => {
            if path.exists() && !force {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "destination exists; pass --force to replace it".into(),
                });
            }
            let service = admin_service(db)?;
            write_atomic(&path, &service.export_native_backup()?)?;
            print_json(&json!({"backup":path,"encrypted":true}))
        }
        VaultCommand::Restore { path } => {
            if db.exists() {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "restore target database already exists".into(),
                });
            }
            let password = prompt("Backup master password: ")?;
            let bytes = fs::read(path).map_err(|_| KeyLeaseError::Storage)?;
            let service = service(db)?;
            let vault_id =
                service.restore_native_backup(password.as_bytes(), &bytes, Duration::minutes(5))?;
            print_json(&json!({"restored":true,"vault_id":vault_id}))
        }
    }
}
fn client_command(db: &Path, command: ClientCommand) -> Result<()> {
    let service = admin_service(db)?;
    match command {
        ClientCommand::Register { name } => {
            let (agent_id, token) = service.register_client(&name)?;
            print_json(
                &json!({"agent_id":agent_id,"client_token":token,"warning":"store this once in a mode-0600 file"}),
            )
        }
        ClientCommand::List => print_json(&service.list_clients()?),
        ClientCommand::Revoke { id } => {
            service.revoke_client(&AgentId(id.clone()))?;
            print_json(&json!({"revoked":id}))
        }
    }
}
fn grant_command(db: &Path, command: GrantCommand) -> Result<()> {
    let service = admin_service(db)?;
    match command {
        GrantCommand::Create(args) => {
            let effect = match args.effect.as_str() {
                "allow" => PolicyEffect::Allow,
                "deny" => PolicyEffect::Deny,
                _ => PolicyEffect::RequireApproval,
            };
            let argument_equals = args
                .argument_equals_json
                .as_deref()
                .map(read_json)
                .transpose()?
                .unwrap_or_default();
            let grant_ttl =
                i64::try_from(args.ttl_seconds).map_err(|_| KeyLeaseError::InvalidRequest {
                    reason: "grant TTL is too large".into(),
                })?;
            let rule = PolicyRule {
                id: format!("grant_{}", uuid_text()),
                version: 1,
                effect,
                agent_id: Some(AgentId(args.client)),
                connection_id: args.connection_id,
                resource_prefix: args.resource,
                actions: args.allow,
                argument_equals,
                not_before: None,
                expires_at: Some(Utc::now() + Duration::seconds(grant_ttl)),
                max_lease_ttl_seconds: args.max_lease_ttl_seconds,
                max_uses: args.max_uses,
                budget: DataBudget {
                    max_items: Some(args.max_items),
                    max_cells: Some(args.max_cells),
                    max_response_bytes: Some(args.max_response_bytes),
                    max_rows_changed: Some(args.max_rows_changed),
                    max_concurrent: Some(args.max_concurrent),
                    max_task_requests: args.max_task_requests,
                    max_task_items: args.max_task_items,
                    max_task_cells: args.max_task_cells,
                    max_task_response_bytes: args.max_task_response_bytes,
                    max_task_rows_changed: args.max_task_rows_changed,
                },
            };
            service.add_grant(rule.clone())?;
            print_json(&rule)
        }
        GrantCommand::Template(args) => {
            let ttl =
                i64::try_from(args.ttl_seconds).map_err(|_| KeyLeaseError::InvalidRequest {
                    reason: "grant template TTL is too large".into(),
                })?;
            let kind = if args.profile == "contributor" {
                PolicyTemplateKind::Contributor
            } else {
                PolicyTemplateKind::ReadOnly
            };
            let rule = materialize_provider_template(PolicyTemplateInput {
                rule_id: format!("grant_{}", uuid_text()),
                version: 1,
                agent_id: AgentId(args.client),
                connection_id: args.connection_id,
                provider: args.provider,
                exact_resource: args.resource,
                kind,
                expires_at: Utc::now() + Duration::seconds(ttl),
            })?;
            service.add_grant(rule.clone())?;
            print_json(&rule)
        }
        GrantCommand::List => print_json(&service.list_grants()?),
        GrantCommand::Revoke { id } => {
            service.revoke_grant(&id)?;
            print_json(&json!({"revoked":id}))
        }
    }
}

async fn entry_command(cli: &Cli, socket: &Path, command: EntryCommand) -> Result<()> {
    match command {
        EntryCommand::Search { query } => {
            print_rpc(
                socket,
                RpcRequest::EntriesSearch {
                    auth: auth(cli)?,
                    query,
                },
            )
            .await
        }
        EntryCommand::Get { id } => {
            print_rpc(
                socket,
                RpcRequest::EntriesGet {
                    auth: auth(cli)?,
                    id: ItemId(id),
                },
            )
            .await
        }
        EntryCommand::Create {
            input_json,
            idempotency_key,
            dry_run,
        } => {
            let input = read_json::<NewEntryInput>(&input_json)?;
            print_rpc(
                socket,
                RpcRequest::EntriesCreate {
                    auth: auth(cli)?,
                    input,
                    idempotency_key,
                    dry_run,
                },
            )
            .await
        }
        EntryCommand::Update {
            id,
            patch_json,
            if_revision,
            idempotency_key,
            dry_run,
        } => {
            let patch = read_json::<EntryPatch>(&patch_json)?;
            print_rpc(
                socket,
                RpcRequest::EntriesUpdate {
                    auth: auth(cli)?,
                    id: ItemId(id),
                    patch,
                    if_revision,
                    idempotency_key,
                    dry_run,
                },
            )
            .await
        }
        EntryCommand::Delete {
            id,
            if_revision,
            idempotency_key,
            dry_run,
        } => {
            print_rpc(
                socket,
                RpcRequest::EntriesDelete {
                    auth: auth(cli)?,
                    id: ItemId(id),
                    if_revision,
                    idempotency_key,
                    dry_run,
                },
            )
            .await
        }
        EntryCommand::Reveal { id, field } => {
            let service = admin_service(&cli.db)?;
            print_json(
                &json!({"item_id":id,"field":field,"value":service.reveal_field_for_human(&ItemId(id.clone()),&field)?}),
            )
        }
        EntryCommand::Totp { id } => {
            let service = admin_service(&cli.db)?;
            let (code, expires_in) = service.totp_for_human(&ItemId(id.clone()))?;
            print_json(&json!({"item_id":id,"code":code,"expires_in":expires_in}))
        }
        EntryCommand::History { id } => {
            let service = admin_service(&cli.db)?;
            print_json(&service.entry_history_for_human(&ItemId(id))?)
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionInput {
    credential: Value,
    authorized_resources: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GoogleOAuthInput {
    client_id: String,
    client_secret: Option<String>,
}
async fn connection_command(cli: &Cli, socket: &Path, command: ConnectionCommand) -> Result<()> {
    match command {
        ConnectionCommand::GoogleOauthBegin { input_json } => {
            let input = read_json::<GoogleOAuthInput>(&input_json)?;
            print_rpc(
                socket,
                RpcRequest::ConnectionGoogleOauthBegin {
                    auth: auth(cli)?,
                    client_id: input.client_id,
                    client_secret: input.client_secret.map(SecretValue),
                },
            )
            .await
        }
        ConnectionCommand::GoogleOauthComplete { flow_id } => {
            print_rpc(
                socket,
                RpcRequest::ConnectionGoogleOauthComplete {
                    auth: auth(cli)?,
                    flow_id,
                },
            )
            .await
        }
        ConnectionCommand::Add {
            provider,
            input_json,
        } => {
            let input = read_json::<ConnectionInput>(&input_json)?;
            let credential = match input.credential {
                Value::String(value) => value,
                value => {
                    serde_json::to_string(&value).map_err(|_| KeyLeaseError::InvalidRequest {
                        reason: "invalid connection credential object".into(),
                    })?
                }
            };
            print_rpc(
                socket,
                RpcRequest::ConnectionAdd {
                    auth: auth(cli)?,
                    provider,
                    credential: SecretValue(credential),
                    authorized_resources: input.authorized_resources,
                },
            )
            .await
        }
        ConnectionCommand::List => {
            print_rpc(socket, RpcRequest::ConnectionsList { auth: auth(cli)? }).await
        }
        ConnectionCommand::Enroll { id, resource } => {
            print_rpc(
                socket,
                RpcRequest::ConnectionEnroll {
                    auth: auth(cli)?,
                    id: ConnectionId(id),
                    resource,
                },
            )
            .await
        }
        ConnectionCommand::Unenroll { id, resource } => {
            print_rpc(
                socket,
                RpcRequest::ConnectionUnenroll {
                    auth: auth(cli)?,
                    id: ConnectionId(id),
                    resource,
                },
            )
            .await
        }
        ConnectionCommand::Test { id } => {
            print_rpc(
                socket,
                RpcRequest::ConnectionTest {
                    auth: auth(cli)?,
                    id: ConnectionId(id),
                },
            )
            .await
        }
        ConnectionCommand::Refresh { id } => {
            print_rpc(
                socket,
                RpcRequest::ConnectionRefresh {
                    auth: auth(cli)?,
                    id: ConnectionId(id),
                },
            )
            .await
        }
        ConnectionCommand::Disconnect { id } => {
            print_rpc(
                socket,
                RpcRequest::ConnectionDisconnect {
                    auth: auth(cli)?,
                    id: ConnectionId(id),
                },
            )
            .await
        }
        ConnectionCommand::Revoke { id } => {
            print_rpc(
                socket,
                RpcRequest::ConnectionRevoke {
                    auth: auth(cli)?,
                    id: ConnectionId(id),
                },
            )
            .await
        }
    }
}
async fn lease_command(cli: &Cli, socket: &Path, command: LeaseCommand) -> Result<()> {
    match command {
        LeaseCommand::Request {
            input_json,
            ttl_seconds,
            max_uses,
            approval_id,
        } => {
            let request = read_json::<ActionRequest>(&input_json)?;
            print_rpc(
                socket,
                RpcRequest::LeaseRequest {
                    auth: auth(cli)?,
                    request,
                    ttl_seconds,
                    max_uses,
                    approval_id,
                },
            )
            .await
        }
        LeaseCommand::Revoke { id } => {
            let service = admin_service(&cli.db)?;
            service.revoke_lease(&id)?;
            print_json(&json!({"revoked":id}))
        }
    }
}
fn approval_command(db: &Path, command: ApprovalCommand) -> Result<()> {
    let service = admin_service(db)?;
    match command {
        ApprovalCommand::Approve { id } => {
            service.approve(&id)?;
            print_json(&json!({"approved":id}))
        }
    }
}
async fn gate_command(cli: &Cli, socket: &Path, command: GateCommand) -> Result<()> {
    match command {
        GateCommand::Execute {
            input_json,
            lease_token_file,
        } => {
            let request = read_json::<ActionRequest>(&input_json)?;
            let lease_token = read_secret_file(&lease_token_file, "lease token")?;
            print_rpc(
                socket,
                RpcRequest::GateExecute {
                    auth: auth(cli)?,
                    lease_token: SecretValue(lease_token.trim().to_owned()),
                    request,
                },
            )
            .await
        }
    }
}

async fn serve(db: &Path, socket: &Path, ttl: i64, start_locked: bool) -> Result<()> {
    let owner_uid = fs::metadata(db)
        .map_err(|_| KeyLeaseError::NotFound {
            resource: db.display().to_string(),
        })?
        .uid();
    if socket.exists() {
        let metadata = fs::symlink_metadata(socket).map_err(|_| KeyLeaseError::Storage)?;
        if !metadata.file_type().is_socket() {
            return Err(KeyLeaseError::Denied {
                reason: "refusing to replace a non-socket path".into(),
            });
        }
        if metadata.uid() != owner_uid {
            return Err(KeyLeaseError::Denied {
                reason: "refusing to replace a socket owned by another user".into(),
            });
        }
        fs::remove_file(socket).map_err(|_| KeyLeaseError::Storage)?;
    }
    let service = Arc::new(service(db)?);
    if !start_locked {
        let password = prompt("Master password: ")?;
        service.unlock(password.as_bytes(), Duration::seconds(ttl))?;
    }
    let listener = UnixListener::bind(socket).map_err(|_| KeyLeaseError::Storage)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))
        .map_err(|_| KeyLeaseError::Storage)?;
    eprintln!("KeyLease listening on {}", socket.display());
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        if stream
            .peer_cred()
            .map_err(|_| KeyLeaseError::Denied {
                reason: "unable to inspect Unix peer credentials".into(),
            })?
            .uid()
            != owner_uid
        {
            eprintln!("rejected Unix peer with unexpected uid");
            continue;
        }
        let service = service.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_stream(service, stream).await {
                eprintln!("request failed: {error}");
            }
        });
    }
}
async fn handle_stream(service: Arc<KeyLeaseService>, stream: UnixStream) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    loop {
        let mut line = Zeroizing::new(String::new());
        let bytes = (&mut reader)
            .take((MAX_LOCAL_JSON_BYTES + 1) as u64)
            .read_line(&mut line)
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        if bytes == 0 {
            break;
        }
        if bytes > MAX_LOCAL_JSON_BYTES || !line.ends_with('\n') {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "local RPC request exceeds size limit or is not newline terminated".into(),
            });
        }
        let request: RpcRequest =
            serde_json::from_str(&line).map_err(|_| KeyLeaseError::InvalidRequest {
                reason: "invalid JSON RPC request".into(),
            })?;
        let response = handle_rpc(&service, request).await;
        let encoded = match response {
            Ok(v) => json!({"ok":true,"result":v}),
            Err(e) => json!({"ok":false,"error":e}),
        };
        write
            .write_all(encoded.to_string().as_bytes())
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        write
            .write_all(b"\n")
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
    }
    Ok(())
}
async fn handle_rpc(service: &KeyLeaseService, request: RpcRequest) -> Result<Value> {
    match request {
        RpcRequest::Status => service.status(),
        RpcRequest::Unlock {
            auth,
            password,
            session_ttl_seconds,
        } => {
            let actor = actor(service, &auth)?;
            let vault_id = service.unlock_for_client(
                &actor.agent_id,
                password.0.as_bytes(),
                Duration::seconds(session_ttl_seconds),
            )?;
            Ok(json!({"unlocked":true,"vault_id":vault_id}))
        }
        RpcRequest::GroupsList { auth } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.list_groups_authorized(&actor)?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::GroupsCreate {
            auth,
            name,
            parent_id,
            idempotency_key,
            dry_run,
        } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.create_group_authorized(
                &actor,
                &name,
                parent_id,
                &idempotency_key,
                dry_run,
            )?)
            .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::GroupsUpdate {
            auth,
            id,
            name,
            if_revision,
            idempotency_key,
            dry_run,
        } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.update_group_authorized(
                &actor,
                &id,
                &name,
                if_revision,
                &idempotency_key,
                dry_run,
            )?)
            .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::GroupsDelete {
            auth,
            id,
            if_revision,
            idempotency_key,
            dry_run,
        } => {
            let actor = actor(service, &auth)?;
            service.delete_group_authorized(&actor, &id, if_revision, &idempotency_key, dry_run)?;
            Ok(json!({"deleted":id}))
        }
        RpcRequest::EntriesSearch { auth, query } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.search_entries(&actor, &query)?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::EntriesGet { auth, id } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.get_entry_metadata(&actor, &id)?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::EntriesCreate {
            auth,
            input,
            idempotency_key,
            dry_run,
        } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.create_entry(&actor, input, &idempotency_key, dry_run)?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::EntriesUpdate {
            auth,
            id,
            patch,
            if_revision,
            idempotency_key,
            dry_run,
        } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.update_entry(
                &actor,
                &id,
                patch,
                if_revision,
                &idempotency_key,
                dry_run,
            )?)
            .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::EntriesDelete {
            auth,
            id,
            if_revision,
            idempotency_key,
            dry_run,
        } => {
            let actor = actor(service, &auth)?;
            service.delete_entry(&actor, &id, if_revision, &idempotency_key, dry_run)?;
            Ok(json!({"deleted":!dry_run,"dry_run":dry_run,"item_id":id}))
        }
        RpcRequest::EntriesReveal { auth, id, field } => {
            let actor = actor(service, &auth)?;
            Ok(json!({
                "item_id":id,
                "field":field,
                "value":service.reveal_field_authorized(&actor, &id, &field)?,
            }))
        }
        RpcRequest::EntriesTotp { auth, id } => {
            let actor = actor(service, &auth)?;
            let (code, expires_in) = service.totp_authorized(&actor, &id)?;
            Ok(json!({"item_id":id,"code":code,"expires_in":expires_in}))
        }
        RpcRequest::EntriesHistory { auth, id } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.entry_history_authorized(&actor, &id)?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::GeneratePassword { auth, length } => {
            actor(service, &auth)?;
            Ok(json!({"password":keylease_service::generate_password(length)?}))
        }
        RpcRequest::ConnectionsList { auth } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.list_connections_authorized(&actor)?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::ConnectionAdd {
            auth,
            provider,
            credential,
            authorized_resources,
        } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.add_connection_authorized(
                &actor,
                &provider,
                credential.0.clone(),
                authorized_resources,
            )?)
            .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::ConnectionEnroll { auth, id, resource } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(
                service.enroll_connection_resource_authorized(&actor, &id, &resource)?,
            )
            .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::ConnectionUnenroll { auth, id, resource } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(
                service.unenroll_connection_resource_authorized(&actor, &id, &resource)?,
            )
            .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::ConnectionTest { auth, id } => {
            let actor = actor(service, &auth)?;
            service.test_connection_authorized(&actor, &id).await?;
            Ok(json!({"healthy":true}))
        }
        RpcRequest::ConnectionRefresh { auth, id } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.refresh_connection_authorized(&actor, &id).await?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::ConnectionDisconnect { auth, id } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.disconnect_connection_authorized(&actor, &id)?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::ConnectionRevoke { auth, id } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.revoke_connection_authorized(&actor, &id).await?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::ConnectionGoogleOauthBegin {
            auth,
            client_id,
            client_secret,
        } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(
                service
                    .begin_google_oauth(
                        &actor,
                        &client_id,
                        client_secret.map(|secret| secret.0.clone()),
                    )
                    .await?,
            )
            .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::ConnectionGoogleOauthComplete { auth, flow_id } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.complete_google_oauth(&actor, &flow_id).await?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::ApprovalsList { auth, limit } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.list_pending_approvals_authorized(&actor, limit)?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::ApprovalDecide { auth, id, approve } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.decide_approval_authorized(&actor, &id, approve)?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::AuditQuery { auth, limit } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.audit_query_authorized(&actor, limit)?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::LeaseRequest {
            auth,
            mut request,
            ttl_seconds,
            max_uses,
            approval_id,
        } => {
            let actor = actor(service, &auth)?;
            request.subject = actor.clone();
            serde_json::to_value(
                service
                    .request_lease(
                        &actor,
                        request,
                        ttl_seconds,
                        max_uses,
                        approval_id.as_deref(),
                    )
                    .await?,
            )
            .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::GateExecute {
            auth,
            lease_token,
            mut request,
        } => {
            let actor = actor(service, &auth)?;
            request.subject = actor.clone();
            serde_json::to_value(service.execute(&actor, &lease_token.0, request).await?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::Lock { auth } => {
            actor(service, &auth)?;
            service.lock()?;
            Ok(json!({"locked":true}))
        }
    }
}

fn actor(service: &KeyLeaseService, auth: &RpcAuth) -> Result<ActorContext> {
    service.authenticate(&auth.agent_id, &auth.token.0, &auth.session_id)
}
fn service(db: &Path) -> Result<KeyLeaseService> {
    KeyLeaseService::new(Arc::new(NativeStore::open(db)?))
}
fn admin_service(db: &Path) -> Result<KeyLeaseService> {
    let password = prompt("Master password: ")?;
    let service = service(db)?;
    service.unlock(password.as_bytes(), Duration::minutes(15))?;
    Ok(service)
}
fn auth(cli: &Cli) -> Result<RpcAuth> {
    let agent = cli
        .agent_id
        .clone()
        .ok_or_else(|| KeyLeaseError::InvalidRequest {
            reason: "--agent-id is required".into(),
        })?;
    let path = cli
        .client_token_file
        .as_ref()
        .ok_or_else(|| KeyLeaseError::InvalidRequest {
            reason: "--client-token-file is required".into(),
        })?;
    let token = read_secret_file(path, "client token")?;
    Ok(RpcAuth {
        agent_id: AgentId(agent),
        token: SecretValue(token.trim().to_owned()),
        session_id: cli.client_session.clone(),
    })
}
fn read_onepux_source(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let path_metadata = fs::symlink_metadata(path).map_err(|_| KeyLeaseError::InvalidRequest {
        reason: "cannot inspect 1PUX source".into(),
    })?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "1PUX source must be a regular file, not a symlink".into(),
        });
    }
    if path_metadata.len() > 64 * 1024 * 1024 {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "1PUX source exceeds the 64 MiB limit".into(),
        });
    }
    let file = fs::File::open(path).map_err(|_| KeyLeaseError::Storage)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| KeyLeaseError::Storage)?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "1PUX source exceeds the 64 MiB limit".into(),
        });
    }
    Ok(bytes)
}
fn read_secret_file(path: &Path, label: &str) -> Result<Zeroizing<String>> {
    let metadata = fs::symlink_metadata(path).map_err(|_| KeyLeaseError::InvalidRequest {
        reason: format!("cannot read {label} file"),
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(KeyLeaseError::Denied {
            reason: format!("{label} path must be a regular non-symlink file"),
        });
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(KeyLeaseError::Denied {
            reason: format!("{label} file must not be accessible by group or others"),
        });
    }
    if metadata.len() == 0 || metadata.len() > 4096 {
        return Err(KeyLeaseError::InvalidRequest {
            reason: format!("{label} file has an invalid size"),
        });
    }
    let value =
        Zeroizing::new(
            fs::read_to_string(path).map_err(|_| KeyLeaseError::InvalidRequest {
                reason: format!("cannot read {label} file"),
            })?,
        );
    if value.trim().is_empty() {
        return Err(KeyLeaseError::InvalidRequest {
            reason: format!("{label} file is empty"),
        });
    }
    Ok(value)
}
fn prompt(label: &str) -> Result<Zeroizing<String>> {
    if !stdin_is_terminal() {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "master/credential password must be read from an interactive TTY".into(),
        });
    }
    rpassword::prompt_password(label)
        .map(Zeroizing::new)
        .map_err(|_| KeyLeaseError::Storage)
}
fn stdin_is_terminal() -> bool {
    use std::io::IsTerminal;
    io::stdin().is_terminal()
}
fn read_json<T: serde::de::DeserializeOwned>(source: &str) -> Result<T> {
    let mut raw = Zeroizing::new(String::new());
    if source == "-" {
        io::stdin()
            .take((MAX_LOCAL_JSON_BYTES + 1) as u64)
            .read_to_string(&mut raw)
            .map_err(|_| KeyLeaseError::InvalidRequest {
                reason: "cannot read stdin".into(),
            })?;
    } else {
        let metadata = fs::metadata(source).map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "cannot read JSON input file".into(),
        })?;
        if metadata.len() > MAX_LOCAL_JSON_BYTES as u64 {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "JSON input exceeds size limit".into(),
            });
        }
        *raw = fs::read_to_string(source).map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "cannot read JSON input file".into(),
        })?;
    }
    if raw.len() > MAX_LOCAL_JSON_BYTES {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "JSON input exceeds size limit".into(),
        });
    }
    serde_json::from_str(&raw).map_err(|_| KeyLeaseError::InvalidRequest {
        reason: "invalid JSON input".into(),
    })
}
async fn print_rpc(socket: &Path, request: RpcRequest) -> Result<()> {
    let mut stream = UnixStream::connect(socket)
        .await
        .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
    let encoded = Zeroizing::new(serde_json::to_vec(&request).map_err(|_| KeyLeaseError::Storage)?);
    stream
        .write_all(&encoded)
        .await
        .map_err(|_| KeyLeaseError::Storage)?;
    stream
        .write_all(b"\n")
        .await
        .map_err(|_| KeyLeaseError::Storage)?;
    let mut line = Zeroizing::new(String::new());
    let bytes = BufReader::new(stream)
        .take((MAX_LOCAL_JSON_BYTES + 1) as u64)
        .read_line(&mut line)
        .await
        .map_err(|_| KeyLeaseError::Storage)?;
    if bytes > MAX_LOCAL_JSON_BYTES || !line.ends_with('\n') {
        return Err(KeyLeaseError::Storage);
    }
    let response: Value = serde_json::from_str(&line).map_err(|_| KeyLeaseError::Storage)?;
    if response.get("ok").and_then(Value::as_bool) == Some(true) {
        let result = response.get("result").cloned().unwrap_or(Value::Null);
        println!(
            "{}",
            serde_json::to_string(&result).map_err(|_| KeyLeaseError::Storage)?
        );
        Ok(())
    } else {
        let error = response
            .get("error")
            .cloned()
            .ok_or(KeyLeaseError::Storage)?;
        Err(serde_json::from_value(error).map_err(|_| KeyLeaseError::Storage)?)
    }
}
fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string(value).map_err(|_| KeyLeaseError::Storage)?
    );
    Ok(())
}
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| KeyLeaseError::Storage)?;
    temporary
        .as_file_mut()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| KeyLeaseError::Storage)?;
    temporary
        .write_all(bytes)
        .map_err(|_| KeyLeaseError::Storage)?;
    temporary
        .as_file_mut()
        .sync_all()
        .map_err(|_| KeyLeaseError::Storage)?;
    temporary
        .persist(path)
        .map_err(|_| KeyLeaseError::Storage)?;
    Ok(())
}
fn default_socket() -> PathBuf {
    std::env::temp_dir().join(format!(
        "keylease-{}.sock",
        std::env::var("USER").unwrap_or_else(|_| "user".into())
    ))
}
fn uuid_text() -> String {
    RequestId::new().0.trim_start_matches("req_").to_owned()
}
fn exit_code(error: &KeyLeaseError) -> i32 {
    match error {
        KeyLeaseError::Denied { .. } => 3,
        KeyLeaseError::VaultLocked { .. } => 4,
        KeyLeaseError::RevisionConflict { .. } => 5,
        KeyLeaseError::ApprovalRequired { .. } => 6,
        KeyLeaseError::LeaseExpired
        | KeyLeaseError::LeaseRevoked
        | KeyLeaseError::LeaseExhausted => 7,
        KeyLeaseError::InvalidRequest { .. } | KeyLeaseError::UnsupportedVersion { .. } => 2,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_capability_debug_output_is_redacted() {
        let auth = RpcAuth {
            agent_id: AgentId("agent_test".into()),
            token: SecretValue("client-token-fixture".into()),
            session_id: "test-session".into(),
        };
        let debug = format!("{auth:?}");
        assert!(!debug.contains("client-token-fixture"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn json_file_input_has_a_hard_size_limit() {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file()
            .set_len((MAX_LOCAL_JSON_BYTES + 1) as u64)
            .unwrap();
        assert!(matches!(
            read_json::<Value>(file.path().to_str().unwrap()),
            Err(KeyLeaseError::InvalidRequest { .. })
        ));
    }

    #[tokio::test]
    async fn desktop_read_and_approval_rpc_require_and_use_capabilities() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(NativeStore::open(directory.path().join("desktop.sqlite")).unwrap());
        let service = KeyLeaseService::new(store.clone()).unwrap();
        let vault_id = service
            .initialize(b"desktop password", Duration::hours(1))
            .unwrap();
        let (agent_id, token) = service.register_client("desktop-test").unwrap();
        service
            .add_grant(PolicyRule {
                id: "desktop-ui".into(),
                version: 1,
                effect: PolicyEffect::Allow,
                agent_id: Some(agent_id.clone()),
                connection_id: None,
                resource_prefix: format!("kl://{}", vault_id.0),
                actions: vec![
                    "connection:list".into(),
                    "connection:add".into(),
                    "connection:enroll".into(),
                    "connection:unenroll".into(),
                    "connection:test".into(),
                    "connection:refresh".into(),
                    "connection:disconnect".into(),
                    "connection:revoke".into(),
                    "approval:list".into(),
                    "approval:decide".into(),
                    "audit:query".into(),
                ],
                argument_equals: Default::default(),
                not_before: None,
                expires_at: Some(Utc::now() + Duration::hours(1)),
                max_lease_ttl_seconds: 60,
                max_uses: 10,
                budget: Default::default(),
            })
            .unwrap();
        let connection = service
            .add_connection("fake", "credential".into(), vec!["fake:resource/1".into()])
            .unwrap();
        let approval = ApprovalRecord {
            id: ApprovalId::new(),
            request_digest_hex: "digest".into(),
            policy_version: 1,
            state: ApprovalState::Pending,
            expires_at: Utc::now() + Duration::minutes(5),
            request_id: None,
            agent_id: None,
            connection_id: None,
            action: None,
            resource: None,
            created_at: None,
            task_id: None,
            risk: None,
            semantic_summary: None,
        };
        store.save_approval(&approval).unwrap();
        let auth = RpcAuth {
            agent_id,
            token: SecretValue(token),
            session_id: "desktop-test".into(),
        };

        let connections = handle_rpc(&service, RpcRequest::ConnectionsList { auth: auth.clone() })
            .await
            .unwrap();
        assert_eq!(connections.as_array().unwrap().len(), 1);
        handle_rpc(
            &service,
            RpcRequest::ConnectionTest {
                auth: auth.clone(),
                id: connection.id.clone(),
            },
        )
        .await
        .unwrap();
        handle_rpc(
            &service,
            RpcRequest::ConnectionEnroll {
                auth: auth.clone(),
                id: connection.id.clone(),
                resource: "fake:resource/2".into(),
            },
        )
        .await
        .unwrap();
        handle_rpc(
            &service,
            RpcRequest::ConnectionUnenroll {
                auth: auth.clone(),
                id: connection.id.clone(),
                resource: "fake:resource/2".into(),
            },
        )
        .await
        .unwrap();
        let disconnected = handle_rpc(
            &service,
            RpcRequest::ConnectionDisconnect {
                auth: auth.clone(),
                id: connection.id.clone(),
            },
        )
        .await
        .unwrap();
        assert_eq!(disconnected["health"], "disconnected");
        let refreshed = handle_rpc(
            &service,
            RpcRequest::ConnectionRefresh {
                auth: auth.clone(),
                id: connection.id.clone(),
            },
        )
        .await
        .unwrap();
        assert_eq!(refreshed["health"], "connected");
        let revoked = handle_rpc(
            &service,
            RpcRequest::ConnectionRevoke {
                auth: auth.clone(),
                id: connection.id.clone(),
            },
        )
        .await
        .unwrap();
        assert_eq!(revoked["health"], "revoked");
        let added = handle_rpc(
            &service,
            RpcRequest::ConnectionAdd {
                auth: auth.clone(),
                provider: "fake".into(),
                credential: SecretValue("another-credential".into()),
                authorized_resources: vec!["fake:resource/3".into()],
            },
        )
        .await
        .unwrap();
        assert_eq!(added["provider"], "fake");
        let approvals = handle_rpc(
            &service,
            RpcRequest::ApprovalsList {
                auth: auth.clone(),
                limit: 20,
            },
        )
        .await
        .unwrap();
        assert_eq!(approvals.as_array().unwrap().len(), 1);
        let decided = handle_rpc(
            &service,
            RpcRequest::ApprovalDecide {
                auth: auth.clone(),
                id: approval.id.0,
                approve: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(decided["state"], "approved");
        let audit = handle_rpc(
            &service,
            RpcRequest::AuditQuery {
                auth: auth.clone(),
                limit: 20,
            },
        )
        .await
        .unwrap();
        assert!(!audit.as_array().unwrap().is_empty());
        let denied = handle_rpc(
            &service,
            RpcRequest::Lock {
                auth: RpcAuth {
                    token: SecretValue("wrong".into()),
                    ..auth.clone()
                },
            },
        )
        .await;
        assert!(matches!(denied, Err(KeyLeaseError::Denied { .. })));
        handle_rpc(&service, RpcRequest::Lock { auth: auth.clone() })
            .await
            .unwrap();
        assert_eq!(service.status().unwrap()["locked"], true);
        handle_rpc(
            &service,
            RpcRequest::Unlock {
                auth,
                password: SecretValue("desktop password".into()),
                session_ttl_seconds: 900,
            },
        )
        .await
        .unwrap();
        assert_eq!(service.status().unwrap()["locked"], false);
    }
}
