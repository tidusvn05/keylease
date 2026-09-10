use chrono::{Duration, Utc};
use clap::{Args, Parser, Subcommand};
use keylease_core::*;
use keylease_service::{
    AgentNewItemGuide, AgentNewItemHandoffInput, AgentNewItemHandoffReceipt, ContentCreateInput,
    ContentDocument, ContentPatch, ContentSummary, EntryPatch, EntryView, FieldView,
    KeyLeaseService, MigrationApplyResult, MigrationPreview, MigrationStatus, NewEntryInput,
};
use keylease_store::NativeStore;
use leasegate_connectors::Connector;
use leasegate_policy::{PolicyTemplateInput, PolicyTemplateKind, materialize_provider_template};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
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
    #[arg(long, global = true, default_value_os_t = default_database())]
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
    Templates {
        #[command(subcommand)]
        command: TemplateCommand,
    },
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    Migrations {
        #[command(subcommand)]
        command: MigrationCommand,
    },
    Projects {
        #[command(subcommand)]
        command: ProjectCommand,
    },
    Content {
        #[command(subcommand)]
        command: ContentCommand,
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
    #[command(hide = true)]
    Desktop {
        #[command(subcommand)]
        command: DesktopCommand,
    },
}
#[derive(Subcommand)]
enum DesktopCommand {
    Inspect {
        #[arg(long)]
        home: Option<PathBuf>,
    },
    InspectSource {
        path: PathBuf,
    },
    Provision {
        #[arg(long)]
        home: Option<PathBuf>,
        #[arg(long, default_value = "-")]
        input_json: String,
    },
    Serve {
        #[arg(long)]
        home: Option<PathBuf>,
    },
    VaultsList,
    VaultCreate {
        #[arg(long, default_value = "-")]
        input_json: String,
    },
    VaultSwitch {
        id: String,
    },
    VaultRename {
        id: String,
        name: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DesktopVaultProfile {
    id: String,
    name: String,
    path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DesktopVaultRegistry {
    version: u32,
    active_id: String,
    profiles: Vec<DesktopVaultProfile>,
}

#[derive(Deserialize)]
struct DesktopVaultCreateInput {
    name: String,
    request: DesktopProvisionInput,
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum DesktopProvisionInput {
    Create {
        password: SecretValue,
    },
    AdoptKeyleaseDatabase {
        source_path: PathBuf,
        password: SecretValue,
    },
    RestoreKeyleaseBackup {
        source_path: PathBuf,
        password: SecretValue,
    },
    ImportKdbx {
        source_path: PathBuf,
        source_password: SecretValue,
        password: SecretValue,
    },
    ImportOnepux {
        source_path: PathBuf,
        password: SecretValue,
        acknowledge_plaintext: bool,
    },
    RepairDesktopClient {
        password: SecretValue,
    },
}
#[derive(Subcommand)]
enum VaultCommand {
    Init {
        /// Read the new vault password from a mode-0600 file. Intended for
        /// unattended self-hosted bootstrap; never pass a password on argv.
        #[arg(long)]
        password_file: Option<PathBuf>,
    },
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
enum TemplateCommand {
    List,
    Get { kind: String },
}

#[derive(Subcommand)]
enum AgentCommand {
    NewItem {
        handoff_id: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum MigrationCommand {
    Status,
    Preview {
        migration_id: String,
    },
    Apply {
        migration_id: String,
        #[arg(long)]
        preview_digest: String,
    },
    Rollback {
        migration_id: String,
    },
}

#[derive(Subcommand)]
enum ProjectCommand {
    List,
    Create {
        slug: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        idempotency_key: String,
    },
}

#[derive(Subcommand)]
enum ContentCommand {
    Search {
        #[arg(default_value = "")]
        query: String,
        #[arg(long, value_parser = ["prompt", "runbook", "note"])]
        r#type: Option<String>,
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        reviewed_only: bool,
    },
    Get {
        id: String,
        #[arg(long)]
        raw: bool,
    },
    Create {
        #[arg(long, value_parser = ["prompt", "runbook", "note"])]
        r#type: String,
        #[arg(long)]
        title: String,
        #[arg(long, default_value = "-")]
        body_file: PathBuf,
        #[arg(long = "tag")]
        tags: Vec<String>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        idempotency_key: String,
    },
    Update {
        id: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        body_file: Option<PathBuf>,
        #[arg(long = "add-tag")]
        add_tags: Vec<String>,
        #[arg(long = "remove-tag")]
        remove_tags: Vec<String>,
        #[arg(long, conflicts_with = "clear_project")]
        project: Option<String>,
        #[arg(long)]
        clear_project: bool,
        #[arg(long)]
        if_revision: u64,
        #[arg(long)]
        idempotency_key: String,
    },
    Access {
        id: String,
        #[arg(value_parser = ["none", "read", "read-write"])]
        access: String,
        #[arg(long)]
        if_revision: u64,
        #[arg(long)]
        idempotency_key: String,
    },
    Review {
        id: String,
        #[arg(long)]
        if_revision: u64,
        #[arg(long)]
        idempotency_key: String,
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
    View {
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
        #[arg(
            long,
            conflicts_with = "field_id",
            required_unless_present = "field_id"
        )]
        field: Option<String>,
        #[arg(long, conflicts_with = "field", required_unless_present = "field")]
        field_id: Option<String>,
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
    GroupsReorder {
        auth: RpcAuth,
        parent_id: Option<GroupId>,
        ordered_ids: Vec<GroupId>,
        expected_revisions: BTreeMap<String, u64>,
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
    TemplatesList {
        auth: RpcAuth,
    },
    TemplatesGet {
        auth: RpcAuth,
        kind: String,
    },
    AgentHandoffCreate {
        auth: RpcAuth,
        input: AgentNewItemHandoffInput,
    },
    AgentHandoffGet {
        auth: RpcAuth,
        handoff_id: String,
    },
    MigrationsStatus {
        auth: RpcAuth,
    },
    MigrationsPreview {
        auth: RpcAuth,
        migration_id: String,
    },
    MigrationsApply {
        auth: RpcAuth,
        migration_id: String,
        preview_digest: String,
    },
    MigrationsRollback {
        auth: RpcAuth,
        migration_id: String,
    },
    ProjectsList {
        auth: RpcAuth,
    },
    ProjectsCreate {
        auth: RpcAuth,
        slug: String,
        name: Option<String>,
        idempotency_key: String,
    },
    ContentSearch {
        auth: RpcAuth,
        query: String,
        kind: Option<String>,
        tag: Option<String>,
        project_slug: Option<String>,
        reviewed_only: bool,
    },
    ContentGet {
        auth: RpcAuth,
        id: ItemId,
    },
    ContentCreate {
        auth: RpcAuth,
        input: ContentCreateInput,
        idempotency_key: String,
    },
    ContentUpdate {
        auth: RpcAuth,
        id: ItemId,
        patch: ContentPatch,
        if_revision: u64,
        idempotency_key: String,
    },
    ContentSetAccess {
        auth: RpcAuth,
        id: ItemId,
        access: AgentAccess,
        if_revision: u64,
        idempotency_key: String,
    },
    ContentReview {
        auth: RpcAuth,
        id: ItemId,
        if_revision: u64,
        idempotency_key: String,
    },
    EntriesSearch {
        auth: RpcAuth,
        query: String,
    },
    EntriesGet {
        auth: RpcAuth,
        id: ItemId,
    },
    EntriesView {
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
    EntriesRevealById {
        auth: RpcAuth,
        id: ItemId,
        field_id: FieldId,
    },
    EntriesRevealMany {
        auth: RpcAuth,
        id: ItemId,
        field_ids: Vec<FieldId>,
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
        #[serde(default)]
        recipe: Option<keylease_service::PasswordRecipe>,
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
        Command::Templates { command } => match command {
            TemplateCommand::List => {
                print_rpc(&socket, RpcRequest::TemplatesList { auth: auth(&cli)? }).await
            }
            TemplateCommand::Get { kind } => {
                print_rpc(
                    &socket,
                    RpcRequest::TemplatesGet {
                        auth: auth(&cli)?,
                        kind,
                    },
                )
                .await
            }
        },
        Command::Agent { command } => agent_command(&cli, &socket, command).await,
        Command::Migrations { command } => match command {
            MigrationCommand::Status => {
                print_rpc(&socket, RpcRequest::MigrationsStatus { auth: auth(&cli)? }).await
            }
            MigrationCommand::Preview { migration_id } => {
                print_rpc(
                    &socket,
                    RpcRequest::MigrationsPreview {
                        auth: auth(&cli)?,
                        migration_id,
                    },
                )
                .await
            }
            MigrationCommand::Apply {
                migration_id,
                preview_digest,
            } => {
                print_rpc(
                    &socket,
                    RpcRequest::MigrationsApply {
                        auth: auth(&cli)?,
                        migration_id,
                        preview_digest,
                    },
                )
                .await
            }
            MigrationCommand::Rollback { migration_id } => {
                print_rpc(
                    &socket,
                    RpcRequest::MigrationsRollback {
                        auth: auth(&cli)?,
                        migration_id,
                    },
                )
                .await
            }
        },
        Command::Projects { command } => match command {
            ProjectCommand::List => {
                print_rpc(&socket, RpcRequest::ProjectsList { auth: auth(&cli)? }).await
            }
            ProjectCommand::Create {
                slug,
                name,
                idempotency_key,
            } => {
                print_rpc(
                    &socket,
                    RpcRequest::ProjectsCreate {
                        auth: auth(&cli)?,
                        slug,
                        name,
                        idempotency_key,
                    },
                )
                .await
            }
        },
        Command::Content { command } => content_command(&cli, &socket, command).await,
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
        Command::Desktop { command } => desktop_command(command).await,
        Command::Contracts => print_json(&json!({
            "contract_version":CONTRACT_VERSION,
            "schemas":{
                "action_request":schemars::schema_for!(ActionRequest),
                "new_entry_input":schemars::schema_for!(NewEntryInput),
                "entry_patch":schemars::schema_for!(EntryPatch),
                "actor_context":schemars::schema_for!(ActorContext),
                "item_metadata":schemars::schema_for!(ItemMetadata),
                "entry_view":schemars::schema_for!(EntryView),
                "field_view":schemars::schema_for!(FieldView),
                "item_kind_definition":schemars::schema_for!(ItemKindDefinition),
                "vault_group":schemars::schema_for!(VaultGroup),
                "vault_project":schemars::schema_for!(VaultProject),
                "content_create_input":schemars::schema_for!(ContentCreateInput),
                "content_patch":schemars::schema_for!(ContentPatch),
                "content_summary":schemars::schema_for!(ContentSummary),
                "content_document":schemars::schema_for!(ContentDocument),
                "agent_new_item_handoff_input":schemars::schema_for!(AgentNewItemHandoffInput),
                "agent_new_item_handoff_receipt":schemars::schema_for!(AgentNewItemHandoffReceipt),
                "agent_new_item_guide":schemars::schema_for!(AgentNewItemGuide),
                "migration_status":schemars::schema_for!(MigrationStatus),
                "migration_preview":schemars::schema_for!(MigrationPreview),
                "migration_apply_result":schemars::schema_for!(MigrationApplyResult),
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

struct DesktopPaths {
    root: PathBuf,
    home: PathBuf,
    database: PathBuf,
    token: PathBuf,
    socket: PathBuf,
}

fn registry_path(root: &Path) -> PathBuf {
    root.join("vaults.json")
}

fn initial_registry() -> DesktopVaultRegistry {
    DesktopVaultRegistry {
        version: 1,
        active_id: "primary".into(),
        profiles: vec![DesktopVaultProfile {
            id: "primary".into(),
            name: "Primary Vault".into(),
            path: ".".into(),
        }],
    }
}

fn load_registry(root: &Path) -> Result<DesktopVaultRegistry> {
    let path = registry_path(root);
    if !path.exists() {
        return Ok(initial_registry());
    }
    let metadata = fs::symlink_metadata(&path).map_err(|_| KeyLeaseError::Storage)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(KeyLeaseError::Denied {
            reason: "vault registry must be a regular file".into(),
        });
    }
    serde_json::from_slice(&fs::read(path).map_err(|_| KeyLeaseError::Storage)?).map_err(|_| {
        KeyLeaseError::InvalidRequest {
            reason: "vault registry is invalid".into(),
        }
    })
}

fn save_registry(root: &Path, registry: &DesktopVaultRegistry) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(registry).map_err(|_| KeyLeaseError::Storage)?;
    write_atomic(&registry_path(root), &bytes)
}

fn profile_home(root: &Path, profile: &DesktopVaultProfile) -> Result<PathBuf> {
    let relative = Path::new(&profile.path);
    if relative == Path::new(".") {
        return Ok(root.to_path_buf());
    }
    if relative.is_absolute()
        || relative.components().any(|part| {
            !matches!(
                part,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
    {
        return Err(KeyLeaseError::Denied {
            reason: "vault profile path must stay inside the managed home".into(),
        });
    }
    let home = root.join(relative);
    if root.exists() && home.exists() {
        let canonical_root = fs::canonicalize(root).map_err(|_| KeyLeaseError::Storage)?;
        let canonical_home = fs::canonicalize(&home).map_err(|_| KeyLeaseError::Storage)?;
        if !canonical_home.starts_with(canonical_root) {
            return Err(KeyLeaseError::Denied {
                reason: "vault profile path escapes the managed home".into(),
            });
        }
    }
    Ok(home)
}

fn desktop_paths(home: Option<PathBuf>) -> Result<DesktopPaths> {
    let home = match home {
        Some(path) => path,
        None => PathBuf::from(std::env::var_os("HOME").ok_or_else(|| {
            KeyLeaseError::InvalidRequest {
                reason: "cannot resolve the current user's home directory".into(),
            }
        })?)
        .join(".keylease"),
    };
    if !home.is_absolute() {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "managed KeyLease home must be an absolute path".into(),
        });
    }
    let root = home;
    let registry = load_registry(&root)?;
    let profile = registry
        .profiles
        .iter()
        .find(|profile| profile.id == registry.active_id)
        .ok_or_else(|| KeyLeaseError::InvalidRequest {
            reason: "active vault profile does not exist".into(),
        })?;
    let home = profile_home(&root, profile)?;
    Ok(DesktopPaths {
        root: root.clone(),
        database: home.join("keylease.sqlite"),
        token: home.join("desktop.token"),
        socket: root.join("run/keylease.sock"),
        home,
    })
}

fn ensure_desktop_home(paths: &DesktopPaths) -> Result<()> {
    if paths.home.exists() {
        let metadata = fs::symlink_metadata(&paths.home).map_err(|_| KeyLeaseError::Storage)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(KeyLeaseError::Denied {
                reason: "managed KeyLease home must be a real directory".into(),
            });
        }
    } else {
        fs::create_dir(&paths.home).map_err(|_| KeyLeaseError::Storage)?;
    }
    fs::set_permissions(&paths.home, fs::Permissions::from_mode(0o700))
        .map_err(|_| KeyLeaseError::Storage)?;
    let socket_parent = paths
        .socket
        .parent()
        .ok_or(KeyLeaseError::Storage)?
        .to_path_buf();
    for directory in [
        paths.home.join("run"),
        paths.home.join("backups"),
        socket_parent,
    ] {
        if directory.exists() {
            let metadata = fs::symlink_metadata(&directory).map_err(|_| KeyLeaseError::Storage)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(KeyLeaseError::Denied {
                    reason: "managed KeyLease subdirectories must not be symlinks".into(),
                });
            }
        } else {
            fs::create_dir(&directory).map_err(|_| KeyLeaseError::Storage)?;
        }
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .map_err(|_| KeyLeaseError::Storage)?;
    }
    Ok(())
}

fn validate_regular_source(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| KeyLeaseError::InvalidRequest {
        reason: "cannot inspect the selected vault file".into(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(KeyLeaseError::Denied {
            reason: "selected vault must be a regular file, not a symlink".into(),
        });
    }
    Ok(())
}

fn inspect_desktop_source(path: &Path) -> Result<&'static str> {
    validate_regular_source(path)?;
    let mut prefix = [0_u8; 64];
    let mut file = fs::File::open(path).map_err(|_| KeyLeaseError::Storage)?;
    let count = file.read(&mut prefix).map_err(|_| KeyLeaseError::Storage)?;
    let prefix = &prefix[..count];
    if prefix.starts_with(b"SQLite format 3\0") {
        return Ok("keylease_database");
    }
    if prefix.starts_with(&[0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5]) {
        return Ok("kdbx");
    }
    if prefix.starts_with(b"PK\x03\x04") {
        return Ok("onepux");
    }
    if prefix.first() == Some(&b'{') {
        if fs::metadata(path)
            .map_err(|_| KeyLeaseError::Storage)?
            .len()
            > MAX_LOCAL_JSON_BYTES as u64
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "selected JSON backup exceeds the local input limit".into(),
            });
        }
        let bytes = fs::read(path).map_err(|_| KeyLeaseError::Storage)?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| KeyLeaseError::InvalidRequest {
                reason: "selected JSON file is not a KeyLease backup".into(),
            })?;
        if value.get("format").and_then(Value::as_str) == Some("keylease-native-backup") {
            return Ok("keylease_backup");
        }
    }
    Err(KeyLeaseError::InvalidRequest {
        reason: "unsupported vault file; choose KeyLease, KDBX, or 1PUX".into(),
    })
}

async fn desktop_command(command: DesktopCommand) -> Result<()> {
    match command {
        DesktopCommand::Inspect { home } => {
            let paths = desktop_paths(home)?;
            let database = paths.database.is_file();
            let token = paths.token.is_file();
            let state = match (database, token) {
                (false, false) => "needs_onboarding",
                (true, true) => "ready",
                _ => "repair_required",
            };
            let user_home = paths.root.parent().unwrap_or_else(|| Path::new("/"));
            let legacy_root = user_home.join("Library/Application Support/KeyLease");
            let legacy_database = legacy_root.join("keylease.sqlite");
            let legacy_preferences = legacy_root.join("desktop-ui.json");
            print_json(&json!({
                "state":state,
                "legacy_available":legacy_database.is_file() || legacy_preferences.is_file(),
                "legacy_database":legacy_database.is_file().then(|| legacy_database.display().to_string()),
                "service_version":env!("CARGO_PKG_VERSION"),
                "contract_version":CONTRACT_VERSION,
                "token_path":paths.token.display().to_string()
            }))
        }
        DesktopCommand::InspectSource { path } => {
            print_json(&json!({"kind":inspect_desktop_source(&path)?}))
        }
        DesktopCommand::Provision { home, input_json } => {
            let paths = desktop_paths(home)?;
            ensure_desktop_home(&paths)?;
            let input = read_json::<DesktopProvisionInput>(&input_json)?;
            provision_desktop(&paths, input)
        }
        DesktopCommand::Serve { home } => {
            let paths = desktop_paths(home)?;
            ensure_desktop_home(&paths)?;
            serve(&paths.database, &paths.socket, 28_800, true).await
        }
        DesktopCommand::VaultsList => {
            let root = managed_home().ok_or_else(|| KeyLeaseError::InvalidRequest {
                reason: "cannot resolve the managed KeyLease home".into(),
            })?;
            let registry = load_registry(&root)?;
            print_json(&registry)
        }
        DesktopCommand::VaultCreate { input_json } => {
            let root = managed_home().ok_or_else(|| KeyLeaseError::InvalidRequest {
                reason: "cannot resolve the managed KeyLease home".into(),
            })?;
            fs::create_dir_all(root.join("vaults")).map_err(|_| KeyLeaseError::Storage)?;
            fs::set_permissions(root.join("vaults"), fs::Permissions::from_mode(0o700))
                .map_err(|_| KeyLeaseError::Storage)?;
            let input = read_json::<DesktopVaultCreateInput>(&input_json)?;
            let name = input.name.trim();
            if name.is_empty() {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "vault name must not be empty".into(),
                });
            }
            let id = format!("vault_{}", uuid_text());
            let relative = format!("vaults/{id}");
            let profile = DesktopVaultProfile {
                id: id.clone(),
                name: name.into(),
                path: relative,
            };
            let home = profile_home(&root, &profile)?;
            let paths = DesktopPaths {
                root: root.clone(),
                database: home.join("keylease.sqlite"),
                token: home.join("desktop.token"),
                socket: root.join("run/keylease.sock"),
                home,
            };
            ensure_desktop_home(&paths)?;
            provision_desktop(&paths, input.request)?;
            let mut registry = load_registry(&root)?;
            registry.profiles.push(profile);
            save_registry(&root, &registry)
        }
        DesktopCommand::VaultSwitch { id } => {
            let root = managed_home().ok_or_else(|| KeyLeaseError::InvalidRequest {
                reason: "cannot resolve the managed KeyLease home".into(),
            })?;
            let mut registry = load_registry(&root)?;
            let profile = registry
                .profiles
                .iter()
                .find(|profile| profile.id == id)
                .ok_or_else(|| KeyLeaseError::NotFound {
                    resource: id.clone(),
                })?;
            let home = profile_home(&root, profile)?;
            if !home.join("keylease.sqlite").is_file() || !home.join("desktop.token").is_file() {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "selected vault profile is incomplete".into(),
                });
            }
            registry.active_id = id.clone();
            save_registry(&root, &registry)?;
            print_json(&json!({"active_id":id,"token_path":home.join("desktop.token")}))
        }
        DesktopCommand::VaultRename { id, name } => {
            let root = managed_home().ok_or_else(|| KeyLeaseError::InvalidRequest {
                reason: "cannot resolve the managed KeyLease home".into(),
            })?;
            if name.trim().is_empty() {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "vault name must not be empty".into(),
                });
            }
            let mut registry = load_registry(&root)?;
            let profile = registry
                .profiles
                .iter_mut()
                .find(|profile| profile.id == id)
                .ok_or(KeyLeaseError::NotFound { resource: id })?;
            profile.name = name.trim().into();
            save_registry(&root, &registry)
        }
    }
}

fn provision_desktop(paths: &DesktopPaths, input: DesktopProvisionInput) -> Result<()> {
    let input = match input {
        DesktopProvisionInput::RepairDesktopClient { password } => {
            if !paths.database.is_file() {
                return Err(KeyLeaseError::NotFound {
                    resource: "managed vault".into(),
                });
            }
            let service = service(&paths.database)?;
            let vault_id = service.unlock(password.0.as_bytes(), Duration::minutes(5))?;
            let (agent_id, token) = service.register_desktop_client()?;
            write_atomic(&paths.token, token.as_bytes())?;
            return print_json(&json!({
                "state":"ready",
                "vault_id":vault_id,
                "agent_id":agent_id,
                "repaired":true
            }));
        }
        input => input,
    };

    if paths.database.exists() || paths.token.exists() {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "managed vault already exists; refusing to overwrite it".into(),
        });
    }

    let staging = tempfile::Builder::new()
        .prefix(".provision-")
        .tempdir_in(&paths.home)
        .map_err(|_| KeyLeaseError::Storage)?;
    fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700))
        .map_err(|_| KeyLeaseError::Storage)?;
    let staging_database = staging.path().join("keylease.sqlite");
    let staging_token = staging.path().join("desktop.token");
    let mut import_result = Value::Null;

    let (service, vault_id) = match input {
        DesktopProvisionInput::Create { password } => {
            let service = service(&staging_database)?;
            let vault_id = service.initialize(password.0.as_bytes(), Duration::minutes(5))?;
            (service, vault_id)
        }
        DesktopProvisionInput::AdoptKeyleaseDatabase {
            source_path,
            password,
        } => {
            validate_regular_source(&source_path)?;
            NativeStore::snapshot_database(&source_path, &staging_database)?;
            let service = service(&staging_database)?;
            let vault_id = service.unlock(password.0.as_bytes(), Duration::minutes(5))?;
            (service, vault_id)
        }
        DesktopProvisionInput::RestoreKeyleaseBackup {
            source_path,
            password,
        } => {
            validate_regular_source(&source_path)?;
            let bytes = fs::read(source_path).map_err(|_| KeyLeaseError::Storage)?;
            let service = service(&staging_database)?;
            let vault_id = service.restore_native_backup(
                password.0.as_bytes(),
                &bytes,
                Duration::minutes(5),
            )?;
            (service, vault_id)
        }
        DesktopProvisionInput::ImportKdbx {
            source_path,
            source_password,
            password,
        } => {
            validate_regular_source(&source_path)?;
            let bytes = fs::read(source_path).map_err(|_| KeyLeaseError::Storage)?;
            let service = service(&staging_database)?;
            let vault_id = service.initialize(password.0.as_bytes(), Duration::minutes(5))?;
            let preview = service.preview_kdbx_import(&bytes, &source_password.0)?;
            import_result = serde_json::to_value(service.commit_kdbx_import(&preview)?)
                .map_err(|_| KeyLeaseError::Storage)?;
            (service, vault_id)
        }
        DesktopProvisionInput::ImportOnepux {
            source_path,
            password,
            acknowledge_plaintext,
        } => {
            if !acknowledge_plaintext {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "1PUX contains plaintext secrets; acknowledgment is required".into(),
                });
            }
            let bytes = read_onepux_source(&source_path)?;
            let service = service(&staging_database)?;
            let vault_id = service.initialize(password.0.as_bytes(), Duration::minutes(5))?;
            let preview = service.preview_onepux_import(&bytes)?;
            import_result = serde_json::to_value(service.commit_onepux_import(&preview)?)
                .map_err(|_| KeyLeaseError::Storage)?;
            (service, vault_id)
        }
        DesktopProvisionInput::RepairDesktopClient { .. } => unreachable!(),
    };

    if service.list_groups()?.is_empty() {
        service.create_group("Personal", None)?;
    }
    let (agent_id, token) = service.register_desktop_client()?;
    fs::write(&staging_token, token.as_bytes()).map_err(|_| KeyLeaseError::Storage)?;
    fs::set_permissions(&staging_token, fs::Permissions::from_mode(0o600))
        .map_err(|_| KeyLeaseError::Storage)?;
    drop(service);

    fs::hard_link(&staging_database, &paths.database).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            KeyLeaseError::InvalidRequest {
                reason: "managed vault already exists; refusing to overwrite it".into(),
            }
        } else {
            KeyLeaseError::Storage
        }
    })?;
    if let Err(error) = fs::hard_link(&staging_token, &paths.token) {
        let _ = fs::remove_file(&paths.database);
        return Err(if error.kind() == io::ErrorKind::AlreadyExists {
            KeyLeaseError::InvalidRequest {
                reason: "managed desktop token already exists".into(),
            }
        } else {
            KeyLeaseError::Storage
        });
    }
    print_json(&json!({
        "state":"ready",
        "vault_id":vault_id,
        "agent_id":agent_id,
        "import":import_result
    }))
}

fn vault_command(db: &Path, command: VaultCommand) -> Result<()> {
    match command {
        VaultCommand::Init { password_file } => {
            let first = if let Some(path) = password_file {
                read_secret_file(&path, "vault password")?
            } else {
                let first = prompt("New master password: ")?;
                let second = prompt("Confirm master password: ")?;
                if first != second {
                    return Err(KeyLeaseError::InvalidRequest {
                        reason: "passwords differ".into(),
                    });
                }
                first
            };
            if first.trim().len() < 10 {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "password is shorter than 10 characters".into(),
                });
            }
            let service = service(db)?;
            let vault_id = service.initialize(first.trim().as_bytes(), Duration::minutes(5))?;
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

async fn agent_command(cli: &Cli, socket: &Path, command: AgentCommand) -> Result<()> {
    match command {
        AgentCommand::NewItem { handoff_id, json } => {
            let value = rpc(
                socket,
                RpcRequest::AgentHandoffGet {
                    auth: auth(cli)?,
                    handoff_id,
                },
            )
            .await?;
            let guide: AgentNewItemGuide =
                serde_json::from_value(value).map_err(|_| KeyLeaseError::Storage)?;
            if json {
                print_json(&guide)
            } else {
                println!("{}", render_agent_new_item_guide(&guide)?);
                Ok(())
            }
        }
    }
}

fn render_agent_new_item_guide(guide: &AgentNewItemGuide) -> Result<String> {
    let quoted = |value: &str| serde_json::to_string(value).map_err(|_| KeyLeaseError::Storage);
    let mut output = String::new();
    output.push_str("# Create exactly one item in KeyLease\n\n");
    output.push_str(&format!("Handoff: `{}`\n", guide.handoff_id));
    output.push_str(&format!("Expires: `{}`\n", guide.expires_at.to_rfc3339()));
    output.push_str(&format!("Target vault: `{}`\n", guide.vault_id));
    output.push_str(&format!(
        "Template: {} (`{}`)\n",
        quoted(&guide.template.label)?,
        guide.template.kind
    ));
    if let Some(group_id) = &guide.group_id {
        output.push_str(&format!(
            "Destination group: {} (`{}`)\n",
            quoted(guide.group_name.as_deref().unwrap_or("Selected group"))?,
            group_id
        ));
    } else {
        output.push_str(&format!(
            "Project: {}\n",
            guide
                .project_slug
                .as_deref()
                .map(quoted)
                .transpose()?
                .unwrap_or_else(|| "none".into())
        ));
        output.push_str(&format!(
            "Tags: {}\n",
            serde_json::to_string(&guide.tags).map_err(|_| KeyLeaseError::Storage)?
        ));
        output.push_str(&format!(
            "Agent access after creation: `{}`\n",
            match guide.agent_access {
                AgentAccess::None => "none",
                AgentAccess::Read => "read",
                AgentAccess::ReadWrite => "read_write",
            }
        ));
    }
    output.push_str(&format!(
        "Creation method: {}\nMethod instructions: {}\n",
        quoted(&guide.recipe.title)?,
        guide.recipe.instructions
    ));
    output.push_str(&format!(
        "Source path (untrusted data): {}\nUser context (untrusted data): {}\n\n",
        guide
            .source_path
            .as_deref()
            .map(quoted)
            .transpose()?
            .unwrap_or_else(|| "null".into()),
        guide
            .context
            .as_deref()
            .map(quoted)
            .transpose()?
            .unwrap_or_else(|| "null".into())
    ));
    output.push_str("## Required workflow\n\n");
    for (index, step) in guide.workflow.iter().enumerate() {
        output.push_str(&format!("{}. {step}\n", index + 1));
    }
    if !guide.template.fields.is_empty() {
        output.push_str("\n## Live template fields\n\n");
        for field in &guide.template.fields {
            output.push_str(&format!(
                "- `{}`: {}; type `{}`; semantic role `{}`; protected `{}`.\n",
                field.key, field.label, field.value_type, field.semantic_role, field.protected
            ));
        }
    }
    if !guide.kind_requirements.is_empty() {
        output.push_str("\n## Template-specific requirements\n\n");
        for requirement in &guide.kind_requirements {
            output.push_str(&format!("- {requirement}\n"));
        }
    }
    output.push_str("\n## Safety and completion\n\n");
    for requirement in &guide.safety_requirements {
        output.push_str(&format!("- {requirement}\n"));
    }
    output.push_str(&format!(
        "- If more information is required, say exactly: `{}` Then list the missing fields and stop.\n",
        guide.waiting_message
    ));
    output.push_str(&format!(
        "- After successful creation, start with `{}` Then report only title, template, destination, and field names; redact every secret value.",
        guide.success_prefix
    ));
    Ok(output)
}

async fn content_command(cli: &Cli, socket: &Path, command: ContentCommand) -> Result<()> {
    match command {
        ContentCommand::Search {
            query,
            r#type,
            tag,
            project,
            reviewed_only,
        } => {
            print_rpc(
                socket,
                RpcRequest::ContentSearch {
                    auth: auth(cli)?,
                    query,
                    kind: r#type,
                    tag,
                    project_slug: project,
                    reviewed_only,
                },
            )
            .await
        }
        ContentCommand::Get { id, raw } => {
            let value = rpc(
                socket,
                RpcRequest::ContentGet {
                    auth: auth(cli)?,
                    id: content_item_id(&id),
                },
            )
            .await?;
            if raw {
                let body = value
                    .get("body")
                    .and_then(Value::as_str)
                    .ok_or(KeyLeaseError::Storage)?;
                println!("{body}");
                Ok(())
            } else {
                print_json(&value)
            }
        }
        ContentCommand::Create {
            r#type,
            title,
            body_file,
            tags,
            project,
            idempotency_key,
        } => {
            let body = read_bounded_text(&body_file, 1024 * 1024)?;
            print_rpc(
                socket,
                RpcRequest::ContentCreate {
                    auth: auth(cli)?,
                    input: ContentCreateInput {
                        kind: format!("core.{type}", type = r#type),
                        title,
                        favorite: false,
                        body,
                        tags,
                        project_slug: project,
                    },
                    idempotency_key,
                },
            )
            .await
        }
        ContentCommand::Update {
            id,
            title,
            body_file,
            add_tags,
            remove_tags,
            project,
            clear_project,
            if_revision,
            idempotency_key,
        } => {
            let body = body_file
                .as_ref()
                .map(|path| read_bounded_text(path, 1024 * 1024))
                .transpose()?;
            print_rpc(
                socket,
                RpcRequest::ContentUpdate {
                    auth: auth(cli)?,
                    id: content_item_id(&id),
                    patch: ContentPatch {
                        title,
                        body,
                        tags: None,
                        add_tags,
                        remove_tags,
                        project_slug: project,
                        clear_project,
                        favorite: None,
                    },
                    if_revision,
                    idempotency_key,
                },
            )
            .await
        }
        ContentCommand::Access {
            id,
            access,
            if_revision,
            idempotency_key,
        } => {
            let access = match access.as_str() {
                "none" => AgentAccess::None,
                "read" => AgentAccess::Read,
                "read-write" => AgentAccess::ReadWrite,
                _ => unreachable!("clap validates agent access"),
            };
            print_rpc(
                socket,
                RpcRequest::ContentSetAccess {
                    auth: auth(cli)?,
                    id: content_item_id(&id),
                    access,
                    if_revision,
                    idempotency_key,
                },
            )
            .await
        }
        ContentCommand::Review {
            id,
            if_revision,
            idempotency_key,
        } => {
            print_rpc(
                socket,
                RpcRequest::ContentReview {
                    auth: auth(cli)?,
                    id: content_item_id(&id),
                    if_revision,
                    idempotency_key,
                },
            )
            .await
        }
    }
}

fn content_item_id(value: &str) -> ItemId {
    if let Some((_, id)) = value.rsplit_once('/')
        && value.starts_with("kl://")
    {
        return ItemId(id.into());
    }
    ItemId(value.into())
}

fn read_bounded_text(path: &Path, maximum: usize) -> Result<String> {
    let mut bytes = Vec::new();
    if path == Path::new("-") {
        io::stdin()
            .take((maximum + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| KeyLeaseError::Storage)?;
    } else {
        let metadata = fs::metadata(path).map_err(|_| KeyLeaseError::Storage)?;
        if metadata.len() > maximum as u64 {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "content body exceeds 1 MiB".into(),
            });
        }
        fs::File::open(path)
            .map_err(|_| KeyLeaseError::Storage)?
            .take((maximum + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| KeyLeaseError::Storage)?;
    }
    if bytes.len() > maximum {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "content body exceeds 1 MiB".into(),
        });
    }
    String::from_utf8(bytes).map_err(|_| KeyLeaseError::InvalidRequest {
        reason: "content body must be UTF-8".into(),
    })
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
        EntryCommand::View { id } => {
            print_rpc(
                socket,
                RpcRequest::EntriesView {
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
        EntryCommand::Reveal {
            id,
            field,
            field_id,
        } => {
            let auth = auth(cli)?;
            let id = ItemId(id);
            match (field, field_id) {
                (Some(field), None) => {
                    print_rpc(socket, RpcRequest::EntriesReveal { auth, id, field }).await
                }
                (None, Some(field_id)) => {
                    print_rpc(
                        socket,
                        RpcRequest::EntriesRevealById {
                            auth,
                            id,
                            field_id: FieldId(field_id),
                        },
                    )
                    .await
                }
                _ => Err(KeyLeaseError::InvalidRequest {
                    reason: "choose exactly one of --field or --field-id".into(),
                }),
            }
        }
        EntryCommand::Totp { id } => {
            print_rpc(
                socket,
                RpcRequest::EntriesTotp {
                    auth: auth(cli)?,
                    id: ItemId(id),
                },
            )
            .await
        }
        EntryCommand::History { id } => {
            print_rpc(
                socket,
                RpcRequest::EntriesHistory {
                    auth: auth(cli)?,
                    id: ItemId(id),
                },
            )
            .await
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
        RpcRequest::GroupsReorder {
            auth,
            parent_id,
            ordered_ids,
            expected_revisions,
            idempotency_key,
            dry_run,
        } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.reorder_groups_authorized(
                &actor,
                parent_id,
                &ordered_ids,
                &expected_revisions,
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
        RpcRequest::TemplatesList { auth } => {
            let _actor = actor(service, &auth)?;
            serde_json::to_value(builtin_item_kinds()).map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::TemplatesGet { auth, kind } => {
            let _actor = actor(service, &auth)?;
            serde_json::to_value(
                item_kind(&kind).ok_or(KeyLeaseError::NotFound { resource: kind })?,
            )
            .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::AgentHandoffCreate { auth, input } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.create_agent_new_item_handoff_authorized(&actor, input)?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::AgentHandoffGet { auth, handoff_id } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(
                service.get_agent_new_item_handoff_authorized(&actor, &handoff_id)?,
            )
            .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::MigrationsStatus { auth } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.migration_status(&actor)?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::MigrationsPreview { auth, migration_id } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.preview_migration(&actor, &migration_id)?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::MigrationsApply {
            auth,
            migration_id,
            preview_digest,
        } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.apply_migration(&actor, &migration_id, &preview_digest)?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::MigrationsRollback { auth, migration_id } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.rollback_migration(&actor, &migration_id)?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::ProjectsList { auth } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.list_projects_agent(&actor)?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::ProjectsCreate {
            auth,
            slug,
            name,
            idempotency_key,
        } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.create_project_agent(
                &actor,
                &slug,
                name.as_deref(),
                &idempotency_key,
            )?)
            .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::ContentSearch {
            auth,
            query,
            kind,
            tag,
            project_slug,
            reviewed_only,
        } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.search_content(
                &actor,
                &query,
                kind.as_deref(),
                tag.as_deref(),
                project_slug.as_deref(),
                reviewed_only,
            )?)
            .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::ContentGet { auth, id } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.get_content(&actor, &id)?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::ContentCreate {
            auth,
            input,
            idempotency_key,
        } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.create_content(&actor, input, &idempotency_key)?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::ContentUpdate {
            auth,
            id,
            patch,
            if_revision,
            idempotency_key,
        } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.update_content(
                &actor,
                &id,
                patch,
                if_revision,
                &idempotency_key,
            )?)
            .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::ContentSetAccess {
            auth,
            id,
            access,
            if_revision,
            idempotency_key,
        } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.set_content_access(
                &actor,
                &id,
                access,
                if_revision,
                &idempotency_key,
            )?)
            .map_err(|_| KeyLeaseError::Storage)
        }
        RpcRequest::ContentReview {
            auth,
            id,
            if_revision,
            idempotency_key,
        } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.review_content(
                &actor,
                &id,
                if_revision,
                &idempotency_key,
            )?)
            .map_err(|_| KeyLeaseError::Storage)
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
        RpcRequest::EntriesView { auth, id } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.get_entry_view(&actor, &id)?)
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
        RpcRequest::EntriesRevealById { auth, id, field_id } => {
            let actor = actor(service, &auth)?;
            Ok(json!({
                "item_id":id,
                "field_id":field_id,
                "value":service.reveal_field_by_id_authorized(&actor, &id, &field_id)?,
            }))
        }
        RpcRequest::EntriesRevealMany {
            auth,
            id,
            field_ids,
        } => {
            let actor = actor(service, &auth)?;
            Ok(json!({
                "item_id":id,
                "values":service.reveal_fields_by_id_authorized(&actor, &id, &field_ids)?,
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
        RpcRequest::GeneratePassword {
            auth,
            length,
            recipe,
        } => {
            actor(service, &auth)?;
            let password = match recipe {
                Some(recipe) => keylease_service::generate_password_with_recipe(&recipe)?,
                None => keylease_service::generate_password(length)?,
            };
            Ok(json!({"password":password}))
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
        .unwrap_or_else(|| "agent_desktop".into());
    let path = cli
        .client_token_file
        .clone()
        .unwrap_or_else(default_client_token);
    let token = read_secret_file(&path, "client token")?;
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
    print_json(&rpc(socket, request).await?)
}

async fn rpc(socket: &Path, request: RpcRequest) -> Result<Value> {
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
        Ok(response.get("result").cloned().unwrap_or(Value::Null))
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
    managed_home()
        .map(|home| home.join("run/keylease.sock"))
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!(
                "keylease-{}.sock",
                std::env::var("USER").unwrap_or_else(|_| "user".into())
            ))
        })
}
fn default_database() -> PathBuf {
    managed_home()
        .and_then(|home| desktop_paths(Some(home)).ok().map(|paths| paths.database))
        .unwrap_or_else(|| PathBuf::from("keylease.sqlite"))
}
fn default_client_token() -> PathBuf {
    managed_home()
        .and_then(|home| desktop_paths(Some(home)).ok().map(|paths| paths.token))
        .unwrap_or_else(|| PathBuf::from("desktop.token"))
}
fn managed_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".keylease"))
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
    fn agent_new_item_command_supports_markdown_and_json() {
        for arguments in [
            vec!["keylease", "agent", "new-item", "handoff_test"],
            vec!["keylease", "agent", "new-item", "handoff_test", "--json"],
        ] {
            let cli = Cli::try_parse_from(arguments).unwrap();
            assert!(matches!(
                cli.command,
                Command::Agent {
                    command: AgentCommand::NewItem { .. }
                }
            ));
        }

        let guide = AgentNewItemGuide {
            protocol_version: 1,
            handoff_id: "handoff_test".into(),
            expires_at: Utc::now() + Duration::hours(2),
            vault_id: VaultId("vault_test".into()),
            recipe: keylease_service::AgentNewItemRecipeView {
                id: "describe".into(),
                title: "Describe what to save".into(),
                instructions: "Ask only for missing values.".into(),
            },
            template: item_kind("core.environment").unwrap(),
            group_id: Some(GroupId("group_test".into())),
            group_name: Some("Work".into()),
            project_slug: None,
            tags: vec![],
            agent_access: AgentAccess::ReadWrite,
            source_path: Some(".env".into()),
            context: Some("Import the development environment".into()),
            workflow: vec![
                "Run `keylease templates get core.environment`, validate, then create exactly one item."
                    .into(),
            ],
            kind_requirements: vec!["Preserve environment names.".into()],
            safety_requirements: vec!["Do not reveal unrelated items.".into()],
            waiting_message: "Waiting for details".into(),
            success_prefix: "Created in KeyLease: <item-id>".into(),
        };
        let markdown = render_agent_new_item_guide(&guide).unwrap();
        assert!(markdown.contains("# Create exactly one item in KeyLease"));
        assert!(markdown.contains("keylease templates get"));
        assert!(markdown.contains("Import the development environment"));
        assert!(markdown.contains("Created in KeyLease: <item-id>"));
        assert!(!markdown.contains("desktop.token"));
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

    #[test]
    fn unattended_vault_init_accepts_only_a_private_password_file() {
        let directory = tempfile::tempdir().unwrap();
        let password_path = directory.path().join("vault-password");
        fs::write(&password_path, "a sufficiently long password\n").unwrap();
        fs::set_permissions(&password_path, fs::Permissions::from_mode(0o600)).unwrap();
        let database = directory.path().join("vault.sqlite");
        vault_command(
            &database,
            VaultCommand::Init {
                password_file: Some(password_path.clone()),
            },
        )
        .unwrap();
        assert!(database.exists());

        fs::set_permissions(&password_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            read_secret_file(&password_path, "vault password"),
            Err(KeyLeaseError::Denied { .. })
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

    #[test]
    fn desktop_create_provisions_private_managed_files_and_personal_group() {
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path().join(".keylease");
        let paths = desktop_paths(Some(home)).unwrap();
        ensure_desktop_home(&paths).unwrap();
        provision_desktop(
            &paths,
            DesktopProvisionInput::Create {
                password: SecretValue("desktop password".into()),
            },
        )
        .unwrap();

        assert!(paths.database.is_file());
        assert!(paths.token.is_file());
        assert_eq!(
            fs::metadata(&paths.token).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let service =
            KeyLeaseService::new(Arc::new(NativeStore::open(&paths.database).unwrap())).unwrap();
        service
            .unlock(b"desktop password", Duration::hours(1))
            .unwrap();
        assert_eq!(service.list_groups().unwrap()[0].name, "Personal");
    }

    #[test]
    fn desktop_registry_preserves_primary_and_resolves_the_active_profile() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join(".keylease");
        fs::create_dir_all(root.join("vaults/team")).unwrap();
        let registry = DesktopVaultRegistry {
            version: 1,
            active_id: "team".into(),
            profiles: vec![
                initial_registry().profiles.remove(0),
                DesktopVaultProfile {
                    id: "team".into(),
                    name: "Team".into(),
                    path: "vaults/team".into(),
                },
            ],
        };
        save_registry(&root, &registry).unwrap();
        let paths = desktop_paths(Some(root.clone())).unwrap();
        assert_eq!(paths.database, root.join("vaults/team/keylease.sqlite"));
        assert_eq!(paths.socket, root.join("run/keylease.sock"));
        assert_eq!(
            fs::metadata(registry_path(&root))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
