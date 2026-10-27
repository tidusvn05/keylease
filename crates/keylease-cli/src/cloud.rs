//! `keylease cloud …` and the relay sync loop (ADR 0006). The service builds
//! every signed, sealed payload; this module only carries them over HTTPS.

use super::*;
use keylease_core::relay::{
    FetchRecoveryKit, HEADER_MEMBER, HEADER_SIGNATURE, HEADER_TIMESTAMP, RecoveryKitResponse,
    RelayAccountCreated, RelayAck, RelayBackupList, RelayInbox, RelayInvite, RelayJoined,
    RelayMember,
};
use keylease_service::{CloudRole, ShareScope};
use reqwest::Method;

/// How often `keylease serve` syncs with a linked cloud.
pub(crate) const SYNC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Debug, Subcommand)]
pub(crate) enum CloudCommand {
    /// Owner: link this vault to a cloud as the account owner and print the
    /// recovery kit (once).
    Init {
        #[arg(long)]
        url: String,
        /// The cloud's admin token (KEYLEASE_ADMIN_TOKEN_FILE on the cloud).
        #[arg(long)]
        admin_token_file: PathBuf,
        /// A name for this device.
        #[arg(long, default_value = "owner")]
        name: String,
    },
    /// Owner: a one-time code that lets a node (a VPS) join.
    Invite { name: String },
    /// Node: join the owner's cloud with an invite code.
    Join {
        #[arg(long)]
        url: String,
        /// The invite code (asked for when omitted).
        #[arg(long)]
        code: Option<String>,
    },
    /// Owner, on a new device: restore the owner keys and the owner's backup
    /// from the recovery kit. Run `vault init` first.
    Recover {
        #[arg(long)]
        url: String,
        #[arg(long)]
        account: String,
        #[arg(long, default_value = "owner")]
        name: String,
    },
    /// Link, fingerprints and counters.
    Status,
    /// Run one sync round now (the daemon does this every minute).
    Sync,
    /// Owner: the nodes this device verified.
    Nodes,
    /// Owner: remove a node; its shares end and it can no longer sync.
    Remove { node: String },
    /// Owner: share an item (default) or a whole project with a node.
    Share {
        /// The item to share.
        item: Option<String>,
        /// Share every item of this project (slug or id) instead.
        #[arg(long, conflicts_with = "item")]
        project: Option<String>,
        /// The node (name or member id).
        #[arg(long)]
        to: String,
        /// End the share after 30m, 1h, 6h, 1d, 7d, 30d…
        #[arg(long)]
        ttl: Option<String>,
    },
    /// Owner: shares and their state.
    Shares,
    /// Owner: end a share; the node drops its copy on its next sync.
    Unshare { share_id: String },
    /// Share requests (owner: received; node: sent).
    Requests,
    /// Owner: approve a request by sharing ITEM with the node that asked.
    Approve {
        request_id: String,
        #[arg(long)]
        item: String,
        #[arg(long)]
        ttl: Option<String>,
    },
    /// Owner: deny a request.
    Deny { request_id: String },
    /// Owner: restore a member's backup to a node, or into this vault.
    Restore {
        /// The member whose backup to restore (a node's name or member id,
        /// or "owner").
        #[arg(long)]
        from: String,
        /// The node to restore to; this vault when omitted.
        #[arg(long)]
        to: Option<String>,
    },
    /// Forget the link and its keys on this device.
    Unlink,
    /// Node agent: ask the owner for an item (no master password needed).
    Request {
        purpose: String,
        /// What is needed, e.g. "prod database".
        #[arg(long)]
        hint: Option<String>,
    },
}

pub(crate) fn parse_ttl(value: &str) -> Result<Duration> {
    let value = value.trim();
    let invalid = || KeyLeaseError::InvalidRequest {
        reason: "a duration is a number followed by m, h or d (30m, 6h, 7d)".into(),
    };
    let (number, unit) = value.split_at(value.len().saturating_sub(1));
    let number: i64 = number.parse().map_err(|_| invalid())?;
    if number <= 0 {
        return Err(invalid());
    }
    match unit {
        "m" => Ok(Duration::minutes(number)),
        "h" => Ok(Duration::hours(number)),
        "d" => Ok(Duration::days(number)),
        _ => Err(invalid()),
    }
}

/// Carries relay requests; signed ones are signed by the service.
pub(crate) struct Relay<'a> {
    service: &'a KeyLeaseService,
    base: String,
    http: reqwest::Client,
}

fn relay_error(context: &str, status: reqwest::StatusCode, body: &str) -> KeyLeaseError {
    let detail: String = body.chars().take(200).collect();
    match status.as_u16() {
        401 | 403 => KeyLeaseError::Denied {
            reason: format!("{context}: the cloud refused ({status}) {detail}"),
        },
        404 => KeyLeaseError::NotFound {
            resource: format!("{context} ({detail})"),
        },
        _ => KeyLeaseError::ConnectorUnavailable { retryable: true },
    }
}

impl<'a> Relay<'a> {
    pub(crate) fn new(service: &'a KeyLeaseService, url: &str) -> Result<Self> {
        Ok(Self {
            service,
            base: url.trim_end_matches('/').to_owned(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .user_agent(concat!("keylease/", env!("CARGO_PKG_VERSION")))
                .build()
                .map_err(|_| KeyLeaseError::Storage)?,
        })
    }

    async fn send<T: serde::de::DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        signed: bool,
        bearer: Option<&str>,
    ) -> Result<T> {
        let mut request = self
            .http
            .request(method.clone(), format!("{}{path}", self.base));
        let bytes = body.unwrap_or_default();
        if signed {
            let signature = self
                .service
                .cloud_sign_request(method.as_str(), path, &bytes)?;
            request = request
                .header(HEADER_MEMBER, signature.member_id)
                .header(HEADER_TIMESTAMP, signature.timestamp.to_string())
                .header(HEADER_SIGNATURE, signature.signature_b64);
        }
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        if !bytes.is_empty() {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(bytes);
        }
        let response = request
            .send()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(relay_error(path, status, &text));
        }
        serde_json::from_str(&text).map_err(|_| KeyLeaseError::InvalidRequest {
            reason: format!("{path}: unexpected cloud response"),
        })
    }

    async fn post<B: Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        signed: bool,
    ) -> Result<T> {
        let bytes = serde_json::to_vec(body).map_err(|_| KeyLeaseError::Storage)?;
        self.send(Method::POST, path, Some(bytes), signed, None)
            .await
    }
}

/// One sync round. Quiet when the vault is unlinked or locked.
pub(crate) async fn sync_once(service: &KeyLeaseService) -> Result<Value> {
    let Some(link) = service.cloud_link()? else {
        return Ok(json!({"linked": false}));
    };
    if link.member_id.is_empty() {
        return Ok(json!({"linked": false, "pending": true}));
    }
    let outcome = sync_round(service, &link).await;
    match &outcome {
        Ok(_) => service.cloud_record_sync(None)?,
        Err(KeyLeaseError::VaultLocked { .. }) => {}
        Err(error) => service.cloud_record_sync(Some(format!("{error:?}")))?,
    }
    outcome
}

async fn sync_round(
    service: &KeyLeaseService,
    link: &keylease_service::CloudLink,
) -> Result<Value> {
    let relay = Relay::new(service, &link.url)?;
    let mut problems = Vec::new();
    let mut published = 0;
    if link.role == CloudRole::Owner {
        let members: Vec<RelayMember> = relay
            .send(Method::GET, "/v1/relay/members", None, true, None)
            .await?;
        problems.extend(service.cloud_verify_members(&members)?);
        published = service.cloud_publish_shares()?;
    }
    let mut sent = 0;
    for message in service.cloud_outbox()? {
        match relay
            .post::<_, Value>("/v1/relay/messages", &message, true)
            .await
        {
            Ok(_) => {}
            // The recipient was removed: the message can never be delivered.
            Err(KeyLeaseError::NotFound { .. }) => {}
            Err(error) => return Err(error),
        }
        service.cloud_outbox_sent(&message.message_id)?;
        sent += 1;
    }
    let mut backed_up = 0;
    loop {
        let batch = service.cloud_backup_batch(50)?;
        if batch.is_empty() {
            break;
        }
        for pending in &batch {
            let bytes = serde_json::to_vec(&pending.backup).map_err(|_| KeyLeaseError::Storage)?;
            relay
                .send::<Value>(Method::PUT, "/v1/relay/backups", Some(bytes), true, None)
                .await?;
            service.cloud_backup_stored(pending)?;
            backed_up += 1;
        }
    }
    let inbox: RelayInbox = relay
        .send(
            Method::GET,
            "/v1/relay/messages?limit=200",
            None,
            true,
            None,
        )
        .await?;
    let applied = service.cloud_apply_inbox(&inbox.messages)?;
    if !applied.acknowledged.is_empty() {
        relay
            .post::<_, Value>(
                "/v1/relay/messages/ack",
                &RelayAck {
                    message_ids: applied.acknowledged.clone(),
                },
                true,
            )
            .await?;
    }
    problems.extend(applied.rejected.iter().cloned());
    Ok(json!({
        "linked": true,
        "role": link.role,
        "published": published,
        "sent": sent,
        "backed_up": backed_up,
        "received": applied.applied,
        "problems": problems,
    }))
}

/// The background sync of `keylease serve`.
pub(crate) fn spawn_sync_loop(service: Arc<KeyLeaseService>) {
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        loop {
            if let Ok(Some(link)) = service.cloud_link()
                && !link.member_id.is_empty()
            {
                match sync_once(&service).await {
                    Ok(value) => {
                        let problems = value["problems"].as_array().map_or(0, Vec::len);
                        if problems > 0 {
                            eprintln!("KeyLease cloud sync: {}", value["problems"]);
                        }
                    }
                    Err(KeyLeaseError::VaultLocked { .. }) => {}
                    Err(error) => eprintln!("KeyLease cloud sync failed: {error:?}"),
                }
            }
            tokio::time::sleep(SYNC_INTERVAL).await;
        }
    });
}

fn require_link(service: &KeyLeaseService) -> Result<keylease_service::CloudLink> {
    service
        .cloud_link()?
        .filter(|link| !link.member_id.is_empty())
        .ok_or_else(|| KeyLeaseError::InvalidRequest {
            reason: "this vault is not linked to a cloud (keylease cloud init / join)".into(),
        })
}

pub(crate) async fn cloud_command(cli: &Cli, socket: &Path, command: CloudCommand) -> Result<()> {
    if let CloudCommand::Request { purpose, hint } = command {
        return print_rpc(
            socket,
            RpcRequest::CloudRequest {
                auth: auth(cli)?,
                purpose,
                hint,
            },
        )
        .await;
    }
    let service = admin_service(&cli.db)?;
    match command {
        CloudCommand::Init {
            url,
            admin_token_file,
            name,
        } => {
            let token = read_secret_file(&admin_token_file, "cloud admin token")?;
            let setup = service.cloud_owner_prepare(&url, &name)?;
            let link = service.cloud_link()?.ok_or(KeyLeaseError::Storage)?;
            let relay = Relay::new(&service, &link.url)?;
            let bytes = serde_json::to_vec(&setup.request).map_err(|_| KeyLeaseError::Storage)?;
            let created: RelayAccountCreated = relay
                .send(
                    Method::POST,
                    "/v1/relay/accounts",
                    Some(bytes),
                    false,
                    Some(token.trim()),
                )
                .await?;
            let link = service.cloud_owner_commit(&created)?;
            println!(
                "Linked to {} as the owner ({}).\nFingerprint: {}\n",
                link.url,
                link.member_id,
                link.fingerprint()
            );
            println!("KeyLease recovery kit: store it offline. It is shown only once.");
            println!("  Cloud:    {}", link.url);
            println!("  Account:  {}", link.account_id);
            println!("  Code:     {}", setup.recovery_code);
            println!(
                "\nOn a new device: keylease vault init, then\n  keylease cloud recover --url {} --account {}",
                link.url, link.account_id
            );
            Ok(())
        }
        CloudCommand::Invite { name } => {
            let link = require_link(&service)?;
            let invite = service.cloud_create_invite(&name)?;
            Relay::new(&service, &link.url)?
                .post::<_, Value>("/v1/relay/invites", &invite.request, true)
                .await?;
            print_json(&json!({
                "code": invite.code,
                "name": name,
                "expires_at": invite.request.expires_at,
                "owner_fingerprint": link.fingerprint(),
                "next": format!(
                    "On the node: keylease cloud join --url {}  (enter the code; check that it shows owner fingerprint {}). Then run keylease cloud sync here.",
                    link.url,
                    link.fingerprint()
                ),
            }))
        }
        CloudCommand::Join { url, code } => {
            let code = match code {
                Some(code) => Zeroizing::new(code),
                None => prompt("Invite code: ")?,
            };
            let lookup = KeyLeaseService::cloud_invite_lookup(&code)?;
            let probe = Relay::new(&service, &url)?;
            let invite: RelayInvite = probe
                .send(
                    Method::GET,
                    &format!("/v1/relay/invites/{lookup}"),
                    None,
                    false,
                    None,
                )
                .await?;
            let join = service.cloud_node_prepare(&url, &code, &invite)?;
            let joined: RelayJoined = probe.post("/v1/relay/join", &join, false).await?;
            let link = service.cloud_node_commit(&joined)?;
            print_json(&json!({
                "joined": link.account_id,
                "member_id": link.member_id,
                "name": link.name,
                "owner_fingerprint": link.owner_fingerprint(),
                "fingerprint": link.fingerprint(),
                "next": "Compare the owner fingerprint with the one the owner saw. A running `keylease serve` picks the link up and syncs every minute.",
            }))
        }
        CloudCommand::Recover { url, account, name } => {
            let code = prompt("Recovery code: ")?;
            let lookup = KeyLeaseService::cloud_recovery_lookup(&code, &account)?;
            let probe = Relay::new(&service, &url)?;
            let kit: RecoveryKitResponse = probe
                .post(
                    "/v1/relay/recovery",
                    &FetchRecoveryKit {
                        account_id: account.clone(),
                        lookup_hex: lookup,
                    },
                    false,
                )
                .await?;
            let link = service.cloud_recover(
                &url,
                &account,
                &kit.owner_member_id,
                &kit.recovery_kit,
                &code,
                &name,
            )?;
            let relay = Relay::new(&service, &link.url)?;
            let backups: RelayBackupList = relay
                .send(
                    Method::GET,
                    &format!("/v1/relay/backups?member={}", link.member_id),
                    None,
                    true,
                    None,
                )
                .await?;
            let restored = service.cloud_restore(&link.member_id, None, &backups.backups)?;
            print_json(&json!({
                "recovered": link.account_id,
                "fingerprint": link.fingerprint(),
                "restored_items": restored,
                "nodes": service.cloud_nodes()?.len(),
            }))
        }
        CloudCommand::Status => print_json(&service.cloud_status()?),
        CloudCommand::Sync => print_json(&sync_once(&service).await?),
        CloudCommand::Nodes => print_json(&service.cloud_nodes()?),
        CloudCommand::Remove { node } => {
            let link = require_link(&service)?;
            let removed = service.cloud_remove_node(&node)?;
            let relay = Relay::new(&service, &link.url)?;
            relay
                .send::<Value>(
                    Method::DELETE,
                    &format!("/v1/relay/members/{}", removed.member_id),
                    None,
                    true,
                    None,
                )
                .await?;
            let _ = sync_once(&service).await;
            print_json(&removed)
        }
        CloudCommand::Share {
            item,
            project,
            to,
            ttl,
        } => {
            let scope = match (item, project) {
                (Some(item), None) => ShareScope::Item {
                    item_id: ItemId(item),
                },
                (None, Some(project)) => ShareScope::Project {
                    project_id: service.cloud_project_id(&project)?,
                },
                _ => {
                    return Err(KeyLeaseError::InvalidRequest {
                        reason: "name an item, or --project".into(),
                    });
                }
            };
            let ttl = ttl.as_deref().map(parse_ttl).transpose()?;
            let share = service.cloud_share(scope, &to, ttl, None)?;
            let synced = sync_once(&service).await.ok();
            print_json(&json!({"share": share, "sync": synced}))
        }
        CloudCommand::Shares => print_json(&service.cloud_shares()?),
        CloudCommand::Unshare { share_id } => {
            let share = service.cloud_revoke_share(&share_id)?;
            let synced = sync_once(&service).await.ok();
            print_json(&json!({"share": share, "sync": synced}))
        }
        CloudCommand::Requests => {
            let _ = sync_once(&service).await;
            print_json(&service.cloud_requests()?)
        }
        CloudCommand::Approve {
            request_id,
            item,
            ttl,
        } => {
            let ttl = ttl.as_deref().map(parse_ttl).transpose()?;
            let share = service.cloud_approve_request(&request_id, &ItemId(item), ttl)?;
            let synced = sync_once(&service).await.ok();
            print_json(&json!({"share": share, "sync": synced}))
        }
        CloudCommand::Deny { request_id } => {
            let request = service.cloud_deny_request(&request_id)?;
            let synced = sync_once(&service).await.ok();
            print_json(&json!({"request": request, "sync": synced}))
        }
        CloudCommand::Restore { from, to } => {
            let link = require_link(&service)?;
            let from_id = if from == "owner" || from == link.member_id {
                link.member_id.clone()
            } else {
                service
                    .cloud_nodes()?
                    .into_iter()
                    .find(|node| node.name == from || node.member_id == from)
                    .map(|node| node.member_id)
                    .ok_or_else(|| KeyLeaseError::NotFound {
                        resource: format!("node {from}"),
                    })?
            };
            let relay = Relay::new(&service, &link.url)?;
            let backups: RelayBackupList = relay
                .send(
                    Method::GET,
                    &format!("/v1/relay/backups?member={from_id}"),
                    None,
                    true,
                    None,
                )
                .await?;
            let restored = service.cloud_restore(&from_id, to.as_deref(), &backups.backups)?;
            let synced = sync_once(&service).await.ok();
            print_json(&json!({"restored": restored, "from": from_id, "to": to, "sync": synced}))
        }
        CloudCommand::Unlink => {
            service.cloud_unlink()?;
            print_json(&json!({"unlinked": true}))
        }
        CloudCommand::Request { .. } => unreachable!("handled above"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_durations_parse() {
        assert_eq!(parse_ttl("30m").unwrap(), Duration::minutes(30));
        assert_eq!(parse_ttl("7d").unwrap(), Duration::days(7));
        assert!(parse_ttl("0h").is_err());
        assert!(parse_ttl("1w").is_err());
        assert!(parse_ttl("").is_err());
    }
}
