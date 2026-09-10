//! The single implementation of the local RPC contract.
//!
//! Both transports depend on this crate: the CLI daemon frames it over a Unix
//! socket, and the mobile FFI layer calls it in process. Neither owns a copy of
//! the request type or the response envelope, so the wire protocol cannot drift
//! between them.
//!
//! Nothing here may touch the filesystem, the environment, stdout or a process.
//! The database path, the transport and the framing all belong to the caller.
//! `keylease-cli` owns `$HOME/.keylease`; this crate must stay unaware of it.

use chrono::Duration;
use keylease_core::*;
use keylease_service::{
    AgentNewItemHandoffInput, ContentCreateInput, ContentPatch, EntryPatch, KeyLeaseService,
    NewEntryInput,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Vault lifecycle operations, in a dispatcher of their own.
///
/// Gated so a binary that never provisions does not carry the code. The
/// security property — that the socket transport cannot reach these — comes
/// from them being a separate enum and a separate function, not from this
/// feature; see the module docs.
#[cfg(feature = "provisioning")]
pub mod provisioning;

/// What a transport is allowed to dispatch.
///
/// This is passed explicitly rather than being a cargo feature because cargo
/// unifies features across a workspace build: `keylease-cli` needs
/// `agent-handoff`, so a `--workspace` build compiles `keylease-rpc` once with
/// it enabled and `keylease-mobile` links that. The feature still trims the
/// code out of the shipped `.so` (which is built with `-p keylease-mobile`
/// alone, without the CLI in the graph), but only this runtime value holds
/// regardless of how the crate was built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RpcCapabilities {
    /// Whether the agent new-item handoff may run. Desktop only: the workflow
    /// hands the user a CLI command to paste into a coding agent on the same
    /// machine.
    pub agent_handoff: bool,
}

impl RpcCapabilities {
    /// The full surface, as the local daemon serves it.
    pub const DESKTOP: Self = Self {
        agent_handoff: true,
    };

    /// The mobile surface. Agent workflows are not offered on a phone.
    pub const MOBILE: Self = Self {
        agent_handoff: false,
    };
}

impl RpcRequest {
    /// Whether this request belongs to the agent handoff workflow.
    pub fn is_agent_handoff(&self) -> bool {
        matches!(
            self,
            RpcRequest::AgentHandoffCreate { .. } | RpcRequest::AgentHandoffGet { .. }
        )
    }
}

/// Upper bound on a single request or response, in bytes.
///
/// The socket transport also enforces this while framing; the check here is the
/// semantic one and applies to every transport.
pub const MAX_LOCAL_JSON_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcAuth {
    pub agent_id: AgentId,
    pub token: SecretValue,
    pub session_id: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum RpcRequest {
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

pub async fn handle_rpc(
    service: &KeyLeaseService,
    capabilities: RpcCapabilities,
    request: RpcRequest,
) -> Result<Value> {
    // One audited place decides what this transport may run. Keeping it here
    // rather than in each arm means a new agent command cannot be added without
    // passing this check.
    if request.is_agent_handoff() && !capabilities.agent_handoff {
        return Err(KeyLeaseError::Denied {
            reason: "agent handoff is not available on this client".into(),
        });
    }
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
        #[cfg(feature = "agent-handoff")]
        RpcRequest::AgentHandoffCreate { auth, input } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(service.create_agent_new_item_handoff_authorized(&actor, input)?)
                .map_err(|_| KeyLeaseError::Storage)
        }
        #[cfg(feature = "agent-handoff")]
        RpcRequest::AgentHandoffGet { auth, handoff_id } => {
            let actor = actor(service, &auth)?;
            serde_json::to_value(
                service.get_agent_new_item_handoff_authorized(&actor, &handoff_id)?,
            )
            .map_err(|_| KeyLeaseError::Storage)
        }
        // The variants stay in the type so the serde representation is
        // identical in every build; only the dispatch arm is gated.
        #[cfg(not(feature = "agent-handoff"))]
        RpcRequest::AgentHandoffCreate { .. } | RpcRequest::AgentHandoffGet { .. } => {
            Err(KeyLeaseError::Denied {
                reason: "agent handoff is not available on this build".into(),
            })
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

/// Wraps a dispatch outcome in the canonical response envelope.
///
/// The shape is load-bearing: the Dart client routes on `ok` and maps
/// `error.error` to a typed code, so it must never change.
pub fn encode_response(outcome: Result<Value>) -> Value {
    match outcome {
        Ok(value) => json!({"ok": true, "result": value}),
        Err(error) => json!({"ok": false, "error": error}),
    }
}

/// Dispatches an already-parsed request and returns the response envelope.
///
/// Taking a [`Value`] rather than a string lets an in-process caller splice an
/// `auth` block into the request without serialising a payload that may hold a
/// master password a second time.
pub async fn dispatch_value(
    service: &KeyLeaseService,
    capabilities: RpcCapabilities,
    request: Value,
) -> Value {
    let parsed =
        serde_json::from_value::<RpcRequest>(request).map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid JSON RPC request".into(),
        });
    match parsed {
        Ok(request) => encode_response(handle_rpc(service, capabilities, request).await),
        Err(error) => encode_response(Err(error)),
    }
}

/// Dispatches one request encoded as JSON text.
///
/// The response is returned in a [`Zeroizing`] buffer because it may carry a
/// revealed secret. Framing (newline termination, the socket read loop) belongs
/// to the transport, not here.
pub async fn dispatch_line(
    service: &KeyLeaseService,
    capabilities: RpcCapabilities,
    line: &str,
) -> Zeroizing<String> {
    if line.len() > MAX_LOCAL_JSON_BYTES {
        return Zeroizing::new(
            encode_response(Err(KeyLeaseError::InvalidRequest {
                reason: "local RPC request exceeds size limit".into(),
            }))
            .to_string(),
        );
    }
    let parsed = serde_json::from_str::<Value>(line).map_err(|_| KeyLeaseError::InvalidRequest {
        reason: "invalid JSON RPC request".into(),
    });
    let response = match parsed {
        Ok(value) => dispatch_value(service, capabilities, value).await,
        Err(error) => encode_response(Err(error)),
    };
    Zeroizing::new(response.to_string())
}
