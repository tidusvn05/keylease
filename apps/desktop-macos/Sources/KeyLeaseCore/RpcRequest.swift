import Foundation

/// One request to the local daemon.
///
/// Mirrors `RpcRequest` in `crates/keylease-rpc/src/lib.rs` minus the `auth`
/// field: like the Dart client, the transport splices a freshly read `auth`
/// block into the encoded object at call time, so the same request value can
/// be sent by either `authorized(_:)` or `unauthenticated(_:)`.
///
/// The wire name of every case is frozen by `test-vectors/rpc/commands.json`
/// and asserted by `WireCommandParityTests` — renaming a `command` string is
/// a protocol break.
public enum RpcRequest: Encodable, Sendable {
    case status
    case unlock(password: SecretValue, sessionTtlSeconds: Int64)
    case groupsList
    case groupsCreate(
        name: String,
        parentId: String?,
        idempotencyKey: String,
        dryRun: Bool
    )
    case groupsUpdate(
        id: String,
        name: String,
        ifRevision: UInt64,
        idempotencyKey: String,
        dryRun: Bool
    )
    case groupsReorder(
        parentId: String?,
        orderedIds: [String],
        expectedRevisions: [String: UInt64],
        idempotencyKey: String,
        dryRun: Bool
    )
    case groupsDelete(
        id: String,
        ifRevision: UInt64,
        idempotencyKey: String,
        dryRun: Bool
    )
    case templatesList
    case templatesGet(kind: String)
    case agentHandoffCreate(input: AgentNewItemHandoffInput)
    case agentHandoffGet(handoffId: String)
    case migrationsStatus
    case migrationsPreview(migrationId: String)
    case migrationsApply(migrationId: String, previewDigest: String)
    case migrationsRollback(migrationId: String)
    case projectsList
    case projectsCreate(slug: String, name: String?, idempotencyKey: String)
    case contentSearch(
        query: String,
        kind: String?,
        tag: String?,
        projectSlug: String?,
        reviewedOnly: Bool
    )
    case contentGet(id: String)
    case contentCreate(input: ContentCreateInput, idempotencyKey: String)
    case contentUpdate(
        id: String,
        patch: ContentPatch,
        ifRevision: UInt64,
        idempotencyKey: String
    )
    case contentSetAccess(
        id: String,
        access: AgentAccess,
        ifRevision: UInt64,
        idempotencyKey: String
    )
    case contentReview(id: String, ifRevision: UInt64, idempotencyKey: String)
    case entriesSearch(query: String)
    case entriesGet(id: String)
    case entriesView(id: String)
    case entriesCreate(
        input: NewEntryInput,
        idempotencyKey: String,
        dryRun: Bool
    )
    case entriesUpdate(
        id: String,
        patch: EntryPatch,
        ifRevision: UInt64,
        idempotencyKey: String,
        dryRun: Bool
    )
    case entriesDelete(
        id: String,
        ifRevision: UInt64,
        idempotencyKey: String,
        dryRun: Bool
    )
    case entriesReveal(id: String, field: String)
    case entriesRevealById(id: String, fieldId: String)
    case entriesRevealMany(id: String, fieldIds: [String])
    case entriesTotp(id: String)
    case entriesHistory(id: String)
    case generatePassword(length: UInt, recipe: PasswordRecipe?)
    case connectionsList
    case connectionAdd(
        provider: String,
        credential: SecretValue,
        authorizedResources: [String]
    )
    case connectionEnroll(id: String, resource: String)
    case connectionUnenroll(id: String, resource: String)
    case connectionTest(id: String)
    case connectionRefresh(id: String)
    case connectionDisconnect(id: String)
    case connectionRevoke(id: String)
    case connectionGoogleOauthBegin(clientId: String, clientSecret: SecretValue?)
    case connectionGoogleOauthComplete(flowId: String)
    case approvalsList(limit: UInt32)
    /// `trust` turns an approval into a time-boxed trust (ADR 0005).
    case approvalDecide(id: String, approve: Bool, trust: TrustDecision? = nil)
    case trustsList
    case trustRevoke(id: String)
    /// A node agent asks the cloud owner for an item (ADR 0006).
    case cloudRequest(purpose: String, hint: String?)
    case agentEnroll(name: String)
    case sshIdentities
    case entriesInject(program: String, fields: [InjectField])
    case dbTarget(id: String)
    case dbScram(
        id: String,
        database: String,
        clientFirstBare: String,
        serverFirst: String
    )
    /// `publicKeyBlob` and `data` are base64.
    case sshSign(publicKeyBlob: String, data: String, flags: UInt32)
    case auditQuery(limit: UInt32)
    case leaseRequest(
        request: ActionRequest,
        ttlSeconds: UInt64,
        maxUses: UInt64,
        approvalId: String?
    )
    case gateExecute(leaseToken: SecretValue, request: ActionRequest)
    case lock

    /// The wire `command` value for this case, in `commands.json` order.
    public var command: String {
        switch self {
        case .status: "status"
        case .unlock: "unlock"
        case .groupsList: "groups_list"
        case .groupsCreate: "groups_create"
        case .groupsUpdate: "groups_update"
        case .groupsReorder: "groups_reorder"
        case .groupsDelete: "groups_delete"
        case .templatesList: "templates_list"
        case .templatesGet: "templates_get"
        case .agentHandoffCreate: "agent_handoff_create"
        case .agentHandoffGet: "agent_handoff_get"
        case .migrationsStatus: "migrations_status"
        case .migrationsPreview: "migrations_preview"
        case .migrationsApply: "migrations_apply"
        case .migrationsRollback: "migrations_rollback"
        case .projectsList: "projects_list"
        case .projectsCreate: "projects_create"
        case .contentSearch: "content_search"
        case .contentGet: "content_get"
        case .contentCreate: "content_create"
        case .contentUpdate: "content_update"
        case .contentSetAccess: "content_set_access"
        case .contentReview: "content_review"
        case .entriesSearch: "entries_search"
        case .entriesGet: "entries_get"
        case .entriesView: "entries_view"
        case .entriesCreate: "entries_create"
        case .entriesUpdate: "entries_update"
        case .entriesDelete: "entries_delete"
        case .entriesReveal: "entries_reveal"
        case .entriesRevealById: "entries_reveal_by_id"
        case .entriesRevealMany: "entries_reveal_many"
        case .entriesTotp: "entries_totp"
        case .entriesHistory: "entries_history"
        case .generatePassword: "generate_password"
        case .connectionsList: "connections_list"
        case .connectionAdd: "connection_add"
        case .connectionEnroll: "connection_enroll"
        case .connectionUnenroll: "connection_unenroll"
        case .connectionTest: "connection_test"
        case .connectionRefresh: "connection_refresh"
        case .connectionDisconnect: "connection_disconnect"
        case .connectionRevoke: "connection_revoke"
        case .connectionGoogleOauthBegin: "connection_google_oauth_begin"
        case .connectionGoogleOauthComplete: "connection_google_oauth_complete"
        case .approvalsList: "approvals_list"
        case .approvalDecide: "approval_decide"
        case .trustsList: "trusts_list"
        case .trustRevoke: "trust_revoke"
        case .agentEnroll: "agent_enroll"
        case .sshIdentities: "ssh_identities"
        case .entriesInject: "entries_inject"
        case .dbTarget: "db_target"
        case .dbScram: "db_scram"
        case .sshSign: "ssh_sign"
        case .cloudRequest: "cloud_request"
        case .auditQuery: "audit_query"
        case .leaseRequest: "lease_request"
        case .gateExecute: "gate_execute"
        case .lock: "lock"
        }
    }

    private struct WireKey: CodingKey {
        var stringValue: String
        var intValue: Int? { nil }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { nil }
    }

    private func key(_ name: String) -> WireKey {
        // All literals below are valid keys; force-unwrap keeps each case to
        // one line.
        WireKey(stringValue: name)!
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: WireKey.self)
        try c.encode(command, forKey: key("command"))
        switch self {
        case .status, .groupsList, .templatesList, .migrationsStatus,
            .projectsList, .connectionsList, .trustsList, .sshIdentities,
            .lock:
            break
        case .unlock(let password, let sessionTtlSeconds):
            try c.encode(password, forKey: key("password"))
            try c.encode(sessionTtlSeconds, forKey: key("session_ttl_seconds"))
        case .groupsCreate(let name, let parentId, let idempotencyKey, let dryRun):
            try c.encode(name, forKey: key("name"))
            try c.encode(parentId, forKey: key("parent_id"))
            try c.encode(idempotencyKey, forKey: key("idempotency_key"))
            try c.encode(dryRun, forKey: key("dry_run"))
        case .groupsUpdate(
            let id, let name, let ifRevision, let idempotencyKey, let dryRun
        ):
            try c.encode(id, forKey: key("id"))
            try c.encode(name, forKey: key("name"))
            try c.encode(ifRevision, forKey: key("if_revision"))
            try c.encode(idempotencyKey, forKey: key("idempotency_key"))
            try c.encode(dryRun, forKey: key("dry_run"))
        case .groupsReorder(
            let parentId, let orderedIds, let expectedRevisions,
            let idempotencyKey, let dryRun
        ):
            try c.encode(parentId, forKey: key("parent_id"))
            try c.encode(orderedIds, forKey: key("ordered_ids"))
            try c.encode(expectedRevisions, forKey: key("expected_revisions"))
            try c.encode(idempotencyKey, forKey: key("idempotency_key"))
            try c.encode(dryRun, forKey: key("dry_run"))
        case .groupsDelete(let id, let ifRevision, let idempotencyKey, let dryRun):
            try c.encode(id, forKey: key("id"))
            try c.encode(ifRevision, forKey: key("if_revision"))
            try c.encode(idempotencyKey, forKey: key("idempotency_key"))
            try c.encode(dryRun, forKey: key("dry_run"))
        case .templatesGet(let kind):
            try c.encode(kind, forKey: key("kind"))
        case .agentHandoffCreate(let input):
            try c.encode(input, forKey: key("input"))
        case .agentHandoffGet(let handoffId):
            try c.encode(handoffId, forKey: key("handoff_id"))
        case .migrationsPreview(let migrationId):
            try c.encode(migrationId, forKey: key("migration_id"))
        case .migrationsApply(let migrationId, let previewDigest):
            try c.encode(migrationId, forKey: key("migration_id"))
            try c.encode(previewDigest, forKey: key("preview_digest"))
        case .migrationsRollback(let migrationId):
            try c.encode(migrationId, forKey: key("migration_id"))
        case .projectsCreate(let slug, let name, let idempotencyKey):
            try c.encode(slug, forKey: key("slug"))
            try c.encode(name, forKey: key("name"))
            try c.encode(idempotencyKey, forKey: key("idempotency_key"))
        case .contentSearch(
            let query, let kind, let tag, let projectSlug, let reviewedOnly
        ):
            try c.encode(query, forKey: key("query"))
            try c.encode(kind, forKey: key("kind"))
            try c.encode(tag, forKey: key("tag"))
            try c.encode(projectSlug, forKey: key("project_slug"))
            try c.encode(reviewedOnly, forKey: key("reviewed_only"))
        case .contentGet(let id):
            try c.encode(id, forKey: key("id"))
        case .contentCreate(let input, let idempotencyKey):
            try c.encode(input, forKey: key("input"))
            try c.encode(idempotencyKey, forKey: key("idempotency_key"))
        case .contentUpdate(
            let id, let patch, let ifRevision, let idempotencyKey
        ):
            try c.encode(id, forKey: key("id"))
            try c.encode(patch, forKey: key("patch"))
            try c.encode(ifRevision, forKey: key("if_revision"))
            try c.encode(idempotencyKey, forKey: key("idempotency_key"))
        case .contentSetAccess(
            let id, let access, let ifRevision, let idempotencyKey
        ):
            try c.encode(id, forKey: key("id"))
            try c.encode(access, forKey: key("access"))
            try c.encode(ifRevision, forKey: key("if_revision"))
            try c.encode(idempotencyKey, forKey: key("idempotency_key"))
        case .contentReview(let id, let ifRevision, let idempotencyKey):
            try c.encode(id, forKey: key("id"))
            try c.encode(ifRevision, forKey: key("if_revision"))
            try c.encode(idempotencyKey, forKey: key("idempotency_key"))
        case .entriesSearch(let query):
            try c.encode(query, forKey: key("query"))
        case .entriesGet(let id), .entriesView(let id), .entriesTotp(let id),
            .entriesHistory(let id):
            try c.encode(id, forKey: key("id"))
        case .entriesCreate(let input, let idempotencyKey, let dryRun):
            try c.encode(input, forKey: key("input"))
            try c.encode(idempotencyKey, forKey: key("idempotency_key"))
            try c.encode(dryRun, forKey: key("dry_run"))
        case .entriesUpdate(
            let id, let patch, let ifRevision, let idempotencyKey, let dryRun
        ):
            try c.encode(id, forKey: key("id"))
            try c.encode(patch, forKey: key("patch"))
            try c.encode(ifRevision, forKey: key("if_revision"))
            try c.encode(idempotencyKey, forKey: key("idempotency_key"))
            try c.encode(dryRun, forKey: key("dry_run"))
        case .entriesDelete(
            let id, let ifRevision, let idempotencyKey, let dryRun
        ):
            try c.encode(id, forKey: key("id"))
            try c.encode(ifRevision, forKey: key("if_revision"))
            try c.encode(idempotencyKey, forKey: key("idempotency_key"))
            try c.encode(dryRun, forKey: key("dry_run"))
        case .entriesReveal(let id, let field):
            try c.encode(id, forKey: key("id"))
            try c.encode(field, forKey: key("field"))
        case .entriesRevealById(let id, let fieldId):
            try c.encode(id, forKey: key("id"))
            try c.encode(fieldId, forKey: key("field_id"))
        case .entriesRevealMany(let id, let fieldIds):
            try c.encode(id, forKey: key("id"))
            try c.encode(fieldIds, forKey: key("field_ids"))
        case .generatePassword(let length, let recipe):
            try c.encode(length, forKey: key("length"))
            // serde `#[serde(default)]`: absent and null are equivalent;
            // omit it so the wire matches what the Dart client sends.
            try c.encodeIfPresent(recipe, forKey: key("recipe"))
        case .connectionAdd(let provider, let credential, let authorizedResources):
            try c.encode(provider, forKey: key("provider"))
            try c.encode(credential, forKey: key("credential"))
            try c.encode(authorizedResources, forKey: key("authorized_resources"))
        case .connectionEnroll(let id, let resource),
            .connectionUnenroll(let id, let resource):
            try c.encode(id, forKey: key("id"))
            try c.encode(resource, forKey: key("resource"))
        case .connectionTest(let id), .connectionRefresh(let id),
            .connectionDisconnect(let id), .connectionRevoke(let id):
            try c.encode(id, forKey: key("id"))
        case .connectionGoogleOauthBegin(let clientId, let clientSecret):
            try c.encode(clientId, forKey: key("client_id"))
            try c.encode(clientSecret, forKey: key("client_secret"))
        case .connectionGoogleOauthComplete(let flowId):
            try c.encode(flowId, forKey: key("flow_id"))
        case .approvalsList(let limit):
            try c.encode(limit, forKey: key("limit"))
        case .approvalDecide(let id, let approve, let trust):
            try c.encode(id, forKey: key("id"))
            try c.encode(approve, forKey: key("approve"))
            // serde `#[serde(default)]`: omitted means a single-use
            // approval, the wire every older client sends.
            try c.encodeIfPresent(trust, forKey: key("trust"))
        case .trustRevoke(let id), .dbTarget(let id):
            try c.encode(id, forKey: key("id"))
        case .agentEnroll(let name):
            try c.encode(name, forKey: key("name"))
        case .cloudRequest(let purpose, let hint):
            try c.encode(purpose, forKey: key("purpose"))
            try c.encodeIfPresent(hint, forKey: key("hint"))
        case .entriesInject(let program, let fields):
            try c.encode(program, forKey: key("program"))
            try c.encode(fields, forKey: key("fields"))
        case .dbScram(let id, let database, let clientFirstBare, let serverFirst):
            try c.encode(id, forKey: key("id"))
            try c.encode(database, forKey: key("database"))
            try c.encode(clientFirstBare, forKey: key("client_first_bare"))
            try c.encode(serverFirst, forKey: key("server_first"))
        case .sshSign(let publicKeyBlob, let data, let flags):
            try c.encode(publicKeyBlob, forKey: key("public_key_blob"))
            try c.encode(data, forKey: key("data"))
            try c.encode(flags, forKey: key("flags"))
        case .auditQuery(let limit):
            try c.encode(limit, forKey: key("limit"))
        case .leaseRequest(let request, let ttlSeconds, let maxUses, let approvalId):
            try c.encode(request, forKey: key("request"))
            try c.encode(ttlSeconds, forKey: key("ttl_seconds"))
            try c.encode(maxUses, forKey: key("max_uses"))
            try c.encode(approvalId, forKey: key("approval_id"))
        case .gateExecute(let leaseToken, let request):
            try c.encode(leaseToken, forKey: key("lease_token"))
            try c.encode(request, forKey: key("request"))
        }
    }
}
