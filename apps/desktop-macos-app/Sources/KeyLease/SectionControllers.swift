import Foundation

import KeyLeaseCore

/// Raised when an approval no longer matches the pending request — the Dart
/// `StaleApprovalException`.
struct StaleApprovalError: Error, Equatable {
    let message: String
}

/// Shared loading/error plumbing for the read-mostly sections
/// (Dart `SectionController`).
@MainActor @Observable
final class SectionController<Item> {
    private(set) var items: [Item] = []
    var error: UserMessage?
    private(set) var loaded = false
    private(set) var loading = false

    private let fetcher: (KeyLeaseClient) async throws -> [Item]
    private var client: KeyLeaseClient?

    init(fetcher: @escaping (KeyLeaseClient) async throws -> [Item]) {
        self.fetcher = fetcher
    }

    func use(_ client: KeyLeaseClient) {
        self.client = client
    }

    func load() async {
        guard let client else { return }
        loading = true
        defer { loading = false }
        do {
            items = try await fetcher(client)
            error = nil
            loaded = true
        } catch {
            self.error = UserMessage(error)
        }
    }

    /// Replaces items without the loading dance — used by the approvals
    /// stale-request re-check.
    func apply(_ next: [Item]) {
        items = next
    }

    func clear() {
        items = []
        error = nil
        loaded = false
        loading = false
    }
}

/// `connections_*` — list/test/refresh/disconnect/revoke, resource
/// enrollment, token-add and the Google OAuth flow.
@MainActor @Observable
final class ConnectionsController {
    let list = SectionController<ConnectionRecord> { client in
        try await client.authorized(.connectionsList)
            .decoded(as: [ConnectionRecord].self)
    }

    private var client: KeyLeaseClient?
    var error: UserMessage?

    func use(_ client: KeyLeaseClient) {
        self.client = client
        list.use(client)
    }

    /// `connection_test` / `connection_refresh` / `connection_disconnect` /
    /// `connection_revoke`.
    func manage(_ connection: ConnectionRecord, operation: String) async {
        guard let client else { return }
        let request: RpcRequest
        switch operation {
        case "test": request = .connectionTest(id: connection.id)
        case "refresh": request = .connectionRefresh(id: connection.id)
        case "disconnect": request = .connectionDisconnect(id: connection.id)
        case "revoke": request = .connectionRevoke(id: connection.id)
        default: return
        }
        do {
            _ = try await client.authorized(request)
            error = nil
        } catch {
            self.error = UserMessage(error)
        }
        await list.load()
    }

    func setResource(
        _ connection: ConnectionRecord, resource: String, enrolled: Bool
    ) async {
        guard let client else { return }
        do {
            _ = try await client.authorized(
                enrolled
                    ? .connectionEnroll(id: connection.id, resource: resource)
                    : .connectionUnenroll(
                        id: connection.id, resource: resource))
            error = nil
        } catch {
            self.error = UserMessage(error)
        }
        await list.load()
    }

    /// `connection_add` — the credential travels wrapped in `SecretValue`.
    func add(provider: String, credential: String, resources: [String]) async
        throws
    {
        guard let client else { return }
        _ = try await client.authorized(
            .connectionAdd(
                provider: provider,
                credential: SecretValue(credential),
                authorizedResources: resources))
        await list.load()
    }

    /// `connection_google_oauth_begin` → `{flow_id, authorization_url}`.
    func beginGoogleOauth(clientId: String, clientSecret: String?) async throws
        -> (flowId: String, authorizationUrl: String)
    {
        guard let client else { throw KeyLeaseError("no client") }
        let result = try await client.authorized(
            .connectionGoogleOauthBegin(
                clientId: clientId,
                clientSecret: clientSecret.flatMap { $0.isEmpty ? nil : $0 }
                    .map(SecretValue.init)))
        guard let flowId = result["flow_id"]?.stringValue,
            let url = result["authorization_url"]?.stringValue
        else {
            throw KeyLeaseError(
                "Malformed OAuth begin response", code: .client)
        }
        return (flowId, url)
    }

    func completeGoogleOauth(flowId: String) async throws {
        guard let client else { return }
        _ = try await client.authorized(
            .connectionGoogleOauthComplete(flowId: flowId))
        await list.load()
    }
}

/// `approvals_list` + `approval_decide` with the stale-request re-check.
@MainActor @Observable
final class ApprovalsController {
    let list = SectionController<ApprovalRecord> { client in
        try await client.authorized(.approvalsList(limit: 100))
            .decoded(as: [ApprovalRecord].self)
    }

    private var client: KeyLeaseClient?

    func use(_ client: KeyLeaseClient) {
        self.client = client
        list.use(client)
    }

    /// Re-reads the pending list and refuses to decide on a request that
    /// expired, was decided elsewhere, or whose digest changed.
    func decide(_ approval: ApprovalRecord, approve: Bool) async throws {
        guard let client else { return }
        let current = try await client.authorized(.approvalsList(limit: 100))
            .decoded(as: [ApprovalRecord].self)
        list.apply(current)
        guard let match = current.first(where: { $0.id == approval.id }),
            match.sameRequestAs(approval)
        else {
            throw StaleApprovalError(
                message: "This request is no longer pending. "
                    + "The list has been refreshed.")
        }
        guard match.decidableNow else {
            throw StaleApprovalError(
                message: "This request expired before the decision was sent.")
        }
        _ = try await client.authorized(
            .approvalDecide(id: approval.id, approve: approve))
        await list.load()
    }
}

extension ApprovalRecord {
    var isPending: Bool { state == .pending }

    /// `decidableAt(now)` — pending and not yet expired.
    var decidableNow: Bool {
        isPending
            && (ISO8601DateFormatter.default.date(from: expiresAt) ?? .distantPast)
                > Date()
    }

    /// The exact request this decision would bind to.
    func sameRequestAs(_ other: ApprovalRecord) -> Bool {
        id == other.id
            && requestDigestHex == other.requestDigestHex
            && policyVersion == other.policyVersion
    }
}

/// `audit_query` + the denied/failed filter.
@MainActor @Observable
final class ActivityController {
    let list = SectionController<AuditEvent> { client in
        try await client.authorized(.auditQuery(limit: 200))
            .decoded(as: [AuditEvent].self)
    }

    var deniedOnly = false

    func use(_ client: KeyLeaseClient) {
        list.use(client)
    }

    var filtered: [AuditEvent] {
        deniedOnly ? list.items.filter(\.denied) : list.items
    }
}

extension AuditEvent {
    var denied: Bool { decision != "allow" || outcome != "success" }

    var volume: String {
        [
            itemCount.map { "\($0) items" },
            cellCount.map { "\($0) cells" },
            byteCount.map { "\($0) bytes" },
        ].compactMap { $0 }.joined(separator: " · ")
    }
}

extension ISO8601DateFormatter {
    /// Lenient parser for daemon timestamps (with or without fractions).
    static let `default`: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()
}
