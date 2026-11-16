import Foundation

import KeyLeaseCore

/// The Server page: this vault's link to keylease-server, console approvals
/// (ADR 0011) and organization membership (ADR 0012). Every call goes through
/// the daemon, which only lets the desktop owner client manage the link.
@MainActor @Observable
final class ServerController {
    private(set) var overview: CloudOverview?
    /// Owner: linked nodes and devices, and requests from node agents.
    private(set) var nodes: [CloudNodeView] = []
    private(set) var requests: [CloudShareRequest] = []
    private(set) var loading = false
    /// The action running now, for its button's progress state.
    private(set) var busy: Action?
    var error: UserMessage?
    var notice: UserMessage?

    enum Action: Equatable {
        case signIn, enableApprovals, disableApprovals, join, leave
        case decide(String), adopt(String)
    }

    private var client: KeyLeaseClient?

    func use(_ client: KeyLeaseClient) {
        self.client = client
    }

    func clear() {
        overview = nil
        nodes = []
        requests = []
        error = nil
        notice = nil
        busy = nil
    }

    func load() async {
        guard let client else { return }
        loading = true
        defer { loading = false }
        do {
            let overview = try await client.authorized(.cloudOverview)
                .decoded(as: CloudOverview.self)
            self.overview = overview
            if overview.linked && overview.isOwner {
                nodes = try await client.authorized(.cloudNodes)
                    .decoded(as: [CloudNodeView].self)
                requests = try await client.authorized(.cloudRequests)
                    .decoded(as: [CloudShareRequest].self)
            } else {
                nodes = []
                requests = []
            }
            error = nil
        } catch {
            self.error = UserMessage(error)
        }
    }

    /// A one-time sign-in link for the KeyLease Console.
    func consoleSignInLink() async -> ConsoleSignInLink? {
        await run(.signIn) { client in
            try await client.authorized(.cloudConsoleSignIn)
                .decoded(as: ConsoleSignInLink.self)
        }
    }

    func enableConsoleApprovals(shareAudit: Bool) async {
        let done: Bool? = await run(.enableApprovals) { client in
            _ = try await client.authorized(
                .consoleApprovalsEnable(shareAudit: shareAudit))
            return true
        }
        if done == true {
            notice = UserMessage(
                title: "Console approvals are on",
                detail: "Approve this Mac's requests in the KeyLease Console "
                    + "with one of your passkeys.")
        }
        await load()
    }

    func disableConsoleApprovals() async {
        let done: Bool? = await run(.disableApprovals) { client in
            _ = try await client.authorized(.consoleApprovalsDisable)
            return true
        }
        if done == true {
            notice = UserMessage(title: "Console approvals are off")
        }
        await load()
    }

    /// Joins an organization with an enrollment code from its console.
    /// Returns true on success so the sheet can close.
    func join(code: String) async -> Bool {
        let trimmed = code.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            error = UserMessage(title: "Enter the enrollment code")
            return false
        }
        let outcome: OrgJoinOutcome? = await run(.join) { client in
            try await client.authorized(.orgJoin(code: SecretValue(trimmed)))
                .decoded(as: OrgJoinOutcome.self)
        }
        await load()
        guard let outcome else { return false }
        notice = UserMessage(
            title: "This Mac is a managed node of \(outcome.orgName)",
            detail: outcome.policyVersion.map { "Policy version \($0) applies." }
                ?? "The organization has no policy yet; KeyLease checks every minute.")
        return true
    }

    func leave() async {
        let done: Bool? = await run(.leave) { client in
            _ = try await client.authorized(.orgLeave)
            return true
        }
        if done == true {
            notice = UserMessage(
                title: "Left the organization",
                detail: "Its rules no longer apply to this vault.")
        }
        await load()
    }

    var pendingRequests: [CloudShareRequest] {
        requests.filter(\.isPending)
    }

    /// Approves a node's request by sharing `itemId` (for `ttlMinutes`, or
    /// until unshared). Returns true on success so the sheet can close.
    func approve(
        _ request: CloudShareRequest, itemId: String, ttlMinutes: UInt32?
    ) async -> Bool {
        let done: Bool? = await run(.decide(request.requestId)) { client in
            _ = try await client.authorized(
                .cloudRequestDecide(
                    requestId: request.requestId, approve: true,
                    itemId: itemId, ttlMinutes: ttlMinutes))
            return true
        }
        if done == true {
            notice = UserMessage(
                title: "Shared with \(request.nodeName ?? "the node")",
                detail: "It arrives on the node's next sync (within a minute).")
        }
        await load()
        return done == true
    }

    func deny(_ request: CloudShareRequest) async {
        let done: Bool? = await run(.decide(request.requestId)) { client in
            _ = try await client.authorized(
                .cloudRequestDecide(
                    requestId: request.requestId, approve: false,
                    itemId: nil, ttlMinutes: nil))
            return true
        }
        if done == true {
            notice = UserMessage(title: "Request denied")
        }
        await load()
    }

    /// Makes a node's items this Mac's own and shares them back.
    func adopt(_ node: CloudNodeView) async {
        let report: AdoptReport? = await run(.adopt(node.memberId)) { client in
            try await client.authorized(.cloudAdopt(node: node.memberId, items: []))
                .decoded(as: AdoptReport.self)
        }
        await load()
        guard let report else { return }
        var detail = "They are now in your vault and shared back with "
            + "\(report.node), which receives them on its next sync. "
            + "Change them here from now on."
        if !report.skipped.isEmpty {
            detail += " Skipped: " + report.skipped.joined(separator: "; ")
        }
        notice = UserMessage(
            title: "Now managing \(report.adopted.count) items from \(report.node)",
            detail: detail)
    }

    private func run<T: Sendable>(
        _ action: Action,
        _ body: @escaping @Sendable (KeyLeaseClient) async throws -> T
    ) async -> T? {
        guard let client, busy == nil else { return nil }
        busy = action
        defer { busy = nil }
        do {
            let value = try await body(client)
            error = nil
            return value
        } catch {
            notice = nil
            self.error = UserMessage(error)
            return nil
        }
    }
}
