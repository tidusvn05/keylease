import Foundation

/// `cloud_overview`: the cloud link, console approvals and the organization
/// as the daemon reports them. Mirrors `CloudOverview` in
/// `crates/keylease-service/src/cloud_remote.rs`. Times are RFC 3339 strings.
public struct CloudOverview: Decodable, Equatable, Sendable {
    public let linked: Bool
    public let url: String?
    /// `owner`, `node` or `device`.
    public let role: String?
    public let name: String?
    public let fingerprint: String?
    public let lastSyncAt: String?
    public let lastError: String?
    public let nodes: Int
    public let activeShares: Int
    public let pendingRequests: Int
    public let consoleApprovals: ConsoleApprovalsOverview
    public let org: OrgOverview?

    public var isOwner: Bool { role == "owner" }

    enum CodingKeys: String, CodingKey {
        case linked, url, role, name, fingerprint, nodes, org
        case lastSyncAt = "last_sync_at"
        case lastError = "last_error"
        case activeShares = "active_shares"
        case pendingRequests = "pending_requests"
        case consoleApprovals = "console_approvals"
    }
}

/// Whether the KeyLease Console may decide this vault's approvals.
public struct ConsoleApprovalsOverview: Decodable, Equatable, Sendable {
    public let enabled: Bool
    /// Where decisions are signed, e.g. `https://keys.example.com`.
    public let origin: String?
    /// Names of the pinned passkeys.
    public let passkeys: [String]
    public let shareAudit: Bool
    public let enabledAt: String?

    enum CodingKeys: String, CodingKey {
        case enabled, origin, passkeys
        case shareAudit = "share_audit"
        case enabledAt = "enabled_at"
    }
}

/// The organization this vault is a managed node of.
public struct OrgOverview: Decodable, Equatable, Sendable {
    public let orgId: String
    public let orgName: String
    public let keyId: String
    public let joinedAt: String
    /// The policy version in force; nil until the organization publishes one.
    public let policyVersion: UInt64?

    enum CodingKeys: String, CodingKey {
        case orgId = "org_id"
        case orgName = "org_name"
        case keyId = "key_id"
        case joinedAt = "joined_at"
        case policyVersion = "policy_version"
    }
}

/// `cloud_console_sign_in`: open `url` once in a browser.
public struct ConsoleSignInLink: Decodable, Equatable, Sendable {
    public let url: String
    public let expiresAt: String

    enum CodingKeys: String, CodingKey {
        case url
        case expiresAt = "expires_at"
    }
}

/// `org_join`.
public struct OrgJoinOutcome: Decodable, Equatable, Sendable {
    public let orgId: String
    public let orgName: String
    public let keyId: String
    public let policyVersion: UInt64?

    enum CodingKeys: String, CodingKey {
        case orgId = "org_id"
        case orgName = "org_name"
        case keyId = "key_id"
        case policyVersion = "policy_version"
    }
}

/// `cloud_nodes`: a node (a VPS) or another device linked to this vault.
/// Mirrors `CloudNodeView` in `crates/keylease-service/src/cloud_remote.rs`.
public struct CloudNodeView: Decodable, Equatable, Sendable, Identifiable {
    public let memberId: String
    public let name: String
    /// `node` or `device`.
    public let role: String
    public let fingerprint: String
    public let verifiedAt: String
    /// Read-only copies of this node's own items on this Mac.
    public let copies: Int

    public var id: String { memberId }
    public var isNode: Bool { role == "node" }

    enum CodingKeys: String, CodingKey {
        case name, role, fingerprint, copies
        case memberId = "member_id"
        case verifiedAt = "verified_at"
    }
}

/// `cloud_requests`: an agent on a node asked for an item.
public struct CloudShareRequest: Decodable, Equatable, Sendable, Identifiable {
    public let requestId: String
    public let agentId: String
    public let purpose: String
    public let hint: String?
    public let nodeMemberId: String?
    public let nodeName: String?
    public let createdAt: String
    /// `pending`, `approved` or `denied`.
    public let status: String
    public let shareId: String?

    public var id: String { requestId }
    public var isPending: Bool { status == "pending" }

    enum CodingKeys: String, CodingKey {
        case purpose, hint, status
        case requestId = "request_id"
        case agentId = "agent_id"
        case nodeMemberId = "node_member_id"
        case nodeName = "node_name"
        case createdAt = "created_at"
        case shareId = "share_id"
    }
}

/// `cloud_adopt`: what moved from a node to this Mac.
public struct AdoptReport: Decodable, Equatable, Sendable {
    public let node: String
    public let adopted: [String]
    /// Project slugs shared back with the node.
    public let projects: [String]
    /// Items without a project, shared one by one.
    public let itemShares: Int
    public let skipped: [String]

    enum CodingKeys: String, CodingKey {
        case node, adopted, projects, skipped
        case itemShares = "item_shares"
    }
}
