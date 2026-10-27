import Foundation

// Hand-maintained mirrors of `keylease-core/src/trust.rs` and the agent
// enrollment result in `keylease-service/src/trust.rs` (ADR 0005). They are
// not part of `keylease contracts`, like `PasswordRecipe`.

/// What a trust covers: the exact resource approved, or every field of its
/// item.
public enum TrustScope: String, Codable, CaseIterable, Equatable, Sendable {
    case resource
    case item
}

/// How long an approval keeps answering for the same agent and action.
/// Wire values are the CLI labels (`30m`, `1h`, …).
public enum TrustDuration: String, Codable, CaseIterable, Equatable, Sendable {
    case once = "once"
    case minutes30 = "30m"
    case hour1 = "1h"
    case hours6 = "6h"
    case day1 = "1d"
    case days3 = "3d"
    case days7 = "7d"

    public var seconds: Int {
        switch self {
        case .once: 0
        case .minutes30: 30 * 60
        case .hour1: 3600
        case .hours6: 6 * 3600
        case .day1: 86400
        case .days3: 3 * 86400
        case .days7: 7 * 86400
        }
    }

    /// Picker copy.
    public var title: String {
        switch self {
        case .once: "Just this once"
        case .minutes30: "30 minutes"
        case .hour1: "1 hour"
        case .hours6: "6 hours"
        case .day1: "1 day"
        case .days3: "3 days"
        case .days7: "7 days"
        }
    }

    /// `max_trust_seconds`: the longest trust a risk tier admits. R4 (reveal,
    /// inject) is approved once, every time. An unknown tier is treated as R4
    /// so the UI never offers more than the daemon would grant.
    public static func ceilingSeconds(for risk: RiskTier?) -> Int {
        switch risk {
        case .r0, .r1: TrustDuration.days7.seconds
        case .r2: TrustDuration.day1.seconds
        case .r3: TrustDuration.hour1.seconds
        case .r4, nil: 0
        }
    }

    /// `allowed_trust_durations`, shortest first; always starts with `.once`.
    public static func allowed(for risk: RiskTier?) -> [TrustDuration] {
        let ceiling = ceilingSeconds(for: risk)
        return allCases.filter { $0.seconds <= ceiling }
    }
}

/// The trust half of an `approval_decide`.
public struct TrustDecision: Codable, Equatable, Sendable {
    public let scope: TrustScope
    public let duration: TrustDuration

    public init(scope: TrustScope, duration: TrustDuration) {
        self.scope = scope
        self.duration = duration
    }
}

/// An active trust, as `trusts_list` returns it.
public struct TrustRecord: Codable, Equatable, Sendable, Identifiable {
    public let id: String
    public let agentId: String
    public let action: String
    public let resourcePrefix: String
    public let connectionId: String?
    public let scope: TrustScope
    public let duration: TrustDuration
    public let risk: RiskTier
    public let approvalId: String
    public let decidedBy: String
    public let createdAt: String
    public let expiresAt: String

    public init(
        id: String, agentId: String, action: String, resourcePrefix: String,
        connectionId: String?, scope: TrustScope, duration: TrustDuration,
        risk: RiskTier, approvalId: String, decidedBy: String,
        createdAt: String, expiresAt: String
    ) {
        self.id = id
        self.agentId = agentId
        self.action = action
        self.resourcePrefix = resourcePrefix
        self.connectionId = connectionId
        self.scope = scope
        self.duration = duration
        self.risk = risk
        self.approvalId = approvalId
        self.decidedBy = decidedBy
        self.createdAt = createdAt
        self.expiresAt = expiresAt
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case agentId = "agent_id"
        case action
        case resourcePrefix = "resource_prefix"
        case connectionId = "connection_id"
        case scope
        case duration
        case risk
        case approvalId = "approval_id"
        case decidedBy = "decided_by"
        case createdAt = "created_at"
        case expiresAt = "expires_at"
    }
}

/// `agent_enroll` result. The token is shown to nobody: the app writes it
/// straight to a mode-0600 file, like `keylease agent enroll`.
public struct EnrolledAgent: Decodable, Sendable {
    public let agentId: String
    public let token: SecretValue
    public let baselineRuleIds: [String]

    private enum CodingKeys: String, CodingKey {
        case agentId = "agent_id"
        case token
        case baselineRuleIds = "baseline_rule_ids"
    }
}

/// One field for `entries_inject` (`InjectRequest`).
public struct InjectField: Codable, Equatable, Sendable {
    public let itemId: String
    public let field: String

    public init(itemId: String, field: String) {
        self.itemId = itemId
        self.field = field
    }

    private enum CodingKeys: String, CodingKey {
        case itemId = "item_id"
        case field
    }
}

/// Agent names become part of the client id and the token file name.
public func isValidAgentName(_ name: String) -> Bool {
    !name.isEmpty && name.count <= 48
        && name.unicodeScalars.allSatisfy {
            ($0.isASCII && CharacterSet.alphanumerics.contains($0))
                || $0 == "-" || $0 == "_"
        }
}
