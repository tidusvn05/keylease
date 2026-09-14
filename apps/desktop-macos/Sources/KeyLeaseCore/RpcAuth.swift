import Foundation

/// Authentication block the daemon expects on every non-`status` request.
/// Mirrors `RpcAuth` in `crates/keylease-rpc/src/lib.rs`.
public struct RpcAuth: Encodable, Sendable {
    public let agentId: String
    public let token: SecretValue
    public let sessionId: String

    public init(agentId: String, token: SecretValue, sessionId: String) {
        self.agentId = agentId
        self.token = token
        self.sessionId = sessionId
    }

    private enum CodingKeys: String, CodingKey {
        case agentId = "agent_id"
        case token
        case sessionId = "session_id"
    }
}
