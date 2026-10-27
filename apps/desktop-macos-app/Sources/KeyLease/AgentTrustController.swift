import Darwin
import Foundation

import KeyLeaseCore

/// What an enrolled agent needs in its environment. The token itself stays
/// in the file; neither the app nor the agent's transcript ever shows it.
struct AgentEnrollment: Sendable, Equatable, Identifiable {
    let agentId: String
    let tokenPath: String

    var id: String { agentId }

    var environment: String {
        """
        export KEYLEASE_AGENT_ID=\(agentId)
        export KEYLEASE_CLIENT_TOKEN_FILE=\(tokenPath)
        """
    }
}

/// `agent_enroll`, `trusts_list` and `trust_revoke` (ADR 0005) — the
/// desktop half of `keylease agent enroll` and `keylease trust …`.
@MainActor @Observable
final class TrustsController {
    let list = SectionController<TrustRecord> { client in
        try await client.authorized(.trustsList)
            .decoded(as: [TrustRecord].self)
    }

    var error: UserMessage?
    /// Agents enrolled from this window, newest first. The daemon has no
    /// listing for clients yet, so this only remembers this session's.
    private(set) var enrolled: [AgentEnrollment] = []
    private var client: KeyLeaseClient?

    func use(_ client: KeyLeaseClient) {
        self.client = client
        list.use(client)
    }

    func clear() {
        list.clear()
        error = nil
    }

    func revoke(_ trust: TrustRecord) async {
        guard let client else { return }
        do {
            _ = try await client.authorized(.trustRevoke(id: trust.id))
            error = nil
        } catch {
            self.error = UserMessage(error)
        }
        await list.load()
    }

    /// Enrolls an agent with the baseline policy (metadata reads allowed,
    /// secret use and writes queue an approval) and writes its token to a
    /// new mode-0600 file under `~/.keylease/clients/`.
    func enroll(name: String) async throws -> AgentEnrollment {
        guard let client else { throw KeyLeaseError("no client") }
        guard isValidAgentName(name) else {
            throw KeyLeaseError(
                "Use letters, digits, '-' or '_' for the agent name.",
                code: .client)
        }
        let directory = "\(ConnectionDefaults.home)/.keylease/clients"
        let path = "\(directory)/agent_\(name).token"
        // Checked before the RPC, like the CLI, so a name clash never
        // leaves a registered client whose token was thrown away.
        guard !FileManager.default.fileExists(atPath: path) else {
            throw KeyLeaseError(
                "An agent named \(name) already has a token file. "
                    + "Choose another name.",
                code: .client)
        }
        try FileManager.default.createDirectory(
            atPath: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        let agent = try await client.authorized(.agentEnroll(name: name))
            .decoded(as: EnrolledAgent.self)
        try Self.writeNewSecretFile(path, contents: agent.token.raw)
        let enrollment = AgentEnrollment(
            agentId: agent.agentId, tokenPath: path)
        enrolled.insert(enrollment, at: 0)
        return enrollment
    }

    /// `O_CREAT | O_EXCL | O_NOFOLLOW`, mode 0600 — never replaces or
    /// follows an existing file.
    private static func writeNewSecretFile(_ path: String, contents: String)
        throws
    {
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else {
            throw KeyLeaseError(
                "Could not create \(path): \(String(cString: strerror(errno)))",
                code: .client)
        }
        defer { close(fd) }
        let bytes = Array(contents.utf8)
        let written = bytes.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        guard written == bytes.count, fsync(fd) == 0 else {
            throw KeyLeaseError("Could not write \(path)", code: .client)
        }
    }
}

extension TrustRecord {
    var expiresDate: Date? { ISO8601DateFormatter.parse(expiresAt) }

    /// "read secret" for `entry:read_secret`, "connect" for `db:connect`.
    var actionTitle: String { approvalActionTitle(action) }
}

/// Plain-language name for a vault action id.
func approvalActionTitle(_ action: String?) -> String {
    guard let action else { return "Access" }
    let verb = action.split(separator: ":").last.map(String.init) ?? action
    switch action {
    case "ssh:sign": return "Sign in over SSH"
    case "db:connect": return "Connect to a database"
    case "entry:inject_secret": return "Run a program with secrets"
    case "entry:read_secret": return "Read a secret"
    case "entry:read_username": return "Read a username"
    default: return verb.replacingOccurrences(of: "_", with: " ").capitalized
    }
}
