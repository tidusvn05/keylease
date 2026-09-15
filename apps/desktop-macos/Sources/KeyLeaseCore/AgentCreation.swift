import Foundation
import Observation

/// One agent-driven creation recipe (Dart `AgentCreationRecipe`).
public struct AgentCreationRecipe: Equatable, Sendable, Identifiable {
    public let id: String
    public let title: String
    public let description: String
    public let defaultKind: String
    public let defaultSourcePath: String?

    public init(
        id: String, title: String, description: String, defaultKind: String,
        defaultSourcePath: String? = nil
    ) {
        self.id = id
        self.title = title
        self.description = description
        self.defaultKind = defaultKind
        self.defaultSourcePath = defaultSourcePath
    }
}

/// `agentCreationRecipes` — same order and copy as the Dart catalog.
public let agentCreationRecipes: [AgentCreationRecipe] = [
    AgentCreationRecipe(
        id: "describe", title: "Describe what to save",
        description:
            "Tell the agent what you need and let it ask for missing fields.",
        defaultKind: "core.login"),
    AgentCreationRecipe(
        id: "project", title: "Inspect current project",
        description:
            "Build one item from the project currently open in the agent.",
        defaultKind: "core.environment"),
    AgentCreationRecipe(
        id: "dotenv", title: "Import a .env file",
        description:
            "Parse one dotenv file into protected and non-protected fields.",
        defaultKind: "core.environment"),
    AgentCreationRecipe(
        id: "ssh_config", title: "Read SSH config or alias",
        description:
            "Capture one host and its related jump hosts from SSH config.",
        defaultKind: "core.ssh_server", defaultSourcePath: "~/.ssh/config"),
    AgentCreationRecipe(
        id: "ssh_topology", title: "Build bastion or tunnels",
        description:
            "Model related servers, ProxyJump hops, sudo, and port forwards.",
        defaultKind: "core.ssh_server"),
    AgentCreationRecipe(
        id: "credential", title: "Capture API or database access",
        description:
            "Save one credential discussed in the current task.",
        defaultKind: "core.api_credential"),
    AgentCreationRecipe(
        id: "prompt", title: "Draft a reusable Prompt",
        description:
            "Turn the current goal and constraints into reusable agent instructions.",
        defaultKind: "core.prompt"),
    AgentCreationRecipe(
        id: "runbook", title: "Draft a Runbook or Note",
        description:
            "Create durable operational steps or project knowledge.",
        defaultKind: "core.runbook"),
]

/// `AgentCreationHandoff` — the `agent_handoff_create` receipt plus the
/// clipboard text the user pastes into the agent.
extension AgentNewItemHandoffReceipt {
    public var expired: Bool {
        Self.expiryFormatter.date(from: expiresAt).map { $0 <= Date() }
            ?? false
    }

    public var clipboardText: String {
        "Create this item in KeyLease. Run `\(command)` and follow the CLI instructions."
    }

    private nonisolated(unsafe) static let expiryFormatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()
}

/// The agent-driven creation draft (Dart `AgentCreationDraft`). The
/// handoff and baseline snapshot live here so a failed save loses nothing.
@Observable
public final class AgentCreationDraft {
    public init(kind: String, groupId: String?) {
        self.kind = kind
        self.groupId = groupId
        initialKind = kind
        initialGroupId = groupId
        sessionId =
            "agent-new-\(Int64(Date().timeIntervalSince1970 * 1_000_000))"
    }

    public let sessionId: String
    public let initialKind: String
    public let initialGroupId: String?
    public var recipeId = "describe"
    public var kind: String
    public var groupId: String?
    public var projectSlug: String?
    public var tags = ""
    public var agentAccess = "read_write"
    public var context = ""
    public var sourcePath = ""
    public var baselineEntryIds: Set<String>?
    public var handoff: AgentNewItemHandoffReceipt?
    public var handoffCopied = false

    public var recipe: AgentCreationRecipe {
        agentCreationRecipes.first(where: { $0.id == recipeId })
            ?? agentCreationRecipes[0]
    }

    public var isAgentContent: Bool { isAgentContentKind(kind) }

    public var isDirty: Bool {
        recipeId != "describe"
            || kind != initialKind
            || groupId != initialGroupId
            || !context.trimmingCharacters(in: .whitespaces).isEmpty
            || !sourcePath.trimmingCharacters(in: .whitespaces).isEmpty
            || !tags.trimmingCharacters(in: .whitespaces).isEmpty
            || projectSlug != nil
            || agentAccess != "read_write"
            || handoffCopied
    }

    public var parsedTags: [String] {
        var seen = Set<String>()
        return tags.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && seen.insert($0).inserted }
    }

    public func invalidateHandoff() {
        handoff = nil
        handoffCopied = false
    }

    public func applyRecipe(_ next: AgentCreationRecipe) {
        recipeId = next.id
        kind = next.defaultKind
        sourcePath = next.defaultSourcePath ?? ""
        invalidateHandoff()
    }

    /// The `agent_handoff_create` input (Dart `createAgentHandoff`).
    public func handoffInput(expectedVaultId: String)
        -> AgentNewItemHandoffInput
    {
        AgentNewItemHandoffInput(
            agentAccess: AgentAccess(rawValue: agentAccess) ?? .readWrite,
            context: context.trimmingCharacters(in: .whitespaces).isEmpty
                ? nil : context.trimmingCharacters(in: .whitespaces),
            expectedVaultId: expectedVaultId,
            groupId: isAgentContent ? nil : groupId,
            kind: kind,
            projectSlug: isAgentContent ? projectSlug : nil,
            protocolVersion: 1,
            recipeId: recipeId,
            sourcePath: sourcePath.trimmingCharacters(in: .whitespaces).isEmpty
                ? nil : sourcePath.trimmingCharacters(in: .whitespaces),
            tags: isAgentContent ? parsedTags : [])
    }
}
