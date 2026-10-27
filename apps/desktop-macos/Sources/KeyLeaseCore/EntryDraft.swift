import Foundation
import Observation

/// Kind strings whose items live in the agent-content store and are mutated
/// through `content_*` commands instead of `entries_*`.
public let agentContentKinds: Set<String> = [
    "core.prompt", "core.runbook", "core.note",
]

public func isAgentContentKind(_ kind: String) -> Bool {
    agentContentKinds.contains(kind)
}

/// The editable snapshot of an entry — a direct port of the Dart
/// `EntryDraft` in `packages/leasegate_vault_ui`.
///
/// Drafts live outside the view tree so a failed save, a rebuild or a
/// navigation change cannot lose typed data. Secret fields start empty on an
/// edit: an empty secret means "keep the stored value", never "clear it".
@Observable
public final class EntryDraft {
    /// `entries_create` draft.
    public init(
        groupId: String? = nil,
        kind: String = "core.login",
        initialPassword: String = ""
    ) {
        entryId = nil
        revision = 0
        self.kind = kind
        self.groupId = groupId
        originalGroupId = groupId
        originalTitle = ""
        originalUsername = ""
        originalUrl = ""
        password = initialPassword
    }

    /// `entries_update` draft over an existing item (`EntrySummary`).
    public init(editing entry: ItemMetadata) {
        entryId = entry.id
        revision = entry.revision
        kind = entry.kind
        groupId = entry.groupId
        originalGroupId = entry.groupId
        originalTitle = entry.title
        originalUsername = entry.username ?? ""
        originalUrl = entry.urls.first ?? ""
        title = entry.title
        username = entry.username ?? ""
        url = entry.urls.first ?? ""
        favorite = entry.favorite
        originalFavorite = entry.favorite
    }

    public let entryId: String?
    public let revision: UInt64
    public var kind: String
    public var groupId: String?

    public let originalGroupId: String?
    public let originalTitle: String
    public let originalUsername: String
    public let originalUrl: String
    public private(set) var originalFavorite = false

    public var title = ""
    public var username = ""
    public var url = ""
    public var password = ""
    public var notes = ""
    public var totp = ""
    /// JSON array of `ItemField` — either hand-written in the custom-fields
    /// box or emitted by a structured editor (environment, SSH, template).
    public var customFields = ""
    /// JSON array of `ItemSection`.
    public var sections = ""
    public var removeFieldIds: [String] = []
    /// Local-only SSH private key bindings, `endpointSectionId` → path.
    public var sshKeyBindings: [String: String] = [:]
    public var sshBindingsToClear: [String] = []
    /// Field errors produced by structured editors, merged into `validate()`.
    public var structuredErrors: [String: String] = [:]
    public var tags = ""
    public var projectSlug: String?
    public var agentAccess = "none"
    public var favorite = false

    public var isAgentContent: Bool { isAgentContentKind(kind) }

    public var isNew: Bool { entryId == nil }

    public var isDirty: Bool {
        title != originalTitle
            || username != originalUsername
            || url != originalUrl
            || groupId != originalGroupId
            || !password.isEmpty
            || !notes.isEmpty
            || !totp.isEmpty
            || !tags.isEmpty
            || projectSlug != nil
            || agentAccess != "none"
            || favorite != originalFavorite
            || !customFields.isEmpty
            || !sections.isEmpty
            || !removeFieldIds.isEmpty
            || !sshKeyBindings.isEmpty
            || !sshBindingsToClear.isEmpty
    }

    /// Field-level validation messages, keyed by field name.
    public func validate() -> [String: String] {
        var errors: [String: String] = [:]
        if title.trimmingCharacters(in: .whitespaces).isEmpty {
            errors["title"] = "Give this item a name."
        }
        if !isAgentContent && (groupId?.isEmpty ?? true) {
            errors["group"] = "Choose a group for this item."
        }
        if !customFields.trimmingCharacters(in: .whitespaces).isEmpty,
            parsedCustomFields() == nil
        {
            errors["custom_fields"] =
                "Custom fields must be a JSON array of field objects."
        }
        if !sections.trimmingCharacters(in: .whitespaces).isEmpty,
            parsedSections() == nil
        {
            errors["sections"] = "Sections must be a JSON array."
        }
        for (key, value) in structuredErrors { errors[key] = value }
        return errors
    }

    /// Decodes `customFields`; nil when it is not a JSON array of fields.
    public func parsedCustomFields() -> [ItemField]? {
        let trimmed = customFields.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty,
            let decoded = try? JSONDecoder().decode(
                JSONValue.self, from: Data(trimmed.utf8)),
            case .array = decoded
        else { return nil }
        return try? decoded.decoded(as: [ItemField].self)
    }

    /// Decodes `sections`; empty input parses as an empty list, nil on
    /// anything that is not a JSON array of sections.
    public func parsedSections() -> [ItemSection]? {
        let trimmed = sections.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { return [] }
        guard let decoded = try? JSONDecoder().decode(
            JSONValue.self, from: Data(trimmed.utf8)),
            case .array = decoded
        else { return nil }
        return try? decoded.decoded(as: [ItemSection].self)
    }

    /// Base32 secrets become a default SHA-1/6-digit/30-second config;
    /// `otpauth://` input travels as `totpUri` instead.
    public func totpConfig() -> TotpConfig? {
        let trimmed = totp.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.lowercased().hasPrefix("otpauth://") else {
            return nil
        }
        return TotpConfig(
            account: nil,
            algorithm: .sha1,
            digits: 6,
            issuer: nil,
            period: 30,
            secretBase32: trimmed,
            sourceRepresentation: "base32"
        )
    }

    public var totpUri: String? {
        let trimmed = totp.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.lowercased().hasPrefix("otpauth://") ? trimmed : nil
    }

    /// `entries_create` input.
    public func createInput() -> NewEntryInput {
        NewEntryInput(
            customFields: parsedCustomFields() ?? [],
            favorite: favorite,
            groupId: groupId ?? "",
            kind: kind,
            notes: notes.isEmpty ? nil : notes,
            password: password.isEmpty ? nil : password,
            projectSlug: nil,
            sections: parsedSections() ?? [],
            title: title.trimmingCharacters(in: .whitespaces),
            totp: totpConfig(),
            totpUri: totpUri,
            url: url.isEmpty ? nil : url,
            username: username
        )
    }

    /// `content_create` input for `core.prompt` / `core.runbook` / `core.note`.
    public func contentCreateInput() -> ContentCreateInput {
        ContentCreateInput(
            body: notes,
            favorite: favorite,
            kind: kind,
            projectSlug: projectSlug,
            tags: parsedTags,
            title: title.trimmingCharacters(in: .whitespaces)
        )
    }

    /// `content_update` patch.
    public func contentPatch() -> ContentPatch {
        ContentPatch(
            addTags: [],
            body: notes.isEmpty ? nil : notes,
            clearProject: false,
            favorite: favorite != originalFavorite ? favorite : nil,
            projectSlug: projectSlug,
            removeTags: [],
            tags: tags.trimmingCharacters(in: .whitespaces).isEmpty
                ? nil : parsedTags,
            title: title.trimmingCharacters(in: .whitespaces)
        )
    }

    /// `entries_update` patch. Empty secrets are omitted so they keep their
    /// stored value instead of being overwritten with a blank.
    public func patch() -> EntryPatch {
        EntryPatch(
            clearProject: nil,
            customFields: nil,
            favorite: favorite != originalFavorite ? favorite : nil,
            fieldUpdates: parsedCustomFields(),
            groupId: groupId != originalGroupId ? groupId : nil,
            notes: notes.isEmpty ? nil : notes,
            password: password.isEmpty ? nil : password,
            projectSlug: nil,
            removeFieldIds: removeFieldIds.isEmpty ? nil : removeFieldIds,
            sections: sections.trimmingCharacters(in: .whitespaces).isEmpty
                ? nil : parsedSections(),
            title: title.trimmingCharacters(in: .whitespaces),
            totp: totpConfig(),
            totpUri: totpUri,
            url: url.isEmpty ? nil : url,
            username: username
        )
    }

    /// Comma-separated `tags`, trimmed, deduplicated, order preserved.
    public var parsedTags: [String] {
        var seen = Set<String>()
        return tags.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && seen.insert($0).inserted }
    }

    /// Removes the secret material a draft accumulated.
    public func wipeSecrets() {
        password = ""
        notes = ""
        totp = ""
        customFields = ""
        sections = ""
        removeFieldIds = []
        sshKeyBindings = [:]
        sshBindingsToClear = []
        structuredErrors = [:]
    }
}
