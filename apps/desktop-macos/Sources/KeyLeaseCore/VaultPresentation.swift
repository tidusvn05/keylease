import Foundation

/// What the entry list is showing right now (Dart `VaultListState`).
public enum VaultListState: Sendable, Equatable {
    case loading, content, empty, searchEmpty
}

/// Right-hand workspace (Dart `EntryWorkspaceMode`).
public enum EntryWorkspaceMode: Sendable, Equatable {
    case detail, create, edit, passwordGenerator
}

/// How a new item is produced (Dart `EntryCreationMode`).
public enum EntryCreationMode: Sendable, Equatable {
    case manual, agentDriven
}

/// `entries_history` element — not part of `keylease contracts` output, so
/// this response shape is maintained by hand like `PasswordRecipe`.
public struct EntryRevision: Codable, Equatable, Sendable {
    public let revision: UInt64
    public let updatedAt: String?

    public init(revision: UInt64, updatedAt: String?) {
        self.revision = revision
        self.updatedAt = updatedAt
    }

    private enum CodingKeys: String, CodingKey {
        case revision, updatedAt = "updated_at"
    }
}

/// `entries_totp` result — same hand-maintained status as `EntryRevision`.
public struct TotpCode: Codable, Equatable, Sendable {
    public let code: String
    public let expiresIn: UInt64?
    public let itemId: String?

    public init(code: String, expiresIn: UInt64?, itemId: String?) {
        self.code = code
        self.expiresIn = expiresIn
        self.itemId = itemId
    }

    private enum CodingKeys: String, CodingKey {
        case code, expiresIn = "expires_in", itemId = "item_id"
    }
}

// MARK: - Structured field helpers (`developer_templates.dart`)

private let structuredIdLock = NSLock()
private nonisolated(unsafe) var structuredIdSequence = 0

/// Unique-enough local id for fields and sections created by the structured
/// editors: `<prefix>_<microseconds>_<salt>_<seq>`.
public func structuredId(_ prefix: String, salt: Int = 0) -> String {
    structuredIdLock.lock()
    defer { structuredIdLock.unlock() }
    let microseconds = Int64(Date().timeIntervalSince1970 * 1_000_000)
    let id = "\(prefix)_\(microseconds)_\(salt)_\(structuredIdSequence)"
    structuredIdSequence += 1
    return id
}

/// One typed field in the JSON arrays `EntryDraft.customFields`/`sections`
/// carry. A `secret` field is concealed + highly sensitive.
public func structuredTextField(
    id: String,
    key: String,
    label: String,
    role: String,
    value: String,
    secret: Bool = false
) -> ItemField {
    ItemField(
        id: id,
        key: key,
        label: label,
        protected: secret,
        semanticRole: role,
        sensitivity: secret ? .highlySensitive : .privateMetadata,
        value: secret
            ? .concealed(FieldValue.FieldValueConcealed(value: value))
            : .text(FieldValue.FieldValueText(value: value))
    )
}

/// Text input → typed `FieldValue`, port of `_typedValue` in the Dart editor.
/// Unknown types degrade to `text` so no kind silently breaks a save.
public func typedFieldValue(_ type: String, _ text: String) -> FieldValue {
    switch type {
    case "month_year":
        if let match = text.firstMatch(
            of: #/^(\d{1,2})\s*[\/\-]\s*(\d{4})$/#),
            let month = UInt8(match.1), let year = UInt16(match.2)
        {
            return .monthYear(FieldValue.FieldValueMonthYear(
                value: MonthYearValue(month: month, year: year)))
        }
        return .text(FieldValue.FieldValueText(value: text))
    case "address":
        return .address(FieldValue.FieldValueAddress(
            value: AddressValue(
                city: "", country: "", postalCode: "", state: "",
                street: text)))
    case "number":
        return .number(FieldValue.FieldValueNumber(
            value: Double(text) ?? 0))
    case "boolean":
        return .boolean(FieldValue.FieldValueBoolean(
            value: text.lowercased() == "true"))
    case "concealed":
        return .concealed(FieldValue.FieldValueConcealed(value: text))
    case "url":
        return .url(FieldValue.FieldValueUrl(value: text))
    case "email":
        return .email(FieldValue.FieldValueEmail(value: text))
    case "phone":
        return .phone(FieldValue.FieldValuePhone(value: text))
    case "date":
        return .date(FieldValue.FieldValueDate(value: text))
    case "certificate":
        return .certificate(FieldValue.FieldValueCertificate(value: text))
    case "attachment_ref":
        return .attachmentRef(FieldValue.FieldValueAttachmentRef(value: text))
    case "reference":
        return .reference(FieldValue.FieldValueReference(value: text))
    default:
        return .text(FieldValue.FieldValueText(value: text))
    }
}

// MARK: - Presentation extensions on generated models

extension VaultGroup: Identifiable {}

extension ItemMetadata {
    /// `EntrySummary.primaryUrl`.
    public var primaryUrl: String? { urls.first }

    public var isAgentContent: Bool { isAgentContentKind(kind) }

    /// Monogram used by the list and detail marks (`EntrySummary.monogram`).
    public var monogram: String {
        let trimmed = title.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { return "?" }
        let words = trimmed.split(whereSeparator: { $0.isWhitespace })
        if words.count > 1, let first = words[0].first, let second = words[1].first {
            return "\(first)\(second)".uppercased()
        }
        return String(trimmed.prefix(2)).uppercased()
    }

    /// `EntrySummary.subtitle`.
    public var subtitle: String {
        ([username].compactMap { $0 }.filter { !$0.isEmpty } + urls)
            .joined(separator: " · ")
    }
}

extension FieldView {
    /// `EntryFieldView.withValue` — returns a copy with a revealed `value`.
    public func withValue(_ next: FieldValue?) -> FieldView {
        FieldView(
            displayHint: displayHint,
            hasValue: hasValue,
            id: id,
            key: key,
            label: label,
            protected: `protected`,
            semanticRole: semanticRole,
            sensitivity: sensitivity,
            value: next,
            valueType: valueType
        )
    }

    /// Human-readable value, `EntryFieldView.displayValue`.
    public var displayValue: String {
        guard let value else {
            return displayHint ?? (hasValue ? "Stored" : "")
        }
        switch value {
        case .text(let payload): return payload.value
        case .concealed(let payload): return payload.value
        case .url(let payload): return payload.value
        case .email(let payload): return payload.value
        case .phone(let payload): return payload.value
        case .date(let payload): return payload.value
        case .certificate(let payload): return payload.value
        case .attachmentRef(let payload): return payload.value
        case .reference(let payload): return payload.value
        case .number(let payload):
            return payload.value.truncatingRemainder(dividingBy: 1) == 0
                ? String(Int64(payload.value)) : String(payload.value)
        case .boolean(let payload): return payload.value ? "true" : "false"
        case .monthYear(let payload):
            return String(
                format: "%02d/%d", payload.value.month, payload.value.year)
        case .address(let payload):
            return [
                payload.value.street, payload.value.city, payload.value.state,
                payload.value.postalCode, payload.value.country,
            ]
            .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
            .joined(separator: ", ")
        case .totp(let payload): return payload.value.issuer ?? "TOTP"
        case .keyPair: return "Key pair"
        case .opaqueJson(let payload): return "\(payload.value)"
        }
    }
}

/// `entryFieldText` — the plaintext a structured editor may hydrate from;
/// protected fields never yield text (the value stays server-side).
public func entryFieldText(_ field: FieldView) -> String? {
    if field.protected { return nil }
    guard let value = field.value else { return field.displayValue }
    switch value {
    case .text(let payload): return payload.value
    case .concealed(let payload): return payload.value
    case .url(let payload): return payload.value
    case .email(let payload): return payload.value
    case .phone(let payload): return payload.value
    case .date(let payload): return payload.value
    case .certificate(let payload): return payload.value
    case .attachmentRef(let payload): return payload.value
    case .reference(let payload): return payload.value
    case .monthYear(let payload):
        return String(
            format: "%02d/%d", payload.value.month, payload.value.year)
    case .address(let payload):
        return [
            payload.value.street, payload.value.city, payload.value.state,
            payload.value.postalCode, payload.value.country,
        ]
        .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
        .joined(separator: ", ")
    case .number(let payload):
        return payload.value.truncatingRemainder(dividingBy: 1) == 0
            ? String(Int64(payload.value)) : String(payload.value)
    case .boolean(let payload): return payload.value ? "true" : "false"
    case .totp, .keyPair, .opaqueJson:
        return field.displayValue
    }
}

/// `fieldsByRole` — fields of a section keyed by semantic role.
public func fieldsByRole(
    _ section: ItemSection, _ detail: EntryView
) -> [String: FieldView] {
    var result: [String: FieldView] = [:]
    for id in section.fieldIds {
        guard let field = detail.fields.first(where: { $0.id == id }),
            let role = field.semanticRole
        else { continue }
        result[role] = field
    }
    return result
}

/// `encodeStructuredSections` — the JSON `EntryDraft.sections` carries.
public func encodeStructuredSections(_ sections: [ItemSection]) -> String {
    guard let data = try? JSONEncoder().encode(sections) else { return "[]" }
    return String(decoding: data, as: UTF8.self)
}

extension ItemSection {
    /// Convenience matching the Dart `EntrySectionView` constructor order.
    public init(
        id: String, label: String, fieldIds: [String], semanticRole: String?
    ) {
        self.init(
            fieldIds: fieldIds, id: id, label: label,
            semanticRole: semanticRole)
    }
}
