import Foundation

/// Dynamic template-field helpers for the entry editor — ports of the
/// classification, payload, and per-field validation in
/// `entry_editor.dart` plus the `template_guidance.dart` table.

/// The standard fields that map onto the draft's own properties instead of
/// the custom-fields JSON (`_isUsername`/`_isPassword`/`_isOtp`/
/// `_isPrimaryUrl`).
public enum StandardTemplateField: Sendable, Equatable {
    case username, password, otp, primaryUrl
}

public func standardTemplateField(_ field: ItemFieldDefinition)
    -> StandardTemplateField?
{
    if field.key == "username" || field.semanticRole == "username" {
        return .username
    }
    if field.key == "password" || field.semanticRole == "password" {
        return .password
    }
    if field.key == "otp" || field.semanticRole == "otp"
        || field.valueType == "totp"
    {
        return .otp
    }
    if field.semanticRole == "website" || field.semanticRole == "url"
        || field.key == "website" || field.key == "url"
    {
        return .primaryUrl
    }
    return nil
}

/// One edited template field's state — what the editor's per-field text
/// controllers track.
public struct TemplateFieldEdit: Equatable, Sendable {
    /// Stored field id once hydrated from `entries_view`; new fields use
    /// `field_<kind-suffix>_<key>`.
    public var id: String?
    /// The stored display value; empty for protected/new fields.
    public var original: String
    public var text: String

    public init(id: String? = nil, original: String = "", text: String = "") {
        self.id = id
        self.original = original
        self.text = text
    }
}

/// The edited template fields as `ItemField`s — the array form of
/// `templateFieldPayload`, so callers merging user-added custom fields
/// encode the combined payload once.
public func templateFieldItemFields(
    definitions: [ItemFieldDefinition],
    edits: [String: TemplateFieldEdit],
    isNew: Bool,
    kind: String
) -> [ItemField] {
    let custom = definitions.filter { standardTemplateField($0) == nil }
    var fields: [ItemField] = []
    for definition in custom {
        let edit = edits[definition.key] ?? TemplateFieldEdit()
        let text = edit.text.trimmingCharacters(in: .whitespaces)
        if text.isEmpty && (isNew || edit.original.isEmpty) { continue }
        if !isNew && text == edit.original { continue }
        fields.append(ItemField(
            id: edit.id
                ?? "field_\(kind.dropFirst(5))_\(definition.key)",
            key: definition.key,
            label: definition.label,
            protected: definition.protected,
            semanticRole: definition.semanticRole,
            sensitivity: definition.sensitivity,
            value: typedFieldValue(definition.valueType, text)))
    }
    return fields
}

/// `_templateFieldPayload` — encodes the edited template fields as the
/// `customFields` JSON array. Skips untouched fields on edit and empty
/// fields on create. Returns nil when there is nothing custom to send.
public func templateFieldPayload(
    definitions: [ItemFieldDefinition],
    edits: [String: TemplateFieldEdit],
    isNew: Bool,
    kind: String
) -> String? {
    let fields = templateFieldItemFields(
        definitions: definitions, edits: edits, isNew: isNew, kind: kind)
    return fields.isEmpty ? nil : encodeItemFields(fields)
}

/// Per-field input validation from the Dart `_validateTemplateFields`.
public func validateTemplateField(
    _ field: ItemFieldDefinition, text: String
) -> String? {
    validateTypedField(field.valueType, text: text)
}

/// `validateTemplateField` without a definition — user-added custom
/// fields validate by their picked value type.
public func validateTypedField(_ valueType: String, text: String) -> String? {
    let value = text.trimmingCharacters(in: .whitespaces)
    if value.isEmpty { return nil }
    switch valueType {
    case "month_year":
        guard let match = value.firstMatch(
            of: #/^(\d{1,2})\s*[\/\-]\s*(\d{4})$/#),
            let month = Int(match.1), (1...12).contains(month)
        else { return "Use MM/YYYY." }
        return nil
    case "number":
        return Double(value) == nil ? "Enter a number." : nil
    default:
        return nil
    }
}

// MARK: - User-defined custom fields ("add field")

/// One user-managed field row in the editor — unlike template fields,
/// label, type, concealment and value are all chosen by the user.
public struct CustomFieldEdit: Equatable, Sendable, Identifiable {
    /// The hydrated server state — detects relabel/type/conceal changes
    /// on stored fields. nil for rows added during this editing session.
    public struct Snapshot: Equatable, Sendable {
        public var label: String
        public var valueType: String
        public var protected: Bool
        public var text: String

        public init(
            label: String, valueType: String, protected: Bool, text: String
        ) {
            self.label = label
            self.valueType = valueType
            self.protected = protected
            self.text = text
        }
    }

    /// Stored field id once hydrated from `entries_view`; new rows carry
    /// a `structuredId` minted at add time.
    public var id: String
    /// Server-side key — stable for stored rows, derived from the label
    /// for new rows at save time.
    public var key: String
    public var label: String
    public var valueType: String
    public var protected: Bool
    public var text: String
    /// A protected value exists server-side — the UI shows "blank keeps
    /// current" and blocks metadata-only changes that would wipe it.
    public var hasStoredValue: Bool
    public var stored: Snapshot?

    public init(
        id: String = structuredId("field"), key: String = "",
        label: String = "", valueType: String = "text",
        protected: Bool = false, text: String = "",
        hasStoredValue: Bool = false, stored: Snapshot? = nil
    ) {
        self.id = id
        self.key = key
        self.label = label
        self.valueType = valueType
        self.protected = protected
        self.text = text
        self.hasStoredValue = hasStoredValue
        self.stored = stored
    }

    /// Nothing user-visible differs from the hydrated state.
    public var unchanged: Bool {
        guard let stored else { return false }
        return text == stored.text && label == stored.label
            && valueType == stored.valueType && protected == stored.protected
    }

    /// Row carries nothing worth saving — brand-new and fully blank.
    public var isEmptyDraft: Bool {
        stored == nil
            && text.trimmingCharacters(in: .whitespaces).isEmpty
            && label.trimmingCharacters(in: .whitespaces).isEmpty
    }

    /// The `ItemField` this row becomes in `field_updates`/`custom_fields`.
    /// Concealment rides on `protected` + sensitivity, so the picked value
    /// type stays intact (a concealed URL stays a URL server-side).
    public func itemField() -> ItemField {
        ItemField(
            id: id,
            key: key,
            label: label.trimmingCharacters(in: .whitespaces),
            protected: protected,
            semanticRole: nil,
            sensitivity: protected
                ? .highlySensitive : .privateMetadata,
            value: typedFieldValue(valueType, text))
    }
}

/// The "add field" menu choices — label plus the value type the row
/// starts with. "Password" is concealed text.
public let customFieldTypes:
    [(value: String, label: String, protected: Bool)] = [
        ("text", "Text", false),
        ("text", "Password", true),
        ("url", "URL", false),
        ("email", "Email", false),
        ("phone", "Phone", false),
        ("date", "Date", false),
        ("month_year", "Month / year", false),
        ("number", "Number", false),
    ]

/// Slug a label into a field key — `Card PIN` → `card_pin`.
public func customFieldKeySlug(_ label: String) -> String {
    let mapped = label.lowercased().unicodeScalars.map {
        CharacterSet.alphanumerics.contains($0) ? Character($0) : "_"
    }
    let slug = String(mapped).split(separator: "_").joined(separator: "_")
    return slug.isEmpty ? "field" : slug
}

/// A key that is neither reserved nor already used — reserved keys and
/// collisions get a numeric suffix.
public func uniqueCustomFieldKey(_ base: String, taken: Set<String>) -> String {
    let reserved: Set<String> = ["username", "password", "otp"]
    var key = base
    var index = 2
    while reserved.contains(key) || taken.contains(key) {
        key = "\(base)_\(index)"
        index += 1
    }
    return key
}

/// Whether a protected stored value exists for this definition — the
/// "(blank keeps current)" label suffix in the Dart editor.
public func templateFieldHasStoredValue(
    _ field: ItemFieldDefinition, detail: EntryView?
) -> Bool {
    guard field.protected, let detail else { return false }
    return detail.fields.contains {
        $0.hasValue
            && ($0.key == field.key
                || $0.semanticRole == field.semanticRole)
    }
}

// MARK: - Template sections and guidance

/// `_templateSection` — the picker groups essentials first, then families.
public func templateSection(_ template: ItemKindDefinition) -> String {
    let essentials: Set<String> = [
        "core.prompt", "core.runbook", "core.environment",
        "core.ssh_server", "core.login", "core.api_credential",
        "core.database", "core.ssh_key",
    ]
    if essentials.contains(template.kind) { return "Developer essentials" }
    switch template.family {
    case .developer: return "Developer"
    case .common: return "Common"
    case .agentKnowledge: return "Agent knowledge"
    case .personal: return "Personal"
    default: return "Other"
    }
}

public struct TemplateGuidance: Equatable, Sendable {
    public let summary: String
    public let useWhen: String
    public init(summary: String, useWhen: String) {
        self.summary = summary
        self.useWhen = useWhen
    }
}

/// `templateGuidance` — same copy as the Dart table.
public let templateGuidance: [String: TemplateGuidance] = [
    "core.prompt": TemplateGuidance(
        summary: "Reusable instructions and context for an agent.",
        useWhen: "Use for tasks you repeat with the same rules or output format."),
    "core.runbook": TemplateGuidance(
        summary: "An ordered operational procedure that an agent can follow.",
        useWhen: "Use for deploys, incidents, backups, recovery, and maintenance."),
    "core.environment": TemplateGuidance(
        summary: "Environment variables and secrets for one project and stage.",
        useWhen: "Use for .env files, CI/CD secrets, containers, or Kubernetes."),
    "core.ssh_server": TemplateGuidance(
        summary: "A complete SSH topology with hosts, bastions, sudo, and tunnels.",
        useWhen: "Use when one system needs direct or multi-hop SSH access."),
    "core.login": TemplateGuidance(
        summary: "A website or app sign-in with password and optional one-time code.",
        useWhen: "Use for accounts you sign in to interactively."),
    "core.api_credential": TemplateGuidance(
        summary: "API keys, tokens, client IDs, and client secrets for a service.",
        useWhen: "Use for programmatic access to an API or cloud provider."),
    "core.database": TemplateGuidance(
        summary: "Database connection details, credentials, and connection string.",
        useWhen: "Use for an application database or an operator connection."),
    "core.ssh_key": TemplateGuidance(
        summary: "An SSH key pair, fingerprint, and optional passphrase.",
        useWhen: "Use to archive or share the key material itself."),
    "core.secure_note": TemplateGuidance(
        summary: "Free-form sensitive information protected as Markdown.",
        useWhen: "Use when structured fields do not fit the secret you need to keep."),
    "core.note": TemplateGuidance(
        summary: "Reusable Markdown knowledge that an agent can read.",
        useWhen: "Use for project context, conventions, references, or decisions."),
    "core.password": TemplateGuidance(
        summary: "A standalone password with an optional related website.",
        useWhen: "Use when there is no username or full login account to store."),
    "core.email_account": TemplateGuidance(
        summary: "Email credentials and incoming or outgoing server settings.",
        useWhen: "Use for mailbox access, IMAP, POP, or SMTP configuration."),
    "core.server": TemplateGuidance(
        summary: "Generic server facts and credentials without SSH topology.",
        useWhen: "Use for inventory or non-SSH access; prefer SSH Server for SSH."),
    "core.software_license": TemplateGuidance(
        summary: "Software license keys, ownership, version, and purchase details.",
        useWhen: "Use for paid desktop, server, or developer software licenses."),
    "core.wireless_router": TemplateGuidance(
        summary: "Router administration and Wi-Fi network credentials.",
        useWhen: "Use for a home, office, or temporary wireless network."),
    "core.credit_card": TemplateGuidance(
        summary: "Payment card number, expiry, verification code, and PIN.",
        useWhen: "Use for a physical or virtual payment card."),
    "core.document": TemplateGuidance(
        summary: "A general document number, issuer, and expiry date.",
        useWhen: "Use when no dedicated identity-document template applies."),
    "core.identity": TemplateGuidance(
        summary: "A person or organization profile with contact information.",
        useWhen: "Use for reusable identity and form-filling details."),
    "core.bank_account": TemplateGuidance(
        summary: "Bank account ownership, routing, IBAN, SWIFT, and PIN details.",
        useWhen: "Use for receiving payments or managing a bank account."),
    "core.crypto_wallet": TemplateGuidance(
        summary: "A wallet address with private key, recovery phrase, and PIN.",
        useWhen: "Use for cryptocurrency or blockchain wallet recovery data."),
    "core.driver_license": TemplateGuidance(
        summary: "Driver license identity, number, issuer, and validity dates.",
        useWhen: "Use for a driving credential issued by an authority."),
    "core.medical_record": TemplateGuidance(
        summary: "Important patient, physician, insurance, and medication details.",
        useWhen: "Use for concise emergency or personal medical information."),
    "core.membership": TemplateGuidance(
        summary: "Membership identifiers, organization, and validity details.",
        useWhen: "Use for clubs, associations, subscriptions, or access cards."),
    "core.outdoor_license": TemplateGuidance(
        summary: "A hunting, fishing, boating, or other outdoor license.",
        useWhen: "Use for regulated activity permits and their expiry dates."),
    "core.passport": TemplateGuidance(
        summary: "Passport identity, document number, issuer, and validity.",
        useWhen: "Use for international identity and travel details."),
    "core.reward_program": TemplateGuidance(
        summary: "Loyalty program membership and account identifiers.",
        useWhen: "Use for airline, hotel, retail, or other rewards accounts."),
    "core.social_security_number": TemplateGuidance(
        summary: "A protected government identity number and holder name.",
        useWhen: "Use for a Social Security Number or equivalent national ID."),
    "core.generic": TemplateGuidance(
        summary: "A flexible item for information that has no dedicated template.",
        useWhen: "Use only when a more specific template does not fit."),
]

public func guidanceForTemplate(_ kind: String, label: String? = nil)
    -> TemplateGuidance
{
    templateGuidance[kind] ?? TemplateGuidance(
        summary: "Structured information for \(label ?? "this item type").",
        useWhen: "Use when this template matches the information you need to keep.")
}

/// `_fallbackTemplate` — when `templates_list` is unavailable the editor
/// still renders the essentials for the common kinds.
public func fallbackTemplate(_ kind: String) -> ItemKindDefinition? {
    func field(
        _ key: String, _ label: String, _ valueType: String,
        _ role: String, protected: Bool = false, section: String = "Details"
    ) -> ItemFieldDefinition {
        ItemFieldDefinition(
            aliases: [], key: key, label: label, maskLast: nil,
            protected: `protected`, section: section, semanticRole: role,
            sensitivity: `protected` ? .highlySensitive : .privateMetadata,
            valueType: valueType)
    }
    let fields: [ItemFieldDefinition]?
    switch kind {
    case "core.login":
        fields = [
            field("username", "Username", "text", "username",
                  section: "Login"),
            field("password", "Password", "concealed", "password",
                  protected: true, section: "Login"),
            field("website", "Website", "url", "website",
                  section: "Login"),
            field("otp", "One-time password", "totp", "otp",
                  protected: true, section: "Login"),
        ]
    case "core.password":
        fields = [
            field("password", "Password", "concealed", "password",
                  protected: true),
            field("website", "Website", "url", "website"),
        ]
    case "core.api_credential":
        fields = [
            field("provider", "Provider", "text", "provider"),
            field("credential", "Credential", "concealed", "credential",
                  protected: true),
            field("hostname", "Host", "url", "host"),
        ]
    case "core.secure_note", "core.generic", "core.prompt", "core.runbook",
        "core.note":
        fields = []
    default:
        fields = nil
    }
    guard let fields else { return nil }
    return ItemKindDefinition(
        family: .other, fields: fields, icon: "",
        kind: kind, label: String(kind.dropFirst(5)),
        markdownNotes: true, templateVersion: 1)
}
