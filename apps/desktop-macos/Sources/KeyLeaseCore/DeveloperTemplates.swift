import Foundation
import Observation

/// Structured editors for the developer templates (`core.environment`,
/// `core.ssh_server`), ported from `developer_templates.dart` and the
/// state-sync parts of `developer_template_editor.dart`.
///
/// Everything here is plain data: the editors render this state and the
/// daemon receives the result through `EntryDraft`'s JSON field payloads.

// MARK: - .env parsing and rendering

@Observable
public final class EnvVariableDraft {
    public init(
        id: String, key: String, value: String, secret: Bool = true,
        existing: Bool = false, hasStoredValue: Bool = false,
        dirty: Bool = true
    ) {
        self.id = id
        self.key = key
        self.value = value
        self.secret = secret
        self.existing = existing
        self.hasStoredValue = hasStoredValue
        self.dirty = dirty
    }

    public let id: String
    public var key: String
    public var value: String
    public var secret: Bool
    public let existing: Bool
    public let hasStoredValue: Bool
    public var dirty: Bool

    public func toField() -> ItemField {
        structuredTextField(
            id: id, key: "env.\(key)", label: key,
            role: "environment_variable", value: value, secret: secret)
    }
}

public struct EnvParseIssue: Equatable, Sendable {
    public let line: Int
    public let message: String
    public init(_ line: Int, _ message: String) {
        self.line = line
        self.message = message
    }
}

public struct EnvParseResult: Equatable, Sendable {
    public struct Variable: Equatable, Sendable {
        public let id: String
        public let key: String
        public let value: String
    }

    public let variables: [Variable]
    public let issues: [EnvParseIssue]
    public let ignoredComments: Int
    public let ignoredBlankLines: Int
    public let normalizedExports: Int

    public var valid: Bool { issues.isEmpty }
}

private nonisolated(unsafe) let environmentKeyPattern =
    #/^[A-Za-z_][A-Za-z0-9_]*$/#
private nonisolated(unsafe) let sshAliasPattern =
    #/^[A-Za-z0-9._-]+$/#

/// `parseDotEnv` — strict dotenv reader with the same acceptance rules as
/// the Dart original: comments, blank lines, `export `, single/double
/// quotes (double quotes support escapes and multiline values).
public func parseDotEnv(_ source: String) -> EnvParseResult {
    let normalized = source
        .replacingOccurrences(of: "\u{FEFF}", with: "")
        .replacingOccurrences(of: "\r\n", with: "\n")
    let lines = normalized.split(separator: "\n", omittingEmptySubsequences: false)
        .map(String.init)
    var variables: [EnvParseResult.Variable] = []
    var issues: [EnvParseIssue] = []
    var seen = Set<String>()
    var comments = 0
    var blanks = 0
    var exports = 0
    var index = 0
    while index < lines.count {
        let lineNumber = index + 1
        var line = lines[index]
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty {
            blanks += 1
            index += 1
            continue
        }
        if trimmed.hasPrefix("#") {
            comments += 1
            index += 1
            continue
        }
        line = String(line.drop(while: { $0 == " " || $0 == "\t" }))
        if line.hasPrefix("export ") {
            exports += 1
            line = String(line.dropFirst(7).drop(while: { $0 == " " || $0 == "\t" }))
        }
        guard let equals = line.firstIndex(of: "="),
            equals > line.startIndex
        else {
            issues.append(EnvParseIssue(lineNumber, "Expected KEY=value."))
            index += 1
            continue
        }
        let key = String(line[..<equals])
            .trimmingCharacters(in: .whitespaces)
        if key.firstMatch(of: environmentKeyPattern) == nil {
            issues.append(
                EnvParseIssue(lineNumber, "Invalid variable name \"\(key)\"."))
            index += 1
            continue
        }
        if !seen.insert(key).inserted {
            issues.append(
                EnvParseIssue(lineNumber, "Duplicate variable \"\(key)\"."))
            index += 1
            continue
        }
        var raw = String(line[line.index(after: equals)...])
            .drop(while: { $0 == " " || $0 == "\t" })
        var value = ""
        if raw.first == "'" || raw.first == "\"" {
            let quote = raw.removeFirst()
            var buffer = ""
            var closed = false
            while true {
                var cursor = raw.startIndex
                while cursor < raw.endIndex {
                    let char = raw[cursor]
                    if char == quote
                        && (quote == "'" || !isEscaped(raw, at: cursor))
                    {
                        let trailing = raw[raw.index(after: cursor)...]
                            .trimmingCharacters(in: .whitespaces)
                        if !trailing.isEmpty && !trailing.hasPrefix("#") {
                            issues.append(EnvParseIssue(
                                lineNumber,
                                "Unexpected text after quoted value."))
                        }
                        closed = true
                        break
                    }
                    if quote == "\"", char == "\\",
                        raw.index(after: cursor) < raw.endIndex
                    {
                        cursor = raw.index(after: cursor)
                        let next = raw[cursor]
                        let mapped =
                            switch next {
                            case "n": "\n"
                            case "r": "\r"
                            case "t": "\t"
                            case "\"": "\""
                            case "\\": "\\"
                            case "$": "$"
                            default: String(next)
                            }
                        buffer.append(mapped)
                    } else {
                        buffer.append(char)
                    }
                    cursor = raw.index(after: cursor)
                }
                if closed || index + 1 >= lines.count { break }
                buffer.append("\n")
                index += 1
                raw = Substring(lines[index])
            }
            if !closed {
                issues.append(
                    EnvParseIssue(lineNumber, "Unclosed quoted value."))
            }
            value = buffer
        } else {
            var text = String(raw)
            if let comment = unquotedCommentIndex(in: text) {
                text = String(text[..<comment])
            }
            value = text.trimmingCharacters(
                in: CharacterSet(charactersIn: " \t"))
        }
        variables.append(EnvParseResult.Variable(
            id: structuredId("field_env", salt: variables.count),
            key: key, value: value))
        index += 1
    }
    return EnvParseResult(
        variables: variables, issues: issues, ignoredComments: comments,
        ignoredBlankLines: blanks, normalizedExports: exports)
}

private func isEscaped(_ value: Substring, at index: String.Index) -> Bool {
    var slashes = 0
    var cursor = index
    while cursor > value.startIndex {
        cursor = value.index(before: cursor)
        if value[cursor] != "\\" { break }
        slashes += 1
    }
    return slashes % 2 == 1
}

/// Index of a `#` that starts a comment inside an unquoted value — a `#`
/// preceded by whitespace, like `_unquotedComment` in Dart.
private func unquotedCommentIndex(in value: String) -> String.Index? {
    var index = value.startIndex
    while index < value.endIndex {
        if value[index] == "#", index > value.startIndex {
            let before = value[value.index(before: index)]
            if before == " " || before == "\t" { return index }
        }
        index = value.index(after: index)
    }
    return nil
}

/// `renderDotEnv` — emits `KEY=value` lines with the smallest safe quoting.
public func renderDotEnv(_ variables: [(key: String, value: String)]) -> String {
    var output = ""
    for variable in variables {
        output += "\(variable.key)=\(renderEnvValue(variable.value))\n"
    }
    return output
}

private nonisolated(unsafe) let envSafePattern =
    #/^[A-Za-z0-9_./:@%+,=-]+$/#

func renderEnvValue(_ value: String) -> String {
    if value.isEmpty { return "" }
    if value.firstMatch(of: envSafePattern) != nil { return value }
    if !value.contains("'") && !value.contains("\n") && !value.contains("\r") {
        return "'\(value)'"
    }
    let escaped = value
        .replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\"", with: "\\\"")
        .replacingOccurrences(of: "$", with: "\\$")
        .replacingOccurrences(of: "\n", with: "\\n")
        .replacingOccurrences(of: "\r", with: "\\r")
        .replacingOccurrences(of: "\t", with: "\\t")
    return "\"\(escaped)\""
}

// MARK: - SSH config rendering

public struct SshEndpointConfig: Equatable, Sendable {
    public let sectionId: String
    public let name: String
    public let alias: String
    public let host: String
    public let port: Int
    public let username: String
    public let authMode: String
    public let connectVia: String?

    public init(
        sectionId: String, name: String, alias: String, host: String,
        port: Int, username: String, authMode: String, connectVia: String? = nil
    ) {
        self.sectionId = sectionId
        self.name = name
        self.alias = alias
        self.host = host
        self.port = port
        self.username = username
        self.authMode = authMode
        self.connectVia = connectVia
    }
}

public struct SshForwardConfig: Equatable, Sendable {
    public let endpointId: String
    public let type: String
    public let bindAddress: String
    public let bindPort: Int
    public let destinationHost: String
    public let destinationPort: Int

    public init(
        endpointId: String, type: String, bindAddress: String, bindPort: Int,
        destinationHost: String, destinationPort: Int
    ) {
        self.endpointId = endpointId
        self.type = type
        self.bindAddress = bindAddress
        self.bindPort = bindPort
        self.destinationHost = destinationHost
        self.destinationPort = destinationPort
    }
}

public struct SshConfigError: Error, Equatable, Sendable {
    public let message: String
    public init(_ message: String) { self.message = message }
}

/// Resolves the per-device key paths needed to render an SSH config — a
/// port of `resolveSshPrivateKeyPaths`. A single discovered key is safe to
/// select automatically; otherwise `select` asks the user. Returning nil
/// means the user cancelled.
@MainActor public func resolveSshPrivateKeyPaths(
    endpoints: [SshEndpointConfig],
    currentPaths: [String: String],
    discover: () async throws -> [String],
    select: (SshEndpointConfig) async -> String?,
    onSelected: (SshEndpointConfig, String) async -> Void
) async -> [String: String]? {
    var paths = currentPaths
    let missing = endpoints.filter {
        $0.authMode == "private_key"
            && (paths[$0.sectionId]?.isEmpty ?? true)
    }
    if missing.isEmpty { return paths }
    var discovered: [String] = []
    do {
        discovered = try await discover()
    } catch {
        // Manual selection remains available when discovery is unsupported.
    }
    for endpoint in missing {
        let path = discovered.count == 1
            ? discovered[0] : await select(endpoint)
        guard let path, !path.isEmpty else { return nil }
        await onSelected(endpoint, path)
        paths[endpoint.sectionId] = path
    }
    return paths
}

/// `renderSshConfig` — emits an `ssh_config(5)` fragment for the endpoints
/// and their tunnels. Throws `SshConfigError` on invalid input.
public func renderSshConfig(
    endpoints: [SshEndpointConfig],
    forwards: [SshForwardConfig],
    privateKeyPaths: [String: String]
) throws -> String {
    let byId = Dictionary(
        endpoints.map { ($0.sectionId, $0) },
        uniquingKeysWith: { first, _ in first })
    var output = ""
    for endpoint in endpoints {
        guard endpoint.alias.firstMatch(of: sshAliasPattern) != nil else {
            throw SshConfigError("Invalid SSH alias.")
        }
        output += "Host \(endpoint.alias)\n"
        output += "  HostName \(try sshToken(endpoint.host))\n"
        if !endpoint.username.isEmpty {
            output += "  User \(try sshToken(endpoint.username))\n"
        }
        output += "  Port \(endpoint.port)\n"
        if endpoint.authMode == "private_key" {
            guard let path = privateKeyPaths[endpoint.sectionId],
                !path.isEmpty
            else {
                throw SshConfigError(
                    "Select a private key for \(endpoint.name) on this device.")
            }
            output += "  IdentityFile \(try sshToken(path))\n"
            output += "  IdentitiesOnly yes\n"
        }
        var chain: [String] = []
        var seen = Set<String>()
        var parent = endpoint.connectVia
        while let hop = parent, !hop.isEmpty {
            guard seen.insert(hop).inserted else {
                throw SshConfigError("SSH jump host cycle.")
            }
            guard let jump = byId[hop] else {
                throw SshConfigError("Missing SSH jump host.")
            }
            chain.insert(jump.alias, at: 0)
            parent = jump.connectVia
        }
        if !chain.isEmpty {
            output += "  ProxyJump \(chain.joined(separator: ","))\n"
        }
        for forward in forwards where forward.endpointId == endpoint.sectionId {
            let bind = "\(try sshToken(forward.bindAddress)):\(forward.bindPort)"
            if forward.type == "dynamic" {
                output += "  DynamicForward \(bind)\n"
            } else {
                let destination =
                    "\(try sshToken(forward.destinationHost)):\(forward.destinationPort)"
                output += forward.type == "remote"
                    ? "  RemoteForward \(bind) \(destination)\n"
                    : "  LocalForward \(bind) \(destination)\n"
            }
        }
        output += "\n"
    }
    return output
}

private nonisolated(unsafe) let sshTokenSafePattern =
    #/^[A-Za-z0-9_./:@%+,-]+$/#

private func sshToken(_ value: String) throws -> String {
    if value.isEmpty || value.unicodeScalars.contains(where: { $0.value < 32 }) {
        throw SshConfigError(
            "SSH values must not contain control characters.")
    }
    if value.firstMatch(of: sshTokenSafePattern) != nil { return value }
    let escaped = value
        .replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\"", with: "\\\"")
    return "\"\(escaped)\""
}

// MARK: - Environment editor state (`EnvironmentTemplateEditor`)

/// Editor state for `core.environment`: project/scope/source metadata plus
/// the variable table. `sync(into:)` writes the structured JSON payloads
/// the draft saves through `field_updates`/`sections`.
@Observable
public final class EnvironmentTemplateState {
    public init(draft: EntryDraft) {
        self.draft = draft
    }

    public let draft: EntryDraft
    public var project = ""
    public var scope = "development"
    public var source = "dotenv"
    public var variables: [EnvVariableDraft] = []
    public private(set) var removed: [String] = []
    private var metadataIds: [String: String] = [:]
    private var hydrated = false

    /// Hydrates from the stored detail once it has loaded; new drafts have
    /// nothing to hydrate. Returns true when hydration ran.
    @discardableResult
    public func hydrate(detail: EntryView?) -> Bool {
        if hydrated || draft.isNew { return hydrated }
        guard let detail else { return false }
        guard let metadata = detail.sections.first(where: {
            $0.semanticRole == "environment_metadata"
        }), let variableSection = detail.sections.first(where: {
            $0.semanticRole == "environment_variables"
        }) else { return false }
        let fields = fieldsByRole(metadata, detail)
        func value(_ role: String, _ fallback: String) -> String {
            guard let field = fields[role] else { return fallback }
            metadataIds[role] = field.id
            return entryFieldText(field) ?? fallback
        }
        project = value("environment_project", "")
        scope = value("environment_scope", "development")
        source = value("environment_source", "dotenv")
        for id in variableSection.fieldIds {
            guard let field = detail.fields.first(where: { $0.id == id }),
                field.semanticRole == "environment_variable"
            else { continue }
            variables.append(EnvVariableDraft(
                id: field.id,
                key: field.label,
                value: entryFieldText(field) ?? "",
                secret: field.protected,
                existing: true,
                hasStoredValue: field.hasValue,
                dirty: false))
        }
        hydrated = true
        return true
    }

    private func metadataId(_ role: String) -> String {
        if let id = metadataIds[role] { return id }
        let id = structuredId("field_environment")
        metadataIds[role] = id
        return id
    }

    /// Validates and writes `customFields`/`sections`/`removeFieldIds`/
    /// `structuredErrors` on the draft — the Dart `_sync`.
    public func sync() {
        var errors: [String: String] = [:]
        if project.trimmingCharacters(in: .whitespaces).isEmpty {
            errors["environment_project"] = "Enter a project or repository."
        }
        var keys = Set<String>()
        for variable in variables {
            if variable.key.firstMatch(of: environmentKeyPattern) == nil {
                errors["environment_variables"] =
                    "Variable names must use shell identifier syntax."
            } else if !keys.insert(variable.key).inserted {
                errors["environment_variables"] =
                    "Variable names must be unique."
            }
            if variable.existing, variable.dirty, variable.hasStoredValue,
                variable.value.isEmpty
            {
                errors["environment_variables"] =
                    "Re-enter a stored secret before renaming it or changing its protection."
            }
        }
        let projectId = metadataId("environment_project")
        let scopeId = metadataId("environment_scope")
        let sourceId = metadataId("environment_source")
        var updates: [ItemField] = [
            structuredTextField(
                id: projectId, key: "environment.project",
                label: "Project / repository", role: "environment_project",
                value: project.trimmingCharacters(in: .whitespaces)),
            structuredTextField(
                id: scopeId, key: "environment.scope", label: "Environment",
                role: "environment_scope", value: scope),
            structuredTextField(
                id: sourceId, key: "environment.source", label: "Source",
                role: "environment_source", value: source),
        ]
        for variable in variables where !variable.existing || variable.dirty {
            updates.append(variable.toField())
        }
        let sections = [
            ItemSection(
                id: "environment_metadata", label: "Environment",
                fieldIds: [projectId, scopeId, sourceId],
                semanticRole: "environment_metadata"),
            ItemSection(
                id: "environment_variables", label: "Variables",
                fieldIds: variables.map(\.id),
                semanticRole: "environment_variables"),
        ]
        draft.customFields = encodeItemFields(updates)
        draft.sections = encodeStructuredSections(sections)
        draft.removeFieldIds = removed
        draft.structuredErrors = errors
    }

    public func addVariable() {
        variables.append(EnvVariableDraft(
            id: structuredId("field_env", salt: variables.count),
            key: "NEW_VARIABLE", value: ""))
        sync()
    }

    public func removeVariable(_ variable: EnvVariableDraft) {
        variables.removeAll { $0.id == variable.id }
        if variable.existing { removed.append(variable.id) }
        sync()
    }

    public func move(_ variable: EnvVariableDraft, offset: Int) {
        guard let from = variables.firstIndex(where: { $0.id == variable.id })
        else { return }
        let to = from + offset
        guard to >= 0, to < variables.count else { return }
        variables.remove(at: from)
        variables.insert(variable, at: to)
        sync()
    }

    /// `applyPaste` — merge or replace variables from parsed .env content.
    /// `replace: true` removes every existing variable first (the view asks
    /// for confirmation before calling it).
    public func applyPaste(_ parsed: EnvParseResult, replace: Bool) {
        guard parsed.valid else { return }
        if replace {
            removed.append(contentsOf: variables.filter(\.existing).map(\.id))
            variables.removeAll()
        }
        for incoming in parsed.variables {
            if let existing = variables.first(where: {
                $0.key == incoming.key
            }) {
                existing.value = incoming.value
                existing.dirty = true
            } else {
                variables.append(EnvVariableDraft(
                    id: incoming.id, key: incoming.key,
                    value: incoming.value))
            }
        }
        sync()
    }
}

// MARK: - SSH editor state (`SshServerTemplateEditor`)

@Observable
public final class SshEndpointDraft {
    public init(id: String, existing: Bool = false) {
        self.id = id
        self.existing = existing
    }

    public let id: String
    public let existing: Bool
    /// Role → stored field id, hydrated from the existing item.
    public var fieldIds: [String: String] = [:]
    /// Roles whose stored value is still secret (never hydrated).
    public var storedRoles: Set<String> = []
    public var name = ""
    public var alias = ""
    public var host = ""
    public var port = "22"
    public var username = ""
    public var connectVia = ""
    public var authMode = "ssh_agent"
    public var password = ""
    public var passphrase = ""
    public var sudoMode = "none"
    public var sudoPassword = ""
    public var fingerprint = ""
}

@Observable
public final class SshForwardDraft {
    public init(id: String, existing: Bool = false) {
        self.id = id
        self.existing = existing
    }

    public let id: String
    public let existing: Bool
    public var fieldIds: [String: String] = [:]
    public var endpointId = ""
    public var type = "local"
    public var bindAddress = "127.0.0.1"
    public var bindPort = ""
    public var destinationHost = ""
    public var destinationPort = ""
}

/// Editor state for `core.ssh_server`: endpoint cards plus tunnel rows,
/// synced into `customFields`/`sections`/`removeFieldIds` exactly like the
/// Dart `_SshServerTemplateEditorState`.
@Observable
public final class SshTemplateState {
    public init(draft: EntryDraft) {
        self.draft = draft
    }

    public let draft: EntryDraft
    public var endpoints: [SshEndpointDraft] = []
    public var forwards: [SshForwardDraft] = []
    private var removed: [String] = []
    private var hydrated = false

    @discardableResult
    public func hydrate(detail: EntryView?) -> Bool {
        if hydrated || draft.isNew { return hydrated }
        guard let detail else { return false }
        for section in detail.sections
        where section.semanticRole == "ssh_endpoint" {
            let endpoint = SshEndpointDraft(id: section.id, existing: true)
            let fields = fieldsByRole(section, detail)
            func value(_ role: String, _ fallback: String = "") -> String {
                guard let field = fields[role] else { return fallback }
                endpoint.fieldIds[role] = field.id
                if field.hasValue { endpoint.storedRoles.insert(role) }
                return entryFieldText(field) ?? fallback
            }
            endpoint.name = value("ssh_display_name")
            endpoint.alias = value("ssh_alias")
            endpoint.host = value("ssh_host")
            endpoint.port = value("ssh_port", "22")
            endpoint.username = value("ssh_username")
            endpoint.connectVia = value("ssh_connect_via")
            endpoint.authMode = value("ssh_auth_mode", "ssh_agent")
            endpoint.sudoMode = value("ssh_sudo_mode", "none")
            endpoint.fingerprint = value("ssh_host_fingerprint")
            _ = value("ssh_password")
            _ = value("ssh_private_key_passphrase")
            _ = value("ssh_sudo_password")
            endpoints.append(endpoint)
        }
        for section in detail.sections
        where section.semanticRole == "ssh_forward" {
            let forward = SshForwardDraft(id: section.id, existing: true)
            let fields = fieldsByRole(section, detail)
            func value(_ role: String, _ fallback: String = "") -> String {
                guard let field = fields[role] else { return fallback }
                forward.fieldIds[role] = field.id
                return entryFieldText(field) ?? fallback
            }
            forward.endpointId = value("ssh_forward_endpoint")
            forward.type = value("ssh_forward_type", "local")
            forward.bindAddress = value("ssh_bind_address", "127.0.0.1")
            forward.bindPort = value("ssh_bind_port")
            forward.destinationHost = value("ssh_destination_host")
            forward.destinationPort = value("ssh_destination_port")
            forwards.append(forward)
        }
        hydrated = true
        return true
    }

    private func fieldId(_ ids: inout [String: String], _ role: String)
        -> String
    {
        if let id = ids[role] { return id }
        let id = structuredId("field_ssh")
        ids[role] = id
        return id
    }

    private func field(
        _ sectionId: String, _ ids: inout [String: String], _ role: String,
        _ value: String, secret: Bool = false
    ) -> ItemField {
        structuredTextField(
            id: fieldId(&ids, role),
            key: "ssh.\(sectionId).\(role.dropFirst(4))",
            label: role.dropFirst(4).replacingOccurrences(of: "_", with: " "),
            role: role, value: value, secret: secret)
    }

    /// Per-endpoint validation — the Dart `_errorsForEndpoint`.
    public func errorsForEndpoint(_ endpoint: SshEndpointDraft)
        -> [String: String]
    {
        var errors: [String: String] = [:]
        if endpoint.name.trimmingCharacters(in: .whitespaces).isEmpty {
            errors["name"] = "Enter a display name."
        }
        if endpoint.host.trimmingCharacters(in: .whitespaces).isEmpty {
            errors["host"] = "Enter a host or IP address."
        }
        let alias = endpoint.alias.trimmingCharacters(in: .whitespaces)
        if alias.isEmpty {
            errors["alias"] = "Enter an SSH alias."
        } else if alias.firstMatch(of: sshAliasPattern) == nil {
            errors["alias"] =
                "Use only letters, digits, dots, underscores, or hyphens."
        } else if endpoints.filter({
            $0.alias.trimmingCharacters(in: .whitespaces) == alias
        }).count > 1 {
            errors["alias"] =
                "This SSH alias is already used by another server."
        }
        if let port = Int(endpoint.port), port >= 1, port <= 65535 {
        } else {
            errors["port"] = "Use a port from 1 to 65535."
        }
        if !endpoint.connectVia.isEmpty,
            !endpoints.contains(where: { $0.id == endpoint.connectVia })
        {
            errors["connectVia"] = "Choose an existing jump host."
        }
        var seen = Set<String>()
        var cursor = endpoint
        while !cursor.connectVia.isEmpty {
            if !seen.insert(cursor.id).inserted {
                errors["connectVia"] =
                    "Jump host chains cannot contain a cycle."
                break
            }
            guard let next = endpoints.first(where: {
                $0.id == cursor.connectVia
            }) else { break }
            cursor = next
        }
        if endpoint.authMode == "password", endpoint.password.isEmpty,
            !endpoint.storedRoles.contains("ssh_password")
        {
            errors["password"] = "Enter the SSH password."
        }
        if endpoint.sudoMode == "same_as_ssh_password",
            endpoint.authMode != "password"
        {
            errors["sudo"] =
                "Reusing the SSH password requires password authentication."
        }
        if endpoint.sudoMode == "separate_password",
            endpoint.sudoPassword.isEmpty,
            !endpoint.storedRoles.contains("ssh_sudo_password")
        {
            errors["sudoPassword"] = "Enter the sudo password."
        }
        return errors
    }

    /// The Dart `_sync`: validates, then writes the structured JSON fields,
    /// sections and removal list onto the draft.
    public func sync() {
        var errors: [String: String] = [:]
        var removals = Set(removed)
        let endpointIds = Set(endpoints.map(\.id))
        if endpoints.contains(where: { !errorsForEndpoint($0).isEmpty }) {
            errors["ssh_endpoints"] =
                "Complete the highlighted SSH server fields."
        }
        var fields: [ItemField] = []
        var sections: [ItemSection] = []
        for endpoint in endpoints {
            var ids = endpoint.fieldIds
            var endpointFields: [ItemField] = [
                field(endpoint.id, &ids, "ssh_display_name", endpoint.name),
                field(endpoint.id, &ids, "ssh_alias", endpoint.alias),
                field(endpoint.id, &ids, "ssh_host", endpoint.host),
                field(endpoint.id, &ids, "ssh_port", endpoint.port),
                field(endpoint.id, &ids, "ssh_username", endpoint.username),
                field(endpoint.id, &ids, "ssh_connect_via", endpoint.connectVia),
                field(endpoint.id, &ids, "ssh_auth_mode", endpoint.authMode),
                field(endpoint.id, &ids, "ssh_sudo_mode", endpoint.sudoMode),
                field(endpoint.id, &ids, "ssh_host_fingerprint",
                    endpoint.fingerprint),
            ]
            if !endpoint.password.isEmpty
                || (!endpoint.existing && endpoint.authMode == "password")
            {
                endpointFields.append(field(
                    endpoint.id, &ids, "ssh_password", endpoint.password,
                    secret: true))
            }
            if !endpoint.passphrase.isEmpty {
                endpointFields.append(field(
                    endpoint.id, &ids, "ssh_private_key_passphrase",
                    endpoint.passphrase, secret: true))
            }
            if !endpoint.sudoPassword.isEmpty
                || (!endpoint.existing
                    && endpoint.sudoMode == "separate_password")
            {
                endpointFields.append(field(
                    endpoint.id, &ids, "ssh_sudo_password",
                    endpoint.sudoPassword, secret: true))
            }
            endpoint.fieldIds = ids
            if endpoint.existing, endpoint.authMode != "password",
                let id = ids["ssh_password"]
            {
                removals.insert(id)
            }
            if endpoint.existing, endpoint.authMode != "private_key",
                let id = ids["ssh_private_key_passphrase"]
            {
                removals.insert(id)
            }
            if endpoint.existing, endpoint.sudoMode != "separate_password",
                let id = ids["ssh_sudo_password"]
            {
                removals.insert(id)
            }
            fields.append(contentsOf: endpointFields)
            let requiredRoles = [
                "ssh_display_name", "ssh_alias", "ssh_host", "ssh_port",
                "ssh_username", "ssh_connect_via", "ssh_auth_mode",
                "ssh_sudo_mode", "ssh_host_fingerprint",
            ]
            var activeRoles = requiredRoles
            if endpoint.authMode == "password",
                ids["ssh_password"] != nil
            {
                activeRoles.append("ssh_password")
            }
            if endpoint.authMode == "private_key",
                ids["ssh_private_key_passphrase"] != nil
            {
                activeRoles.append("ssh_private_key_passphrase")
            }
            if endpoint.sudoMode == "separate_password",
                ids["ssh_sudo_password"] != nil
            {
                activeRoles.append("ssh_sudo_password")
            }
            sections.append(ItemSection(
                id: endpoint.id,
                label: endpoint.name.trimmingCharacters(in: .whitespaces)
                    .isEmpty ? "SSH server"
                    : endpoint.name.trimmingCharacters(in: .whitespaces),
                fieldIds: activeRoles.compactMap { ids[$0] },
                semanticRole: "ssh_endpoint"))
        }
        for forward in forwards {
            var ids = forward.fieldIds
            fields.append(contentsOf: [
                field(forward.id, &ids, "ssh_forward_endpoint",
                    forward.endpointId),
                field(forward.id, &ids, "ssh_forward_type", forward.type),
                field(forward.id, &ids, "ssh_bind_address",
                    forward.bindAddress),
                field(forward.id, &ids, "ssh_bind_port", forward.bindPort),
                field(forward.id, &ids, "ssh_destination_host",
                    forward.destinationHost),
                field(forward.id, &ids, "ssh_destination_port",
                    forward.destinationPort),
            ])
            forward.fieldIds = ids
            let bindPort = Int(forward.bindPort)
            let destinationPort = Int(forward.destinationPort)
            if !endpointIds.contains(forward.endpointId)
                || bindPort == nil || bindPort! < 1 || bindPort! > 65535
                || (forward.type != "dynamic"
                    && (forward.destinationHost.isEmpty
                        || destinationPort == nil || destinationPort! < 1
                        || destinationPort! > 65535))
            {
                errors["ssh_forwards"] =
                    "Every tunnel needs a valid server, bind port, and destination."
            }
            sections.append(ItemSection(
                id: forward.id, label: "\(forward.type) tunnel",
                fieldIds: Array(ids.values),
                semanticRole: "ssh_forward"))
        }
        draft.customFields = encodeItemFields(fields)
        draft.sections = encodeStructuredSections(sections)
        draft.removeFieldIds = Array(removals)
        draft.structuredErrors = errors
    }

    public func addEndpoint() {
        endpoints.append(SshEndpointDraft(
            id: structuredId("ssh_endpoint", salt: endpoints.count)))
        sync()
    }

    /// Removes an endpoint, its tunnels, and any `connectVia` references —
    /// and records the field removals and key-binding cleanup on the draft.
    public func removeEndpoint(_ endpoint: SshEndpointDraft) {
        endpoints.removeAll { $0.id == endpoint.id }
        draft.sshBindingsToClear = Array(
            Set(draft.sshBindingsToClear).union([endpoint.id]))
        if endpoint.existing {
            removed.append(contentsOf: endpoint.fieldIds.values)
        }
        let removedForwards = forwards.filter {
            $0.endpointId == endpoint.id
        }
        for forward in removedForwards where forward.existing {
            removed.append(contentsOf: forward.fieldIds.values)
        }
        forwards.removeAll { $0.endpointId == endpoint.id }
        for item in endpoints where item.connectVia == endpoint.id {
            item.connectVia = ""
        }
        sync()
    }

    public func moveEndpoint(_ endpoint: SshEndpointDraft, offset: Int) {
        guard let from = endpoints.firstIndex(where: { $0.id == endpoint.id })
        else { return }
        let to = from + offset
        guard to >= 0, to < endpoints.count else { return }
        endpoints.remove(at: from)
        endpoints.insert(endpoint, at: to)
        sync()
    }

    public func addForward() {
        let forward = SshForwardDraft(
            id: structuredId("ssh_forward", salt: forwards.count))
        forward.endpointId = endpoints.first?.id ?? ""
        forwards.append(forward)
        sync()
    }

    public func removeForward(_ forward: SshForwardDraft) {
        forwards.removeAll { $0.id == forward.id }
        if forward.existing {
            removed.append(contentsOf: forward.fieldIds.values)
        }
        sync()
    }
}

/// Encodes a list of fields as the JSON array `EntryDraft.customFields`
/// carries — the `jsonEncode(updates)` step in the Dart editors.
public func encodeItemFields(_ fields: [ItemField]) -> String {
    guard let data = try? JSONEncoder().encode(fields) else { return "[]" }
    return String(decoding: data, as: UTF8.self)
}
