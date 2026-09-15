import SwiftUI

import KeyLeaseCore

// MARK: - Environment editor (`EnvironmentTemplateEditor`)

/// The `core.environment` structured editor: project/scope/source metadata,
/// a variable table, and a "paste .env" mode that parses bulk input.
struct EnvironmentTemplateEditor: View {
    let app: AppController
    @Bindable var state: EnvironmentTemplateState
    let draft: EntryDraft

    @State private var pasteMode = false
    @State private var pasteText = ""
    @State private var parseResult: EnvParseResult?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Project").font(.callout)
                TextField(
                    "my-service",
                    text: $state.project)
                    .textFieldStyle(.roundedBorder)
                if let error = draft.structuredErrors["environment_project"] {
                    Text(error).font(.caption).foregroundStyle(.red)
                }
            }

            Picker(
                "Environment",
                selection: $state.scope)
            {
                Text("Local").tag("local")
                Text("Development").tag("development")
                Text("Test").tag("test")
                Text("Staging").tag("staging")
                Text("Production").tag("production")
                Text("Other").tag("other")
            }

            Picker("Source", selection: $state.source) {
                Text(".env").tag("dotenv")
                Text("GitHub Actions").tag("github_actions")
                Text("GitLab CI/CD").tag("gitlab_ci")
                Text("Docker / Compose").tag("docker")
                Text("Kubernetes").tag("kubernetes")
                Text("Other").tag("other")
            }

            GuidanceCard(
                title: "Environment variables",
                summary: "Store the configuration a service or deploy "
                    + "target expects, as a normalized .env file.",
                useWhen: "Enter variables one by one, or paste .env "
                    + "content and review the parsed fields before saving.")

            HStack {
                SectionLabel(title: "Variables")
                Spacer()
                Picker(
                    "",
                    selection: $pasteMode)
                {
                    Text("Fields").tag(false)
                    Text("Paste .env").tag(true)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 180)
            }

            if pasteMode {
                pastePane
            } else {
                variablesPane
            }
        }
    }

    private var pastePane: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(".env content").font(.callout)
            TextEditor(text: $pasteText)
                .font(.body.monospaced())
                .frame(minHeight: 140, maxHeight: 320)
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .stroke(Color.primary.opacity(0.15)))
                .onChange(of: pasteText) {
                    parseResult = parseDotEnv(pasteText)
                }
            if let parseResult {
                Text(
                    parseResult.valid
                        ? "\(parseResult.variables.count) variables · "
                            + "\(parseResult.ignoredComments) comments and "
                            + "\(parseResult.ignoredBlankLines) blank lines "
                            + "will be normalized."
                        : parseResult.issues.map {
                            "Line \($0.line): \($0.message)"
                        }.joined(separator: "\n"))
                    .font(.caption)
                    .foregroundStyle(
                        parseResult.valid ? .secondary : .red)
            }
            HStack {
                Spacer()
                Button("Replace all") {
                    applyPaste(replace: true)
                }
                .disabled(parseResult?.valid == false)
                Button("Merge") {
                    applyPaste(replace: false)
                }
                .buttonStyle(.borderedProminent)
                .disabled(parseResult?.valid == false)
            }
        }
    }

    private var variablesPane: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let error = draft.structuredErrors["environment_variables"] {
                Text(error).font(.caption).foregroundStyle(.red)
            }
            ForEach(state.variables, id: \.id) { variable in
                EnvironmentVariableRow(
                    variable: variable,
                    canMoveUp: state.variables.first?.id != variable.id,
                    canMoveDown: state.variables.last?.id != variable.id,
                    onChanged: { state.sync() },
                    onRemove: { state.removeVariable(variable) },
                    onMove: { offset in state.move(variable, offset: offset) })
            }
            Button("Add variable") { state.addVariable() }
                .controlSize(.small)
        }
    }

    private func applyPaste(replace: Bool) {
        guard let parsed = parseResult else { return }
        if replace, !state.variables.isEmpty {
            guard
                confirmAction(
                    title: "Replace all variables?",
                    message: "\(state.variables.count) existing variables "
                        + "will be removed or replaced.",
                    confirmLabel: "Replace all",
                    destructive: true)
            else { return }
        }
        state.applyPaste(parsed, replace: replace)
        pasteText = ""
        parseResult = nil
        pasteMode = false
    }
}

/// One row of the environment table — key, value, secret flag, reorder and
/// remove controls.
private struct EnvironmentVariableRow: View {
    @Bindable var variable: EnvVariableDraft
    let canMoveUp: Bool
    let canMoveDown: Bool
    let onChanged: () -> Void
    let onRemove: () -> Void
    let onMove: (Int) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                TextField("NAME", text: $variable.key)
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
                    .frame(width: 220)
                    .onChange(of: variable.key) { onChanged() }
                Group {
                    if variable.secret {
                        SecureField("value", text: $variable.value)
                    } else {
                        TextField("value", text: $variable.value)
                    }
                }
                .textFieldStyle(.roundedBorder)
                .font(.body.monospaced())
                .onChange(of: variable.value) { onChanged() }
                Toggle("Secret", isOn: $variable.secret)
                    .toggleStyle(.checkbox)
                    .onChange(of: variable.secret) { onChanged() }
                IconAction(label: "Move up", icon: "arrow.up") {
                    onMove(-1)
                }
                .opacity(canMoveUp ? 1 : 0.3)
                .disabled(!canMoveUp)
                IconAction(label: "Move down", icon: "arrow.down") {
                    onMove(1)
                }
                .opacity(canMoveDown ? 1 : 0.3)
                .disabled(!canMoveDown)
                IconAction(label: "Remove", icon: "trash", danger: true) {
                    onRemove()
                }
            }
            if variable.hasStoredValue {
                Text("Stored; blank keeps current.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(8)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color.primary.opacity(0.1)))
    }
}

// MARK: - SSH server editor (`SshServerTemplateEditor`)

/// The `core.ssh_server` structured editor: endpoint cards with
/// authentication options plus tunnel rows.
struct SshTemplateEditor: View {
    let app: AppController
    @Bindable var state: SshTemplateState
    let draft: EntryDraft
    @State private var keyCandidates: [String] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            GuidanceCard(
                title: "What is an SSH template?",
                summary: "Describe the servers you reach over SSH so the "
                    + "app can generate a ready-to-use ssh_config entry.",
                useWhen: "Store host, alias, authentication mode and "
                    + "optional jump hosts. Private keys stay on this "
                    + "device; secrets stay in the vault.")

            HStack {
                SectionLabel(title: "SSH servers")
                Spacer()
                Button("Add server") { state.addEndpoint() }
                    .controlSize(.small)
            }
            if let error = draft.structuredErrors["ssh_endpoints"] {
                Text(error).font(.caption).foregroundStyle(.red)
            }
            ForEach(state.endpoints, id: \.id) { endpoint in
                SshEndpointCard(
                    app: app,
                    endpoint: endpoint,
                    endpoints: state.endpoints,
                    errors: state.errorsForEndpoint(endpoint),
                    keyCandidates: keyCandidates,
                    draft: draft,
                    onChanged: { state.sync() },
                    onRemove: { state.removeEndpoint(endpoint) },
                    onMove: { offset in
                        state.moveEndpoint(endpoint, offset: offset)
                    })
            }

            GuidanceCard(
                title: "What is an SSH tunnel?",
                summary: "A tunnel securely forwards a local or remote "
                    + "port through one of the endpoints above.",
                useWhen: "Use local forwarding for a remote database or "
                    + "web service, remote forwarding to expose a local "
                    + "service remotely, or dynamic forwarding for a SOCKS "
                    + "proxy.")

            HStack {
                SectionLabel(title: "SSH tunnels")
                Spacer()
                Button("Add tunnel") { state.addForward() }
                    .controlSize(.small)
                    .disabled(state.endpoints.isEmpty)
            }
            if let error = draft.structuredErrors["ssh_forwards"] {
                Text(error).font(.caption).foregroundStyle(.red)
            }
            ForEach(state.forwards, id: \.id) { forward in
                SshForwardCard(
                    forward: forward,
                    endpoints: state.endpoints,
                    onChanged: { state.sync() },
                    onRemove: { state.removeForward(forward) })
            }
        }
        .onAppear {
            if keyCandidates.isEmpty {
                keyCandidates = app.host.discoverSshPrivateKeys()
            }
        }
    }
}

private struct SshEndpointCard: View {
    let app: AppController
    @Bindable var endpoint: SshEndpointDraft
    let endpoints: [SshEndpointDraft]
    let errors: [String: String]
    let keyCandidates: [String]
    let draft: EntryDraft
    let onChanged: () -> Void
    let onRemove: () -> Void
    let onMove: (Int) -> Void

    /// The per-device binding for this endpoint, kept on the draft until
    /// save — never part of the vault payload.
    private var binding: Binding<String> {
        Binding(
            get: { draft.sshKeyBindings[endpoint.id] ?? "" },
            set: { value in
                if value.isEmpty {
                    draft.sshKeyBindings.removeValue(forKey: endpoint.id)
                } else {
                    draft.sshKeyBindings[endpoint.id] = value
                }
            })
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(endpoint.name.isEmpty ? "SSH server" : endpoint.name)
                Spacer()
                IconAction(label: "Move up", icon: "arrow.up") { onMove(-1) }
                IconAction(label: "Move down", icon: "arrow.down") {
                    onMove(1)
                }
                IconAction(label: "Remove", icon: "trash", danger: true) {
                    onRemove()
                }
            }

            field("Display name", text: $endpoint.name, error: errors["name"])
            field(
                "SSH alias", text: $endpoint.alias, error: errors["alias"])
            HStack(spacing: 8) {
                field("Host / IP", text: $endpoint.host,
                      error: errors["host"])
                field("Port", text: $endpoint.port, error: errors["port"])
                    .frame(width: 90)
            }
            field("Username", text: $endpoint.username)

            Picker(
                "Connect via",
                selection: Binding(
                    get: { endpoint.connectVia },
                    set: { endpoint.connectVia = $0; onChanged() })
            ) {
                Text("Direct connection").tag("")
                ForEach(
                    endpoints.filter { $0.id != endpoint.id }, id: \.id
                ) { candidate in
                    Text(
                        candidate.name.isEmpty
                            ? candidate.alias : candidate.name)
                        .tag(candidate.id)
                }
            }
            if let error = errors["connectVia"] {
                Text(error).font(.caption).foregroundStyle(.red)
            }

            Picker(
                "Authentication",
                selection: Binding(
                    get: { endpoint.authMode },
                    set: { changeAuthMode($0) })
            ) {
                Text("SSH agent / system default").tag("ssh_agent")
                Text("Private key").tag("private_key")
                Text("Password").tag("password")
            }

            if endpoint.authMode == "password" {
                secretField(
                    "SSH password", text: $endpoint.password,
                    error: errors["password"],
                    stored: endpoint.storedRoles.contains("ssh_password"))
            }

            if endpoint.authMode == "private_key" {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Private key path on this device").font(.callout)
                    TextField("", text: binding)
                        .textFieldStyle(.roundedBorder)
                    Text("Saved locally only; never synced into the vault.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if !keyCandidates.isEmpty {
                    Picker(
                        "Private key on this device",
                        selection: binding)
                    {
                        Text("Select a private key").tag("")
                        ForEach(keyCandidates, id: \.self) { path in
                            Text(path).tag(path)
                        }
                    }
                    .labelsHidden()
                }
                HStack {
                    Spacer()
                    Button("Choose file…") {
                        if let url = app.host.pickFile(
                            title: "Choose a private key",
                            message: "Select the SSH private key to bind.",
                            directory: FileManager.default.homeDirectoryForCurrentUser
                                .appendingPathComponent(".ssh"))
                        {
                            binding.wrappedValue = url.path
                        }
                    }
                    .controlSize(.small)
                }
                secretField(
                    "Key passphrase (optional)", text: $endpoint.passphrase,
                    stored: endpoint.storedRoles
                        .contains("ssh_private_key_passphrase"))
            }

            Picker(
                "Sudo",
                selection: Binding(
                    get: { endpoint.sudoMode },
                    set: { endpoint.sudoMode = $0; onChanged() })
            ) {
                Text("None").tag("none")
                Text("Passwordless").tag("passwordless")
                Text("Same as SSH password").tag("same_as_ssh_password")
                Text("Separate password").tag("separate_password")
            }
            if let error = errors["sudo"] {
                Text(error).font(.caption).foregroundStyle(.red)
            }
            if endpoint.sudoMode == "separate_password" {
                secretField(
                    "Sudo password", text: $endpoint.sudoPassword,
                    error: errors["sudoPassword"],
                    stored: endpoint.storedRoles.contains("ssh_sudo_password"))
            }

            field(
                "Host key fingerprint (optional)",
                text: $endpoint.fingerprint,
                error: errors["fingerprint"])
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 9)
                .stroke(Color.primary.opacity(0.12)))
    }

    /// Changing away from `private_key` clears the device binding after
    /// save; entering it keeps any existing binding.
    private func changeAuthMode(_ mode: String) {
        if endpoint.authMode == "private_key", mode != "private_key" {
            draft.sshKeyBindings.removeValue(forKey: endpoint.id)
            draft.sshBindingsToClear = Array(
                Set(draft.sshBindingsToClear).union([endpoint.id]))
        } else if mode == "private_key" {
            draft.sshBindingsToClear.removeAll { $0 == endpoint.id }
        }
        endpoint.authMode = mode
        onChanged()
    }

    private func field(
        _ label: String, text: Binding<String>, error: String? = nil
    ) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.callout)
            TextField("", text: text)
                .textFieldStyle(.roundedBorder)
                .onChange(of: text.wrappedValue) { onChanged() }
            if let error {
                Text(error).font(.caption).foregroundStyle(.red)
            }
        }
    }

    private func secretField(
        _ label: String, text: Binding<String>, error: String? = nil,
        stored: Bool = false
    ) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.callout)
            SecureField("", text: text)
                .textFieldStyle(.roundedBorder)
                .onChange(of: text.wrappedValue) { onChanged() }
            if stored {
                Text("Stored; blank keeps current.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if let error {
                Text(error).font(.caption).foregroundStyle(.red)
            }
        }
    }
}

private struct SshForwardCard: View {
    @Bindable var forward: SshForwardDraft
    let endpoints: [SshEndpointDraft]
    let onChanged: () -> Void
    let onRemove: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("SSH tunnel")
                Spacer()
                IconAction(label: "Remove", icon: "trash", danger: true) {
                    onRemove()
                }
            }
            Picker(
                "Server",
                selection: Binding(
                    get: { forward.endpointId },
                    set: { forward.endpointId = $0; onChanged() })
            ) {
                ForEach(endpoints, id: \.id) { endpoint in
                    Text(
                        endpoint.name.isEmpty
                            ? endpoint.alias : endpoint.name)
                        .tag(endpoint.id)
                }
            }
            Picker(
                "Type",
                selection: Binding(
                    get: { forward.type },
                    set: { forward.type = $0; onChanged() })
            ) {
                Text("Local").tag("local")
                Text("Remote").tag("remote")
                Text("Dynamic SOCKS").tag("dynamic")
            }
            HStack(spacing: 8) {
                portField("Bind address", text: $forward.bindAddress)
                portField("Bind port", text: $forward.bindPort)
                    .frame(width: 110)
            }
            if forward.type != "dynamic" {
                HStack(spacing: 8) {
                    portField(
                        "Destination host", text: $forward.destinationHost)
                    portField(
                        "Destination port", text: $forward.destinationPort)
                        .frame(width: 110)
                }
            }
            if ["0.0.0.0", "::", "*"].contains(
                forward.bindAddress.trimmingCharacters(in: .whitespaces))
            {
                Text("Warning: this bind address may expose the tunnel "
                    + "publicly.")
                    .font(.caption).foregroundStyle(.red)
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 9)
                .stroke(Color.primary.opacity(0.12)))
    }

    private func portField(_ label: String, text: Binding<String>)
        -> some View
    {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.callout)
            TextField("", text: text)
                .textFieldStyle(.roundedBorder)
                .onChange(of: text.wrappedValue) { onChanged() }
        }
    }
}

// MARK: - Detail (`_EnvironmentDetail` / `_SshDetail`)

/// The read-only structured sections on the detail page for
/// `core.environment` and `core.ssh_server`.
struct DeveloperTemplateDetail: View {
    let app: AppController
    let item: ItemMetadata
    let detail: EntryView

    var body: some View {
        if item.kind == "core.environment" {
            EnvironmentDetail(app: app, item: item, detail: detail)
        } else {
            SshDetail(app: app, item: item, detail: detail)
        }
    }
}

private struct EnvironmentDetail: View {
    let app: AppController
    let item: ItemMetadata
    let detail: EntryView
    @State private var query = ""
    @State private var error: UserMessage?

    /// Variables in section order — the Dart `_variables` getter.
    private var variables: [FieldView] {
        guard
            let section = detail.sections.first(where: {
                $0.semanticRole == "environment_variables"
            })
        else { return [] }
        let needle = query.trimmingCharacters(in: .whitespaces).lowercased()
        return section.fieldIds.compactMap { id in
            detail.fields.first(where: { $0.id == id })
        }.filter {
            needle.isEmpty || $0.label.lowercased().contains(needle)
        }
    }

    private var metadata: [String: FieldView] {
        guard
            let section = detail.sections.first(where: {
                $0.semanticRole == "environment_metadata"
            })
        else { return [:] }
        return fieldsByRole(section, detail)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionLabel(title: "Environment")
            FieldGroup {
                DetailRow(
                    label: "Project",
                    value: metadata["environment_project"]?.displayValue
                        ?? "")
                DetailRow(
                    label: "Environment",
                    value: metadata["environment_scope"]?.displayValue ?? "")
                DetailRow(
                    label: "Source",
                    value: metadata["environment_source"]?.displayValue ?? "")
            }
            if let error {
                MessageBanner(message: error, onDismiss: { self.error = nil })
            }
            HStack {
                SectionLabel(title: "Variables")
                Spacer()
                IconAction(label: "Copy .env file", icon: "doc.on.doc") {
                    Task { await copyDotEnv() }
                }
            }
            TextField("Find a variable", text: $query)
                .textFieldStyle(.roundedBorder)
            FieldGroup {
                ForEach(variables, id: \.id) { field in
                    if field.protected {
                        SecretRow(
                            label: field.label,
                            revealed: app.vault.revealedValue(
                                item.id, field.id),
                            hint: field.displayHint,
                            onReveal: {
                                _ = await app.vault.revealField(
                                    entryId: item.id, field: field)
                            },
                            onHide: {
                                app.vault.hideSecret(
                                    entryId: item.id, field: field.id)
                            },
                            onCopy: { copyField(field) })
                    } else {
                        DetailRow(
                            label: field.label, value: field.displayValue)
                        {
                            IconAction(
                                label: "Copy \(field.label)",
                                icon: "doc.on.doc")
                            {
                                copyField(field)
                            }
                        }
                    }
                }
            }
        }
    }

    private func copyField(_ field: FieldView) {
        Task {
            let value = field.protected
                ? (app.vault.revealedValue(item.id, field.id)
                    ?? await app.vault.fetchField(
                        entryId: item.id, field: field))
                : field.displayValue
            if let value, !value.isEmpty { _ = app.copySensitive(value) }
        }
    }

    /// `_copyDotEnv` — fetch every variable value and render a normalized
    /// `.env` onto the sensitive clipboard.
    private func copyDotEnv() async {
        guard
            let section = detail.sections.first(where: {
                $0.semanticRole == "environment_variables"
            }), !section.fieldIds.isEmpty
        else { return }
        let fields = section.fieldIds.compactMap { id in
            detail.fields.first(where: { $0.id == id })
        }
        let values = await app.vault.fetchFields(
            entryId: item.id, fields: fields)
        guard !values.isEmpty else {
            error = UserMessage(
                title: "Could not fetch variables",
                detail: "The daemon did not return any values.")
            return
        }
        let content = renderDotEnv(
            fields.map { ($0.label, values[$0.id] ?? "") })
        _ = app.copySensitive(content)
    }
}

private struct SshDetail: View {
    let app: AppController
    let item: ItemMetadata
    let detail: EntryView
    @State private var error: UserMessage?

    private var endpoints: [SshEndpointConfig] {
        detail.sections
            .filter { $0.semanticRole == "ssh_endpoint" }
            .map { section in
                let fields = fieldsByRole(section, detail)
                return SshEndpointConfig(
                    sectionId: section.id,
                    name: fields["ssh_display_name"]?.displayValue
                        ?? section.label,
                    alias: fields["ssh_alias"]?.displayValue ?? "",
                    host: fields["ssh_host"]?.displayValue ?? "",
                    port: Int(
                        fields["ssh_port"]?.displayValue ?? "") ?? 22,
                    username: fields["ssh_username"]?.displayValue ?? "",
                    authMode: fields["ssh_auth_mode"]?.displayValue
                        ?? "ssh_agent",
                    connectVia: fields["ssh_connect_via"]?.displayValue)
            }
    }

    private var forwards: [SshForwardConfig] {
        detail.sections
            .filter { $0.semanticRole == "ssh_forward" }
            .map { section in
                let fields = fieldsByRole(section, detail)
                return SshForwardConfig(
                    endpointId: fields["ssh_forward_endpoint"]?
                        .displayValue ?? "",
                    type: fields["ssh_forward_type"]?.displayValue
                        ?? "local",
                    bindAddress: fields["ssh_bind_address"]?.displayValue
                        ?? "127.0.0.1",
                    bindPort: Int(
                        fields["ssh_bind_port"]?.displayValue ?? "") ?? 0,
                    destinationHost: fields["ssh_destination_host"]?
                        .displayValue ?? "",
                    destinationPort: Int(
                        fields["ssh_destination_port"]?.displayValue
                            ?? "") ?? 0)
            }
    }

    private let secretRoles = [
        "ssh_password", "ssh_private_key_passphrase", "ssh_sudo_password",
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let error {
                MessageBanner(message: error, onDismiss: { self.error = nil })
            }
            HStack {
                SectionLabel(title: "SSH servers")
                Spacer()
                IconAction(label: "Copy SSH config", icon: "doc.on.doc") {
                    Task { await copyConfig() }
                }
            }
            ForEach(endpoints, id: \.sectionId) { endpoint in
                endpointCard(endpoint)
            }
            if !forwards.isEmpty {
                SectionLabel(title: "SSH tunnels")
                FieldGroup {
                    ForEach(forwards, id: \.endpointId) { forward in
                        let name = endpoints.first {
                            $0.sectionId == forward.endpointId
                        }?.name ?? forward.endpointId
                        DetailRow(
                            label: "\(forward.type.uppercased()) · \(name)",
                            value: forward.type == "dynamic"
                                ? "\(forward.bindAddress):\(forward.bindPort)"
                                : "\(forward.bindAddress):\(forward.bindPort) "
                                    + "→ \(forward.destinationHost):"
                                    + "\(forward.destinationPort)")
                    }
                }
            }
        }
    }

    private func endpointCard(_ endpoint: SshEndpointConfig) -> some View {
        let keyPath = app.sshKeyBinding(
            itemId: item.id, endpointId: endpoint.sectionId)
        let jumpName = endpoint.connectVia.flatMap { id in
            endpoints.first { $0.sectionId == id }?.name
        }
        let section = detail.sections.first {
            $0.id == endpoint.sectionId
        }
        let fields = section.map { fieldsByRole($0, detail) } ?? [:]
        return FieldGroup {
            DetailRow(
                label: endpoint.name,
                value: (endpoint.username.isEmpty
                    ? "" : "\(endpoint.username)@")
                    + "\(endpoint.host):\(endpoint.port)")
            {
                IconAction(label: "Copy SSH command", icon: "terminal") {
                    _ = app.copySensitive("ssh \(endpoint.alias)")
                }
            }
            DetailRow(label: "Alias", value: endpoint.alias)
            DetailRow(
                label: "Authentication",
                value: endpoint.authMode.replacingOccurrences(
                    of: "_", with: " "))
            if let jumpName {
                DetailRow(label: "Connect via", value: jumpName)
            }
            if endpoint.authMode == "private_key" {
                DetailRow(
                    label: "Private key on this device",
                    value: keyPath ?? "Not selected on this device")
                {
                    IconAction(
                        label: "Select private key", icon: "folder")
                    {
                        if let url = app.host.pickFile(
                            title: "Choose a private key",
                            message: "Select the SSH private key to bind.",
                            directory: FileManager.default
                                .homeDirectoryForCurrentUser
                                .appendingPathComponent(".ssh"))
                        {
                            try? app.setSshKeyBinding(
                                item.id, endpoint.sectionId, url.path)
                        }
                    }
                }
            }
            ForEach(secretRoles, id: \.self) { role in
                if let field = fields[role], field.hasValue {
                    SecretRow(
                        label: field.label,
                        revealed: app.vault.revealedValue(
                            item.id, field.id),
                        hint: field.displayHint,
                        onReveal: {
                            _ = await app.vault.revealField(
                                entryId: item.id, field: field)
                        },
                        onHide: {
                            app.vault.hideSecret(
                                entryId: item.id, field: field.id)
                        },
                        onCopy: {
                            Task {
                                let value = app.vault.revealedValue(
                                    item.id, field.id)
                                    ?? await app.vault.fetchField(
                                        entryId: item.id, field: field)
                                if let value, !value.isEmpty {
                                    _ = app.copySensitive(value)
                                }
                            }
                        })
                }
            }
        }
    }

    /// `_copyConfig` — resolve per-device private keys, then render the
    /// `ssh_config` fragment onto the sensitive clipboard.
    private func copyConfig() async {
        let current = Dictionary(
            uniqueKeysWithValues: endpoints.compactMap { endpoint in
                app.sshKeyBinding(
                    itemId: item.id, endpointId: endpoint.sectionId)
                    .map { (endpoint.sectionId, $0) }
            })
        let resolved = await resolveSshPrivateKeyPaths(
            endpoints: endpoints,
            currentPaths: current,
            discover: { await app.host.discoverSshPrivateKeys() },
            select: { _ in
                await app.host.pickFile(
                    title: "Choose a private key",
                    message: "Select the SSH private key to bind.",
                    directory: FileManager.default
                        .homeDirectoryForCurrentUser
                        .appendingPathComponent(".ssh"))?.path
            },
            onSelected: { endpoint, path in
                try? await app.setSshKeyBinding(
                    item.id, endpoint.sectionId, path)
            })
        guard let resolved else {
            error = UserMessage(
                title: "Private key needed",
                detail: "Choose a private key on this device before "
                    + "copying the SSH config.")
            return
        }
        do {
            let content = try renderSshConfig(
                endpoints: endpoints, forwards: forwards,
                privateKeyPaths: resolved)
            _ = app.copySensitive(content)
        } catch {
            self.error = UserMessage(error)
        }
    }
}
