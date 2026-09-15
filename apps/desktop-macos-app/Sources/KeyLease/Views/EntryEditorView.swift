import SwiftUI

import KeyLeaseCore

/// The right-hand workspace for both new and edited items — the port of
/// `entry_editor.dart`'s `EntryEditorPane` + `_EntryForm`.
///
/// The draft lives on `VaultController` and survives a failed save: a
/// rejected request leaves every typed value in place so the user can fix
/// one field and retry.
struct EntryEditorView: View {
    let app: AppController

    var body: some View {
        if let draft = app.vault.activeDraft {
            EditorBody(app: app, draft: draft)
                .id(draft.entryId ?? "new-\(ObjectIdentifier(draft).hashValue)")
        }
    }
}

private struct EditorBody: View {
    let app: AppController
    @Bindable var draft: EntryDraft

    /// Per-template-field text state — the Dart `_templateFields` map.
    @State private var edits: [String: TemplateFieldEdit] = [:]
    @State private var errors: [String: String] = [:]
    @State private var failure: UserMessage?
    @State private var failureAction: (() -> Void)?
    @State private var saving = false
    @State private var passwordRevealed = false
    @State private var passwordCopied = false
    @State private var totpScanning = false
    @State private var generatorSettings = false
    @State private var environment: EnvironmentTemplateState?
    @State private var ssh: SshTemplateState?

    private var vault: VaultController { app.vault }
    private var agentDriven: Bool {
        draft.isNew && vault.creationMode == .agentDriven
    }
    private var isDeveloperTemplate: Bool {
        draft.kind == "core.environment" || draft.kind == "core.ssh_server"
    }

    /// `_template` — the kind's definition, or the fallback when the daemon
    /// predates `templates_list`.
    private var template: ItemKindDefinition? {
        vault.templates.first { $0.kind == draft.kind }
            ?? fallbackTemplate(draft.kind)
    }

    private var customTemplateFields: [ItemFieldDefinition] {
        (template?.fields ?? []).filter {
            standardTemplateField($0) == nil
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    if let failure {
                        MessageBanner(
                            message: failure,
                            actionLabel: failureAction == nil
                                ? nil : "Fix",
                            onAction: failureAction,
                            onDismiss: {
                                self.failure = nil
                                failureAction = nil
                            })
                    }

                    if draft.isNew, agentDriven, let agentDraft = vault
                        .agentCreationDraft
                    {
                        AgentCreationPane(app: app, draft: agentDraft)
                    } else {
                        form
                    }
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .onAppear {
            if draft.isNew, vault.creationMode == .agentDriven,
                vault.agentCreationDraft == nil
            {
                Task { await vault.useAgentCreation() }
            }
            hydrateTemplateFields()
            ensureTemplateStates()
        }
        // `entries_view` arrives asynchronously for the entry being edited
        // (which may differ from the selected row).
        .onChange(of: vault.entryViews) {
            hydrateTemplateFields()
            ensureTemplateStates()
        }
        .sheet(isPresented: $generatorSettings) {
            PasswordSettingsSheet(app: app)
        }
    }

    // MARK: Header

    private var header: some View {
        HStack {
            Text(draft.isNew ? "New item" : "Edit item")
                .font(.headline)
            Spacer()
            if draft.isNew {
                Button {
                    Task { await toggleMode() }
                } label: {
                    Label(
                        agentDriven ? "Fill manually" : "Use Agent",
                        systemImage: agentDriven
                            ? "square.and.pencil" : "sparkles")
                }
                .controlSize(.small)
            }
            Button("Cancel") { Task { await cancel() } }
                .disabled(saving)
            if !agentDriven {
                Button(saving ? "Saving…" : "Save") {
                    Task { await save() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(saving)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(12)
    }

    // MARK: Form

    @ViewBuilder private var form: some View {
        if draft.isNew {
            templatePicker
            GuidanceCard(
                title: "About this template",
                summary: guidanceForTemplate(
                    draft.kind, label: template?.label).summary,
                useWhen: guidanceForTemplate(
                    draft.kind, label: template?.label).useWhen)
        }

        if !draft.isAgentContent {
            groupPicker
        }

        labeledField("Title", key: "title") {
            TextField("", text: $draft.title)
                .textFieldStyle(.roundedBorder)
        }

        Toggle("Favorite", isOn: $draft.favorite)

        dynamicTemplateFields

        if isDeveloperTemplate {
            if draft.kind == "core.environment", let environment {
                EnvironmentTemplateEditor(
                    app: app, state: environment, draft: draft)
            } else if draft.kind == "core.ssh_server", let ssh {
                SshTemplateEditor(app: app, state: ssh, draft: draft)
            }
        }

        if template?.markdownNotes == true || draft.isAgentContent {
            SectionLabel(title: draft.isAgentContent
                ? "Agent content" : "Notes")
            TextEditor(text: $draft.notes)
                .font(.body)
                .frame(
                    minHeight: draft.isAgentContent
                        || draft.kind == "core.secure_note" ? 160 : 72,
                    maxHeight: 320)
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .stroke(Color.primary.opacity(0.15)))
            Text(notesLabel).font(.caption).foregroundStyle(.secondary)
        }

        if draft.isAgentContent {
            agentContentExtras
        }

        if template == nil && !draft.isAgentContent {
            SectionLabel(title: "Custom fields (JSON array, optional)")
            Text("Typed fields keep their protected and sensitivity flags.")
                .font(.caption).foregroundStyle(.secondary)
            TextEditor(text: $draft.customFields)
                .font(.body.monospaced())
                .frame(minHeight: 48, maxHeight: 140)
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .stroke(Color.primary.opacity(0.15)))
            if let message = errors["custom_fields"] {
                Text(message).font(.caption).foregroundStyle(.red)
            }
        }

        if let message = errors["sections"] {
            Text(message).font(.caption).foregroundStyle(.red)
        }
        ForEach(draft.structuredErrors.keys.sorted(), id: \.self) { key in
            if let message = draft.structuredErrors[key] {
                Text(message).font(.caption).foregroundStyle(.red)
            }
        }
    }

    private var notesLabel: String {
        draft.isAgentContent
            ? "Markdown body"
            : draft.kind == "core.secure_note"
                ? "Secure note (Markdown)"
                : draft.isNew
                    ? "Notes (Markdown)"
                    : "New notes (blank keeps current)"
    }

    // MARK: Template + group pickers

    private var templatePicker: some View {
        VStack(alignment: .leading, spacing: 6) {
            SectionLabel(title: "Template")
            Picker(
                "",
                selection: Binding(
                    get: { draft.kind },
                    set: { changeTemplate($0) })
            ) {
                let templates = vault.templates
                if templates.isEmpty {
                    Text("Login").tag("core.login")
                    Text("API credential").tag("core.api_credential")
                    Text("Secure note").tag("core.secure_note")
                    Text("Generic item").tag("core.generic")
                } else {
                    ForEach(
                        Dictionary(grouping: templates, by: templateSection)
                            .sorted(by: { $0.key < $1.key }), id: \.key
                    ) { section, group in
                        Section(section) {
                            ForEach(group, id: \.kind) { template in
                                Text(
                                    template.kind == "core.server"
                                        ? "Server (generic)"
                                        : template.label)
                                    .tag(template.kind)
                            }
                        }
                    }
                }
            }
            .labelsHidden()
        }
    }

    private var groupPicker: some View {
        VStack(alignment: .leading, spacing: 6) {
            SectionLabel(title: "Group")
            Picker(
                "",
                selection: Binding(
                    get: { draft.groupId ?? "" },
                    set: { draft.groupId = $0.isEmpty ? nil : $0 })
            ) {
                Text("Choose a group").tag("")
                ForEach(vault.orderedGroups) { group in
                    Text(groupBreadcrumb(group)).tag(group.id)
                }
            }
            .labelsHidden()
            if let message = errors["group"] {
                Text(message).font(.caption).foregroundStyle(.red)
            }
        }
    }

    /// `_groupBreadcrumb` — `Parent / Child` labels so nested groups stay
    /// legible in a flat picker.
    private func groupBreadcrumb(_ group: VaultGroup) -> String {
        var names = [group.name]
        var visited: Set<String> = [group.id]
        var parentId = group.parentId
        while let id = parentId, visited.insert(id).inserted {
            guard let parent = vault.groups.first(where: { $0.id == id })
            else { break }
            names.insert(parent.name, at: 0)
            parentId = parent.parentId
        }
        return names.joined(separator: " / ")
    }

    // MARK: Dynamic template fields

    /// Fields grouped by consecutive `section` labels — the Dart editor
    /// inserts a `SectionLabel` whenever the section name changes.
    private var templateFieldGroups: [(section: String,
        fields: [ItemFieldDefinition])]
    {
        var result: [(String, [ItemFieldDefinition])] = []
        for field in template?.fields ?? [] {
            if result.last?.0 == field.section {
                result[result.count - 1].1.append(field)
            } else {
                result.append((field.section, [field]))
            }
        }
        return result
    }

    @ViewBuilder private var dynamicTemplateFields: some View {
        ForEach(Array(templateFieldGroups.enumerated()), id: \.offset) {
            _, group in
            SectionLabel(title: group.section).padding(.top, 6)
            ForEach(group.fields, id: \.key) { field in
                templateField(field)
            }
        }
    }

    @ViewBuilder
    private func templateField(_ field: ItemFieldDefinition) -> some View {
        let storedProtected = !draft.isNew
            && templateFieldHasStoredValue(
                field, detail: draft.entryId.flatMap { vault.entryViews[$0] })
        let label = storedProtected
            ? "\(field.label) (blank keeps current)" : field.label
        switch standardTemplateField(field) {
        case .username:
            labeledField(label, key: "username") {
                TextField("", text: $draft.username)
                    .textFieldStyle(.roundedBorder)
            }
        case .password:
            labeledField(label, key: "password") {
                HStack {
                    secretOrPlain(
                        revealed: passwordRevealed,
                        text: $draft.password)
                    iconButton(
                        passwordRevealed ? "eye.slash" : "eye",
                        help: passwordRevealed
                            ? "Hide password" : "Reveal password")
                    {
                        passwordRevealed.toggle()
                    }
                    iconButton(
                        passwordCopied ? "checkmark" : "sparkles",
                        help: passwordCopied
                            ? "Password generated and copied"
                            : "Generate and copy password")
                    {
                        Task { await generate() }
                    }
                    iconButton(
                        "gearshape", help: "Password generator settings")
                    {
                        generatorSettings = true
                    }
                }
            }
        case .otp:
            labeledField(
                label, key: "otp",
                description:
                    "Base32 secret or otpauth:// URI. Scan the screen or "
                    + "choose an image."
            ) {
                HStack {
                    TextField("", text: $draft.totp)
                        .textFieldStyle(.roundedBorder)
                    iconButton(
                        totpScanning ? "hourglass" : "qrcode.viewfinder",
                        help: "Scan TOTP QR code from screen")
                    {
                        Task { await scanTotp(.screen) }
                    }
                    iconButton(
                        "photo", help: "Choose TOTP QR code image")
                    {
                        Task { await scanTotp(.image) }
                    }
                }
            }
        case .primaryUrl:
            labeledField(label, key: "url") {
                TextField("", text: $draft.url)
                    .textFieldStyle(.roundedBorder)
            }
        case nil:
            customTemplateField(field, label: label)
        }
    }

    @ViewBuilder
    private func customTemplateField(
        _ field: ItemFieldDefinition, label: String
    ) -> some View {
        let binding = Binding(
            get: { edits[field.key]?.text ?? "" },
            set: { text in
                var edit = edits[field.key] ?? TemplateFieldEdit()
                edit.text = text
                edits[field.key] = edit
                syncTemplatePayload()
            })
        switch field.valueType {
        case "boolean":
            Toggle(
                label,
                isOn: Binding(
                    get: { binding.wrappedValue.lowercased() == "true" },
                    set: { binding.wrappedValue = $0 ? "true" : "false" }))
        default:
            labeledField(
                label, key: "template_\(field.key)",
                description: fieldDescription(field)
            ) {
                if field.protected {
                    SecureField("", text: binding)
                        .textFieldStyle(.roundedBorder)
                } else {
                    TextField("", text: binding)
                        .textFieldStyle(.roundedBorder)
                }
            }
        }
    }

    private func fieldDescription(_ field: ItemFieldDefinition) -> String? {
        switch field.valueType {
        case "month_year": "MM/YYYY"
        case "date": "YYYY-MM-DD"
        case "totp":
            "Base32 secret or otpauth:// URI. Scan the screen or choose an "
                + "image."
        case "address": "Street and address details"
        default: nil
        }
    }

    @ViewBuilder
    private func labeledField<Content: View>(
        _ label: String, key: String, description: String? = nil,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.callout)
            content()
            if let description {
                Text(description)
                    .font(.caption).foregroundStyle(.secondary)
            }
            if let message = errors[key] ?? errors["template_\(key)"] {
                Text(message).font(.caption).foregroundStyle(.red)
            }
        }
    }

    private func iconButton(
        _ icon: String, help: String, action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            Image(systemName: icon)
        }
        .buttonStyle(.borderless)
        .help(help)
    }

    @ViewBuilder
    private func secretOrPlain(
        revealed: Bool, text: Binding<String>
    ) -> some View {
        if revealed {
            TextField("", text: text)
                .textFieldStyle(.roundedBorder)
        } else {
            SecureField("", text: text)
                .textFieldStyle(.roundedBorder)
        }
    }

    // MARK: Agent-content extras

    @ViewBuilder private var agentContentExtras: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Tags").font(.callout)
            TextField("Comma-separated", text: $draft.tags)
                .textFieldStyle(.roundedBorder)
        }
        VStack(alignment: .leading, spacing: 4) {
            Text("Project (optional)").font(.callout)
            Picker(
                "",
                selection: Binding(
                    get: { draft.projectSlug ?? "" },
                    set: {
                        draft.projectSlug = $0.isEmpty ? nil : $0
                    })
            ) {
                Text("No project").tag("")
                ForEach(vault.projects, id: \.slug) { project in
                    Text(project.name).tag(project.slug)
                }
            }
            .labelsHidden()
        }
        if draft.isNew {
            VStack(alignment: .leading, spacing: 4) {
                Text("Agent access").font(.callout)
                Picker(
                    "",
                    selection: Binding(
                        get: { draft.agentAccess },
                        set: { draft.agentAccess = $0 })
                ) {
                    Text("None").tag("none")
                    Text("Read").tag("read")
                    Text("Read and write").tag("read_write")
                }
                .labelsHidden()
            }
        }
    }

    // MARK: Template-field hydration + payload

    /// `_hydrateTemplateFields` — once `entries_view` arrives, fill in
    /// values the user has not touched. Protected fields stay empty.
    private func hydrateTemplateFields() {
        guard let entryId = draft.entryId,
            let detail = vault.entryViews[entryId]
        else { return }
        for definition in customTemplateFields
        where edits[definition.key] == nil {
            guard let field = detail.fields.first(where: {
                $0.key == definition.key
                    || (!definition.semanticRole.isEmpty
                        && $0.semanticRole == definition.semanticRole)
            }) else { continue }
            let original = field.protected ? "" : field.displayValue
            edits[definition.key] = TemplateFieldEdit(
                id: field.id, original: original, text: original)
        }
    }

    /// `_templateFieldPayload` — writes the custom-fields JSON onto the
    /// draft so the typed edits become `field_updates`.
    private func syncTemplatePayload() {
        guard !isDeveloperTemplate else { return }
        draft.customFields = templateFieldPayload(
            definitions: template?.fields ?? [],
            edits: edits, isNew: draft.isNew, kind: draft.kind)
            ?? draft.customFields
    }

    private func ensureTemplateStates() {
        if draft.kind == "core.environment" {
            if environment == nil {
                environment = EnvironmentTemplateState(draft: draft)
            }
            if let entryId = draft.entryId {
                _ = environment?.hydrate(detail: vault.entryViews[entryId])
            }
        } else if draft.kind == "core.ssh_server" {
            if ssh == nil {
                ssh = SshTemplateState(draft: draft)
            }
            if let entryId = draft.entryId {
                _ = ssh?.hydrate(detail: vault.entryViews[entryId])
            }
        }
    }

    // MARK: Actions

    /// `_changeTemplate` — switching kind resets the structured editors
    /// and per-field edits so stale payloads cannot leak across kinds.
    private func changeTemplate(_ kind: String) {
        guard kind != draft.kind else { return }
        draft.kind = kind
        draft.customFields = ""
        draft.sections = ""
        draft.removeFieldIds = []
        draft.structuredErrors = [:]
        edits = [:]
        environment = nil
        ssh = nil
        ensureTemplateStates()
    }

    private func toggleMode() async {
        if vault.creationMode == .agentDriven {
            vault.useManualCreation()
        } else {
            try? await vault.useAgentCreation()
        }
    }

    private func save() async {
        environment?.sync()
        ssh?.sync()
        syncTemplatePayload()
        var validation = draft.validate()
        for field in template?.fields ?? [] {
            let text: String
            switch standardTemplateField(field) {
            case .username: text = draft.username
            case .password: text = draft.password
            case .otp: text = draft.totp
            case .primaryUrl: text = draft.url
            case nil: text = edits[field.key]?.text ?? ""
            }
            if let message = validateTemplateField(field, text: text) {
                validation["template_\(field.key)"] = message
            }
        }
        guard validation.isEmpty else {
            errors = validation
            return
        }
        errors = [:]
        failure = nil
        failureAction = nil
        saving = true
        defer { saving = false }
        do {
            let savedId = try await vault.save(draft)
            var bindingFailure: Error?
            if let savedId {
                do {
                    for endpointId in draft.sshBindingsToClear {
                        try app.setSshKeyBinding(savedId, endpointId, nil)
                    }
                    for (endpointId, path) in draft.sshKeyBindings {
                        try app.setSshKeyBinding(savedId, endpointId, path)
                    }
                } catch {
                    bindingFailure = error
                }
            }
            if bindingFailure != nil {
                failure = UserMessage(
                    title: "Item saved, private key not bound",
                    detail: "Select the private key again from the saved "
                        + "item on this device.")
            }
            vault.closeEditor()
        } catch {
            // The draft is untouched: the user keeps every typed value.
            failure = UserMessage(error)
        }
    }

    private func cancel() async {
        syncTemplatePayload()
        let agentDirty = vault.creationMode == .agentDriven
            && (vault.agentCreationDraft?.isDirty ?? false)
        if draft.isDirty || agentDirty {
            let discard = confirmAction(
                title: "Discard changes?",
                message: "This item has unsaved changes. Discarding cannot "
                    + "be undone.",
                confirmLabel: "Discard",
                destructive: true)
            guard discard else { return }
        }
        vault.closeEditor()
    }

    private func generate() async {
        do {
            let settings = app.passwordGeneratorSettings
            guard let generated = try await vault.generatePassword(settings)
            else { return }
            draft.password = generated
            passwordCopied = app.copySensitive(generated)
            if passwordCopied {
                Task {
                    try? await Task.sleep(for: .seconds(1))
                    passwordCopied = false
                }
            }
        } catch {
            failure = UserMessage(error)
        }
    }

    private enum TotpScanSource { case screen, image }

    private func scanTotp(_ source: TotpScanSource) async {
        guard !totpScanning else { return }
        totpScanning = true
        failure = nil
        failureAction = nil
        defer { totpScanning = false }
        switch source {
        case .screen:
            #if canImport(ScreenCaptureKit)
                let result = await app.host.captureScreenTotp()
                if let uri = result.uri {
                    draft.totp = uri
                } else if result.needsPermission {
                    failure = UserMessage(
                        title: "Screen recording permission needed",
                        detail: "Grant KeyLease screen recording to scan a "
                            + "QR code from the screen.")
                    failureAction = { app.host.openScreenRecordingSettings() }
                }
            #else
                failure = UserMessage(
                    title: "Screen capture unavailable",
                    detail: "Use an image file instead.")
            #endif
        case .image:
            guard let url = await app.host.pickFile(
                title: "Choose a QR code image",
                message: "Select an image containing a TOTP QR code.")
            else { return }
            if let uri = await app.host.scanTotpQrFromImage(url) {
                draft.totp = uri
            } else {
                failure = UserMessage(
                    title: "No TOTP QR code found",
                    detail: "The image did not contain an otpauth:// code.")
            }
        }
    }
}
