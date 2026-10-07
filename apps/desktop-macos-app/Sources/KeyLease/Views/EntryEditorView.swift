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
    /// User-added fields (1Password-style) — hydrated from `entries_view`
    /// plus rows created in this session.
    @State private var customFields: [CustomFieldEdit] = []
    @State private var errors: [String: String] = [:]
    @State private var failure: UserMessage?
    @State private var failureAction: (() -> Void)?
    @State private var saving = false
    @State private var passwordRevealed = false
    @State private var passwordCopied = false
    @State private var totpScanning = false
    @State private var totpScanResult: TotpScanResult?
    @State private var generatorSettings = false
    @State private var environment: EnvironmentTemplateState?
    @State private var ssh: SshTemplateState?
    @State private var unlockPrompt = false
    @State private var unlockPassword = ""
    @State private var unlockBusy = false
    @State private var unlockError: String?

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
        ScrollView {
            VStack(alignment: .leading, spacing: KL.Space.xl) {
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
            .padding(KL.Space.xxl)
            .frame(maxWidth: 840, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .leading)
            .controlSize(.large)
        }
        .navigationTitle(draft.isNew ? "New item" : "Edit item")
        .toolbar { editorToolbar }
        .onAppear {
            if draft.isNew, vault.creationMode == .agentDriven,
                vault.agentCreationDraft == nil
            {
                Task { await vault.useAgentCreation() }
            }
            hydrateTemplateFields()
            hydrateCustomFields()
            ensureTemplateStates()
        }
        // `entries_view` arrives asynchronously for the entry being edited
        // (which may differ from the selected row).
        .onChange(of: vault.entryViews) {
            hydrateTemplateFields()
            hydrateCustomFields()
            ensureTemplateStates()
        }
        .sheet(isPresented: $generatorSettings) {
            PasswordSettingsSheet(app: app)
        }
        .sheet(isPresented: $unlockPrompt) {
            unlockSheet
        }
    }

    /// Inline re-unlock shown when a save hits `vault_locked` — the idle
    /// timeout can expire while a form sits open. Unlocking goes through
    /// `app.unlock`/`refresh`, which keeps `activeDraft` (only the locked
    /// branch calls `vault.clear()`), then the save retries itself.
    private var unlockSheet: some View {
        VStack(spacing: KL.Space.xl) {
            Label("Vault locked", systemImage: "lock.fill")
                .font(.headline)
            Text("Your session expired while this form was open. Unlock "
                + "to save without losing your changes.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            if let unlockError {
                Text(unlockError)
                    .font(.caption).foregroundStyle(KL.Colors.danger)
            }
            KLSecureField(label: "Master password", text: $unlockPassword) {
                Task { await unlockAndSave() }
            }
            HStack {
                KLButton(title: "Cancel") {
                    unlockPassword = ""
                    unlockError = nil
                    unlockPrompt = false
                }
                KLButton(
                    title: unlockBusy ? "Unlocking…" : "Unlock and save",
                    role: .primary
                ) {
                    Task { await unlockAndSave() }
                }
                .disabled(unlockPassword.isEmpty || unlockBusy)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(KL.Space.xxxxl)
        .frame(width: 380)
    }

    private func unlockAndSave() async {
        unlockBusy = true
        unlockError = nil
        defer { unlockBusy = false }
        let unlocked = await app.unlock(unlockPassword)
        unlockPassword = ""
        guard unlocked else {
            unlockError = app.unlockMessage?.title ?? "Unlock failed."
            return
        }
        unlockPrompt = false
        await save()
    }

    // MARK: Header

    @ToolbarContentBuilder private var editorToolbar: some ToolbarContent {
        ToolbarItemGroup(placement: .primaryAction) {
            if draft.isNew {
                Button {
                    Task { await toggleMode() }
                } label: {
                    Label(
                        agentDriven ? "Fill manually" : "Use Agent",
                        systemImage: agentDriven
                            ? "square.and.pencil" : "sparkles")
                }
            }
            KLButton(title: "Cancel") {
                Task { await cancel() }
            }
            .disabled(saving)
            .keyboardShortcut(.cancelAction)
            if !agentDriven {
                KLButton(title: saving ? "Saving…" : "Save",
                         role: .primary) {
                    Task { await save() }
                }
                .disabled(saving)
                .keyboardShortcut(.defaultAction)
            }
        }
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

        // Free-form fields the template does not define — the 1Password/
        // Strongbox "add field" flow. The raw JSON editor stays as the
        // fallback for daemons without `templates_list`.
        if !draft.isAgentContent, !isDeveloperTemplate, template != nil {
            customFieldsSection
        }

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
                    RoundedRectangle(cornerRadius: KL.Radius.small)
                        .stroke(KL.Colors.cardStroke))
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
                    RoundedRectangle(cornerRadius: KL.Radius.small)
                        .stroke(KL.Colors.cardStroke))
            if let message = errors["custom_fields"] {
                Text(message).font(.caption).foregroundStyle(KL.Colors.danger)
            }
        }

        if let message = errors["sections"] {
            Text(message).font(.caption).foregroundStyle(KL.Colors.danger)
        }
        ForEach(draft.structuredErrors.keys.sorted(), id: \.self) { key in
            if let message = draft.structuredErrors[key] {
                Text(message).font(.caption).foregroundStyle(KL.Colors.danger)
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
                Text(message).font(.caption).foregroundStyle(KL.Colors.danger)
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
                VStack(alignment: .leading, spacing: 4) {
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
                    .disabled(totpScanning)
                    if totpScanning {
                        Text("Scanning for a TOTP QR code…")
                            .font(.caption).foregroundStyle(.secondary)
                    } else if let hint = totpScanResult?.hint {
                        Text(hint).font(.caption).foregroundStyle(.secondary)
                        if totpScanResult == .permissionRequired {
                            Button("Open Screen Recording Settings") {
                                app.host.openScreenRecordingSettings()
                            }
                            .buttonStyle(.link).font(.caption)
                        }
                    }
                }
                .onChange(of: draft.totp) {
                    errors["otp"] = nil
                    errors["template_otp"] = nil
                    // A scanned value keeps its success hint; a manual edit clears it.
                    if case .found(let uri) = totpScanResult, uri == draft.totp {
                        return
                    }
                    totpScanResult = nil
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

    // MARK: Custom fields (user-added, 1Password-style)

    /// Stored fields no template definition claims — everything left after
    /// reserved keys and template fields are taken out.
    private var customStoredFields: [FieldView] {
        guard let entryId = draft.entryId,
            let detail = vault.entryViews[entryId]
        else { return [] }
        let reserved: Set<String> = ["username", "password", "otp"]
        let definitions = template?.fields ?? []
        return detail.fields.filter { field in
            !reserved.contains(field.key)
                && !definitions.contains { definition in
                    definition.key == field.key
                        || (!definition.semanticRole.isEmpty
                            && field.semanticRole == definition.semanticRole)
                }
        }
    }

    /// Hydrate stored custom fields once `entries_view` arrives; rows the
    /// user removed stay gone (they sit in `removeFieldIds`).
    private func hydrateCustomFields() {
        guard !isDeveloperTemplate, !draft.isAgentContent else { return }
        for field in customStoredFields
        where !customFields.contains(where: { $0.id == field.id })
            && !draft.removeFieldIds.contains(field.id)
        {
            let text = entryFieldText(field) ?? ""
            customFields.append(CustomFieldEdit(
                id: field.id, key: field.key, label: field.label,
                valueType: field.valueType, protected: field.protected,
                text: text,
                hasStoredValue: field.protected && field.hasValue,
                stored: CustomFieldEdit.Snapshot(
                    label: field.label, valueType: field.valueType,
                    protected: field.protected, text: text)))
        }
    }

    private func addCustomField(_ valueType: String, protected: Bool) {
        customFields.append(CustomFieldEdit(
            valueType: valueType, protected: protected))
        syncTemplatePayload()
    }

    private func removeCustomField(_ row: CustomFieldEdit) {
        customFields.removeAll { $0.id == row.id }
        if row.stored != nil, !draft.removeFieldIds.contains(row.id) {
            draft.removeFieldIds.append(row.id)
        }
        syncTemplatePayload()
    }

    private var customFieldsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                SectionLabel(title: "Custom fields")
                Spacer()
                Menu {
                    ForEach(
                        Array(customFieldTypes.enumerated()), id: \.offset
                    ) { _, type in
                        Button(type.label) {
                            addCustomField(
                                type.value, protected: type.protected)
                        }
                    }
                } label: {
                    Label("Add field", systemImage: "plus")
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
            }
            ForEach($customFields) { $row in
                CustomFieldRow(
                    row: $row,
                    error: errors["custom_\(row.id)"],
                    onChanged: { syncTemplatePayload() },
                    onRemove: { removeCustomField(row) })
            }
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
                Text(message).font(.caption).foregroundStyle(KL.Colors.danger)
            }
        }
    }

    private func iconButton(
        _ icon: String, help: String, action: @escaping () -> Void
    ) -> some View {
        KLIconButton(label: help, icon: icon, action: action)
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
    /// draft so the typed edits become `field_updates`. Template-defined
    /// fields and user-added rows are encoded together.
    private func syncTemplatePayload() {
        guard !isDeveloperTemplate else { return }
        // Without a template the raw JSON editor owns `customFields` —
        // overwriting here would wipe hand-written JSON on save.
        guard template != nil else { return }
        var fields = templateFieldItemFields(
            definitions: template?.fields ?? [],
            edits: edits, isNew: draft.isNew, kind: draft.kind)
        // New rows derive their key from the label; stored rows keep the
        // key the daemon assigned. Taken keys prevent a new row from
        // colliding with a template or sibling field.
        var takenKeys = Set(fields.map(\.key))
        takenKeys.formUnion((template?.fields ?? []).map(\.key))
        takenKeys.formUnion(customStoredFields.map(\.key))
        for index in customFields.indices {
            if customFields[index].stored == nil {
                let label = customFields[index].label
                let key = uniqueCustomFieldKey(
                    customFieldKeySlug(label.isEmpty ? "field" : label),
                    taken: takenKeys)
                customFields[index].key = key
                takenKeys.insert(key)
            }
            let row = customFields[index]
            if row.isEmptyDraft || row.unchanged { continue }
            // Blank text on a stored protected field keeps the server
            // value; validation blocks metadata changes in that state.
            if row.hasStoredValue, row.protected,
                row.text.trimmingCharacters(in: .whitespaces).isEmpty
            { continue }
            fields.append(row.itemField())
        }
        draft.customFields = fields.isEmpty ? "" : encodeItemFields(fields)
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
        customFields = []
        environment = nil
        ssh = nil
        ensureTemplateStates()
    }

    private func toggleMode() async {
        if vault.creationMode == .agentDriven {
            vault.useManualCreation()
        } else {
            await vault.useAgentCreation()
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
        for row in customFields where !row.isEmptyDraft {
            let key = "custom_\(row.id)"
            if row.label.trimmingCharacters(in: .whitespaces).isEmpty {
                validation[key] = "Give this field a label."
            } else if row.hasStoredValue, !row.unchanged,
                row.text.trimmingCharacters(in: .whitespaces).isEmpty
            {
                // `field_updates` replaces the whole field — a stored
                // secret's label/type can only change with a new value.
                validation[key] = "Enter a new value to update this "
                    + "protected field."
            } else if let message = validateTypedField(
                row.valueType, text: row.text)
            {
                validation[key] = message
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
        // `save()` selects the written item, which closes the editor and
        // wipes the draft — snapshot the bindings before they are gone.
        let bindingsToClear = draft.sshBindingsToClear
        let keyBindings = draft.sshKeyBindings
        do {
            let savedId = try await vault.save(draft)
            var bindingFailure: Error?
            if let savedId {
                do {
                    for endpointId in bindingsToClear {
                        try app.setSshKeyBinding(savedId, endpointId, nil)
                    }
                    for (endpointId, path) in keyBindings {
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
            if (error as? KeyLeaseError)?.code == .vaultLocked {
                unlockError = nil
                unlockPrompt = true
            } else if let error = error as? KeyLeaseError,
                error.code == .invalidRequest,
                let reason = error.details?["reason"]?.stringValue,
                ["invalid otpauth TOTP URI", "invalid TOTP secret",
                 "invalid TOTP configuration"].contains(reason)
            {
                errors["otp"] = "Enter a valid TOTP QR URI or Base32 secret."
            } else {
                failure = UserMessage(error)
            }
        }
    }

    private func cancel() async {
        syncTemplatePayload()
        guard vault.confirmDiscardIfDirty() else { return }
        vault.closeEditor()
    }

    private func generate() async {
        do {
            let settings = app.passwordGeneratorSettings
            guard let generated = try await vault.generatePassword(settings)
            else { return }
            draft.password = generated
            passwordCopied = app.copySensitive(generated, label: "Password")
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
        totpScanResult = nil
        defer { totpScanning = false }
        let result: TotpScanResult
        switch source {
        case .screen:
            result = await app.host.captureScreenTotp()
        case .image:
            guard let url = app.host.pickFile(
                title: "Choose a QR code image",
                message: "Select an image containing a TOTP QR code.")
            else { return }
            result = app.host.scanTotpQrFromImage(url)
        }
        guard !Task.isCancelled, vault.activeDraft === draft,
            app.phase == .ready
        else { return }
        totpScanResult = result
        if case .found(let uri) = result { draft.totp = uri }
    }
}

/// One user-managed field row — label, type and conceal controls on the
/// first line, the value full-width on the second so narrow windows keep
/// the value readable (same fix as the environment-variable rows).
private struct CustomFieldRow: View {
    @Binding var row: CustomFieldEdit
    let error: String?
    let onChanged: () -> Void
    let onRemove: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                TextField("Label", text: $row.label)
                    .textFieldStyle(.roundedBorder)
                    .onChange(of: row.label) { onChanged() }
                Picker(
                    "",
                    selection: Binding(
                        get: { row.valueType },
                        set: { row.valueType = $0; onChanged() })
                ) {
                    Text("Text").tag("text")
                    Text("URL").tag("url")
                    Text("Email").tag("email")
                    Text("Phone").tag("phone")
                    Text("Date").tag("date")
                    Text("Month / year").tag("month_year")
                    Text("Number").tag("number")
                    // Stored fields can carry types the menu does not
                    // offer (concealed, address, …) — keep them selectable.
                    let standard = [
                        "text", "url", "email", "phone", "date",
                        "month_year", "number",
                    ]
                    if !standard.contains(row.valueType) {
                        Text(row.valueType).tag(row.valueType)
                    }
                }
                .labelsHidden()
                .frame(width: 120)
                Toggle("Conceal", isOn: $row.protected)
                    .toggleStyle(.checkbox)
                    .onChange(of: row.protected) { onChanged() }
                Spacer(minLength: 0)
                IconAction(label: "Remove field", icon: "trash", danger: true) {
                    onRemove()
                }
            }
            Group {
                if row.protected {
                    SecureField("value", text: $row.text)
                } else {
                    TextField("value", text: $row.text)
                }
            }
            .textFieldStyle(.roundedBorder)
            .frame(maxWidth: .infinity)
            .onChange(of: row.text) { onChanged() }
            if row.hasStoredValue {
                Text("Stored; blank keeps current.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if let error {
                Text(error).font(.caption).foregroundStyle(KL.Colors.danger)
            }
        }
        .padding(KL.Space.m)
        .background(
            RoundedRectangle(cornerRadius: KL.Radius.medium)
                .fill(KL.Colors.insetFill)
                .overlay(
                    RoundedRectangle(cornerRadius: KL.Radius.medium)
                        .stroke(KL.Colors.cardStroke)))
    }
}
