import SwiftUI

import KeyLeaseCore

// MARK: - Password generator (`password_generator.dart`)

/// The standalone generator pane — workspace mode `.passwordGenerator`.
/// "Create Login" hands the password into a new-item draft, matching the
/// Dart `onUse` callback.
struct PasswordGeneratorView: View {
    let app: AppController
    @State private var settings = false

    var body: some View {
        ScrollView {
            PasswordGeneratorForm(app: app, useLabel: "Create Login") {
                password in
                app.vault.beginCreate(initialPassword: password)
            }
            .padding(KL.Space.xxl)
            .frame(maxWidth: 640, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .leading)
            .controlSize(.large)
        }
        .navigationTitle("Password generator")
        .toolbar {
            ToolbarItem(placement: .navigation) {
                IconAction(label: "Back", icon: "chevron.left") {
                    app.vault.closePasswordGenerator()
                }
            }
        }
        .sheet(isPresented: $settings) {
            PasswordSettingsSheet(app: app)
        }
    }
}

/// `PasswordGenerator` — the reusable generator body shared by the pane
/// and (in Dart) the editor settings sheet.
struct PasswordGeneratorForm: View {
    let app: AppController
    let useLabel: String
    let onUse: (String) -> Void

    @State private var password = ""
    @State private var generatedWith: PasswordGeneratorSettings?
    @State private var revealed = false
    @State private var copied = false
    @State private var generating = false
    @State private var failure: UserMessage?
    @State private var showSettings = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let failure {
                MessageBanner(
                    message: failure, onDismiss: { self.failure = nil })
            }
            VStack(alignment: .leading, spacing: 4) {
                Text("Generated password").font(.callout)
                HStack {
                    Group {
                        if revealed {
                            TextField("", text: .constant(password))
                        } else {
                            SecureField("", text: .constant(password))
                        }
                    }
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
                    .disabled(true)
                    if copied {
                        Label("Copied", systemImage: "checkmark")
                            .font(.caption)
                            .foregroundStyle(KL.Colors.success)
                    }
                }
            }
            HStack {
                let bits = (generatedWith ?? app.passwordGeneratorSettings)
                    .estimatedEntropyBits
                Text("\(strengthLabel(bits)) · approximately \(bits) bits")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                IconAction(
                    label: revealed ? "Hide password" : "Reveal password",
                    icon: revealed ? "eye.slash" : "eye")
                {
                    revealed.toggle()
                }
                IconAction(
                    label: "Copy password", icon: "doc.on.doc")
                {
                    copy()
                }
                .disabled(password.isEmpty)
                IconAction(
                    label: "Generate new password", icon: "sparkles")
                {
                    Task { await generate() }
                }
                .disabled(generating)
                IconAction(
                    label: "Password generator settings",
                    icon: "gearshape")
                {
                    showSettings = true
                }
            }
            KLButton(title: useLabel, icon: "plus", role: .primary) {
                onUse(password)
            }
            .disabled(password.isEmpty)
        }
        .sheet(isPresented: $showSettings) {
            PasswordSettingsSheet(app: app)
        }
        .onAppear {
            if password.isEmpty { Task { await generate() } }
        }
    }

    private func strengthLabel(_ bits: Int) -> String {
        switch bits {
        case ..<40: "Weak"
        case ..<60: "Fair"
        case ..<80: "Strong"
        default: "Very strong"
        }
    }

    private func generate() async {
        guard !generating else { return }
        generating = true
        failure = nil
        defer { generating = false }
        do {
            let settings = app.passwordGeneratorSettings
            guard let value = try await app.vault.generatePassword(settings)
            else { return }
            password = value
            generatedWith = settings
            copied = false
        } catch {
            failure = UserMessage(error)
        }
    }

    private func copy() {
        guard !password.isEmpty else { return }
        copied = app.copySensitive(password)
        if copied {
            Task {
                try? await Task.sleep(for: .seconds(2))
                copied = false
            }
        }
    }
}

/// `_PasswordSettingsForm` — the modal settings sheet saved into
/// `ui.json` via `updatePasswordGeneratorSettings`.
struct PasswordSettingsSheet: View {
    let app: AppController
    @Environment(\.dismiss) private var dismiss
    @State private var value = PasswordGeneratorSettings()
    @State private var saving = false
    @State private var failure: UserMessage?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Password generator settings").font(.headline)
            if let failure {
                MessageBanner(
                    message: failure, onDismiss: { self.failure = nil })
            }

            Picker("Pattern", selection: $value.pattern) {
                Text("Random characters").tag(PasswordPattern.random)
                Text("Memorable words").tag(PasswordPattern.words)
                Text("PIN").tag(PasswordPattern.pin)
            }

            switch value.pattern {
            case .random:
                Picker("Length", selection: $value.length) {
                    ForEach([16, 20, 24, 32, 40, 64], id: \.self) {
                        Text("\($0)").tag($0)
                    }
                }
                Toggle("Uppercase letters", isOn: $value.uppercase)
                Toggle("Lowercase letters", isOn: $value.lowercase)
                Toggle("Numbers", isOn: $value.numbers)
                Toggle("Symbols", isOn: $value.symbols)
                Toggle(
                    "Avoid ambiguous characters (0, O, 1, l)",
                    isOn: $value.avoidAmbiguous)
            case .words:
                Picker("Words", selection: $value.wordCount) {
                    ForEach(3...8, id: \.self) { Text("\($0)").tag($0) }
                }
                Picker("Separator", selection: $value.separator) {
                    Text("Hyphen (-)").tag("-")
                    Text("Space ( )").tag(" ")
                    Text("Period (.)").tag(".")
                    Text("Underscore (_)").tag("_")
                }
                Toggle("Capitalize words", isOn: $value.capitalize)
                Toggle("Include a number", isOn: $value.wordNumber)
            case .pin:
                Picker("Digits", selection: $value.pinLength) {
                    ForEach([4, 6, 8, 10, 12], id: \.self) {
                        Text("\($0)").tag($0)
                    }
                }
            }

            Text(
                "\(value.strengthLabel) · approximately "
                    + "\(value.estimatedEntropyBits) bits")
                .font(.caption).foregroundStyle(.secondary)

            HStack {
                Spacer()
                KLButton(title: "Cancel", role: .ghost) { dismiss() }
                    .disabled(saving)
                KLButton(
                    title: saving ? "Saving…" : "Save settings",
                    role: .primary)
                {
                    Task { await save() }
                }
                .disabled(saving)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(KL.Space.xxxl)
        .frame(width: 420)
        .controlSize(.large)
        .onAppear { value = app.passwordGeneratorSettings }
    }

    private func save() async {
        saving = true
        defer { saving = false }
        app.updatePasswordGeneratorSettings(value)
        dismiss()
    }
}

// MARK: - Agent-driven creation (`agent_driven_creation.dart`)

/// The four-step "create this item with a local agent" flow embedded in
/// the editor workspace when `creationMode == .agentDriven`.
struct AgentCreationPane: View {
    let app: AppController
    @Bindable var draft: AgentCreationDraft

    @State private var message: UserMessage?
    @State private var candidates: [ItemMetadata] = []
    @State private var copying = false
    @State private var refreshing = false

    private var launchText: String {
        let handoff = draft.handoff
        return handoff == nil || handoff!.expired
            ? "KeyLease will prepare a temporary CLI handoff when you copy."
            : handoff!.clipboardText
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            GuidanceCard(
                title: "Create this item with a local agent",
                summary: "Choose a starting point, then copy one short "
                    + "command into Codex or another agent with terminal "
                    + "access.",
                useWhen: "The KeyLease CLI supplies the complete, "
                    + "version-matched workflow. The handoff expires after "
                    + "two hours and never needs your master password.")

            stepTitle(1, "Choose a starting point")
            LazyVGrid(
                columns: [
                    GridItem(.flexible(), spacing: 12),
                    GridItem(.flexible(), spacing: 12),
                ], spacing: 12
            ) {
                ForEach(agentCreationRecipes) { recipe in
                    RecipeCard(
                        recipe: recipe,
                        selected: recipe.id == draft.recipeId)
                    {
                        draft.applyRecipe(recipe)
                        message = nil
                        candidates = []
                    }
                }
            }

            stepTitle(2, "Set the target and source")
            Picker(
                "Template",
                selection: Binding(
                    get: { draft.kind },
                    set: { changeTemplate($0) })
            ) {
                ForEach(app.vault.templates, id: \.kind) { template in
                    Text(template.label).tag(template.kind)
                }
            }
            if draft.isAgentContent {
                Picker(
                    "Project (optional)",
                    selection: Binding(
                        get: { draft.projectSlug ?? "" },
                        set: {
                            draft.projectSlug = $0.isEmpty ? nil : $0
                            draft.invalidateHandoff()
                        })
                ) {
                    Text("No project").tag("")
                    ForEach(app.vault.projects, id: \.slug) { project in
                        Text(project.name).tag(project.slug)
                    }
                }
                TextField(
                    "Tags (comma separated)", text: $draft.tags)
                    .textFieldStyle(.roundedBorder)
                    .onChange(of: draft.tags) { draft.invalidateHandoff() }
                Picker(
                    "Agent access after creation",
                    selection: Binding(
                        get: { draft.agentAccess },
                        set: {
                            draft.agentAccess = $0
                            draft.invalidateHandoff()
                        })
                ) {
                    Text("Read and write").tag("read_write")
                    Text("Read only").tag("read")
                    Text("Owner only").tag("none")
                }
            } else {
                Picker(
                    "Group",
                    selection: Binding(
                        get: { draft.groupId ?? "" },
                        set: {
                            draft.groupId = $0.isEmpty ? nil : $0
                            draft.invalidateHandoff()
                        })
                ) {
                    Text("Choose a destination group").tag("")
                    ForEach(app.vault.orderedGroups) { group in
                        Text(groupBreadcrumb(group)).tag(group.id)
                    }
                }
            }
            VStack(alignment: .leading, spacing: 4) {
                Text("Source path (optional)").font(.callout)
                TextField("", text: $draft.sourcePath)
                    .textFieldStyle(.roundedBorder)
                    .onChange(of: draft.sourcePath) {
                        draft.invalidateHandoff()
                        message = nil
                        candidates = []
                    }
                Text("A file or directory the agent may read. Do not enter "
                    + "a secret value here.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text("What should the agent create? (optional)")
                    .font(.callout)
                TextEditor(text: $draft.context)
                    .frame(minHeight: 60, maxHeight: 140)
                    .overlay(
                        RoundedRectangle(cornerRadius: KL.Radius.small)
                            .stroke(KL.Colors.cardStroke))
                    .onChange(of: draft.context) {
                        draft.invalidateHandoff()
                        message = nil
                        candidates = []
                    }
                Text("Describe the goal, host alias, environment, or "
                    + "expected content. Do not paste secret values.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            stepTitle(3, "Copy the CLI handoff")
            KLInsetBlock {
                VStack(alignment: .leading, spacing: KL.Space.m) {
                    Text(launchText)
                        .font(.body.monospaced())
                        .textSelection(.enabled)
                    if let handoff = draft.handoff, !handoff.expired {
                        Text("Available until \(handoff.expiresAt)")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            HStack {
                Spacer()
                KLButton(
                    title: copying ? "Preparing…" : "Copy agent command",
                    icon: "doc.on.doc", role: .primary)
                {
                    Task { await copyAgentInstruction() }
                }
                .disabled(copying)
            }

            stepTitle(4, "Refresh and review")
            Text("Continue the agent conversation until it says “Created "
                + "in KeyLease” and returns an item ID. Then refresh here "
                + "to review and edit the result.")
                .font(.callout).foregroundStyle(.secondary)
            KLButton(
                title: refreshing ? "Refreshing…" : "Refresh & review",
                icon: "arrow.clockwise")
            {
                Task { await refreshAndReview() }
            }
            .disabled(!draft.handoffCopied || refreshing)

            if let message {
                MessageBanner(
                    message: message, onDismiss: { self.message = nil })
            }
            if !candidates.isEmpty {
                SectionLabel(title: "New items")
                ForEach(candidates, id: \.id) { candidate in
                    Button {
                        app.vault.openAgentCreatedEntry(candidate)
                    } label: {
                        Text("\(candidate.title) · "
                            + app.vault.kindLabel(candidate.kind))
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                }
            }
        }
    }

    private func stepTitle(_ number: Int, _ title: String) -> some View {
        HStack(spacing: KL.Space.m) {
            Text("\(number)")
                .font(.caption.weight(.bold))
                .foregroundStyle(KL.Colors.onAccent)
                .frame(width: 22, height: 22)
                .background(Circle().fill(KL.Colors.accent))
            SectionLabel(title: title)
        }
        .padding(.top, KL.Space.m)
    }

    private func groupBreadcrumb(_ group: VaultGroup) -> String {
        var names = [group.name]
        var visited: Set<String> = [group.id]
        var parentId = group.parentId
        while let id = parentId, visited.insert(id).inserted {
            guard let parent = app.vault.groups.first(where: {
                $0.id == id
            }) else { break }
            names.insert(parent.name, at: 0)
            parentId = parent.parentId
        }
        return names.joined(separator: " / ")
    }

    private func changeTemplate(_ kind: String) {
        guard kind != draft.kind else { return }
        draft.kind = kind
        draft.invalidateHandoff()
        message = nil
        candidates = []
    }

    private func validationError() -> String? {
        if (app.status?.vaultId ?? "").isEmpty {
            return "The active vault identity is not available. Refresh "
                + "KeyLease and try again."
        }
        if !draft.isAgentContent && (draft.groupId ?? "").isEmpty {
            return "Choose the group where the agent should create this "
                + "item."
        }
        if draft.recipeId == "dotenv"
            && draft.sourcePath.trimmingCharacters(in: .whitespaces)
                .isEmpty
        {
            return "Enter the path to the .env file the agent may read."
        }
        return nil
    }

    private func copyAgentInstruction() async {
        if let validation = validationError() {
            message = UserMessage(
                title: "Complete the setup", detail: validation)
            return
        }
        copying = true
        message = nil
        defer { copying = false }
        do {
            if draft.baselineEntryIds == nil {
                draft.baselineEntryIds =
                    try? await app.vault.snapshotEntryIds()
            }
            var handoff = draft.handoff
            if handoff == nil || handoff!.expired {
                handoff = try await app.vault.createAgentHandoff(
                    expectedVaultId: app.status!.vaultId!)
                draft.handoff = handoff
            }
            let copied = app.copySensitive(
                handoff!.clipboardText, clearAfter: 120)
            if copied { draft.handoffCopied = true }
        } catch {
            message = UserMessage(error)
        }
    }

    private func refreshAndReview() async {
        guard let baseline = draft.baselineEntryIds else { return }
        refreshing = true
        message = nil
        candidates = []
        defer { refreshing = false }
        do {
            let found = try await app.vault.entriesCreatedSince(baseline)
            if found.count == 1 {
                app.vault.openAgentCreatedEntry(found[0])
            } else if found.isEmpty {
                message = UserMessage(
                    title: "The agent has not created an item yet",
                    detail: "If the agent asked for a title or fields, "
                        + "reply in that chat first. Refresh only after it "
                        + "says “Created in KeyLease” and returns an item "
                        + "ID.")
            } else {
                candidates = found
                message = UserMessage(
                    title: "Choose the item to review",
                    detail: "More than one item changed while the agent "
                        + "was working.")
            }
        } catch {
            message = UserMessage(error)
        }
    }
}

private struct RecipeCard: View {
    let recipe: AgentCreationRecipe
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: KL.Space.xs) {
                Text(recipe.title).font(.callout.weight(.medium))
                Text(recipe.description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(KL.Space.l)
            .background(
                RoundedRectangle(cornerRadius: KL.Radius.medium)
                    .fill(
                        selected
                            ? KL.Colors.markSurface
                            : KL.Colors.insetFill)
                    .overlay(
                        RoundedRectangle(cornerRadius: KL.Radius.medium)
                            .stroke(
                                selected
                                    ? KL.Colors.accent
                                    : KL.Colors.cardStroke)))
        }
        .buttonStyle(.plain)
    }
}
