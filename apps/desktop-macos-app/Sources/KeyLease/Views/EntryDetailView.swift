import SwiftUI

import KeyLeaseCore

/// The selected entry — a direct port of `entry_detail.dart`: header and
/// actions, login details, template/dev-template fields, inline TOTP with
/// countdown, notes, and a metadata disclosure with history.
struct EntryDetailView: View {
    let app: AppController
    @State private var history: [EntryRevision]?
    @State private var historyError: UserMessage?
    @State private var showHistory = false
    @State private var deleting = false

    private var entry: ItemMetadata? { app.vault.selectedEntry }
    private var detail: EntryView? { app.vault.detail }

    var body: some View {
        if let item = entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    header(item)

                    if hasLoginDetails(item) {
                        loginDetails(item)
                    }

                    if let detail,
                        item.kind == "core.environment"
                            || item.kind == "core.ssh_server"
                    {
                        DeveloperTemplateDetail(
                            app: app, item: item, detail: detail)
                    } else if let detail, !additionalFields(detail).isEmpty {
                        additionalSection(item, detail: detail)
                    }

                    if item.hasTotp {
                        totpSection(item)
                    }

                    if item.hasNotes {
                        NotesSection(app: app, entry: item)
                    }

                    metadataSection(item)
                }
                .padding(24)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .id(item.id)
            .sheet(isPresented: $showHistory) {
                historySheet(item)
            }
            .alert(
                "Move to recycle bin?",
                isPresented: $deleting
            ) {
                Button("Delete", role: .destructive) {
                    Task {
                        await app.vault.deleteEntry(item)
                        app.removeSshBindingsForItem(item.id)
                    }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("“\(item.title)” moves to the recycle bin. "
                    + "Anything already copied is unaffected.")
            }
        } else {
            ProgressView()
        }
    }

    // MARK: Header + actions

    private func header(_ item: ItemMetadata) -> some View {
        HStack(alignment: .top, spacing: 14) {
            MonogramMark(text: item.monogram, large: true)
            VStack(alignment: .leading, spacing: 4) {
                Text(item.title).font(.title3.weight(.semibold))
                Text(item.primaryUrl ?? app.vault.kindLabel(item.kind))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                HStack(spacing: 4) {
                    IconAction(
                        label: item.favorite
                            ? "Remove from favorites" : "Add to favorites",
                        icon: item.favorite ? "star.slash" : "star")
                    {
                        Task { await app.vault.toggleFavorite(item) }
                    }
                    IconAction(
                        label: "Copy prompt for agent",
                        icon: "doc.on.clipboard")
                    {
                        _ = app.copyAgentPrompt(item)
                    }
                    IconAction(
                        label: "Copy CLI command", icon: "terminal")
                    {
                        _ = app.copyCliCommand(item)
                    }
                    IconAction(label: "Edit", icon: "square.and.pencil") {
                        app.vault.beginEdit(item)
                    }
                    IconAction(
                        label: "Delete", icon: "trash", danger: true)
                    {
                        deleting = true
                    }
                }
            }
            Spacer()
        }
    }

    // MARK: Login details

    private func hasLoginDetails(_ item: ItemMetadata) -> Bool {
        let username = app.vault.revealedValue(item.id, "username")
            ?? item.username
        return (username?.isEmpty == false) || item.hasPassword
            || item.primaryUrl != nil
    }

    private func loginDetails(_ item: ItemMetadata) -> some View {
        let username = app.vault.revealedValue(item.id, "username")
            ?? item.username
        return VStack(alignment: .leading, spacing: 8) {
            SectionLabel(title: "Login details")
            FieldGroup {
                if username?.isEmpty == false {
                    DetailRow(label: "Username", value: username ?? "") {
                        IconAction(
                            label: "Copy username", icon: "doc.on.doc")
                        {
                            copy(item, field: "username", label: "Username")
                        }
                    }
                }
                if item.hasPassword {
                    SecretRow(
                        label: "Password",
                        revealed: app.vault.revealedValue(item.id, "password"),
                        onReveal: {
                            _ = await app.vault.reveal(
                                entryId: item.id, field: "password")
                        },
                        onHide: {
                            app.vault.hideSecret(
                                entryId: item.id, field: "password")
                        },
                        onCopy: {
                            copy(item, field: "password", label: "Password")
                        })
                }
                if let url = item.primaryUrl {
                    DetailRow(
                        label: "Website", value: url, accent: true,
                        onPress: { openWebsite(url) }
                    ) {
                        IconAction(
                            label: "Open website", icon: "arrow.up.right")
                        {
                            openWebsite(url)
                        }
                    }
                }
            }
        }
    }

    // MARK: Additional typed fields

    /// `_additionalFields` — typed fields that are not the legacy
    /// username/password/url/otp rows rendered above.
    private func additionalFields(_ detail: EntryView) -> [FieldView] {
        let legacyRoles: Set<String> = [
            "username", "password", "website", "url", "otp",
        ]
        let legacyKeys: Set<String> = [
            "username", "password", "url", "website", "otp", "totp",
        ]
        return detail.fields.filter {
            $0.hasValue
                && !legacyRoles.contains($0.semanticRole ?? "")
                && !legacyKeys.contains($0.key.lowercased())
        }
    }

    private func additionalSection(_ item: ItemMetadata, detail: EntryView)
        -> some View
    {
        VStack(alignment: .leading, spacing: 8) {
            SectionLabel(title: "Details")
            FieldGroup {
                ForEach(additionalFields(detail), id: \.id) { field in
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
                            onCopy: {
                                copyField(item, field: field)
                            })
                    } else {
                        DetailRow(label: field.label, value: field.displayValue)
                        {
                            IconAction(
                                label: "Copy \(field.label)",
                                icon: "doc.on.doc")
                            {
                                copyField(item, field: field)
                            }
                        }
                    }
                }
            }
        }
    }

    // MARK: TOTP

    private func totpSection(_ item: ItemMetadata) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionLabel(title: "Two-factor authentication")
            FieldGroup {
                TotpRow(app: app, entry: item)
            }
        }
    }

    // MARK: Metadata + history

    private func metadataSection(_ item: ItemMetadata) -> some View {
        MetadataSection(
            item: item,
            detail: detail,
            templateLabel: app.vault.kindLabel(item.kind),
            projectName: app.vault.projectName(detail?.projectId),
            groupName: app.vault.groups
                .first(where: { $0.id == item.groupId })?.name
                ?? item.groupId
        ) {
            Task {
                do {
                    history = try await app.vault.history(item)
                    historyError = nil
                    showHistory = true
                } catch {
                    historyError = UserMessage(error)
                    history = []
                    showHistory = true
                }
            }
        }
    }

    private func historySheet(_ item: ItemMetadata) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("History · \(item.title)").font(.headline)
            if let historyError {
                MessageBanner(message: historyError)
            }
            if let history, !history.isEmpty {
                List(history, id: \.revision) { revision in
                    LabeledContent(
                        "Revision \(revision.revision)",
                        value: revision.updatedAt ?? "Unknown time")
                }
                .frame(minHeight: 200)
            } else {
                Text("No earlier revisions.")
                    .foregroundStyle(.secondary)
            }
            HStack {
                Spacer()
                Button("Close") { showHistory = false }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(minWidth: 420)
    }

    // MARK: Copy/open helpers

    /// Copy must not un-mask: fetch without displaying (Dart `_copy`).
    private func copy(_ item: ItemMetadata, field: String, label: String) {
        Task {
            let value: String?
            if let revealed = app.vault.revealedValue(item.id, field) {
                value = revealed
            } else {
                value = await app.vault.fetchSecret(
                    entryId: item.id, field: field)
            }
            if let value, !value.isEmpty {
                _ = app.copySensitive(value)
            }
        }
    }

    private func copyField(_ item: ItemMetadata, field: FieldView) {
        Task {
            let value: String?
            if field.protected {
                if let revealed = app.vault.revealedValue(item.id, field.id) {
                    value = revealed
                } else {
                    value = await app.vault.fetchField(
                        entryId: item.id, field: field)
                }
            } else {
                value = field.displayValue
            }
            if let value, !value.isEmpty {
                _ = app.copySensitive(value)
            }
        }
    }

    private func openWebsite(_ raw: String) {
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        let candidate = trimmed.contains("://") ? trimmed : "https://\(trimmed)"
        _ = app.security.openExternal(candidate)
    }
}

// MARK: - Notes (`_InlineNotesSection`)

/// Loads the note body on demand through `entries_reveal` — never kept on
/// screen longer than the entry stays selected.
private struct NotesSection: View {
    let app: AppController
    let entry: ItemMetadata
    @State private var notes: String?
    @State private var error: String?
    @State private var loading = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                SectionLabel(title: "Notes")
                Spacer()
                if notes != nil {
                    IconAction(label: "Copy notes", icon: "doc.on.doc") {
                        if let notes, !notes.isEmpty {
                            _ = app.copySensitive(notes)
                        }
                    }
                }
            }
            ZStack {
                if loading {
                    ProgressView().controlSize(.small)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else if let error {
                    HStack {
                        Text(error).foregroundStyle(.red).font(.callout)
                        Button("Retry") { Task { await load() } }
                            .controlSize(.small)
                    }
                } else {
                    Text(notes ?? "")
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(12)
            .background(
                RoundedRectangle(cornerRadius: 9)
                    .stroke(Color.primary.opacity(0.12)))
        }
        .task(id: entry.id) { await load() }
    }

    private func load() async {
        if loading { return }
        loading = true
        error = nil
        let value: String?
        if entry.isAgentContent {
            value = try? await app.vault.fetchContentBody(entry)
        } else {
            value = await app.vault.fetchSecret(
                entryId: entry.id, field: "notes")
        }
        loading = false
        notes = value
        if value == nil { error = "Could not load notes" }
    }
}

// MARK: - TOTP (`_InlineTotpField`)

/// Live one-time code with countdown — refetches when the code expires.
private struct TotpRow: View {
    let app: AppController
    let entry: ItemMetadata
    @State private var code: String?
    @State private var error: String?
    @State private var remaining = 0
    @State private var loading = false
    @State private var timer: Timer?

    var body: some View {
        DetailRow(
            label: "One-time password",
            value: loading
                ? "Loading code…"
                : code.map { "\($0) · \(remaining)s" }
                    ?? (error ?? "Could not load code")
        ) {
            if code != nil {
                IconAction(
                    label: "Copy one-time password", icon: "doc.on.doc")
                {
                    if let code { _ = app.copySensitive(code) }
                }
            }
            if error != nil {
                IconAction(
                    label: "Retry one-time password", icon: "arrow.clockwise")
                {
                    Task { await load() }
                }
            }
        }
        .onAppear { Task { await load() } }
        .onDisappear { timer?.invalidate() }
    }

    private func load() async {
        if loading { return }
        loading = true
        error = nil
        do {
            let response = try await app.vault.totp(entry)
            code = response.code
            remaining = Int(response.expiresIn ?? 0)
            loading = false
            scheduleCountdown()
        } catch let caught {
            loading = false
            code = nil
            error = UserMessage(caught).detail
                ?? UserMessage(caught).title
        }
    }

    private func scheduleCountdown() {
        timer?.invalidate()
        guard remaining > 0 else { return }
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) {
            _ in
            Task { @MainActor in
                if remaining <= 1 {
                    timer?.invalidate()
                    remaining = 0
                    await load()
                } else {
                    remaining -= 1
                }
            }
        }
    }
}

// MARK: - Metadata (`_MetadataSection`)

private struct MetadataSection: View {
    let item: ItemMetadata
    let detail: EntryView?
    let templateLabel: String
    let projectName: String?
    let groupName: String
    let onHistory: () -> Void
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button {
                expanded.toggle()
            } label: {
                Label(
                    "Metadata",
                    systemImage: expanded ? "chevron.down" : "chevron.right")
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)

            if expanded {
                FieldGroup {
                    DetailRow(label: "Template", value: templateLabel)
                    DetailRow(label: "Group", value: groupName)
                    if let projectName {
                        DetailRow(label: "Project", value: projectName)
                    }
                    if let detail, !detail.tags.isEmpty {
                        DetailRow(
                            label: "Tags",
                            value: detail.tags.joined(separator: ", "))
                    }
                    DetailRow(
                        label: "Last updated", value: item.updatedAt)
                    DetailRow(
                        label: "Revision", value: "\(item.revision)"
                    ) {
                        IconAction(label: "View history", icon: "clock") {
                            onHistory()
                        }
                    }
                }
            }
        }
    }
}
