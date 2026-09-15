import SwiftUI

import KeyLeaseCore

// MARK: - Shared section scaffolding

/// The header + scroll body each top-level section uses.
private struct SectionScaffold<Content: View>: View {
    let title: String
    let subtitle: String
    var actions: () -> AnyView
    @ViewBuilder var content: () -> Content

    init(
        title: String, subtitle: String,
        @ViewBuilder actions: @escaping () -> some View = { EmptyView() },
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.title = title
        self.subtitle = subtitle
        self.actions = { AnyView(actions()) }
        self.content = content
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.headline)
                    Text(subtitle)
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                actions()
            }
            .padding(12)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    content()
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
}

/// The empty/error/loading body shared by list sections.
@ViewBuilder
private func sectionBody<Item>(
    _ controller: SectionController<Item>,
    empty: String,
    @ViewBuilder rows: ([Item]) -> some View
) -> some View {
    if let error = controller.error {
        MessageBanner(
            message: error, actionLabel: "Retry",
            onAction: { Task { await controller.load() } },
            onDismiss: { controller.error = nil })
    }
    if controller.loading, !controller.loaded {
        ProgressView().controlSize(.small)
    } else if controller.items.isEmpty {
        Text(empty).foregroundStyle(.secondary)
    } else {
        rows(controller.items)
    }
}

extension ISO8601DateFormatter {
    fileprivate static func parse(_ value: String?) -> Date? {
        guard let value else { return nil }
        return ISO8601DateFormatter.default.date(from: value)
            ?? ISO8601DateFormatter().date(from: value)
    }
}

// MARK: - Connections (`connections_page.dart`)

struct ConnectionsView: View {
    let app: AppController
    @State private var addToken = false
    @State private var connectGoogle = false

    private var controller: ConnectionsController { app.connections }

    var body: some View {
        SectionScaffold(
            title: "Connections",
            subtitle: "Accounts and providers KeyLease may reach")
        {
            HStack(spacing: 8) {
                Button("Add token connection") { addToken = true }
                    .controlSize(.small)
                Button("Connect Google") { connectGoogle = true }
                    .controlSize(.small)
                Button {
                    Task { await controller.list.load() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .controlSize(.small)
                .help("Refresh")
            }
        } content: {
            if let error = controller.error {
                MessageBanner(
                    message: error,
                    onDismiss: { controller.error = nil })
            }
            sectionBody(
                controller.list,
                empty: "No connections yet. Add a token connection or "
                    + "connect Google to get started."
            ) { items in
                ForEach(items, id: \.id) { connection in
                    ConnectionCard(app: app, connection: connection)
                }
            }
        }
        .task { await controller.list.load() }
        .sheet(isPresented: $addToken) {
            AddTokenSheet(app: app)
        }
        .sheet(isPresented: $connectGoogle) {
            GoogleConnectSheet(app: app)
        }
    }
}

private struct ConnectionCard: View {
    let app: AppController
    let connection: ConnectionRecord
    @State private var enrolling = false
    @State private var resource = ""

    private var healthColor: Color {
        switch connection.health {
        case .connected: .green
        case .degraded: .orange
        case .expired, .revoked, .disconnected: .red
        }
    }

    private var healthLabel: String {
        switch connection.health {
        case .connected: "Working"
        case .degraded: "Having trouble"
        case .expired: "Sign-in expired"
        case .revoked: "Access revoked"
        case .disconnected: "Disconnected"
        }
    }

    /// `ConnectionHealthBadge.remedy` — the daemon's own advice, verbatim.
    private var remedy: String? {
        if connection.reauthorizationRequired == true {
            return "Sign in again to restore access."
        }
        return switch connection.health {
        case .connected: nil
        case .degraded:
            "Run Test to see whether the provider is reachable."
        case .expired:
            "Refresh this connection to get a new credential."
        case .revoked:
            "The provider revoked this credential. Connect again."
        case .disconnected:
            "Reconnect this account to use it again."
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(connection.provider).font(.callout.weight(.semibold))
                    HStack(spacing: 6) {
                        Circle().fill(healthColor).frame(width: 8)
                        Text(healthLabel)
                            .font(.callout).foregroundStyle(healthColor)
                    }
                }
                Spacer()
                HStack(spacing: 4) {
                    IconAction(
                        label: "Test \(connection.provider)",
                        icon: "waveform.path.ecg")
                    {
                        run("test")
                    }
                    IconAction(
                        label: "Refresh \(connection.provider)",
                        icon: "arrow.clockwise")
                    {
                        run("refresh")
                    }
                    IconAction(
                        label: "Disconnect \(connection.provider)",
                        icon: "link.badge.plus")
                    {
                        run("disconnect")
                    }
                    IconAction(
                        label: "Revoke \(connection.provider)",
                        icon: "shield.slash", danger: true)
                    {
                        guard
                            confirmAction(
                                title: "Revoke this connection?",
                                message: "KeyLease will tell the provider "
                                    + "to drop this credential. Anything "
                                    + "that relies on it stops working "
                                    + "immediately.",
                                confirmLabel: "Revoke",
                                destructive: true)
                        else { return }
                        run("revoke")
                    }
                }
            }
            if let remedy {
                Text(
                    connection.healthReason == nil
                        ? remedy : "\(remedy) (\(connection.healthReason!))")
                    .font(.callout).foregroundStyle(healthColor)
            }
            Text(
                connection.trustMode.rawValue
                    .replacingOccurrences(of: "_", with: " ")
                    + " · \(connection.executionLocation)"
                    + " · \(connection.authMethod)")
                .font(.caption).foregroundStyle(.secondary)
            if let checked = connection.lastCheckedAt {
                Text("Last checked \(checked)")
                    .font(.caption).foregroundStyle(.secondary)
            }

            SectionLabel(title: "Resources this connection may touch")
                .padding(.top, 4)
            ForEach(connection.authorizedResources, id: \.self) {
                resource in
                HStack {
                    Text(resource).font(.caption.monospaced())
                    Spacer()
                    IconAction(
                        label: "Remove \(resource)", icon: "xmark")
                    {
                        Task {
                            await app.connections.setResource(
                                connection, resource: resource,
                                enrolled: false)
                        }
                    }
                }
            }
            if enrolling {
                HStack {
                    TextField("Canonical resource ID", text: $resource)
                        .textFieldStyle(.roundedBorder)
                    Button("Enroll") {
                        let value = resource.trimmingCharacters(
                            in: .whitespaces)
                        guard !value.isEmpty else { return }
                        enrolling = false
                        resource = ""
                        Task {
                            await app.connections.setResource(
                                connection, resource: value,
                                enrolled: true)
                        }
                    }
                    .controlSize(.small)
                    Button("Cancel") {
                        enrolling = false
                        resource = ""
                    }
                    .controlSize(.small)
                }
            } else {
                Button("Enroll a resource") { enrolling = true }
                    .controlSize(.small)
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color.primary.opacity(0.12)))
    }

    private func run(_ operation: String) {
        Task {
            await app.connections.manage(connection, operation: operation)
        }
    }
}

/// `_addTokenConnection` — provider + credential + resource list.
private struct AddTokenSheet: View {
    let app: AppController
    @Environment(\.dismiss) private var dismiss
    @State private var provider = "github"
    @State private var credential = ""
    @State private var resources = ""
    @State private var failure: UserMessage?
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Add a token connection").font(.headline)
            if let failure {
                MessageBanner(
                    message: failure, onDismiss: { self.failure = nil })
            }
            Picker("Provider", selection: $provider) {
                Text("GitHub").tag("github")
                Text("Linear").tag("linear")
                Text("Notion").tag("notion")
                Text("Fake (testing)").tag("fake")
            }
            VStack(alignment: .leading, spacing: 4) {
                Text("Token or OAuth credential JSON").font(.callout)
                SecureField("", text: $credential)
                    .textFieldStyle(.roundedBorder)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text("Exact canonical resources (one per line)")
                    .font(.callout)
                TextEditor(text: $resources)
                    .frame(minHeight: 48, maxHeight: 100)
                    .overlay(
                        RoundedRectangle(cornerRadius: 6)
                            .stroke(Color.primary.opacity(0.15)))
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button(busy ? "Adding…" : "Add") {
                    Task { await add() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(credential.isEmpty || busy)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 420)
    }

    private func add() async {
        busy = true
        defer { busy = false }
        let list = resources.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        do {
            try await app.connections.add(
                provider: provider, credential: credential,
                resources: list)
            dismiss()
        } catch {
            failure = UserMessage(error)
        }
    }
}

/// `googleOAuthFlow` — client ID + optional secret, browser hop, then
/// `connection_google_oauth_complete`.
private struct GoogleConnectSheet: View {
    let app: AppController
    @Environment(\.dismiss) private var dismiss
    @State private var clientId = ""
    @State private var clientSecret = ""
    @State private var failure: UserMessage?
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Connect Google").font(.headline)
            Text("KeyLease requests drive.file and opens Google's picker "
                + "so you choose the exact files.")
                .font(.callout).foregroundStyle(.secondary)
            if let failure {
                MessageBanner(
                    message: failure, onDismiss: { self.failure = nil })
            }
            VStack(alignment: .leading, spacing: 4) {
                Text("OAuth client ID").font(.callout)
                TextField("", text: $clientId)
                    .textFieldStyle(.roundedBorder)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text("Client secret (optional for desktop clients)")
                    .font(.callout)
                SecureField("", text: $clientSecret)
                    .textFieldStyle(.roundedBorder)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button(busy ? "Opening…" : "Open Google") {
                    Task { await begin() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(clientId.trimmingCharacters(in: .whitespaces)
                    .isEmpty || busy)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 420)
    }

    private func begin() async {
        busy = true
        defer { busy = false }
        do {
            let flow = try await app.connections.beginGoogleOauth(
                clientId: clientId.trimmingCharacters(in: .whitespaces),
                clientSecret: clientSecret.isEmpty ? nil : clientSecret)
            guard app.security.openExternal(flow.authorizationUrl) else {
                throw KeyLeaseError(
                    "Could not open Google authorization", code: .client)
            }
            let complete = confirmAction(
                title: "Finish in the Google Picker",
                message: "Choose the files in your browser, then come "
                    + "back here.",
                confirmLabel: "Complete connection")
            guard complete else { return }
            try await app.connections.completeGoogleOauth(
                flowId: flow.flowId)
            dismiss()
        } catch {
            failure = UserMessage(error)
        }
    }
}

// MARK: - Approvals (`approvals_page.dart` + `RequestSummary`)

struct ApprovalsView: View {
    let app: AppController
    @State private var failure: UserMessage?

    private var controller: ApprovalsController { app.approvals }

    var body: some View {
        SectionScaffold(
            title: "Approvals",
            subtitle: "Requests waiting for a human decision")
        {
            Button {
                Task { await controller.list.load() }
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .controlSize(.small)
            .help("Refresh")
        } content: {
            if let failure {
                MessageBanner(
                    message: failure, onDismiss: { self.failure = nil })
            }
            sectionBody(
                controller.list,
                empty: "Nothing waiting for you."
            ) { items in
                ForEach(items, id: \.id) { approval in
                    ApprovalCard(
                        approval: approval,
                        onDecide: { approve in
                            await decide(approval, approve: approve)
                        })
                }
            }
        }
        .task { await controller.list.load() }
    }

    private func decide(_ approval: ApprovalRecord, approve: Bool) async {
        let summary = approval.semanticSummary
        guard
            confirmAction(
                title: approve
                    ? "Approve this exact request?" : "Deny this request?",
                message: "\(summary?.operation ?? approval.action ?? "Access")"
                    + " on "
                    + (summary?.target ?? approval.resource
                        ?? "unknown resource"),
                confirmLabel: approve ? "Approve" : "Deny",
                destructive: !approve)
        else { return }
        do {
            try await controller.decide(approval, approve: approve)
        } catch let stale as StaleApprovalError {
            failure = UserMessage(
                title: "That request moved on", detail: stale.message)
        } catch {
            failure = UserMessage(error)
        }
    }
}

private struct ApprovalCard: View {
    let approval: ApprovalRecord
    let onDecide: (Bool) async -> Void
    @State private var busy = false

    private var expiresAt: Date? {
        ISO8601DateFormatter.parse(approval.expiresAt)
    }

    var body: some View {
        let summary = approval.semanticSummary
        let expired = (expiresAt ?? .distantPast) <= Date()
        return VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(
                    summary?.operation ?? approval.action
                        ?? "Access request")
                    .font(.callout.weight(.semibold))
                Spacer()
                if let risk = approval.risk {
                    Text("\(risk.rawValue) risk")
                        .font(.caption)
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(
                            Capsule().fill(
                                risk == .r3 || risk == .r4
                                    ? Color.red.opacity(0.15)
                                    : Color.primary.opacity(0.08)))
                }
                if !approval.isPending || expired {
                    Text(expired ? "Expired" : approval.state.rawValue)
                        .font(.caption)
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(
                            Capsule().stroke(
                                Color.primary.opacity(0.2)))
                }
            }
            line("What it wants to do", approval.action ?? "unknown action")
            line(
                "Where",
                summary?.target ?? approval.resource ?? "unknown resource")
            line("Requested by", approval.agentId ?? "unknown client")
            if let changed = summary?.changedFields, !changed.isEmpty {
                line("Fields it would change", changed.joined(separator: ", "))
            }
            if let blast = summary?.blastRadius {
                line("Scope", blast)
            }
            line(
                expired ? "Expired" : "Expires",
                "\(expiresAt.map(friendlyTime) ?? approval.expiresAt) · "
                    + "policy v\(approval.policyVersion)")
            SectionLabel(title: "Exact request").padding(.top, 4)
            Text(approval.requestDigestHex)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
            HStack {
                Spacer()
                Button("Deny") {
                    busy = true
                    Task {
                        await onDecide(false)
                        busy = false
                    }
                }
                .disabled(busy || !approval.decidableNow)
                Button("Approve") {
                    busy = true
                    Task {
                        await onDecide(true)
                        busy = false
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(busy || !approval.decidableNow)
            }
            .padding(.top, 4)
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color.primary.opacity(0.12)))
    }

    private func line(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 4) {
            Text("\(label):").foregroundStyle(.secondary)
            Text(value)
        }
        .font(.callout)
    }
}

// MARK: - Activity (`activity_page.dart`)

struct ActivityView: View {
    let app: AppController

    private var controller: ActivityController { app.activity }

    var body: some View {
        SectionScaffold(
            title: "Activity",
            subtitle: "What the daemon allowed, denied, or changed")
        {
            HStack(spacing: 8) {
                Picker(
                    "",
                    selection: Binding(
                        get: { controller.deniedOnly },
                        set: { controller.deniedOnly = $0 })
                ) {
                    Text("All events").tag(false)
                    Text("Denied or failed").tag(true)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 220)
                Button {
                    Task { await controller.list.load() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .controlSize(.small)
                .help("Refresh")
            }
        } content: {
            sectionBody(
                controller.list,
                empty: "No events yet."
            ) { _ in
                ForEach(controller.filtered, id: \.requestId) { event in
                    eventRow(event)
                }
            }
        }
        .task { await controller.list.load() }
    }

    private func eventRow(_ event: AuditEvent) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(
                systemName: event.denied
                    ? "exclamationmark.shield" : "checkmark.circle")
                .foregroundStyle(event.denied ? .orange : .green)
            VStack(alignment: .leading, spacing: 2) {
                Text(event.action).font(.callout)
                Text(
                    "\(event.resource)\n\(event.agentId) · "
                        + friendlyTime(
                            ISO8601DateFormatter.parse(event.timestamp))
                        + (event.volume.isEmpty
                            ? "" : " · \(event.volume)"))
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Text(event.denied ? "Denied" : "Allowed")
                .font(.caption)
                .foregroundStyle(event.denied ? .orange : .secondary)
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Migrations (`migration_center.dart`)

struct MigrationsView: View {
    let app: AppController
    @State private var failure: UserMessage?

    private var vault: VaultController { app.vault }

    var body: some View {
        SectionScaffold(
            title: "Vault migrations",
            subtitle: "Pending upgrades and applied history")
        {
            Button {
                Task { await vault.loadMigrations() }
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .controlSize(.small)
            .help("Refresh")
        } content: {
            if let failure {
                MessageBanner(
                    message: failure, onDismiss: { self.failure = nil })
            }
            if let status = vault.migrationStatus {
                SectionLabel(title: "Pending")
                if status.pending.isEmpty {
                    Text("Nothing to migrate.")
                        .foregroundStyle(.secondary)
                }
                ForEach(status.pending, id: \.migrationId) { preview in
                    migrationCard(preview)
                }
                if !status.history.isEmpty {
                    SectionLabel(title: "History").padding(.top, 8)
                    FieldGroup {
                        ForEach(status.history, id: \.migrationId) {
                            entry in
                            DetailRow(
                                label: entry.migrationId,
                                value: "\(entry.state) · "
                                    + "\(entry.itemCount) items · "
                                    + entry.appliedAt)
                            {
                                if entry.rolledBackAt == nil {
                                    IconAction(
                                        label: "Roll back",
                                        icon: "arrow.uturn.backward",
                                        danger: true)
                                    {
                                        Task {
                                            await rollback(
                                                entry.migrationId)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                ProgressView().controlSize(.small)
            }
        }
        .task { await vault.loadMigrations() }
    }

    private func migrationCard(_ preview: MigrationPreview) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(preview.title).font(.callout.weight(.semibold))
                Spacer()
                Text("\(preview.proposals.count) items")
                    .font(.caption).foregroundStyle(.secondary)
            }
            ForEach(preview.proposals, id: \.itemId) { proposal in
                VStack(alignment: .leading, spacing: 2) {
                    Text(
                        "\(proposal.title): \(proposal.currentKind) → "
                            + proposal.proposedKind)
                        .font(.callout)
                    Text(proposal.reasons.joined(separator: " · "))
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            HStack {
                Spacer()
                Button("Apply migration") {
                    Task { await apply(preview) }
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color.primary.opacity(0.12)))
    }

    private func apply(_ preview: MigrationPreview) async {
        guard
            confirmAction(
                title: "Apply this migration?",
                message: "\(preview.proposals.count) items will be "
                    + "updated. A rollback point is kept.",
                confirmLabel: "Apply")
        else { return }
        do {
            try await vault.applyMigration(preview)
        } catch {
            failure = UserMessage(error)
        }
    }

    private func rollback(_ migrationId: String) async {
        guard
            confirmAction(
                title: "Roll back this migration?",
                message: "The items changed by this migration return to "
                    + "their previous state.",
                confirmLabel: "Roll back",
                destructive: true)
        else { return }
        do {
            try await vault.rollbackMigration(migrationId)
        } catch {
            failure = UserMessage(error)
        }
    }
}
