import SwiftUI

import KeyLeaseCore

/// The macOS Settings scene — the Dart `settings_page.dart` general,
/// vaults and security destinations as native tabs.
struct SettingsView: View {
    let app: AppController
    @State private var tab = SettingsTab.general

    enum SettingsTab {
        case general, vaults, migrations, security
    }

    var body: some View {
        TabView(selection: $tab) {
            GeneralSettingsTab(
                app: app, onOpenMigrations: { tab = .migrations })
                .tabItem { Label("General", systemImage: "gearshape") }
                .tag(SettingsTab.general)
            VaultsSettingsTab(app: app)
                .tabItem { Label("Vaults", systemImage: "externaldrive") }
                .tag(SettingsTab.vaults)
            MigrationsView(app: app)
                .tabItem {
                    Label(
                        "Migrations",
                        systemImage: "arrow.triangle.2.circlepath")
                }
                .tag(SettingsTab.migrations)
            SecuritySettingsTab()
                .tabItem { Label("Security", systemImage: "lock") }
                .tag(SettingsTab.security)
        }
        .frame(width: 560, height: 420)
    }
}

// MARK: - General

private struct GeneralSettingsTab: View {
    let app: AppController
    let onOpenMigrations: () -> Void
    @State private var repairPassword = ""
    @State private var repairing = false
    @State private var failure: UserMessage?

    var body: some View {
        Form {
            if let failure {
                Section {
                    MessageBanner(
                        message: failure,
                        onDismiss: { self.failure = nil })
                }
            }
            Section("General") {
                LabeledContent("KeyLease data") {
                    Text(
                        "Vault, backups, and runtime files are kept "
                            + "privately in ~/.keylease.")
                        .font(.caption).foregroundStyle(.secondary)
                    KLButton(title: "Open folder", icon: "folder") {
                        app.openDataFolder()
                    }
                    .controlSize(.small)
                }
                LabeledContent("Vault migrations") {
                    Text(
                        (app.vault.migrationStatus?.pending.isEmpty ?? true)
                            ? "Review migration history and rollback "
                                + "checkpoints."
                            : "\(app.vault.migrationStatus?.pending.first?.proposals.count ?? 0) items need review.")
                        .font(.caption).foregroundStyle(.secondary)
                    KLButton(title: "Review", icon: "arrow.right") {
                        onOpenMigrations()
                    }
                    .controlSize(.small)
                }
                LabeledContent("Background service") {
                    Text(
                        app.serviceVersion.map {
                            "Version \($0) · runs automatically while you "
                                + "are signed in."
                        } ?? "Runs automatically while you are signed in.")
                        .font(.caption).foregroundStyle(.secondary)
                    KLButton(
                        title: "Restart", icon: "arrow.clockwise")
                    {
                        Task { await app.restartService() }
                    }
                    .controlSize(.small)
                }
                LabeledContent("Version") {
                    Text(app.serviceVersion ?? "unknown")
                        .foregroundStyle(.secondary)
                }
            }
            if app.phase == .repairRequired {
                Section("Repair") {
                    Text(
                        "Enter your vault password to recreate this Mac's "
                            + "local desktop credential. Vault data is "
                            + "unchanged.")
                        .font(.caption).foregroundStyle(.secondary)
                    SecureField("Master password", text: $repairPassword)
                        .textFieldStyle(.roundedBorder)
                    KLButton(
                        title: repairing
                            ? "Repairing…" : "Repair connection",
                        role: .primary)
                    {
                        let password = repairPassword
                        guard !password.isEmpty else { return }
                        repairing = true
                        Task {
                            _ = await app.repairClient(password: password)
                            repairPassword = ""
                            repairing = false
                        }
                    }
                    .disabled(repairPassword.isEmpty || repairing)
                    .controlSize(.small)
                }
            }
        }
        .formStyle(.grouped)
        .controlSize(.large)
        .padding()
    }
}

// MARK: - Vaults

private struct VaultsSettingsTab: View {
    let app: AppController
    @State private var creating = false
    @State private var newName = ""
    @State private var newPassword = ""
    @State private var renaming: VaultProfile?
    @State private var renameText = ""
    @State private var failure: UserMessage?

    var body: some View {
        Form {
            if let failure {
                Section {
                    MessageBanner(
                        message: failure,
                        onDismiss: { self.failure = nil })
                }
            }
            Section {
                ForEach(app.vaultProfiles) { profile in
                    LabeledContent(profile.name) {
                        HStack {
                            Text(
                                profile.active
                                    ? "Active vault"
                                    : "Locked until selected")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            IconAction(
                                label: "Rename \(profile.name)",
                                icon: "square.and.pencil")
                            {
                                renaming = profile
                                renameText = profile.name
                            }
                            if !profile.active {
                                KLButton(title: "Switch") {
                                    Task {
                                        await app.switchManagedVault(
                                            profile.id)
                                    }
                                }
                                .controlSize(.small)
                            }
                        }
                    }
                }
            } header: {
                HStack {
                    Text("Vaults")
                    Spacer()
                    KLButton(title: "Import") { importVault() }
                        .controlSize(.small)
                    KLButton(title: "New vault", icon: "plus") {
                        newName = ""
                        newPassword = ""
                        creating = true
                    }
                    .controlSize(.small)
                }
            }
        }
        .formStyle(.grouped)
        .controlSize(.large)
        .padding()
        .alert("New vault", isPresented: $creating) {
            TextField("Vault name", text: $newName)
            SecureField("Master password", text: $newPassword)
                .textFieldStyle(.roundedBorder)
            Button("Create") {
                let name = newName.trimmingCharacters(in: .whitespaces)
                guard !name.isEmpty, !newPassword.isEmpty else { return }
                Task {
                    do {
                        try await app.createManagedVault(
                            name: name,
                            request: .object([
                                "mode": .string("create"),
                                "password": .string(newPassword),
                            ]))
                    } catch {
                        failure = UserMessage(error)
                    }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This vault has its own master password.")
        }
        .alert(
            "Rename vault",
            isPresented: Binding(
                get: { renaming != nil },
                set: { if !$0 { renaming = nil } })
        ) {
            TextField("Vault name", text: $renameText)
            Button("Rename") {
                guard let profile = renaming else { return }
                let name = renameText.trimmingCharacters(in: .whitespaces)
                guard !name.isEmpty, name != profile.name else { return }
                Task {
                    do {
                        try await app.renameManagedVault(
                            profile.id, name: name)
                    } catch {
                        failure = UserMessage(error)
                    }
                }
            }
            Button("Cancel", role: .cancel) { renaming = nil }
        }
        .sheet(item: $importSource) { request in
            ImportVaultSheet(
                app: app, path: request.path, kind: request.kind)
        }
    }

    /// `_importVault` — pick a source, inspect it, then run the matching
    /// `vault-create` mode as a new managed vault.
    private func importVault() {
        guard let path = app.chooseVaultSource() else { return }
        Task {
            do {
                let source = try await app.inspectSource(path: path)
                let kind = source["kind"]?.stringValue ?? ""
                importSheet(path: path, kind: kind)
            } catch {
                failure = UserMessage(error)
            }
        }
    }

    /// The import dialog needs name + passwords, so it is its own sheet.
    private func importSheet(path: String, kind: String) {
        importSource = ImportRequest(path: path, kind: kind)
    }

    @State private var importSource: ImportRequest?

    private struct ImportRequest: Identifiable {
        let id = UUID()
        let path: String
        let kind: String
    }
}

/// The "Import as a new vault" dialog — mode comes from
/// `desktop inspect-source` (`keylease_database` / `keylease_backup` /
/// `kdbx` / `onepux`).
private struct ImportVaultSheet: View {
    let app: AppController
    let path: String
    let kind: String
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var sourcePassword = ""
    @State private var password = ""
    @State private var failure: UserMessage?
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Import as a new vault").font(.headline)
            Text("The imported vault remains independent from your "
                + "current vault.")
                .font(.callout).foregroundStyle(.secondary)
            if let failure {
                MessageBanner(
                    message: failure, onDismiss: { self.failure = nil })
            }
            VStack(alignment: .leading, spacing: 4) {
                Text("Vault name").font(.callout)
                TextField("", text: $name)
                    .textFieldStyle(.roundedBorder)
            }
            if kind == "kdbx" {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Source password").font(.callout)
                    SecureField("", text: $sourcePassword)
                        .textFieldStyle(.roundedBorder)
                }
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(
                    kind == "keylease_database"
                        ? "Vault password" : "New master password")
                    .font(.callout)
                SecureField("", text: $password)
                    .textFieldStyle(.roundedBorder)
            }
            if kind == "onepux" {
                Text("1PUX export contains plaintext secrets; importing "
                    + "acknowledges that.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            HStack {
                Spacer()
                KLButton(title: "Cancel", role: .ghost) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                KLButton(
                    title: busy ? "Importing…" : "Import", role: .primary)
                {
                    Task { await run() }
                }
                .disabled(
                    name.trimmingCharacters(in: .whitespaces).isEmpty
                        || password.isEmpty || busy)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(KL.Space.xxxl)
        .frame(width: 420)
        .controlSize(.large)
    }

    private func run() async {
        busy = true
        defer { busy = false }
        let mode: String = switch kind {
        case "keylease_database": "adopt_keylease_database"
        case "keylease_backup": "restore_keylease_backup"
        case "kdbx": "import_kdbx"
        default: "import_onepux"
        }
        var request: [String: JSONValue] = [
            "mode": .string(mode),
            "source_path": .string(path),
            "password": .string(password),
        ]
        if kind == "kdbx" {
            request["source_password"] = .string(sourcePassword)
        }
        if kind == "onepux" {
            request["acknowledge_plaintext"] = .bool(true)
        }
        do {
            try await app.createManagedVault(
                name: name.trimmingCharacters(in: .whitespaces),
                request: .object(request))
            dismiss()
        } catch {
            failure = UserMessage(error)
        }
    }
}

// MARK: - Security

private struct SecuritySettingsTab: View {
    var body: some View {
        Form {
            Section("Security") {
                LabeledContent("Clipboard") {
                    Text(
                        "Copied secrets are cleared after 30 seconds if "
                            + "nothing else has replaced them.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                LabeledContent("Sleep and screen lock") {
                    Text(
                        "KeyLease locks the vault and hides revealed "
                            + "secrets when this Mac sleeps or locks.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
        .controlSize(.large)
        .padding()
    }
}
