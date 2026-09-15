import SwiftUI

import KeyLeaseCore

@main
struct KeyLeaseApp: App {
    @State private var app = AppController()

    var body: some Scene {
        WindowGroup(id: "main") {
            RootView(app: app)
                .frame(minWidth: 900, minHeight: 560)
                .tint(KL.Colors.accent)
                .task {
                    app.installLockObservers()
                    app.installQuickAccess()
                    await app.bootstrap()
                }
        }
        .defaultSize(width: 1100, height: 700)
        .commands {
            CommandMenu("Go") {
                Button("Vault") { app.section = .vault }
                    .keyboardShortcut("1", modifiers: .command)
                    .disabled(app.phase != .ready)
                Button("Connections") { app.section = .connections }
                    .keyboardShortcut("2", modifiers: .command)
                    .disabled(app.phase != .ready)
                Button("Approvals") { app.section = .approvals }
                    .keyboardShortcut("3", modifiers: .command)
                    .disabled(app.phase != .ready)
                Button("Activity") { app.section = .activity }
                    .keyboardShortcut("4", modifiers: .command)
                    .disabled(app.phase != .ready)
                Button("Migrations") { app.section = .migrations }
                    .keyboardShortcut("5", modifiers: .command)
                    .disabled(app.phase != .ready)
            }
            CommandMenu("Vault") {
                // Dart shortcuts.dart: meta-F search, meta-N new item,
                // meta-L lock; meta-comma opens Settings for free.
                Button("New Item") {
                    guard app.vault.confirmDiscardIfDirty() else { return }
                    app.vault.beginCreate()
                }
                .keyboardShortcut("n", modifiers: .command)
                .disabled(app.phase != .ready)

                Button("Password Generator") {
                    guard app.vault.confirmDiscardIfDirty() else { return }
                    app.vault.openPasswordGenerator()
                }
                .keyboardShortcut("g", modifiers: [.command, .shift])
                .disabled(app.phase != .ready)

                Divider()

                Button("Edit Item") {
                    guard app.vault.confirmDiscardIfDirty(),
                        let entry = app.vault.selectedEntry
                    else { return }
                    app.vault.beginEdit(entry)
                }
                .keyboardShortcut("e", modifiers: .command)
                .disabled(
                    app.phase != .ready || app.vault.selectedEntry == nil
                        || app.vault.workspaceMode == .edit)

                Button("Move to Recycle Bin") {
                    guard let entry = app.vault.selectedEntry,
                        confirmAction(
                            title: "Move to recycle bin?",
                            message: "“\(entry.title)” moves to the "
                                + "recycle bin. Anything already copied "
                                + "is unaffected.",
                            confirmLabel: "Delete",
                            destructive: true)
                    else { return }
                    Task {
                        await app.vault.deleteEntry(entry)
                        app.removeSshBindingsForItem(entry.id)
                    }
                }
                .keyboardShortcut(.delete, modifiers: .command)
                .disabled(
                    app.phase != .ready || app.vault.selectedEntry == nil)

                Divider()

                Button("Refresh") {
                    Task { await app.refresh() }
                }
                .keyboardShortcut("r", modifiers: .command)
                .disabled(app.phase != .ready)

                Divider()

                Button("Lock Vault") {
                    Task { await app.lock() }
                }
                .keyboardShortcut("l", modifiers: .command)
                .disabled(app.phase != .ready)
            }
        }

        Settings {
            SettingsView(app: app)
                .tint(KL.Colors.accent)
        }
    }
}
