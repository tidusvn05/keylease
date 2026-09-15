import SwiftUI

import KeyLeaseCore

@main
struct KeyLeaseApp: App {
    @State private var app = AppController()

    var body: some Scene {
        WindowGroup {
            RootView(app: app)
                .frame(minWidth: 900, minHeight: 560)
                .tint(KL.Colors.accent)
                .task {
                    app.installLockObservers()
                    await app.bootstrap()
                }
        }
        .defaultSize(width: 1100, height: 700)
        .commands {
            CommandMenu("Vault") {
                // Dart shortcuts.dart: meta-F search, meta-N new item,
                // meta-L lock; meta-comma opens Settings for free.
                Button("New Item") {
                    app.vault.beginCreate()
                }
                .keyboardShortcut("n", modifiers: .command)
                .disabled(app.phase != .ready)

                Button("Password Generator") {
                    app.vault.openPasswordGenerator()
                }
                .keyboardShortcut("g", modifiers: [.command, .shift])
                .disabled(app.phase != .ready)

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
