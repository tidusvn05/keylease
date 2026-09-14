import SwiftUI

import KeyLeaseCore

@main
struct KeyLeaseApp: App {
    @State private var app = AppController()

    var body: some Scene {
        WindowGroup {
            RootView(app: app)
                .frame(minWidth: 900, minHeight: 560)
                .task {
                    app.installLockObservers()
                    await app.bootstrap()
                }
        }
        .defaultSize(width: 1100, height: 700)
        .commands {
            CommandMenu("Vault") {
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
        }
    }
}
