import SwiftUI

/// Minimal Settings scene — service info + data folder. The full settings
/// surface (connections, multi-vault, preferences) is part of the port.
struct SettingsView: View {
    let app: AppController

    var body: some View {
        Form {
            Section("Service") {
                LabeledContent(
                    "Version",
                    value: app.serviceVersion ?? "unknown")
                LabeledContent(
                    "Vault",
                    value: app.status?.vaultId ?? "none")
                LabeledContent(
                    "Socket",
                    value: ConnectionDefaults.socketPath)
            }
            Section("Data") {
                Button("Open data folder") {
                    _ = app.runtime.openDataFolder()
                }
            }
        }
        .formStyle(.grouped)
        .frame(width: 460, height: 240)
        .padding()
    }
}
