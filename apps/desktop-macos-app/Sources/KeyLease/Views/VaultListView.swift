import SwiftUI

import KeyLeaseCore

/// Searchable entry list — `entries_search` driven by `.searchable`.
struct VaultListView: View {
    let app: AppController

    var body: some View {
        List(
            app.vault.entries,
            id: \.id,
            selection: Bindable(app.vault).selectedId
        ) { entry in
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(entry.title).font(.headline)
                    if entry.favorite {
                        Image(systemName: "star.fill")
                            .foregroundStyle(.yellow)
                            .font(.caption)
                    }
                    if entry.hasTotp {
                        Image(systemName: "timer")
                            .foregroundStyle(.secondary)
                            .font(.caption)
                    }
                }
                if let username = entry.username {
                    Text(username)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }
            .tag(entry.id)
        }
        .searchable(text: Bindable(app.vault).query, prompt: "Search items")
        .onChange(of: app.vault.query) {
            Task { await app.vault.reload() }
        }
        .overlay {
            if !app.vault.loading && app.vault.entries.isEmpty {
                ContentUnavailableView(
                    "No items",
                    systemImage: "tray",
                    description: Text("The vault has no items yet.")
                )
            }
        }
        .navigationTitle("Vault")
    }
}
