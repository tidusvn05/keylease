import SwiftUI

import KeyLeaseCore

/// Sidebar sections — Vault is live in milestone 1; the rest are placeholders
/// until the feature port lands (docs/desktop-native-swift-port.md §4).
enum AppSection: String, CaseIterable, Identifiable {
    case vault = "Vault"
    case connections = "Connections"
    case approvals = "Approvals"
    case activity = "Activity"
    case migrations = "Migrations"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .vault: "lock.shield"
        case .connections: "link"
        case .approvals: "checkmark.shield"
        case .activity: "clock.arrow.circlepath"
        case .migrations: "arrow.triangle.2.circlepath"
        }
    }
}

struct ContentView: View {
    let app: AppController
    @State private var section: AppSection? = .vault

    var body: some View {
        NavigationSplitView {
            List(AppSection.allCases, selection: $section) { item in
                Label(item.rawValue, systemImage: item.icon)
                    .tag(item)
            }
            .navigationSplitViewColumnWidth(min: 160, ideal: 200)
        } content: {
            switch section {
            case .vault:
                VaultListView(app: app)
            default:
                SectionPlaceholder(name: section?.rawValue ?? "")
            }
        } detail: {
            switch section {
            case .vault:
                if app.vault.selectedId != nil {
                    EntryDetailView(app: app)
                } else {
                    ContentUnavailableView(
                        "Select an item",
                        systemImage: "doc.text.magnifyingglass"
                    )
                }
            default:
                SectionPlaceholder(name: section?.rawValue ?? "")
            }
        }
    }
}

struct SectionPlaceholder: View {
    let name: String

    var body: some View {
        ContentUnavailableView(
            name,
            systemImage: "hammer",
            description: Text("Not yet ported — see the Swift port checklist.")
        )
    }
}
