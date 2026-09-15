import SwiftUI

import KeyLeaseCore

/// Top-level sections — the Dart `AppSection` rail. Vault hosts the group
/// tree and the entry list; the rest are the read/manage surfaces.
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

/// Unified sidebar selection — one `List(selection:)` drives both the
/// section rail and the vault group tree.
private enum SidebarItem: Hashable {
    case section(AppSection)
    case allItems
    case favorites
    case group(String)
}

struct ContentView: View {
    let app: AppController
    @State private var section: AppSection = .vault

    var body: some View {
        Group {
            if section == .vault {
                // Vault keeps the classic three-pane mail layout.
                NavigationSplitView {
                    sidebar
                } content: {
                    VaultListView(app: app)
                        .navigationSplitViewColumnWidth(
                            min: 260, ideal: 306, max: 400)
                } detail: {
                    vaultDetail
                }
            } else {
                // Manage sections want the full window width — the old
                // middle column was only ever a placeholder for them.
                NavigationSplitView {
                    sidebar
                } detail: {
                    sectionContent
                }
            }
        }
        .onChange(of: section) { loadSection() }
        .task { loadSection() }
    }

    private var sidebar: some View {
        SidebarView(app: app, section: $section)
            .navigationSplitViewColumnWidth(min: 180, ideal: 214, max: 280)
    }

    /// Section switches trigger the controller loads, like the Dart
    /// `_select` in the settings/sidebar.
    private func loadSection() {
        switch section {
        case .vault:
            Task { await app.vault.reload() }
        case .connections:
            Task { await app.connections.list.load() }
        case .approvals:
            Task { await app.approvals.list.load() }
        case .activity:
            Task { await app.activity.list.load() }
        case .migrations:
            Task { await app.vault.loadMigrations() }
        }
    }

    @ViewBuilder private var sectionContent: some View {
        switch section {
        case .vault:
            EmptyView()
        case .connections:
            ConnectionsView(app: app)
        case .approvals:
            ApprovalsView(app: app)
        case .activity:
            ActivityView(app: app)
        case .migrations:
            MigrationsView(app: app)
        }
    }

    @ViewBuilder private var vaultDetail: some View {
        switch app.vault.workspaceMode {
        case .create, .edit:
            EntryEditorView(app: app)
        case .passwordGenerator:
            PasswordGeneratorView(app: app)
        case .detail:
            if app.vault.selectedEntry != nil {
                EntryDetailView(app: app)
            } else {
                ContentUnavailableView(
                    "Select an item",
                    systemImage: "doc.text.magnifyingglass",
                    description: Text(
                        "Choose an item on the left to see its details."))
            }
        }
    }
}

/// Sidebar: section rail plus the vault group tree (All items / Favorites /
/// nested groups with create-rename-delete-reorder). Rows ride on the
/// native sidebar selection — no hand-drawn highlight.
private struct SidebarView: View {
    let app: AppController
    @Binding var section: AppSection
    @State private var newGroupAlert = false
    @State private var newGroupName = ""
    @State private var renaming: VaultGroup?
    @State private var renameText = ""
    @State private var groupError: UserMessage?

    /// Maps between the flat `SidebarItem` selection and the two pieces
    /// of state it controls (top-level section + vault group filter).
    private var selection: Binding<SidebarItem?> {
        Binding(
            get: {
                guard section == .vault else { return .section(section) }
                if app.vault.favoritesOnly { return .favorites }
                if let id = app.vault.selectedGroupId { return .group(id) }
                return .allItems
            },
            set: { newValue in
                switch newValue {
                case .section(let item):
                    section = item
                case .allItems:
                    section = .vault
                    app.vault.selectGroup(nil)
                case .favorites:
                    section = .vault
                    app.vault.selectFavorites()
                case .group(let id):
                    section = .vault
                    app.vault.selectGroup(id)
                case nil:
                    break
                }
            })
    }

    var body: some View {
        List(selection: selection) {
            Section {
                ForEach(AppSection.allCases) { item in
                    Label(item.rawValue, systemImage: item.icon)
                        .tag(SidebarItem.section(item))
                }
            }

            if section == .vault {
                vaultGroups
            }
        }
        .listStyle(.sidebar)
        .alert("New group", isPresented: $newGroupAlert) {
            TextField("Group name", text: $newGroupName)
            Button("Create") {
                let name = newGroupName.trimmingCharacters(in: .whitespaces)
                guard !name.isEmpty else { return }
                Task {
                    do {
                        try await app.vault.createGroup(name: name)
                    } catch {
                        groupError = UserMessage(error)
                    }
                }
            }
            Button("Cancel", role: .cancel) {}
        }
        .alert(
            "Rename group",
            isPresented: Binding(
                get: { renaming != nil },
                set: { if !$0 { renaming = nil } })
        ) {
            TextField("Group name", text: $renameText)
            Button("Rename") {
                guard let group = renaming else { return }
                let name = renameText.trimmingCharacters(in: .whitespaces)
                guard !name.isEmpty else { return }
                Task {
                    do {
                        try await app.vault.renameGroup(group, name: name)
                    } catch {
                        groupError = UserMessage(error)
                    }
                }
            }
            Button("Cancel", role: .cancel) { renaming = nil }
        }
    }

    @ViewBuilder private var vaultGroups: some View {
        Section("Items") {
            Label("All items", systemImage: "tray.full")
                .tag(SidebarItem.allItems)
            Label("Favorites", systemImage: "star")
                .tag(SidebarItem.favorites)
        }

        Section {
            ForEach(rootGroups) { group in
                GroupRow(
                    group: group, depth: 0,
                    app: app, children: childrenOf,
                    onRename: {
                        renaming = $0
                        renameText = $0.name
                    },
                    onDelete: deleteGroup,
                    onMove: move)
            }
        } header: {
            HStack {
                Text("Groups")
                Spacer()
                KLIconButton(
                    label: "New group inside the selected group",
                    icon: "plus")
                {
                    newGroupName = ""
                    newGroupAlert = true
                }
            }
        }
    }

    private var rootGroups: [VaultGroup] {
        app.vault.orderedGroups.filter { $0.parentId == nil }
    }

    private func childrenOf(_ group: VaultGroup) -> [VaultGroup] {
        app.vault.orderedGroups.filter { $0.parentId == group.id }
    }

    private func deleteGroup(_ group: VaultGroup) {
        guard confirmAction(
            title: "Delete “\(group.name)”?",
            message: "The group must be empty. Items inside it stay in the "
                + "vault.",
            confirmLabel: "Delete",
            destructive: true
        ) else { return }
        Task {
            do {
                try await app.vault.deleteGroup(group)
            } catch {
                groupError = UserMessage(error)
            }
        }
    }

    private func move(_ group: VaultGroup, offset: Int) {
        let siblings = (group.parentId == nil ? rootGroups : childrenOf(
            app.vault.orderedGroups.first { $0.id == group.parentId }!
        ))
        guard let index = siblings.firstIndex(of: group) else { return }
        let next = index + offset
        guard next >= 0, next < siblings.count else { return }
        var ordered = siblings
        ordered.remove(at: index)
        ordered.insert(group, at: next)
        Task {
            do {
                try await app.vault.reorderGroups(
                    parentId: group.parentId, ordered: ordered)
            } catch {
                groupError = UserMessage(error)
            }
        }
    }
}

/// One group row plus its children — recursive because `OutlineGroup`
/// needs a collection tree, and this also gives indent + context menus.
private struct GroupRow: View {
    let group: VaultGroup
    let depth: Int
    let app: AppController
    let children: (VaultGroup) -> [VaultGroup]
    let onRename: (VaultGroup) -> Void
    let onDelete: (VaultGroup) -> Void
    let onMove: (VaultGroup, Int) -> Void

    var body: some View {
        Label(group.name, systemImage: "folder")
            .padding(.leading, CGFloat(depth) * 14)
            .tag(SidebarItem.group(group.id))
            .contextMenu {
                Button("Rename") { onRename(group) }
                Button("Move up") { onMove(group, -1) }
                Button("Move down") { onMove(group, 1) }
                Divider()
                Button("Delete", role: .destructive) { onDelete(group) }
            }
        ForEach(children(group)) { child in
            GroupRow(
                group: child, depth: depth + 1, app: app,
                children: children, onRename: onRename,
                onDelete: onDelete, onMove: onMove)
        }
    }
}
