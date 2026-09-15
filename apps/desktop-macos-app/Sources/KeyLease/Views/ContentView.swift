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

struct ContentView: View {
    let app: AppController
    @State private var section: AppSection = .vault

    var body: some View {
        NavigationSplitView {
            SidebarView(app: app, section: $section)
                .navigationSplitViewColumnWidth(min: 170, ideal: 210)
        } content: {
            content
                .navigationSplitViewColumnWidth(min: 260, ideal: 320)
        } detail: {
            detail
        }
        .onChange(of: section) { loadSection() }
        .task { loadSection() }
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

    @ViewBuilder private var content: some View {
        switch section {
        case .vault:
            VaultListView(app: app)
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

    @ViewBuilder private var detail: some View {
        switch section {
        case .vault:
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
        default:
            // The manage sections render their own content; the detail
            // column mirrors the current section header.
            ContentUnavailableView(
                section.rawValue,
                systemImage: section.icon,
                description: Text(sectionDetailHint))
        }
    }

    private var sectionDetailHint: String {
        switch section {
        case .connections:
            "Connections are managed in the list on the left."
        case .approvals:
            "Decide a request from the list on the left."
        case .activity:
            "Recent access decisions appear in the list on the left."
        case .migrations:
            "Review pending migrations and history on the left."
        case .vault:
            ""
        }
    }
}

/// Sidebar: section rail plus the vault group tree (All items / Favorites /
/// nested groups with create-rename-delete-reorder).
private struct SidebarView: View {
    let app: AppController
    @Binding var section: AppSection
    @State private var newGroupAlert = false
    @State private var newGroupName = ""
    @State private var renaming: VaultGroup?
    @State private var renameText = ""
    @State private var groupError: UserMessage?

    var body: some View {
        List {
            Section {
                ForEach(AppSection.allCases) { item in
                    Button {
                        section = item
                    } label: {
                        Label(item.rawValue, systemImage: item.icon)
                    }
                    .buttonStyle(.plain)
                    .font(section == item ? .body.weight(.semibold) : .body)
                    .foregroundStyle(
                        section == item ? Color.accentColor : .primary)
                    .listRowBackground(
                        RoundedRectangle(cornerRadius: 6)
                            .fill(section == item
                                ? Color.accentColor.opacity(0.15)
                                : Color.clear))
                }
            }

            if section == .vault {
                vaultGroups
            }
        }
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
            groupRow(
                id: "__all", label: "All items", icon: "tray.full",
                selected: app.vault.selectedGroupId == nil
                    && !app.vault.favoritesOnly
            ) {
                app.vault.selectGroup(nil)
            }
            groupRow(
                id: "__favorites", label: "Favorites", icon: "star",
                selected: app.vault.favoritesOnly
            ) {
                app.vault.selectFavorites()
            }
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
                Button {
                    newGroupName = ""
                    newGroupAlert = true
                } label: {
                    Image(systemName: "plus")
                }
                .buttonStyle(.borderless)
                .help("New group inside the selected group")
            }
        }
    }

    private var rootGroups: [VaultGroup] {
        app.vault.orderedGroups.filter { $0.parentId == nil }
    }

    private func childrenOf(_ group: VaultGroup) -> [VaultGroup] {
        app.vault.orderedGroups.filter { $0.parentId == group.id }
    }

    @ViewBuilder
    private func groupRow(
        id: String, label: String, icon: String, selected: Bool,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            Label(label, systemImage: icon)
        }
        .buttonStyle(.plain)
        .foregroundStyle(selected ? Color.accentColor : .primary)
        .font(selected ? .body.weight(.semibold) : .body)
        .listRowBackground(
            RoundedRectangle(cornerRadius: 6)
                .fill(selected ? Color.accentColor.opacity(0.15) : .clear))
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
        Button {
            app.vault.selectGroup(group.id)
        } label: {
            Label(group.name, systemImage: "folder")
                .padding(.leading, CGFloat(depth) * 14)
        }
        .buttonStyle(.plain)
        .foregroundStyle(
            app.vault.selectedGroupId == group.id ? Color.accentColor
                : .primary)
        .font(
            app.vault.selectedGroupId == group.id
                ? .body.weight(.semibold) : .body)
        .listRowBackground(
            RoundedRectangle(cornerRadius: 6)
                .fill(
                    app.vault.selectedGroupId == group.id
                        ? Color.accentColor.opacity(0.15) : .clear))
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
