import SwiftUI

import KeyLeaseCore

/// The searchable entry list — `entries_search` with the controller's
/// debounce, the Dart `EntryList` behaviour on a Mac list.
struct VaultListView: View {
    let app: AppController
    @State private var searchText = ""
    @State private var deletingEntry: ItemMetadata?

    private var selection: Binding<String?> {
        Binding(
            get: { app.vault.selectedId },
            set: { if let id = $0 {
                guard app.vault.confirmDiscardIfDirty() else { return }
                app.vault.select(id)
            } })
    }

    var body: some View {
        List(app.vault.visibleEntries, id: \.id, selection: selection) {
            entry in
            EntryRow(entry: entry, kindLabel: app.vault.kindLabel(entry.kind))
                .tag(entry.id)
                .contextMenu {
                    Button(entry.favorite
                        ? "Remove from favorites" : "Add to favorites")
                    {
                        Task { await app.vault.toggleFavorite(entry) }
                    }
                    Button("Edit") {
                        guard app.vault.confirmDiscardIfDirty() else { return }
                        app.vault.beginEdit(entry)
                    }
                    Divider()
                    Button("Delete", role: .destructive) {
                        deletingEntry = entry
                    }
                }
        }
        .searchable(text: $searchText, prompt: "Search items")
        .onChange(of: searchText) { app.vault.setQuery(searchText) }
        .onAppear { searchText = app.vault.query }
        // Dart entry_list.dart: arrow keys move the selection.
        .onMoveCommand { direction in
            app.vault.moveSelection(direction == .down ? 1 : -1)
        }
        .overlay { stateOverlay }
        .safeAreaInset(edge: .bottom) {
            if app.vault.listState == .content {
                Text(
                    "\(app.vault.visibleEntries.count) "
                        + (app.vault.visibleEntries.count == 1
                            ? "item" : "items"))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, KL.Space.xxl)
                    .padding(.vertical, KL.Space.s)
                    .background(.bar)
            }
        }
        .navigationTitle("Vault")
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    guard app.vault.confirmDiscardIfDirty() else { return }
                    app.vault.beginCreate()
                } label: {
                    Label("New item", systemImage: "plus")
                }
                .help("New item")

                Button {
                    guard app.vault.confirmDiscardIfDirty() else { return }
                    app.vault.openPasswordGenerator()
                } label: {
                    Label("Password generator", systemImage: "wand.and.stars")
                }
                .labelStyle(.iconOnly)
                .help("Password generator")
            }
        }
        .alert(
            "Move to recycle bin?",
            isPresented: Binding(
                get: { deletingEntry != nil },
                set: { if !$0 { deletingEntry = nil } }),
            presenting: deletingEntry
        ) { entry in
            Button("Delete", role: .destructive) {
                Task {
                    await app.vault.deleteEntry(entry)
                    app.removeSshBindingsForItem(entry.id)
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: { entry in
            Text("“\(entry.title)” moves to the recycle bin. "
                + "Anything already copied is unaffected.")
        }
    }

    @ViewBuilder private var stateOverlay: some View {
        switch app.vault.listState {
        case .loading where app.vault.visibleEntries.isEmpty:
            ProgressView()
        case .empty:
            ContentUnavailableView(
                "No items yet",
                systemImage: "tray",
                description: Text(
                    "Create your first item with the + button."))
        case .searchEmpty:
            ContentUnavailableView(
                "Nothing matches",
                systemImage: "magnifyingglass",
                description: Text("Try a different search."))
        default:
            if let error = app.vault.error {
                VStack {
                    MessageBanner(
                        message: error, actionLabel: "Retry",
                        onAction: { Task { await app.vault.reload() } })
                        .padding()
                    Spacer()
                }
            }
        }
    }
}

/// One list row — monogram, title, subtitle, favorite/TOTP badges.
private struct EntryRow: View {
    let entry: ItemMetadata
    let kindLabel: String

    var body: some View {
        HStack(spacing: KL.Space.l) {
            MonogramMark(text: entry.monogram)
            VStack(alignment: .leading, spacing: KL.Space.xxs) {
                HStack(spacing: KL.Space.s) {
                    Text(entry.title).font(.headline).lineLimit(1)
                    if entry.favorite {
                        Image(systemName: "star.fill")
                            .foregroundStyle(KL.Colors.warning)
                            .font(.caption)
                    }
                    if entry.hasTotp {
                        Image(systemName: "timer")
                            .foregroundStyle(.secondary)
                            .font(.caption)
                    }
                }
                Text(entry.subtitle.isEmpty ? kindLabel : entry.subtitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, KL.Space.xs)
    }
}
