import AppKit
import SwiftUI

import KeyLeaseCore

/// The menu-bar quick-access popover (⌥⌘K): search, copy a secret, or
/// jump to an item in the main window — without leaving the current app.
struct QuickAccessView: View {
    let app: AppController
    @Binding var presented: Bool
    @Environment(\.openWindow) private var openWindow
    @State private var query = ""
    @State private var results: [ItemMetadata] = []
    @State private var highlight = 0
    @State private var copiedId: String?
    @State private var searchTask: Task<Void, Never>?
    @FocusState private var searchFocused: Bool

    var body: some View {
        VStack(spacing: 0) {
            searchField
            Divider()
            content
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            Divider()
            footer
        }
        .frame(width: 340, height: 420)
        .onAppear {
            searchFocused = true
            search()
        }
        .onKeyPress(.escape) {
            presented = false
            return .handled
        }
        .onKeyPress(.upArrow) {
            highlight = max(0, highlight - 1)
            return .handled
        }
        .onKeyPress(.downArrow) {
            highlight = min(results.count - 1, highlight + 1)
            return .handled
        }
        .onKeyPress(.return) {
            guard results.indices.contains(highlight) else {
                return .ignored
            }
            copyPrimary(results[highlight])
            return .handled
        }
    }

    // MARK: Search field

    private var searchField: some View {
        HStack(spacing: KL.Space.l) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)
            TextField("Search vault", text: $query)
                .textFieldStyle(.plain)
                .focused($searchFocused)
                .onSubmit {
                    if results.indices.contains(highlight) {
                        copyPrimary(results[highlight])
                    }
                }
            if !query.isEmpty {
                Button {
                    query = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, KL.Space.xl)
        .padding(.vertical, KL.Space.l)
        .onChange(of: query) { search() }
    }

    // MARK: Results / states

    @ViewBuilder private var content: some View {
        if app.phase != .ready {
            VStack(spacing: KL.Space.l) {
                Image(systemName: "lock.fill")
                    .font(.title2).foregroundStyle(.secondary)
                Text(
                    app.phase == .locked
                        ? "The vault is locked." : "KeyLease is not ready.")
                    .font(.callout).foregroundStyle(.secondary)
                KLButton(title: "Open KeyLease", role: .primary) {
                    openMain()
                }
            }
        } else if results.isEmpty {
            ContentUnavailableView(
                query.isEmpty ? "No items yet" : "Nothing matches",
                systemImage: query.isEmpty ? "tray" : "magnifyingglass",
                description: Text(
                    query.isEmpty
                        ? "Your vault is empty."
                        : "Try a different search."))
        } else {
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(
                        Array(results.enumerated()), id: \.element.id
                    ) { index, entry in
                        row(entry, highlighted: index == highlight)
                    }
                }
            }
        }
    }

    private func row(_ entry: ItemMetadata, highlighted: Bool) -> some View {
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
                }
                Text(
                    entry.username
                        ?? (entry.subtitle.isEmpty
                            ? app.vault.kindLabel(entry.kind)
                            : entry.subtitle))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: KL.Space.l)
            if copiedId == entry.id {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(KL.Colors.success)
            } else {
                HStack(spacing: KL.Space.s) {
                    if entry.username?.isEmpty == false {
                        KLIconButton(
                            label: "Copy username", icon: "person")
                        {
                            copyField(entry, "username", "Username")
                        }
                    }
                    if entry.hasPassword {
                        KLIconButton(label: "Copy password", icon: "key")
                        {
                            copyField(entry, "password", "Password")
                        }
                    }
                    KLIconButton(label: "Open in KeyLease",
                                 icon: "arrow.up.forward.app") {
                        openInApp(entry)
                    }
                }
            }
        }
        .padding(.horizontal, KL.Space.xl)
        .padding(.vertical, KL.Space.s)
        .background(highlighted ? KL.Colors.accent.opacity(0.12) : .clear)
        .contentShape(Rectangle())
        .onTapGesture { copyPrimary(entry) }
    }

    private var footer: some View {
        HStack {
            Button {
                openMain()
            } label: {
                Label("Open KeyLease", systemImage: "macwindow")
                    .font(.callout)
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
            Spacer()
            if app.phase == .ready {
                Button {
                    presented = false
                    Task { await app.lock() }
                } label: {
                    Label("Lock", systemImage: "lock")
                        .font(.callout)
                }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, KL.Space.xl)
        .padding(.vertical, KL.Space.s)
    }

    // MARK: Actions

    /// Popover search — its own query, so the main window's list and
    /// selection stay untouched.
    private func search() {
        searchTask?.cancel()
        searchTask = Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(150))
            guard !Task.isCancelled else { return }
            results = await app.vault.searchEntries(query)
            highlight = 0
        }
    }

    /// Row click / Enter — the password if there is one, else the
    /// username, else just open the item in the main window.
    private func copyPrimary(_ entry: ItemMetadata) {
        if entry.hasPassword {
            copyField(entry, "password", "Password")
        } else if entry.username?.isEmpty == false {
            copyField(entry, "username", "Username")
        } else {
            openInApp(entry)
        }
    }

    private func copyField(
        _ entry: ItemMetadata, _ field: String, _ label: String
    ) {
        Task {
            let value = await app.vault.fetchSecret(
                entryId: entry.id, field: field)
            if let value, !value.isEmpty {
                _ = app.copySensitive(value, label: label)
                copiedId = entry.id
                Task {
                    try? await Task.sleep(for: .seconds(1.5))
                    copiedId = nil
                }
            }
        }
    }

    /// Reveal the item in the main window — the draft guard runs first
    /// so a dirty editor is never wiped silently.
    private func openInApp(_ entry: ItemMetadata) {
        guard app.vault.confirmDiscardIfDirty() else {
            presented = false
            return
        }
        presented = false
        app.vault.openAgentCreatedEntry(entry)
        openMain()
    }

    private func openMain() {
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
    }
}
