import Foundation

import KeyLeaseCore

/// Entries list + selected entry detail — the milestone-1 slice of the Dart
/// `VaultController` (search, view, reveal, TOTP).
@MainActor @Observable
final class VaultController {
    var query = ""
    private(set) var entries: [ItemMetadata] = []
    private(set) var loading = false
    var selectedId: String? {
        didSet { Task { await loadDetail() } }
    }
    private(set) var detail: EntryView?
    /// Revealed values keyed by field id; cleared on lock or reselect.
    private(set) var revealed: [String: String] = [:]
    private(set) var totp: String?
    var error: UserMessage?

    private var client: KeyLeaseClient?

    func load(using client: KeyLeaseClient) async {
        self.client = client
        await reload()
    }

    func reload() async {
        guard let client else { return }
        loading = true
        defer { loading = false }
        do {
            let result = try await client.authorized(
                .entriesSearch(query: query))
            entries = try result.decoded(as: [ItemMetadata].self)
            if let selectedId, !entries.contains(where: { $0.id == selectedId })
            {
                self.selectedId = nil
                detail = nil
            }
            error = nil
        } catch {
            self.error = UserMessage(error)
        }
    }

    func loadDetail() async {
        guard let client, let selectedId else {
            detail = nil
            return
        }
        do {
            let result = try await client.authorized(.entriesView(id: selectedId))
            detail = try result.decoded(as: EntryView.self)
            revealed = [:]
            totp = nil
            error = nil
        } catch {
            self.error = UserMessage(error)
        }
    }

    /// `entries_reveal` — asks the daemon for one concealed field.
    func reveal(_ field: FieldView) async {
        guard let client, let selectedId else { return }
        do {
            let result = try await client.authorized(
                .entriesReveal(id: selectedId, field: field.key))
            if let value = result["value"]?.stringValue {
                revealed[field.id] = value
            }
            error = nil
        } catch {
            self.error = UserMessage(error)
        }
    }

    /// `entries_totp` — current TOTP code for the selected entry.
    func loadTotp() async {
        guard let client, let selectedId else { return }
        do {
            let result = try await client.authorized(
                .entriesTotp(id: selectedId))
            totp = result["code"]?.stringValue
                ?? result["totp"]?.stringValue
                ?? result.objectValue?.values
                    .compactMap(\.stringValue).first
            error = nil
        } catch {
            self.error = UserMessage(error)
        }
    }

    func clear() {
        entries = []
        detail = nil
        revealed = [:]
        totp = nil
        selectedId = nil
        error = nil
    }
}
