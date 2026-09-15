import Foundation

import KeyLeaseCore

/// Vault list/detail state — a direct port of the Dart `VaultController`:
/// groups, debounced search, selection, on-demand reveals, drafts,
/// migrations and agent-driven creation.
@MainActor @Observable
final class VaultController {
    /// Typing settles 220 ms before a search is sent (Dart `searchDebounce`).
    var searchDebounce: Duration = .milliseconds(220)
    /// Revealed values expire after 15 s (Dart `revealTimeout`).
    var revealTimeout: Duration = .seconds(15)

    private(set) var groups: [VaultGroup] = []
    private(set) var entries: [ItemMetadata] = []
    private(set) var templates: [ItemKindDefinition] = []
    private(set) var projects: [VaultProject] = []
    private(set) var migrationStatus: MigrationStatus?

    var query = ""
    private(set) var selectedGroupId: String?
    private(set) var favoritesOnly = false

    private(set) var selectedId: String?
    private(set) var workspaceMode: EntryWorkspaceMode = .detail
    private(set) var activeDraft: EntryDraft?
    private(set) var creationMode: EntryCreationMode = .manual
    private(set) var agentCreationDraft: AgentCreationDraft?

    var error: UserMessage?
    private(set) var lastFailure: Error?

    private(set) var loading = false
    private var loaded = false
    private var searching = false

    private var debounceTask: Task<Void, Never>?
    private var revealTask: Task<Void, Never>?
    private var issued = 0
    private var applied = 0

    /// Revealed values keyed by `entryId/field` — cleared on lock, sleep,
    /// selection change and the reveal timer.
    private(set) var revealed: [String: String] = [:]
    private(set) var entryViews: [String: EntryView] = [:]

    private var client: KeyLeaseClient?

    // MARK: - Derived list state

    var orderedGroups: [VaultGroup] {
        groups.sorted { left, right in
            let leftOrder = left.sortOrder ?? .max
            let rightOrder = right.sortOrder ?? .max
            if leftOrder != rightOrder { return leftOrder < rightOrder }
            let name = left.name.lowercased()
                .localizedStandardCompare(right.name.lowercased())
            return name == .orderedSame
                ? left.id < right.id
                : name == .orderedAscending
        }
    }

    var visibleEntries: [ItemMetadata] {
        if favoritesOnly { return entries.filter(\.favorite) }
        guard let root = selectedGroupId else { return entries }
        var ids: Set<String> = [root]
        var changed = true
        while changed {
            changed = false
            for group in groups
            where group.parentId.map(ids.contains) == true
                && !ids.contains(group.id)
            {
                ids.insert(group.id)
                changed = true
            }
        }
        return entries.filter { ids.contains($0.groupId) }
    }

    var listState: VaultListState {
        if !loaded || searching { return .loading }
        if !visibleEntries.isEmpty { return .content }
        return query.trimmingCharacters(in: .whitespaces).isEmpty
            ? .empty : .searchEmpty
    }

    /// The selection, normalized so an out-of-range id still shows the
    /// first visible entry (Dart `selectedEntry`).
    var selectedEntry: ItemMetadata? {
        let visible = visibleEntries
        if visible.isEmpty { return nil }
        return visible.first { $0.id == selectedId } ?? visible.first
    }

    var hasRevealedSecrets: Bool { !revealed.isEmpty }

    /// `revealedValue` — the on-screen value for `entryId/field`, if any.
    func revealedValue(_ entryId: String, _ field: String) -> String? {
        revealed["\(entryId)/\(field)"]
    }

    func kindLabel(_ kind: String) -> String {
        templates.first { $0.kind == kind }?.label ?? kind
    }

    func projectName(_ id: String?) -> String? {
        guard let id else { return nil }
        return projects.first { $0.id == id }?.name ?? id
    }

    // MARK: - Selection

    func select(_ entryId: String) {
        guard selectedId != entryId else { return }
        selectedId = entryId
        closeEditor()
        hideSecrets()
        Task { await loadEntryView(entryId) }
    }

    func moveSelection(_ delta: Int) {
        let visible = visibleEntries
        guard !visible.isEmpty, confirmDiscardIfDirty() else { return }
        let current = visible.firstIndex { $0.id == selectedId } ?? -1
        let next = min(max(current < 0 ? 0 : current + delta, 0),
                       visible.count - 1)
        select(visible[next].id)
    }

    func selectGroup(_ groupId: String?) {
        selectedGroupId = groupId
        favoritesOnly = false
        closeEditor()
        hideSecrets()
        normalizeSelection()
    }

    func selectFavorites() {
        selectedGroupId = nil
        favoritesOnly = true
        closeEditor()
        hideSecrets()
        normalizeSelection()
    }

    private func normalizeSelection() {
        let visible = visibleEntries
        if visible.isEmpty {
            selectedId = nil
            return
        }
        if !visible.contains(where: { $0.id == selectedId }) {
            selectedId = visible.first?.id
            revealed = [:]
        }
    }

    // MARK: - Draft lifecycle

    /// The editor checks this before discarding a draft (Dart callers do the
    /// same via `draft.isDirty` + a confirmation dialog).
    var draftIsDirty: Bool { activeDraft?.isDirty ?? false }

    /// `true` when no dirty draft blocks a workspace change — or the user
    /// just confirmed dropping it. The editor's Cancel uses the same dialog.
    func confirmDiscardIfDirty() -> Bool {
        let agentDirty = creationMode == .agentDriven
            && (agentCreationDraft?.isDirty ?? false)
        guard draftIsDirty || agentDirty else { return true }
        return confirmAction(
            title: "Discard changes?",
            message: "This item has unsaved changes. Discarding cannot "
                + "be undone.",
            confirmLabel: "Discard",
            destructive: true)
    }

    func beginCreate(kind: String = "core.login", initialPassword: String = "") {
        activeDraft?.wipeSecrets()
        let draft = EntryDraft(
            groupId: selectedGroupId ?? orderedGroups.first?.id,
            kind: kind,
            initialPassword: initialPassword)
        activeDraft = draft
        creationMode = .manual
        agentCreationDraft = AgentCreationDraft(
            kind: draft.kind, groupId: draft.groupId)
        workspaceMode = .create
        hideSecrets()
    }

    func beginCreateContent(kind: String) {
        activeDraft?.wipeSecrets()
        let draft = EntryDraft(kind: kind)
        activeDraft = draft
        creationMode = .manual
        agentCreationDraft = AgentCreationDraft(kind: kind, groupId: nil)
        workspaceMode = .create
        hideSecrets()
    }

    func openPasswordGenerator() {
        activeDraft?.wipeSecrets()
        activeDraft = nil
        agentCreationDraft = nil
        creationMode = .manual
        workspaceMode = .passwordGenerator
        hideSecrets()
    }

    /// Back out of the generator pane without touching the selection.
    func closePasswordGenerator() {
        workspaceMode = .detail
    }

    func beginEdit(_ entry: ItemMetadata) {
        agentCreationDraft = nil
        creationMode = .manual
        activeDraft?.wipeSecrets()
        activeDraft = EntryDraft(editing: entry)
        workspaceMode = .edit
        hideSecrets()
        // The editor hydrates template/dev-template fields from
        // `entries_view` once it arrives (Dart `ensureEntryView`).
        Task { await loadEntryView(entry.id) }
    }

    /// Call only after the UI confirmed a dirty draft may be dropped.
    func closeEditor() {
        activeDraft?.wipeSecrets()
        activeDraft = nil
        agentCreationDraft = nil
        creationMode = .manual
        workspaceMode = .detail
    }

    func useAgentCreation() async {
        guard let manual = activeDraft, manual.isNew else { return }
        let draft = agentCreationDraft ?? AgentCreationDraft(
            kind: manual.kind, groupId: manual.groupId)
        agentCreationDraft = draft
        if !draft.handoffCopied && draft.recipeId == "describe"
            && draft.context.isEmpty && draft.sourcePath.isEmpty
        {
            draft.kind = manual.kind
            draft.groupId = manual.groupId
        }
        creationMode = .agentDriven
        if draft.baselineEntryIds == nil {
            draft.baselineEntryIds = try? await snapshotEntryIds()
        }
    }

    func useManualCreation() {
        guard activeDraft != nil else { return }
        creationMode = .manual
    }

    // MARK: - Agent-driven creation

    func snapshotEntryIds() async throws -> Set<String> {
        guard let client else { return [] }
        let result = try await client.authorized(.entriesSearch(query: ""))
        return Set(try result.decoded(as: [ItemMetadata].self).map(\.id))
    }

    func createAgentHandoff(expectedVaultId: String) async throws
        -> AgentNewItemHandoffReceipt
    {
        guard let client, let draft = agentCreationDraft else {
            throw KeyLeaseError("No agent draft", code: .client)
        }
        let result = try await client.authorized(
            .agentHandoffCreate(input: draft.handoffInput(
                expectedVaultId: expectedVaultId)))
        return try result.decoded(as: AgentNewItemHandoffReceipt.self)
    }

    /// Entries created after the baseline snapshot — the "review what the
    /// agent made" list.
    func entriesCreatedSince(_ baseline: Set<String>) async throws
        -> [ItemMetadata]
    {
        guard let client else { return [] }
        let result = try await client.authorized(.entriesSearch(query: ""))
        let all = try result.decoded(as: [ItemMetadata].self)
        return all
            .filter { !baseline.contains($0.id) }
            .sorted { left, right in
                left.updatedAt == right.updatedAt
                    ? left.title < right.title
                    : left.updatedAt > right.updatedAt
            }
    }

    func openAgentCreatedEntry(_ entry: ItemMetadata) {
        activeDraft?.wipeSecrets()
        activeDraft = nil
        agentCreationDraft = nil
        creationMode = .manual
        workspaceMode = .detail
        query = ""
        selectedGroupId = nil
        favoritesOnly = false
        entries = [entry] + entries.filter { $0.id != entry.id }
        selectedId = entry.id
        hideSecrets()
        Task {
            await loadEntryView(entry.id)
            await search()
        }
    }

    // MARK: - Search

    /// Debounced search — every keystroke updates `query` immediately; only
    /// the newest response may replace the list (Dart `setQuery`/`_search`).
    func setQuery(_ value: String) {
        guard query != value else { return }
        query = value
        searching = true
        debounceTask?.cancel()
        debounceTask = Task { [weak self] in
            try? await Task.sleep(for: self?.searchDebounce ?? .zero)
            guard !Task.isCancelled else { return }
            await self?.search()
        }
    }

    func load(using client: KeyLeaseClient) async {
        self.client = client
        debounceTask?.cancel()
        await search(withGroups: true)
        await loadMigrations()
    }

    func reload() async {
        debounceTask?.cancel()
        await search(withGroups: true)
    }

    private func search(withGroups: Bool = false) async {
        guard let client else { return }
        issued += 1
        let sequence = issued
        searching = true
        defer { if sequence >= issued { searching = false } }
        do {
            var nextGroups: [VaultGroup]?
            var nextTemplates: [ItemKindDefinition]?
            var nextProjects: [VaultProject]?
            if withGroups {
                nextGroups = try await client.authorized(.groupsList)
                    .decoded(as: [VaultGroup].self)
                // Template/project discovery came after the first desktop
                // contract; keep startup working against an older daemon.
                nextTemplates = try? await client.authorized(.templatesList)
                    .decoded(as: [ItemKindDefinition].self)
                nextProjects = try? await client.authorized(.projectsList)
                    .decoded(as: [VaultProject].self)
            }
            let result = try await client.authorized(.entriesSearch(query: query))
            // A slower earlier query must never overwrite a newer screen.
            guard sequence > applied else { return }
            applied = sequence
            if let nextGroups { groups = nextGroups }
            if let nextTemplates { templates = nextTemplates }
            if let nextProjects { projects = nextProjects }
            entries = try result.decoded(as: [ItemMetadata].self)
            error = nil
            lastFailure = nil
            loaded = true
            normalizeSelection()
            if let selectedId {
                Task { await loadEntryView(selectedId) }
            }
        } catch {
            guard sequence > applied else { return }
            applied = sequence
            lastFailure = error
            self.error = UserMessage(error)
        }
    }

    func loadEntryView(_ entryId: String) async {
        guard let client else { return }
        do {
            let result = try await client.authorized(.entriesView(id: entryId))
            entryViews[entryId] = try result.decoded(as: EntryView.self)
            error = nil
        } catch {
            // An older daemon has no field-oriented view; the list data
            // stays and the detail pane degrades gracefully.
            lastFailure = error
        }
    }

    /// Convenience for the detail pane.
    var detail: EntryView? {
        selectedId.flatMap { entryViews[$0] }
    }

    // MARK: - Reveals

    /// Fetches a protected field without putting it on screen — copy uses
    /// this so a copy is not also an un-mask (Dart `fetchSecret`).
    func fetchSecret(entryId: String, field: String) async -> String? {
        guard let client else { return nil }
        do {
            let result = try await client.authorized(
                .entriesReveal(id: entryId, field: field))
            error = nil
            return result["value"]?.stringValue
        } catch {
            self.error = UserMessage(error)
            return nil
        }
    }

    @discardableResult
    func reveal(entryId: String, field: String) async -> String? {
        guard let value = await fetchSecret(entryId: entryId, field: field)
        else { return nil }
        revealed["\(entryId)/\(field)"] = value
        restartRevealTimer()
        return value
    }

    /// `entries_reveal_by_id` — the value returns through `FieldView`'s
    /// display path so typed values format correctly.
    func fetchField(entryId: String, field: FieldView) async -> String? {
        guard let client else { return nil }
        do {
            let result = try await client.authorized(
                .entriesRevealById(id: entryId, fieldId: field.id))
            error = nil
            guard let raw = result["value"] else { return nil }
            return field.withValue(
                try? raw.decoded(as: FieldValue.self)).displayValue
        } catch {
            self.error = UserMessage(error)
            return nil
        }
    }

    @discardableResult
    func revealField(entryId: String, field: FieldView) async -> String? {
        guard let value = await fetchField(entryId: entryId, field: field)
        else { return nil }
        revealed["\(entryId)/\(field.id)"] = value
        restartRevealTimer()
        return value
    }

    /// `entries_reveal_many` — for "copy all" and reveal-many controls.
    @discardableResult
    func fetchFields(entryId: String, fields: [FieldView]) async
        -> [String: String]
    {
        guard let client else { return [:] }
        do {
            let result = try await client.authorized(
                .entriesRevealMany(id: entryId, fieldIds: fields.map(\.id)))
            error = nil
            guard let raw = result["values"]?.objectValue else { return [:] }
            var output: [String: String] = [:]
            for field in fields where raw[field.id] != nil {
                output[field.id] = field.withValue(
                    try? raw[field.id]?.decoded(as: FieldValue.self)
                ).displayValue
            }
            return output
        } catch {
            self.error = UserMessage(error)
            return [:]
        }
    }

    func hideSecret(entryId: String, field: String) {
        revealed.removeValue(forKey: "\(entryId)/\(field)")
        if revealed.isEmpty {
            revealTask?.cancel()
            revealTask = nil
        }
    }

    /// Drops every revealed secret — called on lock, sleep and screen lock.
    func hideSecrets() {
        revealTask?.cancel()
        revealTask = nil
        revealed = [:]
    }

    private func restartRevealTimer() {
        revealTask?.cancel()
        revealTask = Task { [weak self] in
            try? await Task.sleep(for: self?.revealTimeout ?? .seconds(15))
            guard !Task.isCancelled else { return }
            self?.hideSecrets()
        }
    }

    // MARK: - Entry mutations

    private func idempotencyKey() -> String {
        "desktop-\(Int64(Date().timeIntervalSince1970 * 1_000_000))"
    }

    /// Drag-and-drop onto a sidebar group — a single-field
    /// `entries_update` patch guarded by the entry's last known revision.
    /// `groupId` of "" drops the item back into "All items" (ungrouped).
    func moveEntry(_ entryId: String, toGroup groupId: String) async throws {
        guard let client,
            let entry = entries.first(where: { $0.id == entryId }),
            entry.groupId != groupId
        else { return }
        _ = try await client.authorized(
            .entriesUpdate(
                id: entryId,
                patch: EntryPatch(
                    customFields: nil, favorite: nil, fieldUpdates: nil,
                    groupId: groupId, notes: nil, password: nil,
                    removeFieldIds: nil, sections: nil, title: nil,
                    totp: nil, totpUri: nil, url: nil, username: nil),
                ifRevision: entry.revision,
                idempotencyKey: idempotencyKey(),
                dryRun: false))
        await search()
    }

    /// Quick-access search — runs its own query so the menu-bar popover
    /// never disturbs the main window's debounced list and selection.
    func searchEntries(_ query: String) async -> [ItemMetadata] {
        guard let client,
            let result = try? await client.authorized(
                .entriesSearch(query: query))
        else { return [] }
        return (try? result.decoded(as: [ItemMetadata].self)) ?? []
    }

    /// Saves `draft`. On failure the draft is untouched so the editor can
    /// retry — revision conflicts surface as a `UserMessage`, never a
    /// dropped form (Dart `save`).
    @discardableResult
    func save(_ draft: EntryDraft) async throws -> String? {
        guard let client else { return nil }
        var savedId = draft.entryId
        if draft.isNew {
            if draft.isAgentContent {
                let created = try await client.authorized(
                    .contentCreate(
                        input: draft.contentCreateInput(),
                        idempotencyKey: idempotencyKey()))
                if let summary = created["summary"]?.objectValue {
                    savedId = summary["id"]?.stringValue
                }
                if draft.agentAccess != "none",
                    let id = savedId,
                    let revision = created["summary"]?["revision"]?.intValue
                {
                    _ = try await client.authorized(
                        .contentSetAccess(
                            id: id,
                            access: AgentAccess(rawValue: draft.agentAccess)
                                ?? .none,
                            ifRevision: UInt64(revision),
                            idempotencyKey: idempotencyKey()))
                }
            } else {
                let created = try await client.authorized(
                    .entriesCreate(
                        input: draft.createInput(),
                        idempotencyKey: idempotencyKey(),
                        dryRun: false))
                savedId = created["id"]?.stringValue ?? savedId
            }
        } else if draft.isAgentContent {
            _ = try await client.authorized(
                .contentUpdate(
                    id: draft.entryId!,
                    patch: draft.contentPatch(),
                    ifRevision: draft.revision,
                    idempotencyKey: idempotencyKey()))
        } else {
            _ = try await client.authorized(
                .entriesUpdate(
                    id: draft.entryId!,
                    patch: draft.patch(),
                    ifRevision: draft.revision,
                    idempotencyKey: idempotencyKey(),
                    dryRun: false))
        }
        await search()
        // Land on the item just written — a new item should become the
        // selection, an edit keeps it. Only when it is visible under the
        // current filter; the editor's `closeEditor` handles the rest.
        if let savedId,
            visibleEntries.contains(where: { $0.id == savedId })
        {
            select(savedId)
        }
        return savedId
    }

    func toggleFavorite(_ entry: ItemMetadata) async {
        guard let client else { return }
        do {
            if entry.isAgentContent {
                _ = try await client.authorized(
                    .contentUpdate(
                        id: entry.id,
                        patch: ContentPatch(
                            addTags: [], body: nil, clearProject: false,
                            favorite: !entry.favorite, projectSlug: nil,
                            removeTags: [], tags: nil, title: nil),
                        ifRevision: entry.revision,
                        idempotencyKey: idempotencyKey()))
            } else {
                _ = try await client.authorized(
                    .entriesUpdate(
                        id: entry.id,
                        patch: EntryPatch(
                            customFields: nil, favorite: !entry.favorite,
                            fieldUpdates: nil, groupId: nil, notes: nil,
                            password: nil, removeFieldIds: nil,
                            sections: nil, title: nil, totp: nil,
                            totpUri: nil, url: nil, username: nil),
                        ifRevision: entry.revision,
                        idempotencyKey: idempotencyKey(),
                        dryRun: false))
            }
            selectedId = entry.id
            error = nil
            await search()
        } catch {
            self.error = UserMessage(error)
        }
    }

    /// `entries_delete` — callers confirm first; the daemon still enforces
    /// `if_revision`.
    func deleteEntry(_ entry: ItemMetadata) async {
        guard let client else { return }
        do {
            _ = try await client.authorized(
                .entriesDelete(
                    id: entry.id,
                    ifRevision: entry.revision,
                    idempotencyKey: idempotencyKey(),
                    dryRun: false))
            error = nil
            // Deleting the item open in the editor must not leave a
            // ghost draft behind — its save would hit a missing entry.
            if activeDraft?.entryId == entry.id {
                closeEditor()
            }
            await search()
        } catch {
            self.error = UserMessage(error)
        }
    }

    // MARK: - Groups

    func createGroup(name: String) async throws {
        guard let client else { return }
        _ = try await client.authorized(
            .groupsCreate(
                name: name, parentId: selectedGroupId,
                idempotencyKey: idempotencyKey(), dryRun: false))
        await reload()
    }

    func renameGroup(_ group: VaultGroup, name: String) async throws {
        guard let client else { return }
        _ = try await client.authorized(
            .groupsUpdate(
                id: group.id, name: name, ifRevision: group.revision,
                idempotencyKey: idempotencyKey(), dryRun: false))
        await reload()
    }

    /// `groups_delete` — the daemon rejects non-empty groups, so callers
    /// only offer this for empty ones.
    func deleteGroup(_ group: VaultGroup) async throws {
        guard let client else { return }
        _ = try await client.authorized(
            .groupsDelete(
                id: group.id, ifRevision: group.revision,
                idempotencyKey: idempotencyKey(), dryRun: false))
        if selectedGroupId == group.id { selectedGroupId = nil }
        await reload()
    }

    func reorderGroups(parentId: String?, ordered: [VaultGroup]) async throws {
        guard let client else { return }
        _ = try await client.authorized(
            .groupsReorder(
                parentId: parentId,
                orderedIds: ordered.map(\.id),
                expectedRevisions: Dictionary(
                    ordered.map { ($0.id, $0.revision) },
                    uniquingKeysWith: { a, _ in a }),
                idempotencyKey: idempotencyKey(), dryRun: false))
        await reload()
    }

    // MARK: - Migrations

    /// Discovery must not make an otherwise readable vault unavailable —
    /// failures are swallowed like the Dart `loadMigrations`.
    func loadMigrations() async {
        guard let client else { return }
        migrationStatus = try? await client.authorized(.migrationsStatus)
            .decoded(as: MigrationStatus.self)
    }

    func applyMigration(_ preview: MigrationPreview) async throws {
        guard let client else { return }
        _ = try await client.authorized(
            .migrationsApply(
                migrationId: preview.migrationId,
                previewDigest: preview.previewDigest))
        entryViews = [:]
        await search()
        await loadMigrations()
    }

    func rollbackMigration(_ migrationId: String) async throws {
        guard let client else { return }
        _ = try await client.authorized(
            .migrationsRollback(migrationId: migrationId))
        entryViews = [:]
        await search()
        await loadMigrations()
    }

    // MARK: - Detail fetches

    func history(_ entry: ItemMetadata) async throws -> [EntryRevision] {
        guard let client else { return [] }
        let result = try await client.authorized(.entriesHistory(id: entry.id))
        return try result.decoded(as: [EntryRevision].self)
    }

    func totp(_ entry: ItemMetadata) async throws -> TotpCode {
        guard let client else { throw KeyLeaseError("no client") }
        let result = try await client.authorized(.entriesTotp(id: entry.id))
        return try result.decoded(as: TotpCode.self)
    }

    /// Markdown notes for `core.prompt`/`core.runbook`/`core.note` items.
    func fetchContentBody(_ entry: ItemMetadata) async throws -> String? {
        guard let client else { return nil }
        let result = try await client.authorized(.contentGet(id: entry.id))
        return result["body"]?.stringValue
    }

    func generatePassword(_ settings: PasswordGeneratorSettings) async throws
        -> String?
    {
        guard let client else { return nil }
        let result = try await client.authorized(
            .generatePassword(
                length: settings.requestLength, recipe: settings.recipe))
        return result["password"]?.stringValue
    }

    // MARK: - Reset

    /// Clears everything derived from an unlocked vault (Dart `clear`).
    func clear() {
        debounceTask?.cancel()
        hideSecrets()
        groups = []
        entries = []
        templates = []
        projects = []
        migrationStatus = nil
        entryViews = [:]
        query = ""
        selectedId = nil
        selectedGroupId = nil
        favoritesOnly = false
        activeDraft?.wipeSecrets()
        activeDraft = nil
        agentCreationDraft = nil
        creationMode = .manual
        workspaceMode = .detail
        error = nil
        lastFailure = nil
        loaded = false
        searching = false
        client = nil
    }
}
