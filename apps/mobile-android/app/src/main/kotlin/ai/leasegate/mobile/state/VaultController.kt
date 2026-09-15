package ai.leasegate.mobile.state

import ai.leasegate.mobile.core.ActivityEvent
import ai.leasegate.mobile.core.ApprovalSummary
import ai.leasegate.mobile.core.ConnectionSummary
import ai.leasegate.mobile.core.EntryDetailView
import ai.leasegate.mobile.core.EntryFieldView
import ai.leasegate.mobile.core.EntryRevision
import ai.leasegate.mobile.core.EntrySummary
import ai.leasegate.mobile.core.JsonMap
import ai.leasegate.mobile.core.KeyLeaseClient
import ai.leasegate.mobile.core.MigrationHistoryModel
import ai.leasegate.mobile.core.MigrationPreviewModel
import ai.leasegate.mobile.core.MigrationStatusModel
import ai.leasegate.mobile.core.TemplateDefinition
import ai.leasegate.mobile.core.UserMessage
import ai.leasegate.mobile.core.VaultGroup
import ai.leasegate.mobile.core.VaultProjectModel
import ai.leasegate.mobile.core.asJsonMap
import ai.leasegate.mobile.core.parseList
import java.time.LocalDateTime
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** What the entry list is showing right now. */
enum class VaultListState { LOADING, CONTENT, EMPTY, SEARCH_EMPTY }

enum class EntryWorkspaceMode { DETAIL, CREATE, EDIT, PASSWORD_GENERATOR }

data class VaultUiState(
    val groups: List<VaultGroup> = emptyList(),
    val entries: List<EntrySummary> = emptyList(),
    val templates: List<TemplateDefinition> = emptyList(),
    val projects: List<VaultProjectModel> = emptyList(),
    val migrationStatus: MigrationStatusModel? = null,
    val query: String = "",
    val selectedGroupId: String? = null,
    val favoritesOnly: Boolean = false,
    val selectedEntryId: String? = null,
    val workspaceMode: EntryWorkspaceMode = EntryWorkspaceMode.DETAIL,
    val activeDraft: EntryDraft? = null,
    val error: UserMessage? = null,
    val loaded: Boolean = false,
    val searching: Boolean = false,
    val revealed: Map<String, String> = emptyMap(),
    val entryViews: Map<String, EntryDetailView> = emptyMap(),
    val busy: Set<String> = emptySet(),
) {
    val orderedGroups: List<VaultGroup>
        get() = groups.sortedWith(
            compareBy({ it.sortOrder ?: Int.MAX_VALUE }, { it.name.lowercase() }, { it.id }),
        )

    val visibleEntries: List<EntrySummary>
        get() {
            if (favoritesOnly) return entries.filter { it.favorite }
            val root = selectedGroupId ?: return entries
            val ids = mutableSetOf(root)
            var changed = true
            while (changed) {
                changed = false
                for (group in groups) {
                    val parent = group.parentId
                    if (parent != null && parent in ids && ids.add(group.id)) changed = true
                }
            }
            return entries.filter { it.groupId in ids }
        }

    val listState: VaultListState
        get() {
            if (!loaded || searching) return VaultListState.LOADING
            if (visibleEntries.isNotEmpty()) return VaultListState.CONTENT
            return if (query.trim().isEmpty()) VaultListState.EMPTY else VaultListState.SEARCH_EMPTY
        }

    val selectedEntry: EntrySummary?
        get() {
            val visible = visibleEntries
            if (visible.isEmpty()) return null
            return visible.firstOrNull { it.id == selectedEntryId } ?: visible.first()
        }

    val hasRevealedSecrets: Boolean get() = revealed.isNotEmpty()

    fun revealedValue(entryId: String, field: String): String? = revealed["$entryId/$field"]

    fun entryView(entryId: String): EntryDetailView? = entryViews[entryId]

    fun kindLabel(kind: String): String =
        templates.firstOrNull { it.kind == kind }?.label ?: kind

    fun projectName(id: String?): String? =
        id?.let { value -> projects.firstOrNull { it.id == value }?.name ?: value }

    fun isBusy(key: String): Boolean = key in busy
}

/**
 * Vault list/detail state — the port of `VaultController`.
 *
 * Groups, the debounced search, the selection and the on-demand secret
 * reveals. All native calls go through [clientOf]; every mutation lands in
 * [state] so Compose recomposes from one snapshot.
 */
class VaultController(
    private val scope: CoroutineScope,
    private val clientOf: () -> KeyLeaseClient,
    private val searchDebounceMs: Long = 220,
    private val revealTimeoutMs: Long = 15_000,
) {
    private val _state = MutableStateFlow(VaultUiState())
    val state: StateFlow<VaultUiState> = _state.asStateFlow()

    private var debounceJob: Job? = null
    private var revealJob: Job? = null
    private var issued = 0
    private var applied = 0

    fun isBusy(key: String): Boolean = key in _state.value.busy

    private suspend fun <T> track(
        key: String,
        onError: ((Throwable) -> Unit)? = null,
        operation: suspend () -> T,
    ): T? {
        val busy = _state.value.busy
        if (key in busy) return null
        _state.update { it.copy(busy = it.busy + key) }
        try {
            return operation()
        } catch (error: Throwable) {
            if (onError == null) throw error
            onError(error)
            return null
        } finally {
            _state.update { it.copy(busy = it.busy - key) }
        }
    }

    fun select(entryId: String) {
        if (_state.value.selectedEntryId == entryId) return
        _state.update { it.copy(selectedEntryId = entryId) }
        hideSecrets()
        scope.launch { loadEntryView(entryId) }
    }

    fun beginCreate(initialPassword: String = "") {
        val state = _state.value
        val draft = EntryDraft.create(
            groupId = state.selectedGroupId ?: state.orderedGroups.firstOrNull()?.id,
            initialPassword = initialPassword,
        )
        _state.update {
            it.copy(
                activeDraft = draft,
                workspaceMode = EntryWorkspaceMode.CREATE,
            )
        }
        hideSecrets()
    }

    fun openPasswordGenerator() {
        _state.value.activeDraft?.wipeSecrets()
        _state.update {
            it.copy(activeDraft = null, workspaceMode = EntryWorkspaceMode.PASSWORD_GENERATOR)
        }
        hideSecrets()
    }

    fun beginEdit(entry: EntrySummary) {
        _state.update {
            it.copy(
                activeDraft = EntryDraft.edit(entry),
                workspaceMode = EntryWorkspaceMode.EDIT,
            )
        }
        hideSecrets()
    }

    fun closeEditor() {
        _state.value.activeDraft?.wipeSecrets()
        _state.update {
            it.copy(activeDraft = null, workspaceMode = EntryWorkspaceMode.DETAIL)
        }
    }

    /** Moves the selection by [delta] within the visible list. */
    fun moveSelection(delta: Int) {
        val visible = _state.value.visibleEntries
        if (visible.isEmpty()) return
        val current = visible.indexOfFirst { it.id == _state.value.selectedEntryId }
        val next = (if (current < 0) 0 else current + delta).coerceIn(0, visible.size - 1)
        select(visible[next].id)
    }

    fun selectGroup(groupId: String?) {
        _state.update {
            it.copy(
                selectedGroupId = groupId,
                favoritesOnly = false,
                workspaceMode = EntryWorkspaceMode.DETAIL,
            )
        }
        hideSecrets()
        normalizeSelection()
    }

    fun selectFavorites() {
        _state.update {
            it.copy(
                selectedGroupId = null,
                favoritesOnly = true,
                workspaceMode = EntryWorkspaceMode.DETAIL,
            )
        }
        hideSecrets()
        normalizeSelection()
    }

    /** Debounced search: only the newest response may replace the list. */
    fun setQuery(value: String) {
        if (_state.value.query == value) return
        _state.update { it.copy(query = value, searching = true) }
        debounceJob?.cancel()
        debounceJob = scope.launch {
            delay(searchDebounceMs)
            search()
        }
    }

    suspend fun load() {
        debounceJob?.cancel()
        search(withGroups = true)
    }

    suspend fun loadMigrations() {
        try {
            val result = clientOf().authorized(mapOf("command" to "migrations_status"))
            if (result is Map<*, *>) {
                _state.update {
                    it.copy(
                        migrationStatus = MigrationStatusModel.fromJson(result.asJsonMap()),
                    )
                }
            }
        } catch (_: Exception) {
            // Migration discovery must not make an otherwise readable vault
            // unavailable.
        }
    }

    suspend fun applyMigration(preview: MigrationPreviewModel) {
        clientOf().authorized(
            mapOf(
                "command" to "migrations_apply",
                "migration_id" to preview.id,
                "preview_digest" to preview.digest,
            ),
        )
        _state.update { it.copy(entryViews = emptyMap()) }
        search()
        loadMigrations()
    }

    suspend fun rollbackMigration(migrationId: String) {
        clientOf().authorized(
            mapOf(
                "command" to "migrations_rollback",
                "migration_id" to migrationId,
            ),
        )
        _state.update { it.copy(entryViews = emptyMap()) }
        search()
        loadMigrations()
    }

    suspend fun search(withGroups: Boolean = false) {
        val sequence = ++issued
        _state.update { it.copy(searching = true) }
        try {
            val client = clientOf()
            val nextGroups = if (withGroups) {
                client.authorized(mapOf("command" to "groups_list"))
                    .parseList(VaultGroup::fromJson)
            } else {
                null
            }
            var nextTemplates: List<TemplateDefinition>? = null
            var nextProjects: List<VaultProjectModel>? = null
            if (withGroups) {
                try {
                    nextTemplates = client.authorized(mapOf("command" to "templates_list"))
                        .parseList(TemplateDefinition::fromJson)
                    nextProjects = client.authorized(mapOf("command" to "projects_list"))
                        .parseList(VaultProjectModel::fromJson)
                } catch (_: Exception) {
                    // Older daemon without template/project discovery; the
                    // entry list remains usable.
                }
            }
            val result = client.authorized(
                mapOf("command" to "entries_search", "query" to _state.value.query),
            )
            // A slower earlier query must never overwrite a newer screen.
            if (sequence <= applied) return
            applied = sequence
            val entries = result.parseList(EntrySummary::fromJson)
            _state.update {
                it.copy(
                    groups = nextGroups ?: it.groups,
                    templates = nextTemplates ?: it.templates,
                    projects = nextProjects ?: it.projects,
                    entries = entries,
                    error = null,
                    loaded = true,
                )
            }
            normalizeSelection()
            _state.value.selectedEntryId?.let { loadEntryView(it) }
        } catch (caught: Throwable) {
            if (sequence <= applied) return
            applied = sequence
            _state.update { it.copy(error = UserMessage.from(caught)) }
        } finally {
            if (sequence >= issued) {
                _state.update { it.copy(searching = false) }
            }
        }
    }

    suspend fun loadEntryView(entryId: String) {
        try {
            val result = clientOf().authorized(
                mapOf("command" to "entries_view", "id" to entryId),
            )
            if (result is Map<*, *>) {
                _state.update {
                    it.copy(
                        entryViews = it.entryViews +
                            (entryId to EntryDetailView.fromJson(result.asJsonMap())),
                        error = null,
                    )
                }
            }
        } catch (_: Exception) {
            // An older daemon has no field-oriented view. The legacy login
            // detail remains usable.
        }
    }

    private fun normalizeSelection() {
        val visible = _state.value.visibleEntries
        if (visible.isEmpty()) {
            _state.update { it.copy(selectedEntryId = null) }
            return
        }
        if (visible.none { it.id == _state.value.selectedEntryId }) {
            _state.update {
                it.copy(selectedEntryId = visible.first().id, revealed = emptyMap())
            }
        }
    }

    /**
     * Fetches a protected field without putting it on screen. Copying uses
     * this: a copy must not also un-mask the field.
     */
    suspend fun fetchSecret(entry: EntrySummary, field: String): String? =
        track("reveal.${entry.id}/$field", onError = { caught ->
            _state.update { it.copy(error = UserMessage.from(caught)) }
        }) {
            val response = clientOf().authorized(
                mapOf(
                    "command" to "entries_reveal",
                    "id" to entry.id,
                    "field" to field,
                ),
            )
            (response as? Map<*, *>)?.get("value")?.toString()
        }

    /** Fetches a protected field on demand and keeps it visible briefly. */
    suspend fun reveal(entry: EntrySummary, field: String): String? {
        val value = fetchSecret(entry, field) ?: return null
        _state.update { it.copy(revealed = it.revealed + ("${entry.id}/$field" to value)) }
        restartRevealTimer()
        return value
    }

    suspend fun fetchField(entry: EntrySummary, field: EntryFieldView): String? =
        track("reveal.${entry.id}/${field.id}", onError = { caught ->
            _state.update { it.copy(error = UserMessage.from(caught)) }
        }) {
            val response = clientOf().authorized(
                mapOf(
                    "command" to "entries_reveal_by_id",
                    "id" to entry.id,
                    "field_id" to field.id,
                ),
            )
            val raw = (response as? Map<*, *>)?.get("value")
            field.withValue(raw).displayValue
        }

    suspend fun revealField(entry: EntrySummary, field: EntryFieldView): String? {
        val value = fetchField(entry, field) ?: return null
        _state.update {
            it.copy(revealed = it.revealed + ("${entry.id}/${field.id}" to value))
        }
        restartRevealTimer()
        return value
    }

    suspend fun fetchFields(
        entry: EntrySummary,
        fields: List<EntryFieldView>,
    ): Map<String, String> =
        track("reveal.${entry.id}/batch", onError = { caught ->
            _state.update { it.copy(error = UserMessage.from(caught)) }
        }) {
            val response = clientOf().authorized(
                mapOf(
                    "command" to "entries_reveal_many",
                    "id" to entry.id,
                    "field_ids" to fields.map { it.id },
                ),
            )
            val raw = (response as? Map<*, *>)?.get("values") as? Map<*, *> ?: emptyMap<String, String>()
            fields.mapNotNull { field ->
                if (raw.containsKey(field.id)) {
                    field.id to field.withValue(raw[field.id]).displayValue
                } else {
                    null
                }
            }.toMap()
        } ?: emptyMap()

    fun hideSecret(entryId: String, field: String) {
        _state.update { it.copy(revealed = it.revealed - "$entryId/$field") }
        if (_state.value.revealed.isEmpty()) {
            revealJob?.cancel()
            revealJob = null
        }
    }

    /** Drops every revealed secret. Called on lock, sleep and screen lock. */
    fun hideSecrets() {
        revealJob?.cancel()
        revealJob = null
        if (_state.value.revealed.isEmpty()) return
        _state.update { it.copy(revealed = emptyMap()) }
    }

    private fun restartRevealTimer() {
        revealJob?.cancel()
        revealJob = scope.launch {
            delay(revealTimeoutMs)
            hideSecrets()
        }
    }

    /** Clears everything derived from an unlocked vault. */
    fun clear() {
        debounceJob?.cancel()
        hideSecrets()
        _state.value.activeDraft?.wipeSecrets()
        _state.value = VaultUiState()
    }

    suspend fun history(entry: EntrySummary): List<EntryRevision> =
        clientOf().authorized(mapOf("command" to "entries_history", "id" to entry.id))
            .parseList(EntryRevision::fromJson)

    suspend fun totp(entry: EntrySummary): JsonMap {
        val result = clientOf().authorized(
            mapOf("command" to "entries_totp", "id" to entry.id),
        )
        @Suppress("UNCHECKED_CAST")
        return (result as? JsonMap) ?: emptyMap()
    }

    suspend fun fetchContentBody(entry: EntrySummary): String? {
        val result = clientOf().authorized(
            mapOf("command" to "content_get", "id" to entry.id),
        )
        return (result as? Map<*, *>)?.get("body")?.toString()
    }

    suspend fun generatePassword(length: Int = 32, recipe: Map<String, Any?>? = null): String? {
        val result = clientOf().authorized(
            buildMap {
                put("command", "generate_password")
                put("length", length)
                if (recipe != null) put("recipe", recipe)
            },
        )
        return (result as? Map<*, *>)?.get("password")?.toString()
    }

    private fun idempotencyKey(): String = "android-${System.nanoTime()}"

    /** Saves [draft]. On failure the draft is untouched so the editor retries. */
    suspend fun save(draft: EntryDraft): String? {
        val client = clientOf()
        var savedId = draft.entryId
        if (draft.isNew) {
            if (draft.isAgentContent) {
                val created = client.authorized(
                    mapOf(
                        "command" to "content_create",
                        "input" to draft.toContentCreateInput(),
                        "idempotency_key" to idempotencyKey(),
                    ),
                )
                if (draft.agentAccess != "none" && created is Map<*, *>) {
                    val summary = created["summary"]
                    if (summary is Map<*, *>) {
                        savedId = summary["id"]?.toString()
                        client.authorized(
                            mapOf(
                                "command" to "content_set_access",
                                "id" to summary["id"],
                                "access" to draft.agentAccess,
                                "if_revision" to summary["revision"],
                                "idempotency_key" to idempotencyKey(),
                            ),
                        )
                    }
                } else if (created is Map<*, *> && created["summary"] is Map<*, *>) {
                    savedId = (created["summary"] as Map<*, *>)["id"]?.toString()
                }
            } else {
                val created = client.authorized(
                    mapOf(
                        "command" to "entries_create",
                        "input" to draft.toCreateInput(),
                        "idempotency_key" to idempotencyKey(),
                        "dry_run" to false,
                    ),
                )
                if (created is Map<*, *>) savedId = created["id"]?.toString()
            }
        } else if (draft.isAgentContent) {
            client.authorized(
                mapOf(
                    "command" to "content_update",
                    "id" to draft.entryId,
                    "patch" to draft.toContentPatch(),
                    "if_revision" to draft.revision,
                    "idempotency_key" to idempotencyKey(),
                ),
            )
        } else {
            client.authorized(
                mapOf(
                    "command" to "entries_update",
                    "id" to draft.entryId,
                    "patch" to draft.toPatch(),
                    "if_revision" to draft.revision,
                    "idempotency_key" to idempotencyKey(),
                    "dry_run" to false,
                ),
            )
        }
        search()
        return savedId
    }

    suspend fun toggleFavorite(entry: EntrySummary) {
        val favorite = !entry.favorite
        if (entry.kind in setOf("core.prompt", "core.runbook", "core.note")) {
            clientOf().authorized(
                mapOf(
                    "command" to "content_update",
                    "id" to entry.id,
                    "patch" to mapOf(
                        "favorite" to favorite,
                        "add_tags" to emptyList<String>(),
                        "remove_tags" to emptyList<String>(),
                        "clear_project" to false,
                    ),
                    "if_revision" to entry.revision,
                    "idempotency_key" to idempotencyKey(),
                ),
            )
        } else {
            clientOf().authorized(
                mapOf(
                    "command" to "entries_update",
                    "id" to entry.id,
                    "patch" to mapOf("favorite" to favorite),
                    "if_revision" to entry.revision,
                    "idempotency_key" to idempotencyKey(),
                    "dry_run" to false,
                ),
            )
        }
        _state.update { it.copy(selectedEntryId = entry.id) }
        search()
    }

    suspend fun reorderGroups(parentId: String?, ordered: List<VaultGroup>) {
        clientOf().authorized(
            mapOf(
                "command" to "groups_reorder",
                "parent_id" to parentId,
                "ordered_ids" to ordered.map { it.id },
                "expected_revisions" to ordered.associate { it.id to it.revision },
                "idempotency_key" to idempotencyKey(),
                "dry_run" to false,
            ),
        )
        load()
    }

    suspend fun deleteEntry(entry: EntrySummary) {
        clientOf().authorized(
            mapOf(
                "command" to "entries_delete",
                "id" to entry.id,
                "if_revision" to entry.revision,
                "idempotency_key" to idempotencyKey(),
                "dry_run" to false,
            ),
        )
        search()
    }

    suspend fun createGroup(name: String) {
        clientOf().authorized(
            mapOf(
                "command" to "groups_create",
                "name" to name,
                "parent_id" to _state.value.selectedGroupId,
                "idempotency_key" to idempotencyKey(),
                "dry_run" to false,
            ),
        )
        load()
    }

    suspend fun renameGroup(group: VaultGroup, name: String) {
        clientOf().authorized(
            mapOf(
                "command" to "groups_update",
                "id" to group.id,
                "name" to name,
                "if_revision" to group.revision,
                "idempotency_key" to idempotencyKey(),
                "dry_run" to false,
            ),
        )
        load()
    }

    suspend fun deleteGroup(group: VaultGroup) {
        clientOf().authorized(
            mapOf(
                "command" to "groups_delete",
                "id" to group.id,
                "if_revision" to group.revision,
                "idempotency_key" to idempotencyKey(),
                "dry_run" to false,
            ),
        )
        if (_state.value.selectedGroupId == group.id) {
            _state.update { it.copy(selectedGroupId = null) }
        }
        load()
    }
}

// ---------------------------------------------------------------------------
// Section controllers — the port of `section_controllers.dart`.
// ---------------------------------------------------------------------------

data class SectionUiState<T>(
    val items: List<T> = emptyList(),
    val error: UserMessage? = null,
    val loaded: Boolean = false,
    val loading: Boolean = false,
)

abstract class SectionController<T>(
    protected val scope: CoroutineScope,
    protected val clientOf: () -> KeyLeaseClient,
) {
    protected val _state = MutableStateFlow(SectionUiState<T>())
    val state: StateFlow<SectionUiState<T>> = _state.asStateFlow()

    protected abstract suspend fun fetch(): List<T>

    suspend fun load() {
        _state.update { it.copy(loading = true) }
        try {
            val items = fetch()
            _state.update { it.copy(items = items, error = null, loaded = true) }
        } catch (caught: Throwable) {
            _state.update { it.copy(error = UserMessage.from(caught)) }
        } finally {
            _state.update { it.copy(loading = false) }
        }
    }

    fun clear() {
        _state.value = SectionUiState()
    }
}

class ConnectionsController(
    scope: CoroutineScope,
    clientOf: () -> KeyLeaseClient,
) : SectionController<ConnectionSummary>(scope, clientOf) {
    override suspend fun fetch(): List<ConnectionSummary> =
        clientOf().authorized(mapOf("command" to "connections_list"))
            .parseList(ConnectionSummary::fromJson)

    suspend fun manage(connection: ConnectionSummary, operation: String) {
        clientOf().authorized(
            mapOf("command" to "connection_$operation", "id" to connection.id),
        )
        load()
    }

    suspend fun setResource(
        connection: ConnectionSummary,
        resource: String,
        enrolled: Boolean,
    ) {
        clientOf().authorized(
            mapOf(
                "command" to if (enrolled) "connection_enroll" else "connection_unenroll",
                "id" to connection.id,
                "resource" to resource,
            ),
        )
        load()
    }

    suspend fun add(provider: String, credential: String, authorizedResources: List<String>) {
        clientOf().authorized(
            mapOf(
                "command" to "connection_add",
                "provider" to provider,
                "credential" to credential,
                "authorized_resources" to authorizedResources,
            ),
        )
        load()
    }
}

/** Raised when an approval decision no longer matches the pending request. */
class StaleApprovalException(message: String) : Exception(message)

class ApprovalsController(
    scope: CoroutineScope,
    clientOf: () -> KeyLeaseClient,
) : SectionController<ApprovalSummary>(scope, clientOf) {
    override suspend fun fetch(): List<ApprovalSummary> =
        clientOf().authorized(mapOf("command" to "approvals_list", "limit" to 100))
            .parseList(ApprovalSummary::fromJson)

    /**
     * Re-reads the pending list and refuses to decide on a request that has
     * expired, been decided elsewhere, or whose digest changed.
     */
    suspend fun decide(approval: ApprovalSummary, approve: Boolean, now: LocalDateTime? = null) {
        val current = fetch()
        _state.update { it.copy(items = current) }
        val match = current.firstOrNull { it.id == approval.id }
        if (match == null || !match.sameRequestAs(approval)) {
            throw StaleApprovalException(
                "This request is no longer pending. The list has been refreshed.",
            )
        }
        if (!match.decidableAt(now ?: LocalDateTime.now())) {
            throw StaleApprovalException(
                "This request expired before the decision was sent.",
            )
        }
        clientOf().authorized(
            mapOf(
                "command" to "approval_decide",
                "id" to approval.id,
                "approve" to approve,
            ),
        )
        load()
    }
}

data class ActivityUiState(
    val base: SectionUiState<ActivityEvent> = SectionUiState(),
    val deniedOnly: Boolean = false,
) {
    val filtered: List<ActivityEvent>
        get() = if (deniedOnly) base.items.filter { it.denied } else base.items
}

class ActivityController(
    scope: CoroutineScope,
    clientOf: () -> KeyLeaseClient,
) : SectionController<ActivityEvent>(scope, clientOf) {
    private val _deniedOnly = MutableStateFlow(false)
    val deniedOnly: StateFlow<Boolean> = _deniedOnly.asStateFlow()

    override suspend fun fetch(): List<ActivityEvent> =
        clientOf().authorized(mapOf("command" to "audit_query", "limit" to 200))
            .parseList(ActivityEvent::fromJson)

    fun setDeniedOnly(value: Boolean) {
        _deniedOnly.value = value
    }
}
