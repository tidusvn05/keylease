package ai.leasegate.mobile.ui.screens

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.GridView
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.OpenInNew
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.outlined.Star
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import ai.leasegate.mobile.core.EntryDetailView
import ai.leasegate.mobile.core.EntryFieldView
import ai.leasegate.mobile.core.EntryRevision
import ai.leasegate.mobile.core.EntrySectionView
import ai.leasegate.mobile.core.EntrySummary
import ai.leasegate.mobile.core.UserMessage
import ai.leasegate.mobile.state.AppController
import ai.leasegate.mobile.state.EntryWorkspaceMode
import ai.leasegate.mobile.state.VaultListState
import ai.leasegate.mobile.state.fieldsByRole
import ai.leasegate.mobile.state.renderDotEnv
import ai.leasegate.mobile.ui.KeyleaseButton
import ai.leasegate.mobile.ui.KeyleaseMark
import ai.leasegate.mobile.ui.LocalKeyleaseColors
import ai.leasegate.mobile.ui.MessageBanner
import ai.leasegate.mobile.ui.SectionLabel
import ai.leasegate.mobile.ui.StateScreen
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Vault section: on a phone the list routes to the detail/editor; selection
 * and search live in the controller so the round trip keeps both.
 */
@Composable
fun VaultScreen(app: AppController) {
    val vaultState by app.vault.state.collectAsStateWithLifecycle()
    var detailOpen by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    // Editor/generator modes replace the workspace wholesale. The editor
    // owns the discard-confirmation flow itself (a dirty draft never dies to
    // a stray back gesture).
    when (vaultState.workspaceMode) {
        EntryWorkspaceMode.CREATE, EntryWorkspaceMode.EDIT -> {
            EntryEditorPane(app, onClosed = { app.vault.closeEditor() })
            return
        }
        EntryWorkspaceMode.PASSWORD_GENERATOR -> {
            BackHandler { app.vault.closeEditor() }
            PasswordGeneratorPane(app, onClosed = { app.vault.closeEditor() })
            return
        }
        EntryWorkspaceMode.DETAIL -> Unit
    }

    if (detailOpen && vaultState.selectedEntry != null) {
        BackHandler { detailOpen = false }
        EntryDetailPane(
            app = app,
            entry = vaultState.selectedEntry!!,
            onBack = { detailOpen = false },
        )
        return
    }
    detailOpen = false

    EntryListPane(
        app = app,
        onSelect = { detailOpen = true },
    )
}

// ---------------------------------------------------------------------------
// Entry list
// ---------------------------------------------------------------------------

@Composable
private fun EntryListPane(app: AppController, onSelect: () -> Unit) {
    val vaultState by app.vault.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var showGroups by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize()) {
        OutlinedTextField(
            value = vaultState.query,
            onValueChange = app.vault::setQuery,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            placeholder = { Text("Search") },
            leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
            singleLine = true,
        )
        Row(
            modifier = Modifier.padding(horizontal = 16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                when (vaultState.listState) {
                    VaultListState.LOADING -> "Searching…"
                    else -> "${vaultState.visibleEntries.size} " +
                        if (vaultState.visibleEntries.size == 1) "item" else "items"
                },
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f),
            )
            if (vaultState.listState == VaultListState.LOADING) {
                CircularProgressIndicator(Modifier.size(14.dp), strokeWidth = 2.dp)
            }
            TextButton(onClick = { showGroups = true }) {
                Icon(Icons.Filled.Folder, contentDescription = null, modifier = Modifier.size(15.dp))
                Spacer(Modifier.width(4.dp))
                Text(
                    when {
                        vaultState.favoritesOnly -> "Favorites"
                        vaultState.selectedGroupId != null ->
                            vaultState.groups.firstOrNull { it.id == vaultState.selectedGroupId }?.name
                                ?: "Group"
                        else -> "All items"
                    },
                )
            }
        }
        vaultState.error?.let { error ->
            MessageBanner(
                message = error,
                onAction = { scope.launch { app.vault.load() } },
            )
        }
        when (vaultState.listState) {
            VaultListState.LOADING if vaultState.visibleEntries.isEmpty() ->
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator()
                }
            VaultListState.EMPTY -> StateScreen(
                title = "No items yet",
                message = "Add your first item to start using this vault.",
                icon = Icons.Filled.Key,
            ) {
                KeyleaseButton("New item", onClick = { app.vault.beginCreate() })
            }
            VaultListState.SEARCH_EMPTY -> StateScreen(
                title = "No matches",
                message = "Nothing matches \"${vaultState.query}\". Try a shorter search, or clear it to see everything.",
                icon = Icons.Filled.Search,
            ) {
                KeyleaseButton(
                    "Clear search",
                    outline = true,
                    onClick = { app.vault.setQuery("") },
                )
                KeyleaseButton("New item", onClick = { app.vault.beginCreate() })
            }
            else -> LazyColumn(Modifier.fillMaxSize()) {
                items(vaultState.visibleEntries, key = { it.id }) { entry ->
                    EntryRow(
                        entry = entry,
                        onClick = {
                            app.vault.select(entry.id)
                            onSelect()
                        },
                    )
                    HorizontalDivider()
                }
            }
        }
    }

    if (showGroups) {
        GroupPickerDialog(
            app = app,
            onDismiss = { showGroups = false },
        )
    }
}

@Composable
private fun EntryRow(entry: EntrySummary, onClick: () -> Unit) {
    ListItem(
        modifier = Modifier.clickable(onClick = onClick),
        leadingContent = { KeyleaseMark(entry.monogram) },
        headlineContent = {
            Text(entry.title, maxLines = 1, overflow = TextOverflow.Ellipsis)
        },
        supportingContent = {
            if (entry.subtitle.isNotEmpty()) {
                Text(entry.subtitle, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        },
        trailingContent = {
            if (entry.favorite) {
                Icon(
                    Icons.Filled.Star,
                    contentDescription = "Favorite",
                    tint = LocalKeyleaseColors.current.warning,
                    modifier = Modifier.size(16.dp),
                )
            }
        },
    )
}

@Composable
private fun GroupPickerDialog(app: AppController, onDismiss: () -> Unit) {
    val vaultState by app.vault.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var newGroup by remember { mutableStateOf(false) }
    var newGroupName by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Groups") },
        text = {
            Column {
                ListItem(
                    modifier = Modifier.clickable {
                        app.vault.selectGroup(null)
                        onDismiss()
                    },
                    headlineContent = { Text("All items") },
                    leadingContent = { Icon(Icons.Filled.GridView, null) },
                )
                ListItem(
                    modifier = Modifier.clickable {
                        app.vault.selectFavorites()
                        onDismiss()
                    },
                    headlineContent = { Text("Favorites") },
                    leadingContent = { Icon(Icons.Filled.Star, null) },
                )
                for (group in vaultState.orderedGroups) {
                    ListItem(
                        modifier = Modifier.clickable {
                            app.vault.selectGroup(group.id)
                            onDismiss()
                        },
                        headlineContent = {
                            Text(
                                if (group.parentId != null) "↳ ${group.name}" else group.name,
                            )
                        },
                        leadingContent = { Icon(Icons.Filled.Folder, null) },
                    )
                }
                if (newGroup) {
                    OutlinedTextField(
                        value = newGroupName,
                        onValueChange = { newGroupName = it },
                        label = { Text("Group name") },
                        singleLine = true,
                    )
                    TextButton(
                        onClick = {
                            val name = newGroupName.trim()
                            if (name.isNotEmpty()) {
                                scope.launch { app.vault.createGroup(name) }
                                newGroup = false
                                newGroupName = ""
                            }
                        },
                    ) { Text("Create group") }
                } else {
                    TextButton(onClick = { newGroup = true }) {
                        Icon(Icons.Filled.Add, null, modifier = Modifier.size(15.dp))
                        Text(" New group")
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } },
    )
}

// ---------------------------------------------------------------------------
// Entry detail
// ---------------------------------------------------------------------------

@Composable
private fun EntryDetailPane(
    app: AppController,
    entry: EntrySummary,
    onBack: () -> Unit,
) {
    val vaultState by app.vault.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var failure by remember { mutableStateOf<UserMessage?>(null) }
    var confirmDelete by remember { mutableStateOf(false) }
    var historyRevisions by remember { mutableStateOf<List<EntryRevision>?>(null) }

    val detail = vaultState.entryViews[entry.id]
    val password = vaultState.revealedValue(entry.id, "password")
    val username = vaultState.revealedValue(entry.id, "username")
    val hasUsername = (username ?: entry.username)?.isNotEmpty() == true
    val hasLoginDetails = hasUsername || entry.hasPassword || entry.primaryUrl != null
    val isDeveloper = entry.kind in setOf("core.environment", "core.ssh_server")
    val additionalFields = detail?.let { additionalFields(it) } ?: emptyList()

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 14.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Items")
            }
            KeyleaseMark(entry.monogram, size = 54)
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    entry.title,
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    entry.primaryUrl ?: vaultState.kindLabel(entry.kind),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.End,
        ) {
            IconButton(onClick = {
                scope.launch {
                    try {
                        app.vault.toggleFavorite(entry)
                    } catch (caught: Throwable) {
                        failure = UserMessage.from(caught)
                    }
                }
            }) {
                Icon(
                    if (entry.favorite) Icons.Filled.Star else Icons.Outlined.Star,
                    contentDescription = "Favorite",
                    tint = if (entry.favorite) {
                        LocalKeyleaseColors.current.warning
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                )
            }
            IconButton(onClick = { app.vault.beginEdit(entry) }) {
                Icon(Icons.Filled.Edit, contentDescription = "Edit")
            }
            IconButton(onClick = { confirmDelete = true }) {
                Icon(
                    Icons.Filled.Delete,
                    contentDescription = "Delete",
                    tint = LocalKeyleaseColors.current.danger,
                )
            }
        }
        failure?.let {
            MessageBanner(it, onDismiss = { failure = null })
            Spacer(Modifier.height(10.dp))
        }

        if (hasLoginDetails) {
            SectionLabel("Login details")
            Card {
                Column(Modifier.padding(horizontal = 14.dp, vertical = 6.dp)) {
                    if (hasUsername) {
                        DetailFieldRow(
                            label = "Username",
                            value = username ?: entry.username.orEmpty(),
                            onCopy = {
                                scope.launch {
                                    val value = username ?: app.vault.fetchSecret(entry, "username")
                                    if (!value.isNullOrEmpty() && app.copySensitive(value)) {
                                        // Clipboard clears in 30 seconds.
                                    }
                                }
                            },
                        )
                    }
                    if (entry.hasPassword) {
                        SecretRow(
                            label = "Password",
                            revealed = password,
                            busy = vaultState.isBusy("reveal.${entry.id}/password"),
                            onReveal = { scope.launch { app.vault.reveal(entry, "password") } },
                            onHide = { app.vault.hideSecret(entry.id, "password") },
                            onCopy = {
                                scope.launch {
                                    val value = password
                                        ?: app.vault.fetchSecret(entry, "password")
                                    if (!value.isNullOrEmpty()) app.copySensitive(value)
                                }
                            },
                        )
                    }
                    entry.primaryUrl?.let { url ->
                        DetailFieldRow(
                            label = "Website",
                            value = url,
                            accent = true,
                            onOpen = {
                                scope.launch {
                                    val candidate = if (url.trim().contains("://")) {
                                        url.trim()
                                    } else {
                                        "https://${url.trim()}"
                                    }
                                    val opened = app.openExternalUrl?.invoke(candidate) == true
                                    if (!opened) {
                                        failure = UserMessage(
                                            title = "Invalid website",
                                            detail = "Edit this item and enter a valid web URL.",
                                        )
                                    }
                                }
                            },
                        )
                    }
                }
            }
        }

        if (detail != null && isDeveloper) {
            DeveloperTemplateDetail(app = app, item = entry, detail = detail)
        } else if (detail != null && additionalFields.isNotEmpty()) {
            SectionLabel("Details")
            Card {
                Column(Modifier.padding(horizontal = 14.dp, vertical = 6.dp)) {
                    for (field in additionalFields) {
                        if (field.`protected`) {
                            SecretRow(
                                label = field.label,
                                revealed = vaultState.revealedValue(entry.id, field.id),
                                maskedValue = field.displayHint,
                                busy = vaultState.isBusy("reveal.${entry.id}/${field.id}"),
                                onReveal = {
                                    scope.launch { app.vault.revealField(entry, field) }
                                },
                                onHide = { app.vault.hideSecret(entry.id, field.id) },
                                onCopy = {
                                    scope.launch {
                                        val value = vaultState.revealedValue(entry.id, field.id)
                                            ?: app.vault.fetchField(entry, field)
                                        if (!value.isNullOrEmpty()) app.copySensitive(value)
                                    }
                                },
                            )
                        } else {
                            DetailFieldRow(
                                label = field.label,
                                value = field.displayValue,
                                onCopy = {
                                    scope.launch {
                                        app.copySensitive(field.displayValue)
                                    }
                                },
                            )
                        }
                    }
                }
            }
        }

        if (entry.hasTotp) {
            SectionLabel("Two-factor authentication")
            InlineTotpField(app = app, entry = entry)
        }
        if (entry.hasNotes) {
            InlineNotesSection(app = app, entry = entry)
        }
        MetadataSection(
            item = entry,
            detail = detail,
            templateLabel = vaultState.kindLabel(entry.kind),
            projectName = vaultState.projectName(detail?.projectId),
            groupName = vaultState.groups.firstOrNull { it.id == entry.groupId }?.name
                ?: entry.groupId,
            onHistory = {
                scope.launch {
                    try {
                        historyRevisions = app.vault.history(entry)
                    } catch (caught: Throwable) {
                        failure = UserMessage.from(caught)
                    }
                }
            },
        )
    }

    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("Move to recycle bin?") },
            text = {
                Text("\"${entry.title}\" moves to the recycle bin. Anything already copied is unaffected.")
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmDelete = false
                        scope.launch {
                            try {
                                app.vault.deleteEntry(entry)
                                onBack()
                            } catch (caught: Throwable) {
                                failure = UserMessage.from(caught)
                            }
                        }
                    },
                ) { Text("Delete", color = LocalKeyleaseColors.current.danger) }
            },
            dismissButton = {
                TextButton(onClick = { confirmDelete = false }) { Text("Cancel") }
            },
        )
    }

    historyRevisions?.let { revisions ->
        AlertDialog(
            onDismissRequest = { historyRevisions = null },
            title = { Text("History · ${entry.title}") },
            text = {
                if (revisions.isEmpty()) {
                    Text("No earlier revisions.")
                } else {
                    Column {
                        for (revision in revisions) {
                            DetailFieldRow(
                                label = "Revision ${revision.revision}",
                                value = revision.updatedAt?.toString() ?: "Unknown time",
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { historyRevisions = null }) { Text("Close") }
            },
        )
    }
}

private fun additionalFields(detail: EntryDetailView): List<EntryFieldView> {
    val legacyRoles = setOf("username", "password", "website", "url", "otp")
    val legacyKeys = setOf("username", "password", "url", "website", "otp", "totp")
    return detail.fields.filter { field ->
        field.hasValue &&
            field.semanticRole !in legacyRoles &&
            field.key.lowercase() !in legacyKeys
    }
}

@Composable
private fun DetailFieldRow(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
    accent: Boolean = false,
    onCopy: (() -> Unit)? = null,
    onOpen: (() -> Unit)? = null,
) {
    Row(
        modifier.padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                value.ifEmpty { "—" },
                style = MaterialTheme.typography.bodyMedium,
                color = if (accent) LocalKeyleaseColors.current.accentText else MaterialTheme.colorScheme.onSurface,
            )
        }
        if (onOpen != null) {
            IconButton(onClick = onOpen) {
                Icon(Icons.Filled.OpenInNew, contentDescription = "Open $label", modifier = Modifier.size(18.dp))
            }
        }
        if (onCopy != null) {
            IconButton(onClick = onCopy) {
                Icon(Icons.Filled.ContentCopy, contentDescription = "Copy $label", modifier = Modifier.size(18.dp))
            }
        }
    }
}

@Composable
private fun SecretRow(
    label: String,
    revealed: String?,
    onReveal: () -> Unit,
    onHide: () -> Unit,
    onCopy: () -> Unit,
    busy: Boolean = false,
    maskedValue: String? = null,
) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                revealed ?: maskedValue ?: "••••••••",
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        IconButton(onClick = if (revealed == null) onReveal else onHide, enabled = !busy) {
            Icon(
                if (revealed == null) Icons.Outlined.Visibility else Icons.Outlined.VisibilityOff,
                contentDescription = if (revealed == null) "Reveal $label" else "Hide $label",
                modifier = Modifier.size(18.dp),
            )
        }
        IconButton(onClick = onCopy, enabled = !busy) {
            Icon(
                Icons.Filled.ContentCopy,
                contentDescription = "Copy $label",
                modifier = Modifier.size(18.dp),
            )
        }
    }
}

/** Fetches the current TOTP on demand and refreshes it as it rotates. */
@Composable
private fun InlineTotpField(app: AppController, entry: EntrySummary) {
    val scope = rememberCoroutineScope()
    var code by remember(entry.id) { mutableStateOf<String?>(null) }
    var error by remember(entry.id) { mutableStateOf<String?>(null) }
    var remaining by remember(entry.id) { mutableIntStateOf(0) }
    var loading by remember(entry.id) { mutableStateOf(false) }
    var expiresIn by remember(entry.id) { mutableIntStateOf(0) }

    suspend fun load() {
        if (loading) return
        loading = true
        error = null
        try {
            val response = app.vault.totp(entry)
            code = "${response["code"]}"
            val e = (response["expires_in"] as? Number)?.toInt() ?: 0
            expiresIn = e
            remaining = e
        } catch (caught: Throwable) {
            code = null
            error = UserMessage.from(caught).detail
        } finally {
            loading = false
        }
    }

    LaunchedEffect(entry.id) { load() }
    LaunchedEffect(remaining) {
        if (remaining == 1 && expiresIn > 0) {
            delay(1000)
            remaining = 0
            load()
        } else if (remaining > 1) {
            delay(1000)
            remaining--
        }
    }

    Card {
        Row(
            Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    "One-time password",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    when {
                        loading -> "Loading code…"
                        code == null -> error ?: "Could not load code"
                        else -> "$code · ${remaining}s"
                    },
                    style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                )
            }
            if (code != null) {
                IconButton(onClick = { app.copySensitive(code!!) }) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = "Copy one-time password", modifier = Modifier.size(18.dp))
                }
            }
            if (error != null) {
                IconButton(onClick = { scope.launch { load() } }) {
                    Icon(Icons.Filled.Refresh, contentDescription = "Retry", modifier = Modifier.size(18.dp))
                }
            }
        }
    }
}

@Composable
private fun InlineNotesSection(app: AppController, entry: EntrySummary) {
    var notes by remember(entry.id) { mutableStateOf<String?>(null) }
    var error by remember(entry.id) { mutableStateOf(false) }
    var loading by remember(entry.id) { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    suspend fun load() {
        if (loading) return
        loading = true
        error = false
        val value = app.vault.fetchSecret(entry, "notes")
        loading = false
        notes = value
        if (value == null) error = true
    }

    LaunchedEffect(entry.id) { load() }

    SectionLabel("Notes")
    Card {
        Box(Modifier.padding(14.dp)) {
            when {
                loading -> CircularProgressIndicator(Modifier.size(20.dp))
                error -> Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        "Could not load notes",
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.weight(1f),
                    )
                    TextButton(onClick = { scope.launch { load() } }) { Text("Retry") }
                }
                else -> SelectionContainer {
                    Text(notes.orEmpty(), style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}

@Composable
private fun MetadataSection(
    item: EntrySummary,
    detail: EntryDetailView?,
    templateLabel: String,
    projectName: String?,
    groupName: String,
    onHistory: () -> Unit,
) {
    var expanded by remember(item.id) { mutableStateOf(false) }
    Column {
        TextButton(onClick = { expanded = !expanded }) {
            Icon(
                Icons.Filled.ChevronRight,
                contentDescription = null,
                modifier = Modifier.size(16.dp),
            )
            Text("Metadata")
        }
        if (expanded) {
            Card {
                Column(Modifier.padding(horizontal = 14.dp, vertical = 6.dp)) {
                    DetailFieldRow("Template", templateLabel)
                    DetailFieldRow("Group", groupName)
                    if (projectName != null) DetailFieldRow("Project", projectName)
                    if (detail?.tags?.isNotEmpty() == true) {
                        DetailFieldRow("Tags", detail.tags.joinToString(", "))
                    }
                    DetailFieldRow("Last updated", item.updatedAt?.toString() ?: "Unknown")
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            DetailFieldRow("Revision", "${item.revision}")
                        }
                        IconButton(onClick = onHistory) {
                            Icon(Icons.Filled.History, contentDescription = "View history", modifier = Modifier.size(18.dp))
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Developer template detail — port of `developer_template_detail.dart`.
// ---------------------------------------------------------------------------

@Composable
private fun DeveloperTemplateDetail(
    app: AppController,
    item: EntrySummary,
    detail: EntryDetailView,
) {
    when (item.kind) {
        "core.environment" -> EnvironmentDetail(app, item, detail)
        "core.ssh_server" -> SshDetail(app, item, detail)
    }
}

@Composable
private fun EnvironmentDetail(app: AppController, item: EntrySummary, detail: EntryDetailView) {
    val vaultState by app.vault.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var query by remember { mutableStateOf("") }
    var failure by remember { mutableStateOf<UserMessage?>(null) }

    val variableSection = detail.sections.firstOrNull {
        it.semanticRole == "environment_variables"
    }
    val byId = detail.fields.associateBy { it.id }
    val variables = (variableSection?.fieldIds ?: emptyList())
        .mapNotNull { byId[it] }
        .filter { query.isBlank() || it.label.lowercase().contains(query.trim().lowercase()) }

    val metadata = detail.sections.firstOrNull {
        it.semanticRole == "environment_metadata"
    }?.let { fieldsByRole(it, detail) } ?: emptyMap()

    SectionLabel("Environment")
    Card {
        Column(Modifier.padding(horizontal = 14.dp, vertical = 6.dp)) {
            DetailFieldRow("Project / repository", metadata["environment_project"]?.displayValue ?: "")
            DetailFieldRow("Environment", metadata["environment_scope"]?.displayValue ?: "")
            DetailFieldRow("Source", metadata["environment_source"]?.displayValue ?: "")
        }
    }
    Spacer(Modifier.height(14.dp))
    Row(verticalAlignment = Alignment.CenterVertically) {
        SectionLabel("Variables", Modifier.weight(1f))
        TextButton(onClick = {
            scope.launch {
                val section = variableSection ?: return@launch
                val fields = section.fieldIds.mapNotNull { byId[it] }
                try {
                    val values = app.vault.fetchFields(item, fields)
                    val content = renderDotEnv(fields.map { it.label to (values[it.id] ?: "") })
                    app.copySensitive(content)
                } catch (caught: Throwable) {
                    failure = UserMessage.from(caught)
                }
            }
        }) {
            Icon(Icons.Filled.ContentCopy, null, modifier = Modifier.size(15.dp))
            Text(" Copy .env file")
        }
    }
    failure?.let { MessageBanner(it, onDismiss = { failure = null }) }
    OutlinedTextField(
        value = query,
        onValueChange = { query = it },
        placeholder = { Text("Find a variable") },
        leadingIcon = { Icon(Icons.Filled.Search, null, modifier = Modifier.size(16.dp)) },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    Spacer(Modifier.height(8.dp))
    Card {
        Column(Modifier.padding(horizontal = 14.dp, vertical = 6.dp)) {
            for (field in variables) {
                if (field.`protected`) {
                    SecretRow(
                        label = field.label,
                        revealed = vaultState.revealedValue(item.id, field.id),
                        maskedValue = field.displayHint,
                        busy = vaultState.isBusy("reveal.${item.id}/${field.id}"),
                        onReveal = { scope.launch { app.vault.revealField(item, field) } },
                        onHide = { app.vault.hideSecret(item.id, field.id) },
                        onCopy = {
                            scope.launch {
                                val value = app.vault.fetchField(item, field)
                                if (!value.isNullOrEmpty()) app.copySensitive(value)
                            }
                        },
                    )
                } else {
                    DetailFieldRow(
                        label = field.label,
                        value = field.displayValue,
                        onCopy = {
                            scope.launch { app.copySensitive(field.displayValue) }
                        },
                    )
                }
            }
        }
    }
}

@Composable
private fun SshDetail(app: AppController, item: EntrySummary, detail: EntryDetailView) {
    val vaultState by app.vault.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()

    val endpoints = detail.sections
        .filter { it.semanticRole == "ssh_endpoint" }
        .map { section ->
            val fields = fieldsByRole(section, detail)
            ai.leasegate.mobile.state.SshEndpointConfig(
                sectionId = section.id,
                name = fields["ssh_display_name"]?.displayValue ?: section.label,
                alias = fields["ssh_alias"]?.displayValue ?: "",
                host = fields["ssh_host"]?.displayValue ?: "",
                port = fields["ssh_port"]?.displayValue?.toIntOrNull() ?: 22,
                username = fields["ssh_username"]?.displayValue ?: "",
                authMode = fields["ssh_auth_mode"]?.displayValue ?: "ssh_agent",
                connectVia = fields["ssh_connect_via"]?.displayValue,
            ) to fields
        }
    val forwards = detail.sections
        .filter { it.semanticRole == "ssh_forward" }
        .map { section ->
            val fields = fieldsByRole(section, detail)
            ai.leasegate.mobile.state.SshForwardConfig(
                endpointId = fields["ssh_forward_endpoint"]?.displayValue ?: "",
                type = fields["ssh_forward_type"]?.displayValue ?: "local",
                bindAddress = fields["ssh_bind_address"]?.displayValue ?: "127.0.0.1",
                bindPort = fields["ssh_bind_port"]?.displayValue?.toIntOrNull() ?: 0,
                destinationHost = fields["ssh_destination_host"]?.displayValue ?: "",
                destinationPort = fields["ssh_destination_port"]?.displayValue?.toIntOrNull() ?: 0,
            )
        }

    SectionLabel("SSH servers")
    for ((endpoint, fields) in endpoints) {
        Card(Modifier.padding(vertical = 6.dp)) {
            Column(Modifier.padding(horizontal = 14.dp, vertical = 6.dp)) {
                DetailFieldRow(
                    label = endpoint.name,
                    value = "${if (endpoint.username.isEmpty()) "" else "${endpoint.username}@"}${endpoint.host}:${endpoint.port}",
                    onCopy = { scope.launch { app.copySensitive("ssh ${endpoint.alias}") } },
                )
                DetailFieldRow("Alias", endpoint.alias)
                DetailFieldRow("Authentication", endpoint.authMode.replace('_', ' '))
                endpoints.firstOrNull { it.first.sectionId == endpoint.connectVia }?.let {
                    DetailFieldRow("Connect via", it.first.name)
                }
                if (endpoint.authMode == "private_key" && !app.capabilities.sshKeyBinding) {
                    DetailFieldRow(
                        "Private key on this device",
                        "Not available on this device",
                    )
                }
                for (role in listOf("ssh_password", "ssh_private_key_passphrase", "ssh_sudo_password")) {
                    fields[role]?.takeIf { it.hasValue }?.let { field ->
                        SecretRow(
                            label = field.label,
                            revealed = vaultState.revealedValue(item.id, field.id),
                            maskedValue = field.displayHint,
                            busy = vaultState.isBusy("reveal.${item.id}/${field.id}"),
                            onReveal = { scope.launch { app.vault.revealField(item, field) } },
                            onHide = { app.vault.hideSecret(item.id, field.id) },
                            onCopy = {
                                scope.launch {
                                    val value = app.vault.fetchField(item, field)
                                    if (!value.isNullOrEmpty()) app.copySensitive(value)
                                }
                            },
                        )
                    }
                }
            }
        }
    }
    if (forwards.isNotEmpty()) {
        SectionLabel("SSH tunnels")
        Card {
            Column(Modifier.padding(horizontal = 14.dp, vertical = 6.dp)) {
                for (forward in forwards) {
                    DetailFieldRow(
                        label = "${forward.type.uppercase()} · " +
                            (endpoints.firstOrNull { it.first.sectionId == forward.endpointId }
                                ?.first?.name ?: forward.endpointId),
                        value = if (forward.type == "dynamic") {
                            "${forward.bindAddress}:${forward.bindPort}"
                        } else {
                            "${forward.bindAddress}:${forward.bindPort} → ${forward.destinationHost}:${forward.destinationPort}"
                        },
                    )
                }
            }
        }
    }
}

/** TOTP code dialog with a live countdown — port of `showTotpDialog`. */
@Composable
fun TotpDialog(
    code: String,
    expiresIn: Int,
    onCopy: () -> Unit,
    onDismiss: () -> Unit,
) {
    var remaining by remember { mutableIntStateOf(expiresIn) }
    LaunchedEffect(Unit) {
        while (remaining > 0) {
            delay(1000)
            remaining--
        }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("One-time password") },
        text = {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    "This code is shown on request and is not stored by the app.",
                    style = MaterialTheme.typography.bodySmall,
                )
                Spacer(Modifier.height(14.dp))
                SelectionContainer {
                    Text(
                        if (remaining == 0) "••• •••" else code,
                        style = MaterialTheme.typography.displaySmall.copy(
                            fontFamily = FontFamily.Monospace,
                            letterSpacing = androidx.compose.ui.unit.TextUnit.Unspecified,
                        ),
                        textAlign = TextAlign.Center,
                    )
                }
                Spacer(Modifier.height(14.dp))
                LinearProgressIndicator(
                    progress = { if (expiresIn == 0) 0f else remaining / expiresIn.toFloat() },
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    if (remaining == 0) {
                        "This code expired. Close and ask for a new one."
                    } else {
                        "Expires in ${remaining}s"
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onCopy) { Text("Copy code") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Close") }
        },
    )
}
