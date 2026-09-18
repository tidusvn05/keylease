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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Circle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.LinkOff
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.ShieldMoon
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.Timeline
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusDirection
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import ai.leasegate.mobile.core.ActivityEvent
import ai.leasegate.mobile.core.ApprovalSummary
import ai.leasegate.mobile.core.ConnectionSummary
import ai.leasegate.mobile.core.LocalVaultProfile
import ai.leasegate.mobile.core.UserMessage
import ai.leasegate.mobile.state.AppController
import ai.leasegate.mobile.state.AppPhase
import ai.leasegate.mobile.state.StaleApprovalException
import ai.leasegate.mobile.ui.KeyleaseButton
import ai.leasegate.mobile.ui.LocalKeyleaseColors
import ai.leasegate.mobile.ui.MessageBanner
import ai.leasegate.mobile.ui.SectionLabel
import ai.leasegate.mobile.ui.SelectField
import ai.leasegate.mobile.ui.StateScreen
import java.time.Duration
import java.time.LocalDateTime
import kotlinx.coroutines.launch

// ---------------------------------------------------------------------------
// Approvals — port of `approvals_page.dart`. A decision is always bound to
// the exact request digest the user just read.
// ---------------------------------------------------------------------------

@Composable
fun ApprovalsScreen(app: AppController) {
    val state by app.approvals.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()

    LaunchedEffect(Unit) { app.approvals.load() }

    if (state.loading && !state.loaded) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            CircularProgressIndicator()
        }
        return
    }
    Column(Modifier.fillMaxSize()) {
        state.error?.let {
            MessageBanner(it, onAction = { scope.launch { app.approvals.load() } })
        }
        if (state.items.isEmpty()) {
            StateScreen(
                title = "Nothing waiting for you",
                message = "Requests that need your decision appear here.",
                icon = Icons.Filled.Shield,
            )
        } else {
            LazyColumn(
                Modifier.fillMaxSize().padding(horizontal = 18.dp),
            ) {
                items(state.items, key = { it.id }) { approval ->
                    ApprovalCard(app, approval)
                }
            }
        }
    }
}

@Composable
private fun ApprovalCard(app: AppController, approval: ApprovalSummary) {
    val scope = rememberCoroutineScope()
    var pending by remember { mutableStateOf<Boolean?>(null) }
    var stale by remember { mutableStateOf<String?>(null) }
    var failure by remember { mutableStateOf<UserMessage?>(null) }
    val decidable = approval.decidableAt(LocalDateTime.now())

    Card(Modifier.padding(vertical = 6.dp)) {
        Column(Modifier.padding(14.dp)) {
            RequestSummaryView(approval)
            failure?.let {
                Spacer(Modifier.height(8.dp))
                MessageBanner(it, onDismiss = { failure = null })
            }
            Spacer(Modifier.height(14.dp))
            Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
                KeyleaseButton(
                    "Deny",
                    outline = true,
                    enabled = decidable,
                    onClick = { pending = false },
                )
                Spacer(Modifier.width(10.dp))
                KeyleaseButton(
                    "Approve",
                    enabled = decidable,
                    onClick = { pending = true },
                )
            }
        }
    }

    pending?.let { approve ->
        AlertDialog(
            onDismissRequest = { pending = null },
            title = { Text(if (approve) "Approve this exact request?" else "Deny this request?") },
            text = {
                Column {
                    Text(
                        if (approve) {
                            "Your approval applies only to the request below. Anything else, even from the same client, still needs a new decision."
                        } else {
                            "Denying stops this request. The client can ask again."
                        },
                    )
                    Spacer(Modifier.height(10.dp))
                    SelectionContainer {
                        Text(
                            approval.requestDigestHex,
                            style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    pending = null
                    scope.launch {
                        try {
                            app.approvals.decide(approval, approve)
                        } catch (caught: StaleApprovalException) {
                            stale = caught.message
                        } catch (caught: Throwable) {
                            failure = UserMessage.from(caught)
                        }
                    }
                }) {
                    Text(
                        if (approve) "Approve" else "Deny",
                        color = if (approve) MaterialTheme.colorScheme.primary
                        else LocalKeyleaseColors.current.danger,
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { pending = null }) { Text("Cancel") }
            },
        )
    }

    stale?.let { message ->
        AlertDialog(
            onDismissRequest = { stale = null },
            title = { Text("That request moved on") },
            text = { Text(message) },
            confirmButton = {
                TextButton(onClick = { stale = null }) { Text("Close") }
            },
        )
    }
}

/** Port of `RequestSummary`: every shown field exists on the record. */
@Composable
private fun RequestSummaryView(approval: ApprovalSummary, dense: Boolean = false) {
    val reference = LocalDateTime.now()
    val expired = !approval.expiresAt.isAfter(reference)
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                approval.operation ?: approval.action ?: "Access request",
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.weight(1f),
            )
            approval.risk?.let { risk ->
                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = if (risk == "high") {
                        LocalKeyleaseColors.current.danger.copy(alpha = 0.15f)
                    } else {
                        MaterialTheme.colorScheme.surfaceVariant
                    },
                ) {
                    Text(
                        "$risk risk",
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                        style = MaterialTheme.typography.labelSmall,
                        color = if (risk == "high") LocalKeyleaseColors.current.danger
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            if (!approval.isPending || expired) {
                Spacer(Modifier.width(8.dp))
                Text(
                    if (expired) "Expired" else approval.state,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Spacer(Modifier.height(6.dp))
        SummaryLine("What it wants to do", approval.action ?: "unknown action")
        SummaryLine("Where", approval.target ?: approval.resource ?: "unknown resource")
        SummaryLine("Requested by", approval.agentId ?: "unknown client")
        if (approval.changedFields.isNotEmpty()) {
            SummaryLine("Fields it would change", approval.changedFields.joinToString(", "))
        }
        approval.blastRadius?.let { SummaryLine("Scope", it) }
        SummaryLine(
            if (expired) "Expired" else "Expires",
            "${relative(approval.expiresAt, reference)} · policy v${approval.policyVersion}",
        )
        if (!dense) {
            SectionLabel("Exact request")
            SelectionContainer {
                Text(
                    approval.requestDigestHex,
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun SummaryLine(label: String, value: String) {
    Row(Modifier.padding(vertical = 2.dp)) {
        Text(
            label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(140.dp),
        )
        Text(value, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
    }
}

private fun relative(when_: LocalDateTime, now: LocalDateTime): String {
    val seconds = Duration.between(now, when_).seconds
    val past = seconds < 0
    val magnitude = kotlin.math.abs(seconds)
    val text = when {
        magnitude < 60 -> "$magnitude sec"
        magnitude < 3600 -> "${magnitude / 60} min"
        magnitude < 86400 -> "${magnitude / 3600} hr"
        else -> "${magnitude / 86400} days"
    }
    return if (past) "$text ago" else "in $text"
}

// ---------------------------------------------------------------------------
// Activity — port of `activity_page.dart`.
// ---------------------------------------------------------------------------

private fun friendlyTime(when_: LocalDateTime?): String {
    if (when_ == null) return "Unknown time"
    val delta = Duration.between(when_, LocalDateTime.now())
    if (delta.seconds < 60) return "Just now"
    if (delta.toMinutes() < 60) return "${delta.toMinutes()} min ago"
    if (delta.toHours() < 24) return "${delta.toHours()} hr ago"
    if (delta.toDays() < 7) return "${delta.toDays()} days ago"
    return "%04d-%02d-%02d".format(when_.year, when_.monthValue, when_.dayOfMonth)
}

@Composable
fun ActivityContent(app: AppController) {
    val state by app.activity.state.collectAsStateWithLifecycle()
    val deniedOnly by app.activity.deniedOnly.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    val events = if (deniedOnly) state.items.filter { it.denied } else state.items

    LaunchedEffect(Unit) { app.activity.load() }

    if (state.loading && !state.loaded) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            CircularProgressIndicator()
        }
        return
    }
    Column(Modifier.fillMaxSize()) {
        state.error?.let {
            MessageBanner(it, onAction = { scope.launch { app.activity.load() } })
        }
        Row(Modifier.padding(horizontal = 18.dp, vertical = 10.dp)) {
            KeyleaseButton(
                "All events",
                outline = deniedOnly,
                onClick = { app.activity.setDeniedOnly(false) },
            )
            Spacer(Modifier.width(10.dp))
            KeyleaseButton(
                "Denied or failed",
                outline = !deniedOnly,
                onClick = { app.activity.setDeniedOnly(true) },
            )
        }
        if (events.isEmpty()) {
            StateScreen(
                title = if (deniedOnly) "Nothing was refused" else "No activity yet",
                message = if (deniedOnly) {
                    "No request was denied or failed in this window."
                } else {
                    "Actions taken through KeyLease show up here."
                },
                icon = Icons.Filled.History,
            )
        } else {
            LazyColumn(Modifier.fillMaxSize().padding(horizontal = 18.dp)) {
                items(events) { event -> EventRow(event) }
            }
        }
    }
}

@Composable
private fun EventRow(event: ActivityEvent) {
    ListItem(
        leadingContent = {
            Icon(
                if (event.denied) Icons.Filled.ShieldMoon else Icons.Filled.CheckCircle,
                contentDescription = null,
                tint = if (event.denied) {
                    LocalKeyleaseColors.current.warning
                } else {
                    LocalKeyleaseColors.current.success
                },
                modifier = Modifier.size(18.dp),
            )
        },
        headlineContent = { Text(event.action) },
        supportingContent = {
            Text(
                "${event.resource}\n${event.agentId} · ${friendlyTime(event.timestamp)}" +
                    if (event.volume.isEmpty()) "" else " · ${event.volume}",
            )
        },
        trailingContent = {
            Text(
                if (event.denied) "Denied" else "Allowed",
                style = MaterialTheme.typography.labelSmall,
                color = if (event.denied) {
                    LocalKeyleaseColors.current.warning
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            )
        },
    )
    HorizontalDivider()
}

// ---------------------------------------------------------------------------
// Connections — port of `connections_page.dart` (token connections only on
// Android; Google OAuth is desktop-gated).
// ---------------------------------------------------------------------------

private fun connectionHealthLabel(connection: ConnectionSummary) = when (connection.health) {
    "connected" -> "Working"
    "degraded" -> "Having trouble"
    "expired" -> "Sign-in expired"
    "revoked" -> "Access revoked"
    "disconnected" -> "Disconnected"
    else -> "Unknown"
}

private fun connectionRemedy(connection: ConnectionSummary): String? {
    if (connection.reauthorizationRequired) return "Sign in again to restore access."
    return when (connection.health) {
        "connected" -> null
        "degraded" -> "Run Test to see whether the provider is reachable."
        "expired" -> "Refresh this connection to get a new credential."
        "revoked" -> "The provider revoked this credential. Connect again."
        "disconnected" -> "Reconnect this account to use it again."
        else -> "Run Test to check this connection."
    }
}

@Composable
fun ConnectionsContent(app: AppController) {
    val state by app.connections.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var showAdd by remember { mutableStateOf(false) }
    var failure by remember { mutableStateOf<UserMessage?>(null) }

    LaunchedEffect(Unit) { app.connections.load() }

    if (state.loading && !state.loaded) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            CircularProgressIndicator()
        }
        return
    }
    Column(Modifier.fillMaxSize()) {
        state.error?.let {
            MessageBanner(it, onAction = { scope.launch { app.connections.load() } })
        }
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.End,
        ) {
            KeyleaseButton(
                "Add token connection",
                outline = true,
                icon = Icons.Filled.Link,
                onClick = { showAdd = true },
            )
            if (app.capabilities.googleOauth) {
                Spacer(Modifier.width(10.dp))
                KeyleaseButton("Connect Google", icon = Icons.Filled.Storage, onClick = {})
            }
        }
        failure?.let { MessageBanner(it, onDismiss = { failure = null }) }
        if (state.items.isEmpty()) {
            StateScreen(
                title = "No connections yet",
                message = "Connect an account so KeyLease can act on the exact resources you allow.",
                icon = Icons.Filled.Link,
            )
        } else {
            LazyColumn(Modifier.fillMaxSize().padding(horizontal = 18.dp)) {
                items(state.items, key = { it.id }) { connection ->
                    ConnectionCard(app, connection, onFailure = { failure = it })
                }
            }
        }
    }

    if (showAdd) {
        AddTokenConnectionDialog(
            onDismiss = { showAdd = false },
            onAdd = { provider, credential, resources ->
                showAdd = false
                scope.launch {
                    try {
                        app.connections.add(provider, credential, resources)
                    } catch (caught: Throwable) {
                        failure = UserMessage.from(caught)
                    }
                }
            },
        )
    }
}

@Composable
private fun ConnectionCard(
    app: AppController,
    connection: ConnectionSummary,
    onFailure: (UserMessage) -> Unit,
) {
    val scope = rememberCoroutineScope()
    var confirmRevoke by remember { mutableStateOf(false) }
    var enroll by remember { mutableStateOf(false) }
    val remedy = connectionRemedy(connection)

    fun run(operation: String) {
        if (operation == "revoke") {
            confirmRevoke = true
            return
        }
        scope.launch {
            try {
                app.connections.manage(connection, operation)
            } catch (caught: Throwable) {
                onFailure(UserMessage.from(caught))
            }
        }
    }

    Card(Modifier.padding(vertical = 6.dp)) {
        Column(Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(
                        connection.provider,
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Surface(
                            shape = CircleShape,
                            color = LocalKeyleaseColors.current.statusColor(connection.health),
                            modifier = Modifier.size(8.dp),
                        ) {}
                        Spacer(Modifier.width(7.dp))
                        Text(
                            connectionHealthLabel(connection),
                            style = MaterialTheme.typography.bodySmall,
                            color = LocalKeyleaseColors.current.statusColor(connection.health),
                        )
                    }
                }
                IconButton(onClick = { run("test") }) {
                    Icon(Icons.Filled.Timeline, "Test ${connection.provider}", Modifier.size(18.dp))
                }
                IconButton(onClick = { run("refresh") }) {
                    Icon(Icons.Filled.Refresh, "Refresh ${connection.provider}", Modifier.size(18.dp))
                }
                IconButton(onClick = { run("disconnect") }) {
                    Icon(Icons.Filled.LinkOff, "Disconnect ${connection.provider}", Modifier.size(18.dp))
                }
                IconButton(onClick = { run("revoke") }) {
                    Icon(
                        Icons.Filled.Shield,
                        "Revoke ${connection.provider}",
                        Modifier.size(18.dp),
                        tint = LocalKeyleaseColors.current.danger,
                    )
                }
            }
            if (remedy != null) {
                Spacer(Modifier.height(10.dp))
                Text(
                    if (connection.healthReason == null) remedy
                    else "$remedy (${connection.healthReason})",
                    style = MaterialTheme.typography.bodySmall,
                    color = LocalKeyleaseColors.current.statusColor(connection.health),
                )
            }
            Spacer(Modifier.height(10.dp))
            Text(
                "${connection.trustMode} · ${connection.executionLocation} · ${connection.authMethod}",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            connection.lastCheckedAt?.let {
                Text(
                    "Last checked $it",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            SectionLabel("Resources this connection may touch")
            if (connection.authorizedResources.isEmpty()) {
                Text(
                    "No resources enrolled yet.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                Column {
                    for (resource in connection.authorizedResources) {
                        Surface(
                            shape = RoundedCornerShape(6.dp),
                            color = MaterialTheme.colorScheme.surfaceVariant,
                            modifier = Modifier.padding(vertical = 2.dp),
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    resource,
                                    style = MaterialTheme.typography.bodySmall,
                                    modifier = Modifier.padding(start = 10.dp),
                                )
                                IconButton(
                                    onClick = {
                                        scope.launch {
                                            try {
                                                app.connections.setResource(
                                                    connection, resource, enrolled = false,
                                                )
                                            } catch (caught: Throwable) {
                                                onFailure(UserMessage.from(caught))
                                            }
                                        }
                                    },
                                ) {
                                    Icon(Icons.Filled.Close, "Remove $resource", Modifier.size(13.dp))
                                }
                            }
                        }
                    }
                }
            }
            Spacer(Modifier.height(10.dp))
            KeyleaseButton(
                "Enroll a resource",
                outline = true,
                icon = Icons.Filled.Add,
                onClick = { enroll = true },
            )
        }
    }

    if (confirmRevoke) {
        AlertDialog(
            onDismissRequest = { confirmRevoke = false },
            title = { Text("Revoke this connection?") },
            text = {
                Text("KeyLease asks the provider to revoke the credential. This cannot be undone.")
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmRevoke = false
                    scope.launch {
                        try {
                            app.connections.manage(connection, "revoke")
                        } catch (caught: Throwable) {
                            onFailure(UserMessage.from(caught))
                        }
                    }
                }) { Text("Revoke", color = LocalKeyleaseColors.current.danger) }
            },
            dismissButton = {
                TextButton(onClick = { confirmRevoke = false }) { Text("Cancel") }
            },
        )
    }

    if (enroll) {
        var resource by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { enroll = false },
            title = { Text("Enroll an exact resource") },
            text = {
                Column {
                    Text("KeyLease only touches resources you list here.")
                    Spacer(Modifier.height(10.dp))
                    OutlinedTextField(
                        value = resource,
                        onValueChange = { resource = it },
                        label = { Text("Canonical resource ID") },
                        singleLine = true,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val value = resource.trim()
                    if (value.isEmpty()) return@TextButton
                    enroll = false
                    scope.launch {
                        try {
                            app.connections.setResource(connection, value, enrolled = true)
                        } catch (caught: Throwable) {
                            onFailure(UserMessage.from(caught))
                        }
                    }
                }) { Text("Enroll") }
            },
            dismissButton = {
                TextButton(onClick = { enroll = false }) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun AddTokenConnectionDialog(
    onDismiss: () -> Unit,
    onAdd: (provider: String, credential: String, resources: List<String>) -> Unit,
) {
    var provider by remember { mutableStateOf("github") }
    var credential by remember { mutableStateOf("") }
    var resources by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = {},
        title = { Text("Add a token connection") },
        text = {
            Column {
                SelectField(
                    label = "Provider",
                    items = listOf(
                        "GitHub" to "github", "Linear" to "linear",
                        "Notion" to "notion", "Fake (testing)" to "fake",
                    ),
                    value = provider,
                    onChange = { provider = it },
                )
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(
                    value = credential,
                    onValueChange = { credential = it },
                    label = { Text("Token or OAuth credential JSON") },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(
                    value = resources,
                    onValueChange = { resources = it },
                    label = { Text("Exact canonical resources (one per line)") },
                    minLines = 2,
                    maxLines = 5,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val secret = credential
                val list = resources.split('\n')
                    .map { it.trim() }
                    .filter { it.isNotEmpty() }
                credential = ""
                if (secret.isNotEmpty()) onAdd(provider, secret, list)
            }) { Text("Add") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

// ---------------------------------------------------------------------------
// Settings — port of `settings_page.dart` (compact: list → pushed page).
// ---------------------------------------------------------------------------

private enum class SettingsDestination(val label: String) {
    GENERAL("General"),
    VAULTS("Vaults"),
    CONNECTIONS("Connections"),
    SECURITY("Security"),
    ACTIVITY("Activity"),
}

@Composable
fun SettingsScreen(app: AppController) {
    var destination by remember { mutableStateOf<SettingsDestination?>(null) }
    val scope = rememberCoroutineScope()

    fun select(next: SettingsDestination) {
        destination = next
        if (!app.state.value.isReady) return
        scope.launch {
            when (next) {
                SettingsDestination.CONNECTIONS -> app.connections.load()
                SettingsDestination.ACTIVITY -> app.activity.load()
                else -> Unit
            }
        }
    }

    val current = destination
    if (current != null) {
        BackHandler { destination = null }
        Column(Modifier.fillMaxSize()) {
            Row(
                modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                IconButton(onClick = { destination = null }) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Settings")
                }
                Text(
                    current.label,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
            }
            HorizontalDivider()
            SettingsContent(app, current)
        }
        return
    }

    LazyColumn(Modifier.fillMaxSize().padding(18.dp)) {
        items(SettingsDestination.entries) { item ->
            ListItem(
                modifier = Modifier.clickable { select(item) },
                leadingContent = {
                    Icon(
                        when (item) {
                            SettingsDestination.GENERAL -> Icons.Filled.Tune
                            SettingsDestination.VAULTS -> Icons.Filled.Shield
                            SettingsDestination.CONNECTIONS -> Icons.Filled.Link
                            SettingsDestination.SECURITY -> Icons.Filled.ShieldMoon
                            SettingsDestination.ACTIVITY -> Icons.Filled.History
                        },
                        contentDescription = null,
                        tint = LocalKeyleaseColors.current.accentText,
                    )
                },
                headlineContent = { Text(item.label) },
                trailingContent = {
                    Icon(Icons.Filled.ChevronRight, contentDescription = null)
                },
            )
        }
    }
}

@Composable
private fun SettingsContent(app: AppController, destination: SettingsDestination) {
    when (destination) {
        SettingsDestination.GENERAL -> GeneralSettings(app)
        SettingsDestination.VAULTS -> VaultsSettings(app)
        SettingsDestination.CONNECTIONS -> ConnectionsContent(app)
        SettingsDestination.SECURITY -> SecuritySettings(app)
        SettingsDestination.ACTIVITY -> ActivityContent(app)
    }
}

@Composable
private fun SettingsCard(
    title: String,
    subtitle: String,
    trailing: (@Composable () -> Unit)? = null,
) {
    Card(Modifier.padding(vertical = 5.dp)) {
        Row(
            Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(4.dp))
                Text(
                    subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (trailing != null) {
                Spacer(Modifier.width(16.dp))
                trailing()
            }
        }
    }
}

@Composable
private fun GeneralSettings(app: AppController) {
    val appState by app.state.collectAsStateWithLifecycle()
    val vaultState by app.vault.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var repairPassword by remember { mutableStateOf("") }

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(18.dp),
    ) {
        SectionLabel("General", Modifier.padding(start = 0.dp))
        SettingsCard(
            title = "KeyLease data",
            subtitle = "Vault, backups, and runtime files are kept privately in this app's storage.",
        )
        if (appState.isReady) {
            SettingsCard(
                title = "Vault migrations",
                subtitle = if (vaultState.migrationStatus?.pending?.isNotEmpty() == true) {
                    "${vaultState.migrationStatus!!.pending.first().proposals.size} items need review."
                } else {
                    "Review migration history and rollback checkpoints."
                },
                trailing = {
                    if (app.capabilities.vaultMigrations) {
                        TextButton(onClick = {}) { Text("Manage") }
                    }
                },
            )
        }
        SettingsCard(
            title = "Background service",
            subtitle = if (appState.serviceVersion == null) {
                "Runs automatically while you are signed in."
            } else {
                "Version ${appState.serviceVersion} · runs automatically while you are signed in."
            },
            trailing = {
                TextButton(onClick = { scope.launch { app.refresh() } }) { Text("Refresh") }
            },
        )
        if (appState.phase == AppPhase.REPAIR_REQUIRED) {
            SectionLabel("Repair", Modifier.padding(start = 0.dp))
            Text(
                "Enter your vault password to recreate this device's local credential. Vault data is unchanged.",
                style = MaterialTheme.typography.bodySmall,
            )
            Spacer(Modifier.height(10.dp))
            OutlinedTextField(
                value = repairPassword,
                onValueChange = { repairPassword = it },
                label = { Text("Master password") },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(10.dp))
            KeyleaseButton(
                "Repair connection",
                onClick = {
                    val password = repairPassword
                    if (password.isEmpty()) return@KeyleaseButton
                    repairPassword = ""
                    scope.launch {
                        app.provision(mapOf("mode" to "repair_desktop_client", "password" to password))
                    }
                },
            )
        }
    }
}

@Composable
private fun VaultsSettings(app: AppController) {
    val appState by app.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var failure by remember { mutableStateOf<UserMessage?>(null) }
    var create by remember { mutableStateOf(false) }
    var importing by remember { mutableStateOf(false) }
    var rename by remember { mutableStateOf<LocalVaultProfile?>(null) }
    var importingSource by remember { mutableStateOf<Pair<String, String>?>(null) }

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(18.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            SectionLabel("Vaults", Modifier.weight(1f).padding(start = 0.dp))
            KeyleaseButton("Import", outline = true, onClick = {
                scope.launch {
                    try {
                        val path = app.chooseVaultSource?.invoke() ?: return@launch
                        val inspected = app.inspectSource(path)
                        if (inspected["supported"] == false) {
                            failure = UserMessage(
                                title = "Unsupported source",
                                detail = inspected["reason"]?.toString()
                                    ?: "This file is not a supported vault.",
                            )
                            return@launch
                        }
                        importingSource = path to ("${inspected["kind"]}")
                    } catch (caught: Throwable) {
                        failure = UserMessage.from(caught)
                    }
                }
            })
            Spacer(Modifier.width(8.dp))
            KeyleaseButton("New vault", onClick = { create = true })
        }
        failure?.let {
            MessageBanner(it, onDismiss = { failure = null })
            Spacer(Modifier.height(10.dp))
        }
        for (profile in appState.vaultProfiles) {
            ListItem(
                leadingContent = {
                    Icon(
                        if (profile.active) Icons.Filled.CheckCircle else Icons.Filled.Circle,
                        contentDescription = null,
                        tint = if (profile.active) LocalKeyleaseColors.current.success
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(17.dp),
                    )
                },
                headlineContent = { Text(profile.name) },
                supportingContent = {
                    Text(if (profile.active) "Active vault" else "Locked until selected")
                },
                trailingContent = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        IconButton(onClick = { rename = profile }) {
                            Icon(Icons.Filled.Edit, "Rename ${profile.name}", Modifier.size(16.dp))
                        }
                        if (!profile.active) {
                            TextButton(onClick = {
                                scope.launch {
                                    try {
                                        app.switchManagedVault(profile.id)
                                    } catch (caught: Throwable) {
                                        failure = UserMessage.from(caught)
                                    }
                                }
                            }) { Text("Switch") }
                        }
                    }
                },
            )
            HorizontalDivider()
        }
    }

    if (create) {
        var name by remember { mutableStateOf("") }
        var password by remember { mutableStateOf("") }
        fun submit() {
            val vaultName = name.trim()
            val secret = password
            password = ""
            if (vaultName.isEmpty() || secret.isEmpty()) return
            create = false
            scope.launch {
                try {
                    app.createManagedVault(
                        vaultName,
                        mapOf("mode" to "create", "password" to secret),
                    )
                } catch (caught: Throwable) {
                    failure = UserMessage.from(caught)
                }
            }
        }
        AlertDialog(
            onDismissRequest = { create = false },
            title = { Text("New vault") },
            text = {
                val focusManager = LocalFocusManager.current
                Column {
                    Text("This vault has its own master password.")
                    Spacer(Modifier.height(10.dp))
                    OutlinedTextField(
                        value = name,
                        onValueChange = { name = it },
                        label = { Text("Vault name") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                        keyboardActions = KeyboardActions(
                            onNext = { focusManager.moveFocus(FocusDirection.Down) },
                        ),
                    )
                    Spacer(Modifier.height(10.dp))
                    OutlinedTextField(
                        value = password,
                        onValueChange = { password = it },
                        label = { Text("Master password") },
                        visualTransformation = PasswordVisualTransformation(),
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                        keyboardActions = KeyboardActions(onDone = { submit() }),
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = ::submit) { Text("Create") }
            },
            dismissButton = {
                TextButton(onClick = { create = false; password = "" }) { Text("Cancel") }
            },
        )
    }

    rename?.let { profile ->
        var name by remember { mutableStateOf(profile.name) }
        fun submit() {
            val value = name.trim()
            if (value.isEmpty() || value == profile.name) {
                rename = null
                return
            }
            rename = null
            scope.launch {
                try {
                    app.renameManagedVault(profile.id, value)
                } catch (caught: Throwable) {
                    failure = UserMessage.from(caught)
                }
            }
        }
        AlertDialog(
            onDismissRequest = { rename = null },
            title = { Text("Rename vault") },
            text = {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Vault name") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                    keyboardActions = KeyboardActions(onDone = { submit() }),
                )
            },
            confirmButton = {
                TextButton(onClick = ::submit) { Text("Rename") }
            },
            dismissButton = {
                TextButton(onClick = { rename = null }) { Text("Cancel") }
            },
        )
    }

    importingSource?.let { (path, kind) ->
        var name by remember { mutableStateOf("") }
        var sourcePassword by remember { mutableStateOf("") }
        var password by remember { mutableStateOf("") }
        fun submit() {
            val vaultName = name.trim()
            val sourceSecret = sourcePassword
            val secret = password
            sourcePassword = ""
            password = ""
            if (vaultName.isEmpty() || secret.isEmpty()) return
            importingSource = null
            val request = buildMap {
                put(
                    "mode",
                    when (kind) {
                        "keylease_database" -> "adopt_keylease_database"
                        "keylease_backup" -> "restore_keylease_backup"
                        "kdbx" -> "import_kdbx"
                        else -> "import_onepux"
                    },
                )
                put("source_path", path)
                put("password", secret)
                if (kind == "kdbx") put("source_password", sourceSecret)
                if (kind == "onepux") put("acknowledge_plaintext", true)
            }
            scope.launch {
                try {
                    app.createManagedVault(vaultName, request)
                } catch (caught: Throwable) {
                    failure = UserMessage.from(caught)
                }
            }
        }
        AlertDialog(
            onDismissRequest = { importingSource = null },
            title = { Text("Import as a new vault") },
            text = {
                val focusManager = LocalFocusManager.current
                Column {
                    Text("The imported vault remains independent from your current vault.")
                    Spacer(Modifier.height(10.dp))
                    OutlinedTextField(
                        value = name,
                        onValueChange = { name = it },
                        label = { Text("Vault name") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                        keyboardActions = KeyboardActions(
                            onNext = { focusManager.moveFocus(FocusDirection.Down) },
                        ),
                    )
                    if (kind == "kdbx") {
                        Spacer(Modifier.height(10.dp))
                        OutlinedTextField(
                            value = sourcePassword,
                            onValueChange = { sourcePassword = it },
                            label = { Text("Source password") },
                            visualTransformation = PasswordVisualTransformation(),
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                            keyboardActions = KeyboardActions(
                                onNext = { focusManager.moveFocus(FocusDirection.Down) },
                            ),
                        )
                    }
                    Spacer(Modifier.height(10.dp))
                    OutlinedTextField(
                        value = password,
                        onValueChange = { password = it },
                        label = {
                            Text(
                                if (kind == "keylease_database") "Vault password"
                                else "New master password",
                            )
                        },
                        visualTransformation = PasswordVisualTransformation(),
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                        keyboardActions = KeyboardActions(onDone = { submit() }),
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = ::submit) { Text("Import") }
            },
            dismissButton = {
                TextButton(onClick = {
                    importingSource = null
                    sourcePassword = ""
                    password = ""
                }) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun SecuritySettings(app: AppController) {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(18.dp),
    ) {
        SectionLabel("Security", Modifier.padding(start = 0.dp))
        SettingsCard(
            title = "Clipboard",
            subtitle = "Copied secrets are cleared after 30 seconds if nothing else has replaced them.",
        )
        SettingsCard(
            title = "Sleep and screen lock",
            subtitle = "KeyLease locks the vault and hides revealed secrets when this device sleeps or locks.",
        )
    }
}
