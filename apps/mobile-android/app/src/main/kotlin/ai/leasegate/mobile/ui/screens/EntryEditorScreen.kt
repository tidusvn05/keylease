package ai.leasegate.mobile.ui.screens

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import ai.leasegate.mobile.core.EntryDetailView
import ai.leasegate.mobile.core.EntryFieldView
import ai.leasegate.mobile.core.EntrySectionView
import ai.leasegate.mobile.core.TemplateDefinition
import ai.leasegate.mobile.core.TemplateFieldDefinition
import ai.leasegate.mobile.core.UserMessage
import ai.leasegate.mobile.core.VaultGroup
import ai.leasegate.mobile.state.AppController
import ai.leasegate.mobile.state.EntryDraft
import ai.leasegate.mobile.state.EnvVariableDraft
import ai.leasegate.mobile.state.PasswordGeneratorSettings
import ai.leasegate.mobile.state.PasswordPattern
import ai.leasegate.mobile.state.encodeStructuredSections
import ai.leasegate.mobile.state.entryFieldText
import ai.leasegate.mobile.state.fieldsByRole
import ai.leasegate.mobile.state.guidanceForTemplate
import ai.leasegate.mobile.state.parseDotEnv
import ai.leasegate.mobile.state.structuredId
import ai.leasegate.mobile.state.structuredTextField
import ai.leasegate.mobile.ui.KeyleaseButton
import ai.leasegate.mobile.ui.LocalKeyleaseColors
import ai.leasegate.mobile.ui.MessageBanner
import ai.leasegate.mobile.ui.SectionLabel
import ai.leasegate.mobile.ui.SearchableSelectField
import ai.leasegate.mobile.ui.SelectField
import ai.leasegate.mobile.ui.SelectOption
import kotlin.math.ln
import kotlin.math.roundToInt
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.json.JSONArray

private val DEVELOPER_KINDS = setOf("core.environment", "core.ssh_server")

/**
 * Entry create/edit workspace — the port of `EntryEditorPane` + `_EntryForm`.
 *
 * The draft object lives in the vault controller and is mutated by every
 * field change, so a failed save or a recomposition never loses input.
 */
@Composable
fun EntryEditorPane(app: AppController, onClosed: () -> Unit) {
    val vaultState by app.vault.state.collectAsStateWithLifecycle()
    val draft = vaultState.activeDraft ?: return
    val scope = rememberCoroutineScope()
    var saving by remember { mutableStateOf(false) }
    var confirmDiscard by remember { mutableStateOf(false) }
    var failure by remember { mutableStateOf<UserMessage?>(null) }
    var errors by remember { mutableStateOf<Map<String, String>>(emptyMap()) }

    fun close() {
        app.vault.closeEditor()
        onClosed()
    }

    fun cancel() {
        if (draft.isDirty) {
            confirmDiscard = true
        } else {
            close()
        }
    }

    // A dirty draft must not vanish to a stray back gesture.
    BackHandler { cancel() }

    fun save() {
        val validation = LinkedHashMap(draft.validate())
        validation.putAll(validateTemplateFields(app, draft))
        if (validation.isNotEmpty()) {
            errors = validation
            return
        }
        errors = emptyMap()
        failure = null
        saving = true
        scope.launch {
            try {
                app.vault.save(draft)
                close()
            } catch (caught: Throwable) {
                // The draft is untouched: the user keeps every typed value.
                failure = UserMessage.from(caught)
            } finally {
                saving = false
            }
        }
    }

    Column(Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = ::cancel) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
            }
            Text(
                if (draft.isNew) "New item" else "Edit item",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = ::cancel, enabled = !saving) { Text("Cancel") }
            KeyleaseButton(
                if (saving) "Saving…" else "Save",
                onClick = ::save,
                enabled = !saving,
            )
        }
        HorizontalDivider()
        Column(
            Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 14.dp),
        ) {
            failure?.let {
                MessageBanner(it, onDismiss = { failure = null })
                Spacer(Modifier.height(12.dp))
            }
            EntryForm(
                app = app,
                draft = draft,
                errors = errors,
                onErrorsChanged = { errors = it },
                onFailure = { failure = it },
            )
        }
    }

    if (confirmDiscard) {
        AlertDialog(
            onDismissRequest = { confirmDiscard = false },
            title = { Text("Discard changes?") },
            text = { Text("This item has unsaved changes. Discarding cannot be undone.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmDiscard = false
                    close()
                }) { Text("Discard", color = LocalKeyleaseColors.current.danger) }
            },
            dismissButton = {
                TextButton(onClick = { confirmDiscard = false }) { Text("Keep editing") }
            },
        )
    }
}

// ---------------------------------------------------------------------------
// Form
// ---------------------------------------------------------------------------

/** Field-level validation for template inputs — port of `_validateTemplateFields`. */
private fun validateTemplateFields(
    app: AppController,
    draft: EntryDraft,
): Map<String, String> {
    val result = LinkedHashMap<String, String>()
    for (field in templateFor(app, draft.kind)?.fields ?: emptyList()) {
        val value = templateFieldText(draft, field).trim()
        if (value.isEmpty()) continue
        if (field.valueType == "month_year") {
            val match = Regex("^(\\d{1,2})\\s*[/\\-]\\s*(\\d{4})$").find(value)
            val month = match?.groupValues?.get(1)?.toIntOrNull()
            if (month == null || month < 1 || month > 12) {
                result["template_${field.key}"] = "Use MM/YYYY."
            }
        }
        if (field.valueType == "number" && value.toDoubleOrNull() == null) {
            result["template_${field.key}"] = "Enter a number."
        }
    }
    return result
}

private fun templateFor(app: AppController, kind: String): TemplateDefinition? {
    app.vault.state.value.templates.firstOrNull { it.kind == kind }?.let { return it }
    return fallbackTemplate(kind)
}

private fun fallbackField(
    key: String,
    label: String,
    valueType: String,
    role: String,
    `protected`: Boolean = false,
    section: String = "Details",
) = TemplateFieldDefinition(
    key = key,
    label = label,
    valueType = valueType,
    semanticRole = role,
    sensitivity = if (`protected`) "highly_sensitive" else "private_metadata",
    `protected` = `protected`,
    section = section,
)

private fun fallbackTemplate(kind: String): TemplateDefinition? {
    val fields = when (kind) {
        "core.login" -> listOf(
            fallbackField("username", "Username", "text", "username", section = "Login"),
            fallbackField("password", "Password", "concealed", "password", `protected` = true, section = "Login"),
            fallbackField("website", "Website", "url", "website", section = "Login"),
            fallbackField("otp", "One-time password", "totp", "otp", `protected` = true, section = "Login"),
        )
        "core.password" -> listOf(
            fallbackField("password", "Password", "concealed", "password", `protected` = true),
            fallbackField("website", "Website", "url", "website"),
        )
        "core.api_credential" -> listOf(
            fallbackField("provider", "Provider", "text", "provider"),
            fallbackField("credential", "Credential", "concealed", "credential", `protected` = true),
            fallbackField("hostname", "Host", "url", "host"),
        )
        "core.secure_note", "core.generic", "core.prompt", "core.runbook", "core.note" ->
            emptyList()
        else -> return null
    }
    return TemplateDefinition(
        kind = kind,
        label = kind.substring(5),
        family = "other",
        markdownNotes = true,
        fields = fields,
    )
}

private fun isUsername(field: TemplateFieldDefinition) =
    field.key == "username" || field.semanticRole == "username"

private fun isPassword(field: TemplateFieldDefinition) =
    field.key == "password" || field.semanticRole == "password"

private fun isOtp(field: TemplateFieldDefinition) =
    field.key == "otp" || field.semanticRole == "otp" || field.valueType == "totp"

private fun isPrimaryUrl(field: TemplateFieldDefinition) =
    field.semanticRole == "website" || field.semanticRole == "url" ||
        field.key == "website" || field.key == "url"

private fun isStandardField(field: TemplateFieldDefinition) =
    isUsername(field) || isPassword(field) || isOtp(field) || isPrimaryUrl(field)

/** Reads a template field's current text from the draft's structured JSON. */
private fun templateFieldText(draft: EntryDraft, field: TemplateFieldDefinition): String =
    when {
        isUsername(field) -> draft.username
        isPassword(field) -> draft.password
        isOtp(field) -> draft.totp
        isPrimaryUrl(field) -> draft.url
        else -> draft.customFieldTexts()[field.key] ?: ""
    }

/** Custom template values ride inside `customFields` as a JSON array. */
private fun EntryDraft.customFieldTexts(): Map<String, String> {
    val out = LinkedHashMap<String, String>()
    val parsed = parseCustomFields() ?: return out
    for (item in parsed) {
        if (item !is Map<*, *>) continue
        val key = item["key"]?.toString() ?: continue
        val raw = (item["value"] as? Map<*, *>)?.get("value")
        out[key] = when (raw) {
            is Map<*, *> -> raw.values.filterNotNull().joinToString(", ")
            null -> ""
            else -> raw.toString()
        }
    }
    return out
}

private fun typedValue(type: String, text: String): Map<String, Any?> {
    if (type == "month_year") {
        val match = Regex("^(\\d{1,2})\\s*[/\\-]\\s*(\\d{4})$").find(text)
        if (match != null) {
            return mapOf(
                "type" to type,
                "value" to mapOf(
                    "month" to match.groupValues[1].toInt(),
                    "year" to match.groupValues[2].toInt(),
                ),
            )
        }
    }
    if (type == "address") {
        return mapOf(
            "type" to type,
            "value" to mapOf(
                "street" to text,
                "city" to "",
                "state" to "",
                "postal_code" to "",
                "country" to "",
            ),
        )
    }
    if (type == "number") {
        return mapOf("type" to type, "value" to (text.toDoubleOrNull() ?: 0))
    }
    if (type == "boolean") {
        return mapOf("type" to type, "value" to (text.lowercase() == "true"))
    }
    val supported = setOf(
        "text", "concealed", "url", "email", "phone", "date",
        "certificate", "attachment_ref", "reference",
    )
    return mapOf("type" to (if (type in supported) type else "text"), "value" to text)
}

@Composable
private fun EntryForm(
    app: AppController,
    draft: EntryDraft,
    errors: Map<String, String>,
    onErrorsChanged: (Map<String, String>) -> Unit,
    onFailure: (UserMessage?) -> Unit,
) {
    val vaultState by app.vault.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    val template = templateFor(app, draft.kind)
    val guidance = guidanceForTemplate(draft.kind, label = template?.label)
    val isDeveloper = draft.kind in DEVELOPER_KINDS

    var title by remember { mutableStateOf(draft.title) }
    var username by remember { mutableStateOf(draft.username) }
    var url by remember { mutableStateOf(draft.url) }
    var password by remember { mutableStateOf(draft.password) }
    var notes by remember { mutableStateOf(draft.notes) }
    var totp by remember { mutableStateOf(draft.totp) }
    var custom by remember { mutableStateOf(draft.customFields) }
    var tags by remember { mutableStateOf(draft.tags) }
    var passwordRevealed by remember { mutableStateOf(false) }
    var passwordCopied by remember { mutableStateOf(false) }
    var totpScanning by remember { mutableStateOf(false) }
    var showGeneratorSettings by remember { mutableStateOf(false) }

    // Non-standard template fields keep their own text state, keyed on the
    // template key. Values hydrate once the entry view arrives.
    val templateTexts = remember { mutableStateMapOf<String, String>() }
    val templateFieldIds = remember { mutableStateMapOf<String, String>() }
    val templateFieldOriginals = remember { mutableStateMapOf<String, String>() }

    fun sync() {
        draft.title = title
        draft.username = username
        draft.url = url
        draft.password = password
        draft.notes = notes
        draft.totp = totp
        draft.tags = tags
        if (!isDeveloper) {
            draft.customFields = templateFieldPayload(
                draft, template, templateTexts, templateFieldIds, templateFieldOriginals,
            ) ?: custom
        }
    }

    fun changeTemplate(next: String) {
        if (next == draft.kind) return
        username = ""
        password = ""
        url = ""
        totp = ""
        custom = ""
        draft.customFields = ""
        draft.sections = ""
        draft.removeFieldIds = emptyList()
        draft.structuredErrors = emptyMap()
        draft.sshKeyBindings = emptyMap()
        draft.sshBindingsToClear = emptyList()
        templateTexts.clear()
        templateFieldIds.clear()
        templateFieldOriginals.clear()
        draft.kind = next
        onErrorsChanged(emptyMap())
        sync()
    }

    // Hydrate custom template fields once the entry view is available.
    val entryId = draft.entryId
    val detail = entryId?.let { vaultState.entryViews[it] }
    LaunchedEffect(detail) {
        if (entryId == null || detail == null) return@LaunchedEffect
        for (definition in (template?.fields ?: emptyList()).filter { !isStandardField(it) }) {
            if (templateFieldIds.containsKey(definition.key)) continue
            val field = detail.fields.firstOrNull { candidate ->
                candidate.key == definition.key ||
                    (definition.semanticRole.isNotEmpty() &&
                        candidate.semanticRole == definition.semanticRole)
            } ?: continue
            templateFieldIds[definition.key] = field.id
            val original = if (field.`protected`) "" else field.displayValue
            templateFieldOriginals[definition.key] = original
            templateTexts[definition.key] = original
        }
        sync()
    }

    fun generate() {
        scope.launch {
            try {
                val settings = app.state.value.passwordGeneratorSettings
                val generated = app.vault.generatePassword(
                    length = settings.requestLength,
                    recipe = settings.recipe,
                ) ?: return@launch
                password = generated
                sync()
                if (app.copySensitive(generated)) {
                    passwordCopied = true
                    delay(1000)
                    passwordCopied = false
                }
            } catch (caught: Throwable) {
                onFailure(UserMessage.from(caught))
            }
        }
    }

    fun scanTotp(fromCamera: Boolean) {
        if (totpScanning) return
        totpScanning = true
        onFailure(null)
        scope.launch {
            try {
                val uri = if (fromCamera) {
                    app.scanTotpFromCamera?.invoke()
                } else {
                    app.scanTotpFromImage?.invoke()
                }
                if (uri != null) {
                    totp = uri
                    sync()
                }
            } catch (caught: Throwable) {
                onFailure(UserMessage.from(caught))
            } finally {
                totpScanning = false
            }
        }
    }

    Column {
        if (draft.isNew) {
            SearchableSelectField(
                label = "Template",
                options = vaultState.templates.ifEmpty {
                    listOf(
                        TemplateDefinition("core.login", "Login", "common", true, emptyList()),
                        TemplateDefinition("core.api_credential", "API credential", "common", true, emptyList()),
                        TemplateDefinition("core.secure_note", "Secure note", "common", true, emptyList()),
                        TemplateDefinition("core.generic", "Generic item", "other", true, emptyList()),
                    )
                }.map { item ->
                    SelectOption(
                        value = item.kind,
                        label = if (item.kind == "core.server") "Server (generic)" else item.label,
                        section = templateSection(item),
                        subtitle = guidanceForTemplate(item.kind, label = item.label).summary,
                        searchTerms = listOf(item.kind, item.family),
                    )
                },
                value = draft.kind,
                onChange = { next -> if (next != null) changeTemplate(next) },
            )
            Spacer(Modifier.height(8.dp))
            GuidanceCard(title = "About this template", summary = guidance.summary, useWhen = guidance.useWhen)
        }
        Spacer(Modifier.height(10.dp))
        if (!draft.isAgentContent) {
            SearchableSelectField(
                label = "Group",
                hint = "Choose a group",
                error = errors["group"],
                options = vaultState.groups.map { group ->
                    SelectOption(
                        value = group.id,
                        label = groupBreadcrumb(group, vaultState.groups),
                        searchTerms = listOf(group.name, group.id),
                    )
                },
                value = draft.groupId,
                onChange = { draft.groupId = it },
            )
            Spacer(Modifier.height(10.dp))
        }
        OutlinedTextField(
            value = title,
            onValueChange = { title = it; sync() },
            label = { Text("Title") },
            isError = errors["title"] != null,
            supportingText = errors["title"]?.let { e -> { Text(e) } },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(
                checked = draft.favorite,
                onCheckedChange = { draft.favorite = it },
            )
            Text("Favorite")
        }

        // Dynamic template fields, sectioned like the Flutter form.
        var section: String? = null
        for (field in template?.fields ?: emptyList()) {
            if (field.section != section) {
                section = field.section
                SectionLabel(section!!)
            }
            Spacer(Modifier.height(8.dp))
            TemplateFieldEditor(
                app = app,
                draft = draft,
                field = field,
                detail = detail,
                error = errors["template_${field.key}"],
                username = username,
                onUsername = { username = it; sync() },
                url = url,
                onUrl = { url = it; sync() },
                password = password,
                onPassword = { password = it; sync() },
                totp = totp,
                onTotp = { totp = it; sync() },
                passwordRevealed = passwordRevealed,
                onPasswordRevealed = { passwordRevealed = it },
                passwordCopied = passwordCopied,
                onGenerate = ::generate,
                onGeneratorSettings = { showGeneratorSettings = true },
                totpScanning = totpScanning,
                onScanTotp = ::scanTotp,
                text = templateTexts[field.key] ?: "",
                onText = { next ->
                    templateTexts[field.key] = next
                    sync()
                },
            )
        }

        if (isDeveloper) {
            DeveloperTemplateEditor(app = app, draft = draft, detail = detail)
        }

        if (template?.markdownNotes == true || draft.isAgentContent) {
            SectionLabel(if (draft.isAgentContent) "Agent content" else "Notes")
            OutlinedTextField(
                value = notes,
                onValueChange = { notes = it; sync() },
                label = {
                    Text(
                        when {
                            draft.isAgentContent -> "Markdown body"
                            draft.kind == "core.secure_note" -> "Secure note (Markdown)"
                            draft.isNew -> "Notes (Markdown)"
                            else -> "New notes (blank keeps current)"
                        },
                    )
                },
                minLines = if (draft.isAgentContent || draft.kind == "core.secure_note") 8 else 3,
                modifier = Modifier.fillMaxWidth(),
            )
        }

        if (draft.isAgentContent) {
            Spacer(Modifier.height(10.dp))
            OutlinedTextField(
                value = tags,
                onValueChange = { tags = it; sync() },
                label = { Text("Tags") },
                supportingText = { Text("Comma-separated") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(10.dp))
            SearchableSelectField(
                label = "Project (optional)",
                options = listOf(SelectOption("", "No project")) +
                    vaultState.projects.map {
                        SelectOption(it.slug, it.name, subtitle = it.slug, searchTerms = listOf(it.slug))
                    },
                value = draft.projectSlug ?: "",
                onChange = { draft.projectSlug = it?.takeIf { v -> v.isNotEmpty() } },
            )
            if (draft.isNew) {
                Spacer(Modifier.height(10.dp))
                SelectField(
                    label = "Agent access",
                    items = listOf(
                        "None" to "none",
                        "Read" to "read",
                        "Read and write" to "read_write",
                    ),
                    value = draft.agentAccess,
                    onChange = { draft.agentAccess = it },
                )
            }
        }

        if (template == null && !draft.isAgentContent) {
            Spacer(Modifier.height(10.dp))
            OutlinedTextField(
                value = custom,
                onValueChange = { custom = it; sync() },
                label = { Text("Custom fields (JSON array, optional)") },
                supportingText = { Text("Typed fields keep their protected and sensitivity flags.") },
                isError = errors["custom_fields"] != null,
                minLines = 2,
                maxLines = 6,
                modifier = Modifier.fillMaxWidth(),
            )
            errors["custom_fields"]?.let {
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }
        }
    }

    if (showGeneratorSettings) {
        PasswordGeneratorSettingsDialog(
            app = app,
            onDismiss = { showGeneratorSettings = false },
        )
    }
}

/** Serializes non-standard template fields — port of `_templateFieldPayload`. */
private fun templateFieldPayload(
    draft: EntryDraft,
    template: TemplateDefinition?,
    texts: Map<String, String>,
    ids: Map<String, String>,
    originals: Map<String, String>,
): String? {
    val customFields = (template?.fields ?: emptyList()).filter { !isStandardField(it) }
    if (customFields.isEmpty()) return null
    val fields = mutableListOf<Map<String, Any?>>()
    for (definition in customFields) {
        val text = texts[definition.key]?.trim() ?: ""
        val original = originals[definition.key] ?: ""
        if (text.isEmpty() && (draft.isNew || original.isEmpty())) continue
        if (!draft.isNew && text == original) continue
        fields.add(
            mapOf(
                "id" to (ids[definition.key]
                    ?: "field_${draft.kind.substring(5)}_${definition.key}"),
                "key" to definition.key,
                "label" to definition.label,
                "value" to typedValue(definition.valueType, text),
                "sensitivity" to definition.sensitivity,
                "protected" to definition.`protected`,
                "semantic_role" to definition.semanticRole,
            ),
        )
    }
    return JSONArray(fields).toString()
}

private fun groupBreadcrumb(group: VaultGroup, groups: List<VaultGroup>): String {
    val names = mutableListOf(group.name)
    val visited = mutableSetOf(group.id)
    var parentId = group.parentId
    while (parentId != null && visited.add(parentId)) {
        val parent = groups.firstOrNull { it.id == parentId } ?: break
        names.add(0, parent.name)
        parentId = parent.parentId
    }
    return names.joinToString(" / ")
}

private fun templateSection(template: TemplateDefinition): String {
    val essentials = setOf(
        "core.prompt", "core.runbook", "core.environment", "core.ssh_server",
        "core.login", "core.api_credential", "core.database", "core.ssh_key",
    )
    if (template.kind in essentials) return "Developer essentials"
    return when (template.family) {
        "developer" -> "Developer"
        "common" -> "Common"
        "agent_knowledge" -> "Agent knowledge"
        "personal" -> "Personal"
        else -> "Other"
    }
}

@Composable
private fun GuidanceCard(title: String, summary: String, useWhen: String?) {
    Card {
        Column(Modifier.padding(12.dp)) {
            Text(title, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(4.dp))
            Text(summary, style = MaterialTheme.typography.bodySmall)
            if (useWhen != null) {
                Spacer(Modifier.height(3.dp))
                Text(
                    useWhen,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun TemplateFieldEditor(
    app: AppController,
    draft: EntryDraft,
    field: TemplateFieldDefinition,
    detail: EntryDetailView?,
    error: String?,
    username: String,
    onUsername: (String) -> Unit,
    url: String,
    onUrl: (String) -> Unit,
    password: String,
    onPassword: (String) -> Unit,
    totp: String,
    onTotp: (String) -> Unit,
    passwordRevealed: Boolean,
    onPasswordRevealed: (Boolean) -> Unit,
    passwordCopied: Boolean,
    onGenerate: () -> Unit,
    onGeneratorSettings: () -> Unit,
    totpScanning: Boolean,
    onScanTotp: (Boolean) -> Unit,
    text: String,
    onText: (String) -> Unit,
) {
    val storedProtected = !draft.isNew && field.`protected` &&
        (detail?.fields?.any {
            it.hasValue &&
                (it.key == field.key || it.semanticRole == field.semanticRole)
        } == true)
    val label = if (storedProtected) "${field.label} (blank keeps current)" else field.label

    val (value, onValue) = when {
        isUsername(field) -> username to onUsername
        isPassword(field) -> password to onPassword
        isOtp(field) -> totp to onTotp
        isPrimaryUrl(field) -> url to onUrl
        else -> text to onText
    }

    if (field.valueType == "boolean") {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(
                checked = value.lowercase() == "true",
                onCheckedChange = { onValue("$it") },
            )
            Text(label)
        }
        return
    }

    OutlinedTextField(
        value = value,
        onValueChange = onValue,
        label = { Text(label) },
        supportingText = {
            val description = when (field.valueType) {
                "month_year" -> "MM/YYYY"
                "date" -> "YYYY-MM-DD"
                "totp" -> "Base32 secret or otpauth:// URI. Scan with the camera or choose an image."
                "address" -> "Street and address details"
                else -> null
            }
            when {
                error != null -> Text(error)
                description != null -> Text(description)
                else -> Unit
            }
        },
        isError = error != null,
        visualTransformation = if (field.`protected` && (!isPassword(field) || !passwordRevealed)) {
            PasswordVisualTransformation()
        } else {
            VisualTransformation.None
        },
        keyboardOptions = KeyboardOptions(
            keyboardType = when (field.valueType) {
                "number" -> KeyboardType.Number
                "email" -> KeyboardType.Email
                "url" -> KeyboardType.Uri
                else -> KeyboardType.Text
            },
        ),
        trailingIcon = {
            when {
                isPassword(field) -> Row {
                    IconButton(onClick = { onPasswordRevealed(!passwordRevealed) }) {
                        Icon(
                            if (passwordRevealed) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                            contentDescription = if (passwordRevealed) "Hide password" else "Reveal password",
                            modifier = Modifier.size(16.dp),
                        )
                    }
                    IconButton(onClick = onGenerate) {
                        Icon(
                            if (passwordCopied) Icons.Filled.Check else Icons.Filled.AutoAwesome,
                            contentDescription = if (passwordCopied) {
                                "Password generated and copied"
                            } else {
                                "Generate and copy password"
                            },
                            modifier = Modifier.size(16.dp),
                        )
                    }
                    IconButton(onClick = onGeneratorSettings) {
                        Icon(
                            Icons.Filled.Settings,
                            contentDescription = "Password generator settings",
                            modifier = Modifier.size(14.dp),
                        )
                    }
                }
                isOtp(field) -> Row {
                    if (app.capabilities.cameraQrScan) {
                        IconButton(onClick = { onScanTotp(true) }, enabled = !totpScanning) {
                            if (totpScanning) {
                                CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                            } else {
                                Icon(
                                    Icons.Filled.QrCodeScanner,
                                    contentDescription = "Scan TOTP QR code with the camera",
                                    modifier = Modifier.size(16.dp),
                                )
                            }
                        }
                    }
                    if (app.capabilities.imageQrScan) {
                        IconButton(onClick = { onScanTotp(false) }, enabled = !totpScanning) {
                            Icon(
                                Icons.Filled.Image,
                                contentDescription = "Choose TOTP QR code image",
                                modifier = Modifier.size(15.dp),
                            )
                        }
                    }
                }
            }
        },
        modifier = Modifier.fillMaxWidth(),
    )
}

// ---------------------------------------------------------------------------
// Developer template editors — port of `developer_template_editor.dart`.
// ---------------------------------------------------------------------------

@Composable
private fun DeveloperTemplateEditor(
    app: AppController,
    draft: EntryDraft,
    detail: EntryDetailView?,
) {
    when (draft.kind) {
        "core.environment" -> EnvironmentTemplateEditor(draft, detail)
        "core.ssh_server" -> SshServerTemplateEditor(app, draft, detail)
    }
}

@Composable
private fun EnvironmentTemplateEditor(draft: EntryDraft, detail: EntryDetailView?) {
    var project by remember { mutableStateOf("") }
    var scope by remember { mutableStateOf("development") }
    var source by remember { mutableStateOf("dotenv") }
    var paste by remember { mutableStateOf("") }
    var pasteMode by remember { mutableStateOf(false) }
    val variables = remember { mutableStateListOf<EnvVariableDraft>() }
    val removed = remember { mutableStateListOf<String>() }
    val metadataIds = remember { mutableStateMapOf<String, String>() }
    var hydrated by remember { mutableStateOf(false) }
    var confirmReplace by remember { mutableStateOf(false) }

    val parseResult = remember(paste) { if (pasteMode && paste.isNotEmpty()) parseDotEnv(paste) else null }

    fun metadataId(role: String): String =
        metadataIds.getOrPut(role) { structuredId("field_environment") }

    fun sync() {
        if (!hydrated && !draft.isNew) return
        val errors = LinkedHashMap<String, String>()
        if (project.trim().isEmpty()) {
            errors["environment_project"] = "Enter a project or repository."
        }
        val keys = mutableSetOf<String>()
        for (variable in variables) {
            if (!Regex("^[A-Za-z_][A-Za-z0-9_]*$").matches(variable.key)) {
                errors["environment_variables"] =
                    "Variable names must use shell identifier syntax."
            } else if (!keys.add(variable.key)) {
                errors["environment_variables"] = "Variable names must be unique."
            }
            if (variable.existing && variable.dirty &&
                variable.hasStoredValue && variable.value.isEmpty()
            ) {
                errors["environment_variables"] =
                    "Re-enter a stored secret before renaming it or changing its protection."
            }
        }
        val projectId = metadataId("environment_project")
        val scopeId = metadataId("environment_scope")
        val sourceId = metadataId("environment_source")
        val updates = mutableListOf(
            structuredTextField(
                id = projectId, key = "environment.project",
                label = "Project / repository", role = "environment_project",
                value = project.trim(),
            ),
            structuredTextField(
                id = scopeId, key = "environment.scope",
                label = "Environment", role = "environment_scope", value = scope,
            ),
            structuredTextField(
                id = sourceId, key = "environment.source",
                label = "Source", role = "environment_source", value = source,
            ),
        )
        for (variable in variables) {
            if (!variable.existing || variable.dirty) updates.add(variable.toField())
        }
        val sections = listOf(
            EntrySectionView(
                id = "environment_metadata", label = "Environment",
                fieldIds = listOf(projectId, scopeId, sourceId),
                semanticRole = "environment_metadata",
            ),
            EntrySectionView(
                id = "environment_variables", label = "Variables",
                fieldIds = variables.map { it.id },
                semanticRole = "environment_variables",
            ),
        )
        draft.customFields = JSONArray(updates).toString()
        draft.sections = encodeStructuredSections(sections)
        draft.removeFieldIds = removed.toList()
        draft.structuredErrors = errors
    }

    // Hydrate from the stored entry view once.
    LaunchedEffect(detail) {
        if (hydrated || draft.isNew || detail == null) return@LaunchedEffect
        val metadata = detail.sections.firstOrNull {
            it.semanticRole == "environment_metadata"
        }
        val variableSection = detail.sections.firstOrNull {
            it.semanticRole == "environment_variables"
        }
        if (metadata == null || variableSection == null) return@LaunchedEffect
        val fields = fieldsByRole(metadata, detail)
        fun value(role: String, fallback: String): String {
            val field = fields[role] ?: return fallback
            metadataIds[role] = field.id
            return entryFieldText(field) ?: fallback
        }
        project = value("environment_project", "")
        scope = value("environment_scope", "development")
        source = value("environment_source", "dotenv")
        for (id in variableSection.fieldIds) {
            val field = detail.fields.firstOrNull { it.id == id } ?: continue
            if (field.semanticRole != "environment_variable") continue
            variables.add(
                EnvVariableDraft(
                    id = field.id,
                    key = field.label,
                    value = entryFieldText(field) ?: "",
                    secret = field.`protected`,
                    existing = true,
                    hasStoredValue = field.hasValue,
                    dirty = false,
                ),
            )
        }
        hydrated = true
        sync()
    }
    LaunchedEffect(Unit) { if (draft.isNew) sync() }

    fun applyPaste(replace: Boolean) {
        val parsed = parseDotEnv(paste)
        if (!parsed.valid) return
        if (replace) {
            removed.addAll(variables.filter { it.existing }.map { it.id })
            variables.clear()
        }
        for (incoming in parsed.variables) {
            val existing = variables.firstOrNull { it.key == incoming.key }
            if (existing == null) {
                variables.add(incoming)
            } else {
                existing.value = incoming.value
                existing.dirty = true
            }
        }
        paste = ""
        pasteMode = false
        sync()
    }

    Column {
        Spacer(Modifier.height(18.dp))
        GuidanceCard(
            title = "How to use an Environment item",
            summary = "Keep the variables for one project and environment together. Mark sensitive values as secrets so they stay protected.",
            useWhen = "Enter variables one by one, or paste .env content and review the parsed fields before saving.",
        )
        SectionLabel("Environment")
        OutlinedTextField(
            value = project,
            onValueChange = { project = it; sync() },
            label = { Text("Project / repository") },
            isError = draft.structuredErrors["environment_project"] != null,
            supportingText = draft.structuredErrors["environment_project"]?.let { e -> { Text(e) } },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(10.dp))
        SelectField(
            label = "Environment",
            items = listOf(
                "Local" to "local", "Development" to "development",
                "Test" to "test", "Staging" to "staging",
                "Production" to "production", "Other" to "other",
            ),
            value = scope,
            onChange = { scope = it; sync() },
        )
        Spacer(Modifier.height(10.dp))
        SelectField(
            label = "Source",
            items = listOf(
                ".env" to "dotenv", "GitHub Actions" to "github_actions",
                "GitLab CI/CD" to "gitlab_ci", "Docker / Compose" to "docker",
                "Kubernetes" to "kubernetes", "Other" to "other",
            ),
            value = source,
            onChange = { source = it; sync() },
        )
        Row(verticalAlignment = Alignment.CenterVertically) {
            SectionLabel("Variables", Modifier.weight(1f))
            TextButton(onClick = { pasteMode = false }) { Text("Fields") }
            KeyleaseButton(
                "Paste .env",
                outline = !pasteMode,
                onClick = { pasteMode = true },
            )
        }
        if (pasteMode) {
            OutlinedTextField(
                value = paste,
                onValueChange = { paste = it },
                label = { Text(".env content") },
                minLines = 7,
                maxLines = 16,
                modifier = Modifier.fillMaxWidth(),
            )
            parseResult?.let { result ->
                Spacer(Modifier.height(6.dp))
                Text(
                    if (result.valid) {
                        "${result.variables.size} variables · ${result.ignoredComments} comments and ${result.ignoredBlankLines} blank lines will be normalized."
                    } else {
                        result.issues.joinToString("\n") { "Line ${it.line}: ${it.message}" }
                    },
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
                KeyleaseButton("Replace all", outline = true, onClick = {
                    if (variables.isNotEmpty()) confirmReplace = true else applyPaste(replace = true)
                })
                Spacer(Modifier.width(8.dp))
                KeyleaseButton("Merge", onClick = { applyPaste(replace = false) })
            }
        } else {
            draft.structuredErrors["environment_variables"]?.let {
                Text(it, color = MaterialTheme.colorScheme.error)
            }
            variables.forEachIndexed { index, variable ->
                EnvVariableRow(
                    variable = variable,
                    canMoveUp = index > 0,
                    canMoveDown = index < variables.size - 1,
                    onChanged = ::sync,
                    onRemove = {
                        variables.remove(variable)
                        if (variable.existing) removed.add(variable.id)
                        sync()
                    },
                    onMove = { offset ->
                        val from = variables.indexOf(variable)
                        val to = from + offset
                        if (to in variables.indices) {
                            variables.removeAt(from)
                            variables.add(to, variable)
                            sync()
                        }
                    },
                )
            }
            KeyleaseButton(
                "Add variable",
                outline = true,
                icon = Icons.Filled.Add,
                onClick = {
                    variables.add(
                        EnvVariableDraft(
                            id = structuredId("field_env", variables.size),
                            key = "NEW_VARIABLE",
                            value = "",
                        ),
                    )
                    sync()
                },
            )
        }
    }

    if (confirmReplace) {
        AlertDialog(
            onDismissRequest = { confirmReplace = false },
            title = { Text("Replace all variables?") },
            text = { Text("${variables.size} existing variables will be removed or replaced.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmReplace = false
                    applyPaste(replace = true)
                }) { Text("Replace all", color = LocalKeyleaseColors.current.danger) }
            },
            dismissButton = {
                TextButton(onClick = { confirmReplace = false }) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun EnvVariableRow(
    variable: EnvVariableDraft,
    canMoveUp: Boolean,
    canMoveDown: Boolean,
    onChanged: () -> Unit,
    onRemove: () -> Unit,
    onMove: (Int) -> Unit,
) {
    var key by remember(variable.id) { mutableStateOf(variable.key) }
    var value by remember(variable.id) { mutableStateOf(variable.value) }

    Column(Modifier.padding(bottom = 10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = key,
                onValueChange = {
                    key = it
                    variable.key = it.trim()
                    variable.dirty = true
                    onChanged()
                },
                label = { Text("Name") },
                singleLine = true,
                modifier = Modifier.weight(2f),
            )
            Spacer(Modifier.width(8.dp))
            OutlinedTextField(
                value = value,
                onValueChange = {
                    value = it
                    variable.value = it
                    variable.dirty = true
                    onChanged()
                },
                label = {
                    Text(
                        if (variable.hasStoredValue && value.isEmpty()) {
                            "Value (stored; blank keeps it)"
                        } else {
                            "Value"
                        },
                    )
                },
                visualTransformation = if (variable.secret) {
                    PasswordVisualTransformation()
                } else {
                    VisualTransformation.None
                },
                singleLine = true,
                modifier = Modifier.weight(3f),
            )
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(
                checked = variable.secret,
                onCheckedChange = {
                    variable.secret = it
                    variable.dirty = true
                    onChanged()
                },
            )
            Text("Secret", modifier = Modifier.weight(1f))
            IconButton(onClick = { onMove(-1) }, enabled = canMoveUp) {
                Icon(Icons.Filled.ArrowUpward, contentDescription = "Move up", modifier = Modifier.size(16.dp))
            }
            IconButton(onClick = { onMove(1) }, enabled = canMoveDown) {
                Icon(Icons.Filled.ArrowDownward, contentDescription = "Move down", modifier = Modifier.size(16.dp))
            }
            IconButton(onClick = onRemove) {
                Icon(Icons.Filled.Delete, contentDescription = "Remove variable", modifier = Modifier.size(16.dp))
            }
        }
    }
}

// --- SSH server template ----------------------------------------------------

private class SshEndpointDraft(val id: String, val existing: Boolean = false) {
    val fieldIds = mutableMapOf<String, String>()
    val storedRoles = mutableSetOf<String>()
    var name by mutableStateOf("")
    var alias by mutableStateOf("")
    var host by mutableStateOf("")
    var port by mutableStateOf("22")
    var username by mutableStateOf("")
    var connectVia by mutableStateOf("")
    var authMode by mutableStateOf("ssh_agent")
    var password by mutableStateOf("")
    var passphrase by mutableStateOf("")
    var sudoMode by mutableStateOf("none")
    var sudoPassword by mutableStateOf("")
    var fingerprint by mutableStateOf("")
}

private class SshForwardDraft(val id: String, val existing: Boolean = false) {
    val fieldIds = mutableMapOf<String, String>()
    var endpointId by mutableStateOf("")
    var type by mutableStateOf("local")
    var bindAddress by mutableStateOf("127.0.0.1")
    var bindPort by mutableStateOf("")
    var destinationHost by mutableStateOf("")
    var destinationPort by mutableStateOf("")
}

@Composable
private fun SshServerTemplateEditor(
    app: AppController,
    draft: EntryDraft,
    detail: EntryDetailView?,
) {
    val endpoints = remember { mutableStateListOf<SshEndpointDraft>() }
    val forwards = remember { mutableStateListOf<SshForwardDraft>() }
    val removed = remember { mutableStateListOf<String>() }
    var hydrated by remember { mutableStateOf(false) }

    fun fieldId(ids: MutableMap<String, String>, role: String): String =
        ids.getOrPut(role) { structuredId("field_ssh") }

    fun field(
        sectionId: String,
        ids: MutableMap<String, String>,
        role: String,
        value: String,
        secret: Boolean = false,
    ) = structuredTextField(
        id = fieldId(ids, role),
        key = "ssh.$sectionId.${role.substring(4)}",
        label = role.substring(4).replace('_', ' '),
        role = role,
        value = value,
        secret = secret,
    )

    fun errorsForEndpoint(endpoint: SshEndpointDraft): Map<String, String> {
        val errors = LinkedHashMap<String, String>()
        if (endpoint.name.trim().isEmpty()) errors["name"] = "Enter a display name."
        if (endpoint.host.trim().isEmpty()) errors["host"] = "Enter a host or IP address."
        val alias = endpoint.alias.trim()
        if (alias.isEmpty()) {
            errors["alias"] = "Enter an SSH alias."
        } else if (!Regex("^[A-Za-z0-9._-]+$").matches(alias)) {
            errors["alias"] = "Use only letters, digits, dots, underscores, or hyphens."
        } else if (endpoints.count { it.alias.trim() == alias } > 1) {
            errors["alias"] = "This SSH alias is already used by another server."
        }
        val port = endpoint.port.toIntOrNull()
        if (port == null || port < 1 || port > 65535) {
            errors["port"] = "Use a port from 1 to 65535."
        }
        if (endpoint.connectVia.isNotEmpty() &&
            endpoints.none { it.id == endpoint.connectVia }
        ) {
            errors["connectVia"] = "Choose an existing jump host."
        }
        val seen = mutableSetOf<String>()
        var cursor = endpoint
        while (cursor.connectVia.isNotEmpty()) {
            if (!seen.add(cursor.id)) {
                errors["connectVia"] = "Jump host chains cannot contain a cycle."
                break
            }
            val next = endpoints.firstOrNull { it.id == cursor.connectVia } ?: break
            cursor = next
        }
        if (endpoint.authMode == "password" && endpoint.password.isEmpty() &&
            "ssh_password" !in endpoint.storedRoles
        ) {
            errors["password"] = "Enter the SSH password."
        }
        if (endpoint.sudoMode == "same_as_ssh_password" &&
            endpoint.authMode != "password"
        ) {
            errors["sudo"] = "Reusing the SSH password requires password authentication."
        }
        if (endpoint.sudoMode == "separate_password" && endpoint.sudoPassword.isEmpty() &&
            "ssh_sudo_password" !in endpoint.storedRoles
        ) {
            errors["sudoPassword"] = "Enter the sudo password."
        }
        return errors
    }

    fun sync() {
        val errors = LinkedHashMap<String, String>()
        val removals = removed.toMutableSet()
        val endpointIds = endpoints.map { it.id }.toSet()
        if (endpoints.any { errorsForEndpoint(it).isNotEmpty() }) {
            errors["ssh_endpoints"] = "Complete the highlighted SSH server fields."
        }
        val fields = mutableListOf<Map<String, Any?>>()
        val sections = mutableListOf<EntrySectionView>()
        for (endpoint in endpoints) {
            val endpointFields = mutableListOf(
                field(endpoint.id, endpoint.fieldIds, "ssh_display_name", endpoint.name),
                field(endpoint.id, endpoint.fieldIds, "ssh_alias", endpoint.alias),
                field(endpoint.id, endpoint.fieldIds, "ssh_host", endpoint.host),
                field(endpoint.id, endpoint.fieldIds, "ssh_port", endpoint.port),
                field(endpoint.id, endpoint.fieldIds, "ssh_username", endpoint.username),
                field(endpoint.id, endpoint.fieldIds, "ssh_connect_via", endpoint.connectVia),
                field(endpoint.id, endpoint.fieldIds, "ssh_auth_mode", endpoint.authMode),
                field(endpoint.id, endpoint.fieldIds, "ssh_sudo_mode", endpoint.sudoMode),
                field(endpoint.id, endpoint.fieldIds, "ssh_host_fingerprint", endpoint.fingerprint),
            )
            if (endpoint.password.isNotEmpty() ||
                (!endpoint.existing && endpoint.authMode == "password")
            ) {
                endpointFields.add(
                    field(endpoint.id, endpoint.fieldIds, "ssh_password", endpoint.password, secret = true),
                )
            }
            if (endpoint.passphrase.isNotEmpty()) {
                endpointFields.add(
                    field(endpoint.id, endpoint.fieldIds, "ssh_private_key_passphrase", endpoint.passphrase, secret = true),
                )
            }
            if (endpoint.sudoPassword.isNotEmpty() ||
                (!endpoint.existing && endpoint.sudoMode == "separate_password")
            ) {
                endpointFields.add(
                    field(endpoint.id, endpoint.fieldIds, "ssh_sudo_password", endpoint.sudoPassword, secret = true),
                )
            }
            if (endpoint.existing && endpoint.authMode != "password") {
                endpoint.fieldIds["ssh_password"]?.let { removals.add(it) }
            }
            if (endpoint.existing && endpoint.authMode != "private_key") {
                endpoint.fieldIds["ssh_private_key_passphrase"]?.let { removals.add(it) }
            }
            if (endpoint.existing && endpoint.sudoMode != "separate_password") {
                endpoint.fieldIds["ssh_sudo_password"]?.let { removals.add(it) }
            }
            fields.addAll(endpointFields)
            val requiredRoles = listOf(
                "ssh_display_name", "ssh_alias", "ssh_host", "ssh_port",
                "ssh_username", "ssh_connect_via", "ssh_auth_mode",
                "ssh_sudo_mode", "ssh_host_fingerprint",
            )
            val activeRoles = requiredRoles + listOfNotNull(
                "ssh_password".takeIf {
                    endpoint.authMode == "password" &&
                        endpoint.fieldIds.containsKey("ssh_password")
                },
                "ssh_private_key_passphrase".takeIf {
                    endpoint.authMode == "private_key" &&
                        endpoint.fieldIds.containsKey("ssh_private_key_passphrase")
                },
                "ssh_sudo_password".takeIf {
                    endpoint.sudoMode == "separate_password" &&
                        endpoint.fieldIds.containsKey("ssh_sudo_password")
                },
            )
            sections.add(
                EntrySectionView(
                    id = endpoint.id,
                    label = endpoint.name.trim().ifEmpty { "SSH server" },
                    fieldIds = activeRoles.map { endpoint.fieldIds[it]!! },
                    semanticRole = "ssh_endpoint",
                ),
            )
        }
        for (forward in forwards) {
            fields.addAll(
                listOf(
                    field(forward.id, forward.fieldIds, "ssh_forward_endpoint", forward.endpointId),
                    field(forward.id, forward.fieldIds, "ssh_forward_type", forward.type),
                    field(forward.id, forward.fieldIds, "ssh_bind_address", forward.bindAddress),
                    field(forward.id, forward.fieldIds, "ssh_bind_port", forward.bindPort),
                    field(forward.id, forward.fieldIds, "ssh_destination_host", forward.destinationHost),
                    field(forward.id, forward.fieldIds, "ssh_destination_port", forward.destinationPort),
                ),
            )
            val bindPort = forward.bindPort.toIntOrNull()
            val destinationPort = forward.destinationPort.toIntOrNull()
            if (forward.endpointId !in endpointIds ||
                bindPort == null || bindPort < 1 || bindPort > 65535 ||
                (forward.type != "dynamic" &&
                    (forward.destinationHost.isEmpty() ||
                        destinationPort == null ||
                        destinationPort < 1 ||
                        destinationPort > 65535))
            ) {
                errors["ssh_forwards"] =
                    "Every tunnel needs a valid server, bind port, and destination."
            }
            sections.add(
                EntrySectionView(
                    id = forward.id,
                    label = "${forward.type} tunnel",
                    fieldIds = forward.fieldIds.values.toList(),
                    semanticRole = "ssh_forward",
                ),
            )
        }
        draft.customFields = JSONArray(fields).toString()
        draft.sections = encodeStructuredSections(sections)
        draft.removeFieldIds = removals.toList()
        draft.structuredErrors = errors
    }

    LaunchedEffect(detail) {
        if (hydrated || draft.isNew || detail == null) return@LaunchedEffect
        for (section in detail.sections.filter { it.semanticRole == "ssh_endpoint" }) {
            val endpoint = SshEndpointDraft(id = section.id, existing = true)
            val fields = fieldsByRole(section, detail)
            fun value(role: String, fallback: String = ""): String {
                val f = fields[role] ?: return fallback
                endpoint.fieldIds[role] = f.id
                if (f.hasValue) endpoint.storedRoles.add(role)
                return entryFieldText(f) ?: fallback
            }
            endpoint.name = value("ssh_display_name")
            endpoint.alias = value("ssh_alias")
            endpoint.host = value("ssh_host")
            endpoint.port = value("ssh_port", "22")
            endpoint.username = value("ssh_username")
            endpoint.connectVia = value("ssh_connect_via")
            endpoint.authMode = value("ssh_auth_mode", "ssh_agent")
            endpoint.sudoMode = value("ssh_sudo_mode", "none")
            endpoint.fingerprint = value("ssh_host_fingerprint")
            value("ssh_password")
            value("ssh_private_key_passphrase")
            value("ssh_sudo_password")
            endpoints.add(endpoint)
        }
        for (section in detail.sections.filter { it.semanticRole == "ssh_forward" }) {
            val forward = SshForwardDraft(id = section.id, existing = true)
            val fields = fieldsByRole(section, detail)
            fun value(role: String, fallback: String = ""): String {
                val f = fields[role] ?: return fallback
                forward.fieldIds[role] = f.id
                return entryFieldText(f) ?: fallback
            }
            forward.endpointId = value("ssh_forward_endpoint")
            forward.type = value("ssh_forward_type", "local")
            forward.bindAddress = value("ssh_bind_address", "127.0.0.1")
            forward.bindPort = value("ssh_bind_port")
            forward.destinationHost = value("ssh_destination_host")
            forward.destinationPort = value("ssh_destination_port")
            forwards.add(forward)
        }
        hydrated = true
        sync()
    }
    LaunchedEffect(Unit) {
        if (draft.isNew) {
            endpoints.add(SshEndpointDraft(id = structuredId("ssh_endpoint")))
            sync()
        }
    }

    fun removeEndpoint(endpoint: SshEndpointDraft) {
        endpoints.remove(endpoint)
        draft.sshBindingsToClear = (draft.sshBindingsToClear + endpoint.id).distinct()
        if (endpoint.existing) removed.addAll(endpoint.fieldIds.values)
        val removedForwards = forwards.filter { it.endpointId == endpoint.id }
        for (forward in removedForwards) {
            if (forward.existing) removed.addAll(forward.fieldIds.values)
        }
        forwards.removeAll { it.endpointId == endpoint.id }
        for (item in endpoints.filter { it.connectVia == endpoint.id }) {
            item.connectVia = ""
        }
        sync()
    }

    Column {
        Spacer(Modifier.height(18.dp))
        GuidanceCard(
            title = "How to use an SSH server item",
            summary = "Describe each host once: name, alias, address, and how to reach it. Add tunnels when a host forwards ports.",
            useWhen = "Use one endpoint per machine. Chain jump hosts with Connect via.",
        )
        if (!app.capabilities.sshKeyBinding) {
            Spacer(Modifier.height(8.dp))
            Text(
                "Private key binding is not available on this device; use an agent or password.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        draft.structuredErrors["ssh_endpoints"]?.let {
            Text(it, color = MaterialTheme.colorScheme.error)
        }
        endpoints.forEachIndexed { index, endpoint ->
            SshEndpointCard(
                endpoint = endpoint,
                index = index,
                endpoints = endpoints,
                errors = errorsForEndpoint(endpoint),
                onChanged = ::sync,
                onRemove = { removeEndpoint(endpoint) },
                onMove = { offset ->
                    val to = index + offset
                    if (to in endpoints.indices) {
                        endpoints.removeAt(index)
                        endpoints.add(to, endpoint)
                        sync()
                    }
                },
            )
        }
        KeyleaseButton(
            "Add SSH server",
            outline = true,
            icon = Icons.Filled.Add,
            onClick = {
                endpoints.add(SshEndpointDraft(id = structuredId("ssh_endpoint", endpoints.size)))
                sync()
            },
        )
        if (forwards.isNotEmpty() || endpoints.isNotEmpty()) {
            SectionLabel("Tunnels")
            draft.structuredErrors["ssh_forwards"]?.let {
                Text(it, color = MaterialTheme.colorScheme.error)
            }
            forwards.forEachIndexed { index, forward ->
                SshForwardCard(
                    forward = forward,
                    endpoints = endpoints,
                    onChanged = ::sync,
                    onRemove = {
                        forwards.remove(forward)
                        if (forward.existing) removed.addAll(forward.fieldIds.values)
                        sync()
                    },
                )
            }
            KeyleaseButton(
                "Add tunnel",
                outline = true,
                icon = Icons.Filled.Add,
                onClick = {
                    forwards.add(
                        SshForwardDraft(id = structuredId("ssh_forward", forwards.size)).apply {
                            endpointId = endpoints.firstOrNull()?.id ?: ""
                        },
                    )
                    sync()
                },
            )
        }
    }
}

@Composable
private fun SshEndpointCard(
    endpoint: SshEndpointDraft,
    index: Int,
    endpoints: List<SshEndpointDraft>,
    errors: Map<String, String>,
    onChanged: () -> Unit,
    onRemove: () -> Unit,
    onMove: (Int) -> Unit,
) {
    Card(Modifier.padding(vertical = 6.dp)) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    endpoint.name.ifEmpty { "Server ${index + 1}" },
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.weight(1f),
                )
                IconButton(onClick = { onMove(-1) }, enabled = index > 0) {
                    Icon(Icons.Filled.ArrowUpward, "Move up", Modifier.size(16.dp))
                }
                IconButton(onClick = { onMove(1) }, enabled = index < endpoints.size - 1) {
                    Icon(Icons.Filled.ArrowDownward, "Move down", Modifier.size(16.dp))
                }
                IconButton(onClick = onRemove) {
                    Icon(Icons.Filled.Delete, "Remove server", Modifier.size(16.dp))
                }
            }
            OutlinedTextField(
                value = endpoint.name,
                onValueChange = { endpoint.name = it; onChanged() },
                label = { Text("Display name") },
                isError = errors["name"] != null,
                supportingText = errors["name"]?.let { e -> { Text(e) } },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = endpoint.alias,
                onValueChange = { endpoint.alias = it; onChanged() },
                label = { Text("SSH alias") },
                isError = errors["alias"] != null,
                supportingText = errors["alias"]?.let { e -> { Text(e) } },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Row {
                OutlinedTextField(
                    value = endpoint.host,
                    onValueChange = { endpoint.host = it; onChanged() },
                    label = { Text("Host") },
                    isError = errors["host"] != null,
                    supportingText = errors["host"]?.let { e -> { Text(e) } },
                    singleLine = true,
                    modifier = Modifier.weight(3f),
                )
                Spacer(Modifier.width(8.dp))
                OutlinedTextField(
                    value = endpoint.port,
                    onValueChange = { endpoint.port = it; onChanged() },
                    label = { Text("Port") },
                    isError = errors["port"] != null,
                    supportingText = errors["port"]?.let { e -> { Text(e) } },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.weight(1f),
                )
            }
            OutlinedTextField(
                value = endpoint.username,
                onValueChange = { endpoint.username = it; onChanged() },
                label = { Text("Username") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            SelectField(
                label = "Connect via",
                items = listOf("Direct connection" to "") +
                    endpoints.filter { it.id != endpoint.id }
                        .map { (it.name.ifEmpty { it.alias.ifEmpty { it.id } }) to it.id },
                value = endpoint.connectVia,
                onChange = { endpoint.connectVia = it; onChanged() },
            )
            errors["connectVia"]?.let {
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }
            SelectField(
                label = "Authentication",
                items = listOf(
                    "SSH agent" to "ssh_agent",
                    "Private key" to "private_key",
                    "Password" to "password",
                ),
                value = endpoint.authMode,
                onChange = { endpoint.authMode = it; onChanged() },
            )
            if (endpoint.authMode == "password") {
                OutlinedTextField(
                    value = endpoint.password,
                    onValueChange = { endpoint.password = it; onChanged() },
                    label = {
                        Text(
                            if ("ssh_password" in endpoint.storedRoles) {
                                "Password (stored; blank keeps it)"
                            } else {
                                "Password"
                            },
                        )
                    },
                    isError = errors["password"] != null,
                    supportingText = errors["password"]?.let { e -> { Text(e) } },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            if (endpoint.authMode == "private_key") {
                OutlinedTextField(
                    value = endpoint.passphrase,
                    onValueChange = { endpoint.passphrase = it; onChanged() },
                    label = {
                        Text(
                            if ("ssh_private_key_passphrase" in endpoint.storedRoles) {
                                "Key passphrase (stored; blank keeps it)"
                            } else {
                                "Key passphrase (optional)"
                            },
                        )
                    },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            SelectField(
                label = "Sudo",
                items = listOf(
                    "No sudo" to "none",
                    "Same as SSH password" to "same_as_ssh_password",
                    "Separate password" to "separate_password",
                ),
                value = endpoint.sudoMode,
                onChange = { endpoint.sudoMode = it; onChanged() },
            )
            errors["sudo"]?.let {
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }
            if (endpoint.sudoMode == "separate_password") {
                OutlinedTextField(
                    value = endpoint.sudoPassword,
                    onValueChange = { endpoint.sudoPassword = it; onChanged() },
                    label = {
                        Text(
                            if ("ssh_sudo_password" in endpoint.storedRoles) {
                                "Sudo password (stored; blank keeps it)"
                            } else {
                                "Sudo password"
                            },
                        )
                    },
                    isError = errors["sudoPassword"] != null,
                    supportingText = errors["sudoPassword"]?.let { e -> { Text(e) } },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            OutlinedTextField(
                value = endpoint.fingerprint,
                onValueChange = { endpoint.fingerprint = it; onChanged() },
                label = { Text("Host fingerprint (optional)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
private fun SshForwardCard(
    forward: SshForwardDraft,
    endpoints: List<SshEndpointDraft>,
    onChanged: () -> Unit,
    onRemove: () -> Unit,
) {
    Card(Modifier.padding(vertical = 6.dp)) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "${forward.type} tunnel",
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.weight(1f),
                )
                IconButton(onClick = onRemove) {
                    Icon(Icons.Filled.Delete, "Remove tunnel", Modifier.size(16.dp))
                }
            }
            SelectField(
                label = "Server",
                items = endpoints.map {
                    (it.name.ifEmpty { it.alias.ifEmpty { it.id } }) to it.id
                },
                value = forward.endpointId,
                onChange = { forward.endpointId = it; onChanged() },
            )
            SelectField(
                label = "Type",
                items = listOf(
                    "Local" to "local", "Remote" to "remote", "Dynamic (SOCKS)" to "dynamic",
                ),
                value = forward.type,
                onChange = { forward.type = it; onChanged() },
            )
            Row {
                OutlinedTextField(
                    value = forward.bindAddress,
                    onValueChange = { forward.bindAddress = it; onChanged() },
                    label = { Text("Bind address") },
                    singleLine = true,
                    modifier = Modifier.weight(2f),
                )
                Spacer(Modifier.width(8.dp))
                OutlinedTextField(
                    value = forward.bindPort,
                    onValueChange = { forward.bindPort = it; onChanged() },
                    label = { Text("Bind port") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.weight(1f),
                )
            }
            if (forward.type != "dynamic") {
                Row {
                    OutlinedTextField(
                        value = forward.destinationHost,
                        onValueChange = { forward.destinationHost = it; onChanged() },
                        label = { Text("Destination host") },
                        singleLine = true,
                        modifier = Modifier.weight(2f),
                    )
                    Spacer(Modifier.width(8.dp))
                    OutlinedTextField(
                        value = forward.destinationPort,
                        onValueChange = { forward.destinationPort = it; onChanged() },
                        label = { Text("Port") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Password generator — port of `password_generator.dart`.
// ---------------------------------------------------------------------------

@Composable
fun PasswordGeneratorPane(app: AppController, onClosed: () -> Unit) {
    Column(Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onClosed) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
            }
            Text(
                "Password generator",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
        }
        HorizontalDivider()
        Column(
            Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 14.dp),
        ) {
            PasswordGenerator(
                app = app,
                useLabel = "Create Login",
                onUse = { generated ->
                    app.vault.beginCreate(initialPassword = generated)
                },
            )
        }
    }
}

@Composable
private fun PasswordGenerator(
    app: AppController,
    onUse: (String) -> Unit,
    useLabel: String,
) {
    val appState by app.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var generatedWith by remember { mutableStateOf<PasswordGeneratorSettings?>(null) }
    var revealed by remember { mutableStateOf(false) }
    var generating by remember { mutableStateOf(false) }
    var copied by remember { mutableStateOf(false) }
    var failure by remember { mutableStateOf<UserMessage?>(null) }
    var showSettings by remember { mutableStateOf(false) }

    fun entropyBits(settings: PasswordGeneratorSettings): Int = when (settings.pattern) {
        PasswordPattern.RANDOM -> {
            val pool = (if (settings.uppercase) 24 else 0) +
                (if (settings.lowercase) 25 else 0) +
                (if (settings.numbers) 8 else 0) +
                (if (settings.symbols) 14 else 0)
            if (pool == 0) 0 else (settings.length * ln(pool.toDouble()) / ln(2.0)).roundToInt()
        }
        PasswordPattern.WORDS -> settings.wordCount * 12 + (if (settings.wordNumber) 7 else 0)
        PasswordPattern.PIN -> (settings.pinLength * ln(10.0) / ln(2.0)).roundToInt()
    }

    fun strength(bits: Int) = when {
        bits < 40 -> "Weak"
        bits < 60 -> "Fair"
        bits < 80 -> "Strong"
        else -> "Very strong"
    }

    fun showCopied() {
        copied = true
        scope.launch {
            delay(1000)
            copied = false
        }
    }

    fun generate() {
        if (generating) return
        val settings = appState.passwordGeneratorSettings
        generating = true
        failure = null
        copied = false
        scope.launch {
            try {
                val value = app.vault.generatePassword(
                    length = settings.requestLength,
                    recipe = settings.recipe,
                ) ?: return@launch
                password = value
                generatedWith = settings
                if (app.copySensitive(value)) showCopied()
            } catch (caught: Throwable) {
                failure = UserMessage.from(caught)
            } finally {
                generating = false
            }
        }
    }

    LaunchedEffect(Unit) { generate() }

    val effective = generatedWith ?: appState.passwordGeneratorSettings
    val bits = entropyBits(effective)

    Column {
        failure?.let {
            MessageBanner(it)
            Spacer(Modifier.height(12.dp))
        }
        OutlinedTextField(
            value = password,
            onValueChange = {},
            label = { Text("Generated password") },
            readOnly = true,
            visualTransformation = if (revealed) VisualTransformation.None else PasswordVisualTransformation(),
            trailingIcon = {
                if (copied) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Filled.Check, null, Modifier.size(14.dp))
                        Text(" Copied", style = MaterialTheme.typography.bodySmall)
                        Spacer(Modifier.width(10.dp))
                    }
                }
            },
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "${strength(bits)} · approximately $bits bits",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f),
            )
            IconButton(onClick = { revealed = !revealed }) {
                Icon(
                    if (revealed) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                    contentDescription = if (revealed) "Hide password" else "Reveal password",
                )
            }
            IconButton(
                onClick = {
                    if (password.isNotEmpty() && app.copySensitive(password)) showCopied()
                },
                enabled = password.isNotEmpty(),
            ) {
                Icon(Icons.Filled.ContentCopy, contentDescription = "Copy password")
            }
            IconButton(onClick = ::generate, enabled = !generating) {
                Icon(Icons.Filled.AutoAwesome, contentDescription = "Generate new password")
            }
            IconButton(onClick = { showSettings = true }) {
                Icon(Icons.Filled.Settings, contentDescription = "Password generator settings")
            }
        }
        Spacer(Modifier.height(18.dp))
        KeyleaseButton(
            useLabel,
            icon = Icons.Filled.Add,
            enabled = password.isNotEmpty(),
            onClick = { onUse(password) },
        )
    }

    if (showSettings) {
        PasswordGeneratorSettingsDialog(app = app, onDismiss = { showSettings = false })
    }
}

/** Saved settings are reused everywhere — port of `_PasswordSettingsForm`. */
@Composable
fun PasswordGeneratorSettingsDialog(app: AppController, onDismiss: () -> Unit) {
    var value by remember { mutableStateOf(app.state.value.passwordGeneratorSettings) }
    var error by remember { mutableStateOf<String?>(null) }
    var saving by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    fun change(next: PasswordGeneratorSettings) {
        value = next
        error = null
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Password generator settings") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                SelectField(
                    label = "Pattern",
                    items = listOf(
                        "Random characters" to PasswordPattern.RANDOM,
                        "Memorable words" to PasswordPattern.WORDS,
                        "PIN" to PasswordPattern.PIN,
                    ),
                    value = value.pattern,
                    onChange = { change(value.copy(pattern = it)) },
                )
                Spacer(Modifier.height(10.dp))
                when (value.pattern) {
                    PasswordPattern.RANDOM -> {
                        SelectField(
                            label = "Length",
                            items = listOf(16, 20, 24, 32, 40, 64).map { "$it" to it },
                            value = value.length,
                            onChange = { change(value.copy(length = it)) },
                        )
                        LabeledCheck("Uppercase letters", value.uppercase) {
                            change(value.copy(uppercase = it))
                        }
                        LabeledCheck("Lowercase letters", value.lowercase) {
                            change(value.copy(lowercase = it))
                        }
                        LabeledCheck("Numbers", value.numbers) {
                            change(value.copy(numbers = it))
                        }
                        LabeledCheck("Symbols", value.symbols) {
                            change(value.copy(symbols = it))
                        }
                        LabeledCheck("Avoid ambiguous characters (0, O, 1, l)", value.avoidAmbiguous) {
                            change(value.copy(avoidAmbiguous = it))
                        }
                    }
                    PasswordPattern.WORDS -> {
                        SelectField(
                            label = "Words",
                            items = (3..8).map { "$it" to it },
                            value = value.wordCount,
                            onChange = { change(value.copy(wordCount = it)) },
                        )
                        Spacer(Modifier.height(10.dp))
                        SelectField(
                            label = "Separator",
                            items = listOf(
                                "Hyphen (-)" to "-", "Space" to " ",
                                "Period (.)" to ".", "Underscore (_)" to "_",
                            ),
                            value = value.separator,
                            onChange = { change(value.copy(separator = it)) },
                        )
                        LabeledCheck("Capitalize words", value.capitalize) {
                            change(value.copy(capitalize = it))
                        }
                        LabeledCheck("Include a number", value.wordNumber) {
                            change(value.copy(wordNumber = it))
                        }
                    }
                    PasswordPattern.PIN -> {
                        SelectField(
                            label = "Digits",
                            items = listOf(4, 6, 8, 10, 12).map { "$it" to it },
                            value = value.pinLength,
                            onChange = { change(value.copy(pinLength = it)) },
                        )
                    }
                }
                error?.let {
                    Spacer(Modifier.height(8.dp))
                    Text(it, color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = !saving,
                onClick = {
                    if (value.pattern == PasswordPattern.RANDOM &&
                        !value.uppercase && !value.lowercase &&
                        !value.numbers && !value.symbols
                    ) {
                        error = "Select at least one character type."
                        return@TextButton
                    }
                    saving = true
                    scope.launch {
                        app.updatePasswordGeneratorSettings(value)
                        onDismiss()
                    }
                },
            ) { Text(if (saving) "Saving…" else "Save settings") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !saving) { Text("Cancel") }
        },
    )
}

@Composable
private fun LabeledCheck(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = checked, onCheckedChange = onChange)
        Text(label)
    }
}
