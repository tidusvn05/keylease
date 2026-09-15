package ai.leasegate.mobile.state

import ai.leasegate.mobile.core.EntrySummary
import ai.leasegate.mobile.core.toList
import ai.leasegate.mobile.core.toMap
import org.json.JSONArray
import org.json.JSONObject

/**
 * The editable snapshot of an entry — the port of `EntryDraft`.
 *
 * Drafts live outside composition so a failed save, a recomposition or a
 * navigation change cannot lose typed data. Secret fields start empty on an
 * edit: an empty secret means "keep the stored value", never "clear it".
 */
class EntryDraft private constructor(
    val entryId: String?,
    val revision: Int,
    kind: String,
    groupId: String?,
    originalTitle: String,
    originalUsername: String,
    originalUrl: String,
    originalFavorite: Boolean,
) {
    var kind: String = kind
    var groupId: String? = groupId

    private val originalGroupId: String? = groupId
    private val originalTitle: String = originalTitle
    private val originalUsername: String = originalUsername
    private val originalUrl: String = originalUrl
    private val originalFavorite: Boolean = originalFavorite

    var title: String = ""
    var username: String = ""
    var url: String = ""
    var password: String = ""
    var notes: String = ""
    var totp: String = ""
    var customFields: String = ""
    var sections: String = ""
    var removeFieldIds: List<String> = emptyList()
    var sshKeyBindings: Map<String, String> = emptyMap()
    var sshBindingsToClear: List<String> = emptyList()
    var structuredErrors: Map<String, String> = emptyMap()
    var tags: String = ""
    var projectSlug: String? = null
    var agentAccess: String = "none"
    var favorite: Boolean = false

    val isAgentContent: Boolean
        get() = kind in setOf("core.prompt", "core.runbook", "core.note")

    val isNew: Boolean get() = entryId == null

    val isDirty: Boolean
        get() = title != originalTitle ||
            username != originalUsername ||
            url != originalUrl ||
            groupId != originalGroupId ||
            password.isNotEmpty() ||
            notes.isNotEmpty() ||
            totp.isNotEmpty() ||
            tags.isNotEmpty() ||
            projectSlug != null ||
            agentAccess != "none" ||
            favorite != originalFavorite ||
            customFields.isNotEmpty() ||
            sections.isNotEmpty() ||
            removeFieldIds.isNotEmpty() ||
            sshKeyBindings.isNotEmpty() ||
            sshBindingsToClear.isNotEmpty()

    /** Field-level validation messages, keyed by field name. */
    fun validate(): Map<String, String> {
        val errors = LinkedHashMap<String, String>()
        if (title.trim().isEmpty()) {
            errors["title"] = "Give this item a name."
        }
        if (!isAgentContent && groupId.isNullOrEmpty()) {
            errors["group"] = "Choose a group for this item."
        }
        if (customFields.trim().isNotEmpty() && parseCustomFields() == null) {
            errors["custom_fields"] = "Custom fields must be a JSON array."
        }
        if (sections.trim().isNotEmpty() && parseSections() == null) {
            errors["sections"] = "Sections must be a JSON array."
        }
        errors.putAll(structuredErrors)
        return errors
    }

    fun parseCustomFields(): List<Any?>? = try {
        JSONArray(customFields).toList()
    } catch (_: Exception) {
        null
    }

    fun parseSections(): List<Any?>? {
        if (sections.trim().isEmpty()) return emptyList()
        return try {
            JSONArray(sections).toList()
        } catch (_: Exception) {
            null
        }
    }

    private fun totpPayload(): Map<String, Any?>? =
        if (totp.trim().isEmpty() || totp.startsWith("otpauth://")) {
            null
        } else {
            mapOf(
                "secret_base32" to totp.trim(),
                "issuer" to null,
                "account" to null,
                "algorithm" to "sha1",
                "digits" to 6,
                "period" to 30,
                "source_representation" to "base32",
            )
        }

    private val totpUri: String? get() =
        if (totp.startsWith("otpauth://")) totp.trim() else null

    /** `entries_create` input. */
    fun toCreateInput(): Map<String, Any?> = mapOf(
        "group_id" to groupId,
        "kind" to kind,
        "title" to title.trim(),
        "favorite" to favorite,
        "username" to username,
        "password" to password.ifEmpty { null },
        "url" to url.ifEmpty { null },
        "notes" to notes.ifEmpty { null },
        "custom_fields" to (parseCustomFields() ?: emptyList<Any?>()),
        "sections" to (parseSections() ?: emptyList<Any?>()),
        "totp" to totpPayload(),
        "totp_uri" to totpUri,
    )

    fun toContentCreateInput(): Map<String, Any?> = mapOf(
        "kind" to kind,
        "title" to title.trim(),
        "body" to notes,
        "tags" to tags.split(',')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .toSet()
            .toList(),
        "project_slug" to projectSlug,
        "favorite" to favorite,
    )

    fun toContentPatch(): Map<String, Any?> = buildMap {
        put("title", title.trim())
        if (notes.isNotEmpty()) put("body", notes)
        if (tags.trim().isNotEmpty()) {
            put(
                "tags",
                tags.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                    .toSet().toList(),
            )
        }
        put("add_tags", emptyList<String>())
        put("remove_tags", emptyList<String>())
        if (projectSlug != null) put("project_slug", projectSlug)
        put("clear_project", false)
        if (favorite != originalFavorite) put("favorite", favorite)
    }

    /**
     * `entries_update` patch. Empty secrets are omitted so they keep their
     * stored value instead of being overwritten with a blank.
     */
    fun toPatch(): Map<String, Any?> = buildMap {
        put("title", title.trim())
        put("username", username)
        put("url", url.ifEmpty { null })
        if (groupId != originalGroupId) put("group_id", groupId)
        if (favorite != originalFavorite) put("favorite", favorite)
        if (password.isNotEmpty()) put("password", password)
        if (notes.isNotEmpty()) put("notes", notes)
        totpPayload()?.let { put("totp", it) }
        totpUri?.let { put("totp_uri", it) }
        parseCustomFields()?.let { put("field_updates", it) }
        if (sections.trim().isNotEmpty()) put("sections", parseSections())
        if (removeFieldIds.isNotEmpty()) put("remove_field_ids", removeFieldIds)
    }

    /** Removes the secret material a draft accumulated. */
    fun wipeSecrets() {
        password = ""
        notes = ""
        totp = ""
        customFields = ""
        sections = ""
        removeFieldIds = emptyList()
        sshKeyBindings = emptyMap()
        sshBindingsToClear = emptyList()
        structuredErrors = emptyMap()
    }

    companion object {
        fun create(groupId: String?, kind: String = "core.login", initialPassword: String = "") =
            EntryDraft(
                entryId = null,
                revision = 0,
                kind = kind,
                groupId = groupId,
                originalTitle = "",
                originalUsername = "",
                originalUrl = "",
                originalFavorite = false,
            ).apply { password = initialPassword }

        fun edit(entry: EntrySummary) = EntryDraft(
            entryId = entry.id,
            revision = entry.revision,
            kind = entry.kind,
            groupId = entry.groupId,
            originalTitle = entry.title,
            originalUsername = entry.username ?: "",
            originalUrl = entry.primaryUrl ?: "",
            originalFavorite = entry.favorite,
        ).apply {
            title = entry.title
            username = entry.username ?: ""
            url = entry.primaryUrl ?: ""
            favorite = entry.favorite
        }
    }
}

/** JSON-array encode helper for the structured editors. */
fun encodeSectionsJson(sections: List<Map<String, Any?>>): String =
    JSONArray(sections).toString()
