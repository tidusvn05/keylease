package ai.leasegate.mobile.core

import java.time.Instant
import java.time.LocalDateTime
import java.time.OffsetDateTime
import java.time.ZoneId

/**
 * Typed views over the local IPC payloads; the mirror of `models.dart`.
 * Every field here exists in the service contract — UI-only guesses never
 * enter these models.
 */

private fun Any?.asString(): String? = this as? String

private fun Any?.asInt(): Int? = (this as? Number)?.toInt()

private fun Any?.asStrings(): List<String> =
    (this as? List<*>)?.map { it.toString() } ?: emptyList()

/** Parses an ISO-8601 timestamp into the device's wall clock. */
fun parseTime(value: Any?): LocalDateTime? = (value as? String)?.let { raw ->
    runCatching { OffsetDateTime.parse(raw).atZoneSameInstant(ZoneId.systemDefault()).toLocalDateTime() }
        .recoverCatching { Instant.parse(raw).atZone(ZoneId.systemDefault()).toLocalDateTime() }
        .recoverCatching { LocalDateTime.parse(raw) }
        .getOrNull()
}

@Suppress("UNCHECKED_CAST")
fun Map<*, *>.asJsonMap(): JsonMap = this as JsonMap

inline fun <T> Any?.parseList(parse: (JsonMap) -> T): List<T> =
    (this as? List<*>)?.mapNotNull { (it as? Map<*, *>)?.asJsonMap()?.let(parse) } ?: emptyList()

/** `status` result. See `KeyLeaseService::status`. */
data class VaultStatus(
    val locked: Boolean,
    val requiresUserAction: Boolean = false,
    val vaultId: String? = null,
    val idleExpiresAt: LocalDateTime? = null,
) {
    companion object {
        fun fromJson(json: JsonMap) = VaultStatus(
            locked = json["locked"] != false,
            requiresUserAction = json["requires_user_action"] == true,
            vaultId = json["vault_id"].asString(),
            idleExpiresAt = parseTime(json["idle_expires_at"]),
        )
    }
}

/** `groups_list` element. See `VaultGroup`. */
data class VaultGroup(
    val id: String,
    val name: String,
    val revision: Int,
    val parentId: String? = null,
    val sortOrder: Int? = null,
) {
    companion object {
        fun fromJson(json: JsonMap) = VaultGroup(
            id = "${json["id"]}",
            name = json["name"].asString() ?: "Group",
            revision = json["revision"].asInt() ?: 0,
            parentId = json["parent_id"].asString(),
            sortOrder = json["sort_order"].asInt(),
        )
    }
}

/** `entries_search` / `entries_get` element. See `ItemMetadata`. */
data class EntrySummary(
    val id: String,
    val groupId: String,
    val kind: String,
    val title: String,
    val revision: Int,
    val username: String? = null,
    val urls: List<String> = emptyList(),
    val hasPassword: Boolean = false,
    val hasNotes: Boolean = false,
    val hasTotp: Boolean = false,
    val favorite: Boolean = false,
    val updatedAt: LocalDateTime? = null,
) {
    companion object {
        fun fromJson(json: JsonMap) = EntrySummary(
            id = "${json["id"]}",
            groupId = "${json["group_id"]}",
            kind = json["kind"].asString() ?: "core.generic",
            title = json["title"].asString() ?: "Untitled",
            revision = json["revision"].asInt() ?: 0,
            username = json["username"].asString(),
            urls = json["urls"].asStrings(),
            hasPassword = json["has_password"] == true,
            hasNotes = json["has_notes"] == true,
            hasTotp = json["has_totp"] == true,
            favorite = json["favorite"] == true,
            updatedAt = parseTime(json["updated_at"]),
        )
    }

    val primaryUrl: String? get() = urls.firstOrNull()

    /** Monogram used by the list and detail marks. */
    val monogram: String
        get() {
            val trimmed = title.trim()
            if (trimmed.isEmpty()) return "?"
            val words = trimmed.split(Regex("\\s+"))
            if (words.size > 1 && words[1].isNotEmpty()) {
                return "${words[0][0]}${words[1][0]}".uppercase()
            }
            return (if (trimmed.length > 1) trimmed.substring(0, 2) else trimmed).uppercase()
        }

    val subtitle: String
        get() = listOfNotNull(
            username?.takeIf { it.isNotEmpty() },
            *urls.toTypedArray(),
        ).joinToString(" · ")
}

/**
 * A field from `entries_view`. Protected values are intentionally absent
 * until the user explicitly reveals or copies the field.
 */
data class EntryFieldView(
    val id: String,
    val key: String,
    val label: String,
    val valueType: String,
    val sensitivity: String,
    val protected: Boolean,
    val hasValue: Boolean,
    val semanticRole: String? = null,
    val value: Any? = null,
    val displayHint: String? = null,
) {
    companion object {
        fun fromJson(json: JsonMap) = EntryFieldView(
            id = "${json["id"]}",
            key = json["key"].asString() ?: "",
            label = json["label"].asString() ?: json["key"].asString() ?: "Field",
            semanticRole = json["semantic_role"].asString(),
            valueType = json["value_type"].asString() ?: "text",
            sensitivity = json["sensitivity"].asString() ?: "private_metadata",
            protected = json["protected"] == true,
            hasValue = json["has_value"] == true,
            value = json["value"],
            displayHint = json["display_hint"].asString(),
        )
    }

    fun withValue(next: Any?) = copy(value = next)

    val displayValue: String
        get() {
            val v = value ?: return displayHint ?: (if (hasValue) "Stored" else "")
            if (v !is Map<*, *>) return "$v"
            val type = "${v["type"]}"
            val content = v["value"]
            if (type == "month_year" && content is Map<*, *>) {
                val month = content["month"].asInt()
                val year = content["year"].asInt()
                if (month != null && year != null) {
                    return "${month.toString().padStart(2, '0')}/$year"
                }
            }
            if (type == "address" && content is Map<*, *>) {
                return content.values
                    .filter { it != null && "$it".trim().isNotEmpty() }
                    .joinToString(", ") { "$it" }
            }
            if (content is Map<*, *> || content is List<*>) return "$content"
            return content?.toString() ?: ""
        }
}

/** Full, field-oriented entry projection used by the detail pane. */
data class EntryDetailView(
    val metadata: EntrySummary,
    val templateVersion: Int,
    val tags: List<String>,
    val sections: List<EntrySectionView>,
    val fields: List<EntryFieldView>,
    val projectId: String? = null,
    val hasNotes: Boolean = false,
) {
    companion object {
        fun fromJson(json: JsonMap) = EntryDetailView(
            metadata = EntrySummary.fromJson((json["metadata"] as Map<*, *>).asJsonMap()),
            templateVersion = json["template_version"].asInt() ?: 1,
            projectId = json["project_id"].asString(),
            tags = json["tags"].asStrings(),
            sections = json["sections"].parseList(EntrySectionView::fromJson),
            fields = json["fields"].parseList(EntryFieldView::fromJson),
            hasNotes = json["has_notes"] == true,
        )
    }
}

data class EntrySectionView(
    val id: String,
    val label: String,
    val fieldIds: List<String>,
    val semanticRole: String? = null,
) {
    companion object {
        fun fromJson(json: JsonMap) = EntrySectionView(
            id = "${json["id"]}",
            label = json["label"].asString() ?: "Details",
            fieldIds = json["field_ids"].asStrings(),
            semanticRole = json["semantic_role"].asString(),
        )
    }

    fun toJson(): JsonMap = mapOf(
        "id" to id,
        "label" to label,
        "field_ids" to fieldIds,
        "semantic_role" to semanticRole,
    )
}

data class TemplateDefinition(
    val kind: String,
    val label: String,
    val family: String,
    val markdownNotes: Boolean,
    val fields: List<TemplateFieldDefinition>,
) {
    companion object {
        fun fromJson(json: JsonMap) = TemplateDefinition(
            kind = "${json["kind"]}",
            label = json["label"].asString() ?: "${json["kind"]}",
            family = json["family"].asString() ?: "other",
            markdownNotes = json["markdown_notes"] == true,
            fields = json["fields"].parseList(TemplateFieldDefinition::fromJson),
        )
    }
}

data class TemplateFieldDefinition(
    val key: String,
    val label: String,
    val valueType: String,
    val semanticRole: String,
    val sensitivity: String,
    val protected: Boolean,
    val section: String,
) {
    companion object {
        fun fromJson(json: JsonMap) = TemplateFieldDefinition(
            key = "${json["key"]}",
            label = "${json["label"]}",
            valueType = json["value_type"].asString() ?: "text",
            semanticRole = json["semantic_role"].asString() ?: "${json["key"]}",
            sensitivity = json["sensitivity"].asString() ?: "private_metadata",
            protected = json["protected"] == true,
            section = json["section"].asString() ?: "Details",
        )
    }
}

data class VaultProjectModel(val id: String, val slug: String, val name: String) {
    companion object {
        fun fromJson(json: JsonMap) = VaultProjectModel(
            id = "${json["id"]}",
            slug = json["slug"].asString() ?: "",
            name = json["name"].asString() ?: json["slug"].asString() ?: "",
        )
    }
}

data class MigrationProposalModel(
    val itemId: String,
    val title: String,
    val currentKind: String,
    val proposedKind: String,
    val confidence: String,
    val reasons: List<String>,
    val expectedRevision: Int,
) {
    companion object {
        fun fromJson(json: JsonMap) = MigrationProposalModel(
            itemId = "${json["item_id"]}",
            title = json["title"].asString() ?: "Untitled",
            currentKind = json["current_kind"].asString() ?: "core.generic",
            proposedKind = json["proposed_kind"].asString() ?: "core.generic",
            confidence = json["confidence"].asString() ?: "unknown",
            reasons = json["reasons"].asStrings(),
            expectedRevision = json["expected_revision"].asInt() ?: 0,
        )
    }
}

data class MigrationPreviewModel(
    val id: String,
    val version: Int,
    val title: String,
    val type: String,
    val digest: String,
    val proposals: List<MigrationProposalModel>,
) {
    companion object {
        fun fromJson(json: JsonMap) = MigrationPreviewModel(
            id = "${json["migration_id"]}",
            version = json["version"].asInt() ?: 1,
            title = json["title"].asString() ?: "${json["migration_id"]}",
            type = json["migration_type"].asString() ?: "semantic",
            digest = json["preview_digest"].asString() ?: "",
            proposals = json["proposals"].parseList(MigrationProposalModel::fromJson),
        )
    }
}

data class MigrationStatusModel(
    val frameworkVersion: Int,
    val pending: List<MigrationPreviewModel>,
    val history: List<MigrationHistoryModel>,
) {
    companion object {
        fun fromJson(json: JsonMap) = MigrationStatusModel(
            frameworkVersion = json["framework_version"].asInt() ?: 1,
            pending = json["pending"].parseList(MigrationPreviewModel::fromJson),
            history = json["history"].parseList(MigrationHistoryModel::fromJson),
        )
    }
}

data class MigrationHistoryModel(
    val id: String,
    val version: Int,
    val state: String,
    val itemCount: Int,
    val appliedAt: LocalDateTime? = null,
    val rolledBackAt: LocalDateTime? = null,
) {
    companion object {
        fun fromJson(json: JsonMap) = MigrationHistoryModel(
            id = "${json["migration_id"]}",
            version = json["version"].asInt() ?: 1,
            state = json["state"].asString() ?: "unknown",
            itemCount = json["item_count"].asInt() ?: 0,
            appliedAt = parseTime(json["applied_at"]),
            rolledBackAt = parseTime(json["rolled_back_at"]),
        )
    }
}

/** `connections_list` element. See `ConnectionRecord`. */
data class ConnectionSummary(
    val id: String,
    val provider: String,
    val health: String,
    val authMethod: String,
    val trustMode: String,
    val executionLocation: String,
    val authorizedResources: List<String>,
    val healthReason: String? = null,
    val reauthorizationRequired: Boolean = false,
    val grantedPermissions: List<String> = emptyList(),
    val lastCheckedAt: LocalDateTime? = null,
    val lastRefreshedAt: LocalDateTime? = null,
) {
    companion object {
        fun fromJson(json: JsonMap) = ConnectionSummary(
            id = "${json["id"]}",
            provider = json["provider"].asString() ?: "unknown",
            health = json["health"].asString() ?: "unknown",
            authMethod = json["auth_method"].asString() ?: "unknown",
            trustMode = json["trust_mode"].asString() ?: "unknown",
            executionLocation = json["execution_location"].asString() ?: "unknown",
            authorizedResources = json["authorized_resources"].asStrings(),
            healthReason = json["health_reason"].asString(),
            reauthorizationRequired = json["reauthorization_required"] == true,
            grantedPermissions = json["granted_permissions"].asStrings(),
            lastCheckedAt = parseTime(json["last_checked_at"]),
            lastRefreshedAt = parseTime(json["last_refreshed_at"]),
        )
    }
}

/** `approvals_list` element. See `ApprovalRecord`. */
data class ApprovalSummary(
    val id: String,
    val requestDigestHex: String,
    val policyVersion: Int,
    val state: String,
    val expiresAt: LocalDateTime,
    val agentId: String? = null,
    val action: String? = null,
    val resource: String? = null,
    val risk: String? = null,
    val createdAt: LocalDateTime? = null,
    val operation: String? = null,
    val target: String? = null,
    val changedFields: List<String> = emptyList(),
    val blastRadius: String? = null,
) {
    companion object {
        fun fromJson(json: JsonMap): ApprovalSummary {
            val semantic = (json["semantic_summary"] as? Map<*, *>)?.asJsonMap()
            return ApprovalSummary(
                id = "${json["id"]}",
                requestDigestHex = json["request_digest_hex"].asString() ?: "",
                policyVersion = json["policy_version"].asInt() ?: 0,
                state = json["state"].asString() ?: "pending",
                expiresAt = parseTime(json["expires_at"])
                    ?: LocalDateTime.ofEpochSecond(0, 0, java.time.ZoneOffset.UTC),
                agentId = json["agent_id"].asString(),
                action = json["action"].asString(),
                resource = json["resource"].asString(),
                risk = json["risk"].asString(),
                createdAt = parseTime(json["created_at"]),
                operation = semantic?.get("operation").asString(),
                target = semantic?.get("target").asString(),
                changedFields = semantic?.get("changed_fields")?.asStrings() ?: emptyList(),
                blastRadius = semantic?.get("blast_radius").asString(),
            )
        }
    }

    val isPending: Boolean get() = state == "pending"

    fun decidableAt(now: LocalDateTime): Boolean = isPending && expiresAt.isAfter(now)

    /** The exact request this decision would bind to. */
    fun sameRequestAs(other: ApprovalSummary): Boolean =
        id == other.id &&
            requestDigestHex == other.requestDigestHex &&
            policyVersion == other.policyVersion
}

/** `audit_query` element. See `AuditEvent`. */
data class ActivityEvent(
    val action: String,
    val resource: String,
    val decision: String,
    val outcome: String,
    val agentId: String,
    val timestamp: LocalDateTime? = null,
    val policyVersion: Int? = null,
    val itemCount: Int? = null,
    val cellCount: Int? = null,
    val byteCount: Int? = null,
    val changedFields: List<String> = emptyList(),
    val connector: String? = null,
) {
    companion object {
        fun fromJson(json: JsonMap) = ActivityEvent(
            action = json["action"].asString() ?: "unknown",
            resource = json["resource"].asString() ?: "",
            decision = json["decision"].asString() ?: "unknown",
            outcome = json["outcome"].asString() ?: "unknown",
            agentId = json["agent_id"].asString() ?: "unknown client",
            timestamp = parseTime(json["timestamp"]),
            policyVersion = json["policy_version"].asInt(),
            itemCount = json["item_count"].asInt(),
            cellCount = json["cell_count"].asInt(),
            byteCount = json["byte_count"].asInt(),
            changedFields = json["changed_fields"].asStrings(),
            connector = json["connector"].asString(),
        )
    }

    val denied: Boolean get() = decision != "allow" || outcome != "success"

    val volume: String
        get() = listOfNotNull(
            itemCount?.let { "$it items" },
            cellCount?.let { "$it cells" },
            byteCount?.let { "$it bytes" },
        ).joinToString(" · ")
}

/** `entries_history` element. */
data class EntryRevision(val revision: Int, val updatedAt: LocalDateTime? = null) {
    companion object {
        fun fromJson(json: JsonMap) = EntryRevision(
            revision = json["revision"].asInt() ?: 0,
            updatedAt = parseTime(json["updated_at"]),
        )
    }
}

/** A vault this device holds; mirror of `LocalVaultProfile`. */
data class LocalVaultProfile(
    val id: String,
    val name: String,
    val active: Boolean,
    val vaultId: String? = null,
    val provenance: String? = null,
    val path: String? = null,
)
