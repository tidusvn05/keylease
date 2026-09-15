package ai.leasegate.mobile.state

import ai.leasegate.mobile.core.EntryDetailView
import ai.leasegate.mobile.core.EntryFieldView
import ai.leasegate.mobile.core.EntrySectionView
import ai.leasegate.mobile.core.JsonMap
import java.util.concurrent.atomic.AtomicLong
import org.json.JSONArray

/**
 * Structured `.env` / SSH editor helpers — the port of
 * `developer_templates.dart`.
 */

private val environmentKey = Regex("^[A-Za-z_][A-Za-z0-9_]*$")
private val sshAlias = Regex("^[A-Za-z0-9._-]+$")
private val structuredIdSequence = AtomicLong(0)

fun structuredId(prefix: String, salt: Int = 0): String =
    "${prefix}_${System.nanoTime()}_${salt}_${structuredIdSequence.getAndIncrement()}"

fun structuredTextField(
    id: String,
    key: String,
    label: String,
    role: String,
    value: String,
    secret: Boolean = false,
): JsonMap = mapOf(
    "id" to id,
    "key" to key,
    "label" to label,
    "value" to mapOf("type" to if (secret) "concealed" else "text", "value" to value),
    "sensitivity" to if (secret) "highly_sensitive" else "private_metadata",
    "protected" to secret,
    "semantic_role" to role,
)

class EnvVariableDraft(
    val id: String,
    var key: String,
    var value: String,
    var secret: Boolean = true,
    val existing: Boolean = false,
    val hasStoredValue: Boolean = false,
    var dirty: Boolean = true,
) {
    fun toField(): JsonMap = structuredTextField(
        id = id,
        key = "env.$key",
        label = key,
        role = "environment_variable",
        value = value,
        secret = secret,
    )
}

data class EnvParseIssue(val line: Int, val message: String)

data class EnvParseResult(
    val variables: List<EnvVariableDraft>,
    val issues: List<EnvParseIssue>,
    val ignoredComments: Int,
    val ignoredBlankLines: Int,
    val normalizedExports: Int,
) {
    val valid: Boolean get() = issues.isEmpty()
}

fun parseDotEnv(source: String): EnvParseResult {
    val normalized = source.replaceFirst("﻿", "").replace("\r\n", "\n")
    val lines = normalized.split("\n")
    val variables = mutableListOf<EnvVariableDraft>()
    val issues = mutableListOf<EnvParseIssue>()
    val seen = mutableSetOf<String>()
    var comments = 0
    var blanks = 0
    var exports = 0
    var index = 0
    while (index < lines.size) {
        val lineNumber = index + 1
        var line = lines[index]
        val trimmed = line.trim()
        if (trimmed.isEmpty()) {
            blanks++
            index++
            continue
        }
        if (trimmed.startsWith("#")) {
            comments++
            index++
            continue
        }
        line = line.trimStart()
        if (line.startsWith("export ")) {
            exports++
            line = line.substring(7).trimStart()
        }
        val equals = line.indexOf('=')
        if (equals < 1) {
            issues.add(EnvParseIssue(lineNumber, "Expected KEY=value."))
            index++
            continue
        }
        val key = line.substring(0, equals).trim()
        if (!environmentKey.matches(key)) {
            issues.add(EnvParseIssue(lineNumber, "Invalid variable name \"$key\"."))
            index++
            continue
        }
        if (!seen.add(key)) {
            issues.add(EnvParseIssue(lineNumber, "Duplicate variable \"$key\"."))
            index++
            continue
        }
        var raw = line.substring(equals + 1).trimStart()
        val value: String
        if (raw.startsWith("'") || raw.startsWith("\"")) {
            val quote = raw[0]
            val buffer = StringBuilder()
            var closed = false
            raw = raw.substring(1)
            while (true) {
                var cursor = 0
                while (cursor < raw.length) {
                    val char = raw[cursor]
                    if (char == quote && (quote == '\'' || !isEscaped(raw, cursor))) {
                        val trailing = raw.substring(cursor + 1).trim()
                        if (trailing.isNotEmpty() && !trailing.startsWith("#")) {
                            issues.add(
                                EnvParseIssue(
                                    lineNumber,
                                    "Unexpected text after quoted value.",
                                ),
                            )
                        }
                        closed = true
                        break
                    }
                    if (quote == '"' && char == '\\' && cursor + 1 < raw.length) {
                        when (val next = raw[++cursor]) {
                            'n' -> buffer.append('\n')
                            'r' -> buffer.append('\r')
                            't' -> buffer.append('\t')
                            '"' -> buffer.append('"')
                            '\\' -> buffer.append('\\')
                            '$' -> buffer.append('$')
                            else -> buffer.append(next)
                        }
                    } else {
                        buffer.append(char)
                    }
                    cursor++
                }
                if (closed || index + 1 >= lines.size) break
                buffer.append('\n')
                raw = lines[++index]
            }
            if (!closed) {
                issues.add(EnvParseIssue(lineNumber, "Unclosed quoted value."))
            }
            value = buffer.toString()
        } else {
            val comment = unquotedComment(raw)
            if (comment >= 0) raw = raw.substring(0, comment)
            value = raw.trimEnd()
        }
        variables.add(
            EnvVariableDraft(
                id = structuredId("field_env", variables.size),
                key = key,
                value = value,
            ),
        )
        index++
    }
    return EnvParseResult(
        variables = variables,
        issues = issues,
        ignoredComments = comments,
        ignoredBlankLines = blanks,
        normalizedExports = exports,
    )
}

private fun isEscaped(value: String, index: Int): Boolean {
    var slashes = 0
    var cursor = index - 1
    while (cursor >= 0 && value[cursor] == '\\') {
        slashes++
        cursor--
    }
    return slashes % 2 == 1
}

private fun unquotedComment(value: String): Int {
    for (index in 1 until value.length) {
        if (value[index] == '#' && value[index - 1].isWhitespace()) return index
    }
    return -1
}

fun renderDotEnv(variables: List<Pair<String, String>>): String {
    val output = StringBuilder()
    for ((key, value) in variables) {
        output.append(key).append('=').append(renderEnvValue(value)).append('\n')
    }
    return output.toString()
}

private fun renderEnvValue(value: String): String {
    if (value.isEmpty()) return ""
    if (Regex("^[A-Za-z0-9_./:@%+,=-]+$").matches(value)) return value
    if (!value.contains("'") && !value.contains("\n") && !value.contains("\r")) {
        return "'$value'"
    }
    val escaped = value
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\$", "\\\$")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    return "\"$escaped\""
}

data class SshEndpointConfig(
    val sectionId: String,
    val name: String,
    val alias: String,
    val host: String,
    val port: Int,
    val username: String,
    val authMode: String,
    val connectVia: String? = null,
)

data class SshForwardConfig(
    val endpointId: String,
    val type: String,
    val bindAddress: String,
    val bindPort: Int,
    val destinationHost: String,
    val destinationPort: Int,
)

class SshConfigException(message: String) : Exception(message)

fun renderSshConfig(
    endpoints: List<SshEndpointConfig>,
    forwards: List<SshForwardConfig>,
    privateKeyPaths: Map<String, String>,
): String {
    val byId = endpoints.associateBy { it.sectionId }
    val output = StringBuilder()
    for (endpoint in endpoints) {
        if (!sshAlias.matches(endpoint.alias)) {
            throw SshConfigException("Invalid SSH alias.")
        }
        output.append("Host ${endpoint.alias}\n")
        output.append("  HostName ${sshToken(endpoint.host)}\n")
        if (endpoint.username.isNotEmpty()) {
            output.append("  User ${sshToken(endpoint.username)}\n")
        }
        output.append("  Port ${endpoint.port}\n")
        val path = privateKeyPaths[endpoint.sectionId]
        if (endpoint.authMode == "private_key") {
            if (path.isNullOrEmpty()) {
                throw SshConfigException(
                    "Select a private key for ${endpoint.name} on this device.",
                )
            }
            output.append("  IdentityFile ${sshToken(path)}\n")
            output.append("  IdentitiesOnly yes\n")
        }
        val chain = mutableListOf<String>()
        val seen = mutableSetOf<String>()
        var parent = endpoint.connectVia
        while (!parent.isNullOrEmpty()) {
            if (!seen.add(parent)) {
                throw SshConfigException("SSH jump host cycle.")
            }
            val jump = byId[parent] ?: throw SshConfigException("Missing SSH jump host.")
            chain.add(0, jump.alias)
            parent = jump.connectVia
        }
        if (chain.isNotEmpty()) output.append("  ProxyJump ${chain.joinToString(",")}\n")
        for (forward in forwards.filter { it.endpointId == endpoint.sectionId }) {
            val bind = "${sshToken(forward.bindAddress)}:${forward.bindPort}"
            if (forward.type == "dynamic") {
                output.append("  DynamicForward $bind\n")
            } else {
                val destination =
                    "${sshToken(forward.destinationHost)}:${forward.destinationPort}"
                output.append(
                    "  ${if (forward.type == "remote") "RemoteForward" else "LocalForward"} $bind $destination\n",
                )
            }
        }
        output.append('\n')
    }
    return output.toString()
}

private fun sshToken(value: String): String {
    if (value.isEmpty() || value.any { it.code < 32 }) {
        throw SshConfigException("SSH values must not contain control characters.")
    }
    if (Regex("^[A-Za-z0-9_./:@%+,-]+$").matches(value)) return value
    return "\"${value.replace("\\", "\\\\").replace("\"", "\\\"")}\""
}

fun entryFieldText(field: EntryFieldView): String? {
    if (field.`protected`) return null
    val value = field.value
    if (value is Map<*, *> && value["value"] != null) return "${value["value"]}"
    return field.displayValue
}

fun fieldsByRole(
    section: EntrySectionView,
    detail: EntryDetailView,
): Map<String, EntryFieldView> {
    val byId = detail.fields.associateBy { it.id }
    val out = LinkedHashMap<String, EntryFieldView>()
    for (id in section.fieldIds) {
        val field = byId[id] ?: continue
        val role = field.semanticRole ?: continue
        out[role] = field
    }
    return out
}

fun encodeStructuredSections(sections: List<EntrySectionView>): String =
    JSONArray(sections.map { org.json.JSONObject(it.toJson()) }).toString()
