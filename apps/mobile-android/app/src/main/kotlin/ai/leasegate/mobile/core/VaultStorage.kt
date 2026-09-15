package ai.leasegate.mobile.core

import java.io.File
import java.security.SecureRandom
import kotlin.math.min

/**
 * Vault files in Android app-private storage, over JNI.
 *
 * Port of `FfiVaultStorage` in the Flutter client: the registry is a plain
 * non-secret JSON file, the vault database is authoritative and is never
 * modified here.
 */
class VaultStorage(
    private val vault: VaultSession,
    private val supportDirectory: String,
) {
    private var databasePath: String = "$supportDirectory/vault.sqlite"
    private var activeId: String? = null
    private var profiles: MutableList<MutableMap<String, Any?>> = mutableListOf()

    private val registry: File get() = File("$supportDirectory/vault_profiles.json")

    suspend fun initialize() {
        if (registry.exists()) {
            try {
                val raw = jsonDecode(registry.readText())
                activeId = raw.string("active_id")
                profiles = raw.list("profiles")
                    .mapNotNull { (it as? Map<*, *>)?.asJsonMap() }
                    .map { LinkedHashMap(it) }
                    .toMutableList()
                val active = findProfile(activeId)
                if (active != null) {
                    databasePath = active["path"] as String
                }
            } catch (_: Exception) {
                // A damaged non-secret registry must not hide the legacy
                // vault. The vault database remains authoritative.
            }
        }
        File("$supportDirectory/vaults").mkdirs()
        val opened = vault.openVault(databasePath)
        if (opened["ok"] == false) {
            throw KeyLeaseException.fromDaemon(opened["error"])
        }
    }

    /** Whether a vault database already exists in app-private storage. */
    suspend fun vaultExists(): Boolean {
        val response = vault.provision(mapOf("provision" to "inspect"))
        if (response["ok"] == false) return false
        return response.map("result")?.get("initialized") == true
    }

    /** The version string the Rust core reports. */
    suspend fun serviceVersion(): String? {
        val response = vault.provision(mapOf("provision" to "inspect"))
        return response.map("result")?.map("status")?.string("service_version")
    }

    /** Runs a provisioning request against the open vault. */
    suspend fun provision(request: JsonMap): JsonMap {
        val response = vault.provision(request)
        if (response["ok"] == false) {
            throw KeyLeaseException.fromDaemon(response["error"])
        }
        @Suppress("UNCHECKED_CAST")
        val result = (response["result"] as? JsonMap) ?: emptyMap()
        if (request["provision"] in setOf("create", "restore_backup", "import_kdbx")) {
            registerCurrent(result, request["provision"] as String)
            val sourcePath = request["source_path"]
            if (sourcePath is String && sourcePath.startsWith("$supportDirectory/imports/")) {
                try {
                    File(sourcePath).delete()
                } catch (_: Exception) {
                    // The managed vault is already committed. A failed cleanup
                    // must not turn a successful import into a second attempt.
                }
            }
        }
        return result
    }

    suspend fun listVaults(): List<LocalVaultProfile> = profiles.map { profile ->
        LocalVaultProfile(
            id = profile["id"] as String,
            name = profile["name"] as String,
            active = profile["id"] == activeId,
            vaultId = profile["vault_id"] as? String,
            provenance = profile["provenance"] as? String,
        )
    }

    /** Creates a new vault file named [name]. */
    suspend fun createVault(name: String, request: JsonMap) {
        val id = newProfileId()
        val previousPath = databasePath
        val previousId = activeId
        databasePath = "$supportDirectory/vaults/$id.sqlite"
        val opened = vault.openVault(databasePath)
        if (opened["ok"] == false) {
            databasePath = previousPath
            activeId = previousId
            vault.openVault(previousPath)
            throw KeyLeaseException.fromDaemon(opened["error"])
        }
        try {
            provision(request)
            val index = profiles.indexOfFirst { it["id"] == activeId }
            if (index >= 0) profiles[index]["name"] = safeName(name)
            saveRegistry()
        } catch (error: Exception) {
            databasePath = previousPath
            activeId = previousId
            vault.openVault(previousPath)
            throw error
        }
    }

    /** Makes [id] the active vault. */
    suspend fun switchVault(id: String) {
        val profile = findProfile(id)
            ?: throw KeyLeaseException("The selected vault is no longer available.")
        val nextPath = profile["path"] as String
        val opened = vault.openVault(nextPath)
        if (opened["ok"] == false) {
            throw KeyLeaseException.fromDaemon(opened["error"])
        }
        databasePath = nextPath
        activeId = id
        saveRegistry()
    }

    suspend fun renameVault(id: String, name: String) {
        val profile = findProfile(id) ?: return
        profile["name"] = safeName(name)
        saveRegistry()
    }

    /**
     * Registers a vault created by a pre-registry app version after its first
     * successful unlock. A rejected password never reaches this callback.
     */
    suspend fun recordUnlocked(result: JsonMap) {
        if (findProfile(activeId) == null) {
            registerCurrent(result, "existing_keylease_vault")
        }
    }

    private suspend fun registerCurrent(result: JsonMap, sourceKind: String) {
        var profile = profiles.firstOrNull { it["path"] == databasePath }
        if (profile == null) {
            profile = mutableMapOf(
                "id" to newProfileId(),
                "name" to if (profiles.isEmpty()) "My Vault" else "Vault ${profiles.size + 1}",
                "path" to databasePath,
            )
            profiles.add(profile)
        }
        profile["vault_id"] = result["vault_id"]
        profile["provenance"] = result["provenance"] ?: sourceKind
        profile["source_kind"] = sourceKind
        activeId = profile["id"] as String
        saveRegistry()
    }

    private fun newProfileId(): String {
        val random = SecureRandom().nextInt(Int.MAX_VALUE).toString(16)
        return "vault_${System.currentTimeMillis() * 1000}_$random"
    }

    private fun findProfile(id: String?): MutableMap<String, Any?>? =
        profiles.firstOrNull { it["id"] == id }

    private fun safeName(value: String): String {
        val trimmed = value.trim()
        return if (trimmed.isEmpty()) "Vault" else trimmed.substring(0, min(80, trimmed.length))
    }

    private fun saveRegistry() {
        val temporary = File("${registry.path}.tmp")
        temporary.writeText(jsonEncode(mapOf("active_id" to activeId, "profiles" to profiles)))
        temporary.renameTo(registry)
    }

    /**
     * Maps the UI's mode-shaped provisioning request onto the mobile
     * provisioning vocabulary; port of `FfiLocalRuntimeAdapter`.
     */
    fun mobileProvisionRequest(request: JsonMap): JsonMap {
        if (request.containsKey("provision")) return request
        val password = request["password"]
        return when (request["mode"]) {
            "create" -> mapOf(
                "provision" to "create",
                "password" to password,
                "session_ttl_seconds" to 900,
                "acknowledge_standalone" to true,
            )
            "restore_keylease_backup" -> mapOf(
                "provision" to "restore_backup",
                "source_path" to request["source_path"],
                "password" to password,
                "session_ttl_seconds" to 900,
            )
            "import_kdbx" -> mapOf(
                "provision" to "import_kdbx",
                "source_path" to request["source_path"],
                "source_password" to request["source_password"],
                "password" to password,
                "session_ttl_seconds" to 900,
            )
            else -> throw KeyLeaseException(
                "Android supports encrypted KeyLease backups and password-only KDBX files.",
            )
        }
    }
}
