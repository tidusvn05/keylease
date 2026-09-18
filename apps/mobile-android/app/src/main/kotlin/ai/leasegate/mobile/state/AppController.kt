package ai.leasegate.mobile.state

import ai.leasegate.mobile.core.BiometricVault
import ai.leasegate.mobile.core.JsonMap
import ai.leasegate.mobile.core.KeyLeaseClient
import ai.leasegate.mobile.core.KeyLeaseErrorCode
import ai.leasegate.mobile.core.KeyLeaseException
import ai.leasegate.mobile.core.LocalVaultProfile
import ai.leasegate.mobile.core.SecureClipboard
import ai.leasegate.mobile.core.UserMessage
import ai.leasegate.mobile.core.VaultSession
import ai.leasegate.mobile.core.VaultStatus
import ai.leasegate.mobile.core.VaultStorage
import ai.leasegate.mobile.core.EntrySummary
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** Mobile app phases — the port of `AppPhase`. */
enum class AppPhase {
    CHECKING,
    ONBOARDING,
    PROVISIONING,
    REPAIR_REQUIRED,
    BACKGROUND_APPROVAL_REQUIRED,
    SERVICE_UNAVAILABLE,
    LOCKED,
    PERMISSION_DENIED,
    READY,
}

enum class AppSection(val label: String, val requiresReady: Boolean) {
    VAULT("Vault", true),
    APPROVALS("Approvals", true),
    SETTINGS("Settings", false),
}

/** What this build offers — the port of `AppCapabilities.androidPhone`. */
data class AppCapabilities(
    val agentWorkflows: Boolean = false,
    val sshKeyBinding: Boolean = false,
    val developerTemplateEditing: Boolean = false,
    val screenQrScan: Boolean = false,
    val cameraQrScan: Boolean = false,
    val imageQrScan: Boolean = false,
    val googleOauth: Boolean = false,
    val connectionCreation: Boolean = false,
    val vaultMigrations: Boolean = false,
    val dataFolder: Boolean = false,
    val loginItems: Boolean = false,
    val windowTrafficLights: Boolean = false,
    val mobileVaultLifecycle: Boolean = false,
) {
    val anyQrScan: Boolean get() = screenQrScan || cameraQrScan || imageQrScan

    companion object {
        val androidPhone = AppCapabilities(
            developerTemplateEditing = true,
            cameraQrScan = true,
            imageQrScan = true,
            mobileVaultLifecycle = true,
        )
    }
}

data class AppUiState(
    val phase: AppPhase = AppPhase.CHECKING,
    val section: AppSection = AppSection.VAULT,
    val status: VaultStatus? = null,
    val phaseMessage: UserMessage? = null,
    val banner: UserMessage? = null,
    val unlockMessage: UserMessage? = null,
    val serviceVersion: String? = null,
    val vaultProfiles: List<LocalVaultProfile> = emptyList(),
    /** The open vault's file — identifies it even before a profile exists. */
    val activeVaultPath: String? = null,
    val passwordGeneratorSettings: PasswordGeneratorSettings = PasswordGeneratorSettings(),
    val busy: Set<String> = emptySet(),
    val sectionLoadTick: Int = 0,
) {
    val isReady: Boolean get() = phase == AppPhase.READY
    val activeVaultProfile: LocalVaultProfile? get() = vaultProfiles.firstOrNull { it.active }

    fun isBusy(key: String): Boolean = key in busy
}

/** How long the app may sit in the foreground untouched before locking. */
private const val IDLE_TIMEOUT_MS = 3 * 60 * 1000L

/**
 * Top-level app state — the port of `AppController` for the Android build.
 *
 * Owned by [ai.leasegate.mobile.KeyleaseApplication] so it survives activity
 * recreation; security decisions still belong to the Rust core — this class
 * only decides what the user is told and shown.
 */
class AppController(
    private val session: VaultSession,
    private val storage: VaultStorage,
    private val preferences: ai.leasegate.mobile.core.PreferencesStore,
    private val clipboard: SecureClipboard,
    val capabilities: AppCapabilities = AppCapabilities.androidPhone,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    private val _state = MutableStateFlow(AppUiState())
    val state: StateFlow<AppUiState> = _state.asStateFlow()

    val client: KeyLeaseClient = KeyLeaseClient(session, onUnlocked = storage::recordUnlocked)

    val vault = VaultController(scope, clientOf = { client })
    val connections = ConnectionsController(scope) { client }
    val approvals = ApprovalsController(scope) { client }
    val activity = ActivityController(scope) { client }

    /** Bound by MainActivity — biometric prompts need a FragmentActivity. */
    var biometric: BiometricVault? = null

    /**
     * Bound by MainActivity — SAF picker that copies the chosen document into
     * app-private `imports/` and returns its path, or null on cancel.
     */
    var chooseVaultSource: (suspend () -> String?)? = null

    /** Bound by MainActivity — opens a URL in the user's browser. */
    var openExternalUrl: (suspend (String) -> Boolean)? = null

    /** QR scanners — camera rides the Compose overlay; image is SAF+ML Kit. */
    val qrScan = QrScanCoordinator()
    var scanTotpFromCamera: (suspend () -> String?)? = qrScan::scan
    var scanTotpFromImage: (suspend () -> String?)? = null

    private var started = false
    private var createFirstItemRequested = false
    private var prefsSnapshot: MutableMap<String, Any?> = mutableMapOf()
    private var idleJob: Job? = null

    // --- startup ---------------------------------------------------------

    /** Loads saved, non-secret preferences and probes the vault state. */
    fun start() {
        if (started) return
        started = true
        scope.launch {
            val stored = preferences.load()
            prefsSnapshot = LinkedHashMap(stored)
            _state.update {
                it.copy(
                    passwordGeneratorSettings = PasswordGeneratorSettings.fromJson(
                        stored["password_generator"],
                    ),
                )
            }
            try {
                storage.initialize()
                syncVaultProfiles()
                _state.update {
                    it.copy(serviceVersion = storage.serviceVersion())
                }
                if (!storage.vaultExists()) {
                    enter(AppPhase.ONBOARDING, null)
                    return@launch
                }
            } catch (caught: Throwable) {
                enter(AppPhase.SERVICE_UNAVAILABLE, UserMessage.from(caught))
                return@launch
            }
            refresh()
        }
    }

    private suspend fun persistPreferences() {
        prefsSnapshot["password_generator"] = _state.value.passwordGeneratorSettings.toJson()
        preferences.save(prefsSnapshot)
    }

    // --- preferences -----------------------------------------------------

    fun updatePasswordGeneratorSettings(value: PasswordGeneratorSettings) {
        _state.update { it.copy(passwordGeneratorSettings = value) }
        scope.launch { persistPreferences() }
    }

    // --- navigation ------------------------------------------------------

    fun selectSection(value: AppSection) {
        if (_state.value.section == value) return
        _state.update { it.copy(section = value) }
        scope.launch { loadSection() }
    }

    fun dismissBanner() {
        _state.update { it.copy(banner = null) }
    }

    fun clearUnlockMessage() {
        _state.update { it.copy(unlockMessage = null) }
    }

    // --- phase machine -----------------------------------------------------

    /** Recomputes [AppUiState.phase] from the core, keeping failures distinct. */
    suspend fun refresh() = track("app.refresh", onError = { caught ->
        enter(AppPhase.SERVICE_UNAVAILABLE, UserMessage.from(caught))
    }) {
        val raw = try {
            client.unauthenticated(mapOf("command" to "status"))
        } catch (caught: Throwable) {
            if (caught is CancellationException) throw caught
            val code = (caught as? KeyLeaseException)?.code
            enter(
                if (code == KeyLeaseErrorCode.CLIENT) {
                    AppPhase.REPAIR_REQUIRED
                } else {
                    AppPhase.SERVICE_UNAVAILABLE
                },
                UserMessage.from(caught),
            )
            return@track
        }
        @Suppress("UNCHECKED_CAST")
        val status = VaultStatus.fromJson((raw as? JsonMap) ?: emptyMap())
        _state.update { it.copy(status = status) }
        if (status.locked) {
            clearSessionData()
            enter(
                AppPhase.LOCKED,
                UserMessage(
                    title = "Welcome back",
                    detail = "Unlock your vault to access your items.",
                    actionLabel = "Unlock vault",
                ),
            )
            return@track
        }

        // Unlocked is not the same as allowed: probe one authorized read so a
        // policy denial is reported as a denial and not as a locked vault.
        try {
            client.authorized(mapOf("command" to "groups_list"))
        } catch (caught: Throwable) {
            if (caught is CancellationException) throw caught
            val code = (caught as? KeyLeaseException)?.code
            enter(
                when (code) {
                    KeyLeaseErrorCode.DENIED -> AppPhase.PERMISSION_DENIED
                    KeyLeaseErrorCode.VAULT_LOCKED -> AppPhase.LOCKED
                    KeyLeaseErrorCode.TRANSPORT -> AppPhase.SERVICE_UNAVAILABLE
                    KeyLeaseErrorCode.CLIENT -> AppPhase.REPAIR_REQUIRED
                    else -> AppPhase.SERVICE_UNAVAILABLE
                },
                UserMessage.from(caught),
            )
            return@track
        }

        enter(AppPhase.READY, null)
        vault.loadMigrations()
        loadSection()
    }

    private suspend fun loadSection() {
        if (!_state.value.isReady) return
        when (_state.value.section) {
            AppSection.VAULT -> vault.load()
            AppSection.APPROVALS -> approvals.load()
            AppSection.SETTINGS -> {
                connections.load()
                activity.load()
            }
        }
        _state.update { it.copy(sectionLoadTick = it.sectionLoadTick + 1) }
    }

    private fun enter(next: AppPhase, message: UserMessage?) {
        _state.update { it.copy(phase = next, phaseMessage = message) }
    }

    private fun clearSessionData() {
        vault.clear()
        connections.clear()
        approvals.clear()
        activity.clear()
    }

    // --- provisioning ----------------------------------------------------

    suspend fun inspectSource(path: String): JsonMap =
        storage.provision(mapOf("provision" to "inspect_source", "source_path" to path))

    /**
     * Runs a mode-shaped provisioning request (`create`,
     * `restore_keylease_backup`, `import_kdbx`), then unlocks with the same
     * password when the request carried one.
     */
    suspend fun provision(request: JsonMap): Boolean = withContext(NonCancellable) {
        var completed = false
        createFirstItemRequested = request["mode"] == "create"
        enter(AppPhase.PROVISIONING, null)
        track("app.provision", onError = { caught ->
            createFirstItemRequested = false
            _state.update { it.copy(banner = UserMessage.from(caught)) }
            enter(AppPhase.ONBOARDING, null)
        }) {
            storage.provision(storage.mobileProvisionRequest(request))
            completed = true
        }
        if (completed) {
            (request["password"] as? String)?.let { password ->
                unlock(password, enableBiometric = request["enable_biometric"] == true)
            }
        }
        completed
    }

    fun consumeCreateFirstItemRequest(): Boolean {
        if (!createFirstItemRequested || !_state.value.isReady) return false
        createFirstItemRequested = false
        return true
    }

    // --- unlock / lock -----------------------------------------------------

    suspend fun unlock(password: String, enableBiometric: Boolean = false): Boolean =
        withContext(NonCancellable) {
            var unlocked = false
            _state.update { it.copy(unlockMessage = null) }
            track("app.unlock", onError = { caught ->
                _state.update { it.copy(unlockMessage = UserMessage.fromUnlock(caught)) }
            }) {
                client.unlock(password)
                unlocked = true
            }
            if (unlocked) {
                _state.update { it.copy(unlockMessage = null) }
                syncVaultProfiles()
                if (enableBiometric) {
                    val vaultId = _state.value.activeVaultProfile?.vaultId
                    val adapter = biometric
                    if (vaultId != null && adapter != null) {
                        try {
                            adapter.enable(vaultId, password)
                        } catch (caught: Throwable) {
                            _state.update { it.copy(banner = UserMessage.from(caught)) }
                        }
                    }
                }
                refresh()
                restartIdleTimer()
            }
            unlocked
        }

    suspend fun canUnlockWithBiometrics(): Boolean {
        val vaultId = _state.value.activeVaultProfile?.vaultId ?: return false
        val adapter = biometric ?: return false
        if (!adapter.isAvailable()) return false
        return adapter.hasCredential(vaultId)
    }

    suspend fun unlockWithBiometrics(): Boolean {
        val vaultId = _state.value.activeVaultProfile?.vaultId ?: return false
        val adapter = biometric ?: return false
        return try {
            val password = adapter.unlock(vaultId)
            if (password.isNullOrEmpty()) false else unlock(password)
        } catch (caught: Throwable) {
            if (caught is CancellationException) throw caught
            _state.update { it.copy(unlockMessage = UserMessage.from(caught)) }
            false
        }
    }

    suspend fun lock() = withContext(NonCancellable) {
        track("app.lock", onError = { caught ->
            _state.update { it.copy(banner = UserMessage.from(caught)) }
        }) {
            clipboard.clearIfUnchanged()
            try {
                client.authorized(mapOf("command" to "lock"))
            } finally {
                clearSessionData()
            }
            refresh()
        }
    }

    // --- vault profiles ----------------------------------------------------

    suspend fun reloadVaultProfiles() = syncVaultProfiles()

    private suspend fun syncVaultProfiles() {
        _state.update {
            it.copy(
                vaultProfiles = storage.listVaults(),
                activeVaultPath = storage.activePath,
            )
        }
    }

    suspend fun createManagedVault(name: String, request: JsonMap) = withContext(NonCancellable) {
        if (_state.value.isReady) lock()
        clearSessionData()
        storage.createVault(name, storage.mobileProvisionRequest(request))
        reloadVaultProfiles()
        _state.update { it.copy(status = null) }
        refresh()
    }

    suspend fun renameManagedVault(id: String, name: String) = withContext(NonCancellable) {
        storage.renameVault(id, name)
        reloadVaultProfiles()
    }

    suspend fun switchManagedVault(id: String) = withContext(NonCancellable) {
        val previous = _state.value.activeVaultProfile
        if (previous?.id == id) return@withContext
        if (_state.value.isReady) lock()
        clearSessionData()
        try {
            storage.switchVault(id)
            reloadVaultProfiles()
            refresh()
        } catch (caught: Throwable) {
            if (previous != null) {
                storage.switchVault(previous.id)
                reloadVaultProfiles()
            }
            throw caught
        }
    }

    // --- clipboard ---------------------------------------------------------

    /** Copies a secret through the conditional-clear clipboard. */
    fun copySensitive(value: String, clearAfterSeconds: Int = 30): Boolean =
        try {
            clipboard.copySensitive(value, clearAfterSeconds)
            _state.update { it.copy(banner = null) }
            true
        } catch (caught: Throwable) {
            _state.update { it.copy(banner = UserMessage.from(caught)) }
            false
        }

    fun copyAgentPrompt(entry: EntrySummary): Boolean =
        copySensitive(agentPromptForEntry(entry), clearAfterSeconds = 120)

    fun copyCliCommand(entry: EntrySummary): Boolean =
        copySensitive(cliCommandForEntry(entry), clearAfterSeconds = 120)

    // --- lifecycle / idle lock ---------------------------------------------

    /**
     * Process-level foreground/background, driven by ProcessLifecycleOwner.
     * `paused`/`hidden`/`detached` in the Flutter observer map to ON_STOP:
     * `inactive` (transient system dialogs) is deliberately excluded, and
     * FLAG_SECURE already blanks the recents thumbnail.
     */
    fun onProcessLifecycle(foregrounded: Boolean) {
        if (!foregrounded) {
            vault.hideSecrets()
            idleJob?.cancel()
            onLockRequested()
            return
        }
        restartIdleTimer()
    }

    /** Call on any user interaction to defer the idle lock. */
    fun noteActivity() {
        if (_state.value.isReady) restartIdleTimer()
    }

    private fun restartIdleTimer() {
        idleJob?.cancel()
        idleJob = scope.launch {
            delay(IDLE_TIMEOUT_MS)
            onLockRequested()
        }
    }

    private fun onLockRequested() {
        // Sensitive material leaves the screen before the round-trip starts.
        vault.hideSecrets()
        // Reaching the Rust side drops the in-process session keys, not just
        // the UI's view of them.
        scope.launch {
            try {
                session.lock()
            } catch (_: Exception) {
            }
        }
        if (!_state.value.isReady || _state.value.isBusy("app.lock")) return
        scope.launch { lock() }
    }

    private suspend fun <T> track(
        key: String,
        onError: (suspend (Throwable) -> Unit)? = null,
        operation: suspend () -> T,
    ): T? {
        if (key in _state.value.busy) return null
        _state.update { it.copy(busy = it.busy + key) }
        try {
            return operation()
        } catch (caught: Throwable) {
            if (caught is CancellationException) throw caught
            if (onError == null) throw caught
            onError(caught)
            return null
        } finally {
            _state.update { it.copy(busy = it.busy - key) }
        }
    }

    companion object {
        const val refreshKey = "app.refresh"
        const val unlockKey = "app.unlock"
        const val lockKey = "app.lock"

        private fun isAgentContent(entry: EntrySummary) =
            entry.kind in setOf("core.prompt", "core.runbook", "core.note")

        fun agentPromptForEntry(entry: EntrySummary): String {
            val readInstructions = if (isAgentContent(entry)) {
                "Read its content: `keylease content get ${entry.id} --raw`\n" +
                    "If access is denied, ask me to grant this agent read access."
            } else {
                "Inspect it: `keylease entries get ${entry.id}`\n" +
                    "List its fields: `keylease entries view ${entry.id}`\n" +
                    "Reveal only a needed field: `keylease entries reveal ${entry.id} --field <field-id>`\n" +
                    "Get its OTP if needed: `keylease entries totp ${entry.id}`"
            }
            return "Use KeyLease Vault item ${JSONObject.quote(entry.title)} (`${entry.id}`) for this task.\n\n" +
                "Connect to KeyLease directly; do not ask me to paste the item content.\n" +
                "$readInstructions\n\n" +
                "Keep returned content and secrets private. If the vault is locked, ask me to unlock KeyLease."
        }

        fun cliCommandForEntry(entry: EntrySummary): String =
            if (isAgentContent(entry)) {
                "keylease content get ${entry.id} --raw"
            } else {
                "keylease entries get ${entry.id}"
            }
    }
}
