package ai.leasegate.mobile.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Circle
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Monitor
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.SwapHoriz
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material.icons.filled.Build
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import ai.leasegate.mobile.core.LocalVaultProfile
import ai.leasegate.mobile.core.UserMessage
import ai.leasegate.mobile.state.AppController
import ai.leasegate.mobile.state.AppPhase
import ai.leasegate.mobile.state.AppSection
import kotlinx.coroutines.launch

/** The screen for the current [AppPhase]. Each phase keeps its own next step. */
@Composable
fun PhaseScreen(app: AppController, phase: AppPhase) {
    val appState by app.state.collectAsStateWithLifecycle()
    val details = appState.phaseMessage?.diagnostics
    when (phase) {
        AppPhase.CHECKING -> StateScreen(
            title = "Checking KeyLease",
            message = "Looking for the local service on this machine…",
            icon = Icons.Filled.Refresh,
        ) { CircularProgressIndicator() }
        AppPhase.ONBOARDING -> OnboardingScreen(app)
        AppPhase.PROVISIONING -> StateScreen(
            title = "Preparing your vault",
            message = "KeyLease is securely setting everything up on this device…",
            icon = Icons.Filled.Refresh,
        ) { CircularProgressIndicator() }
        AppPhase.REPAIR_REQUIRED -> StateScreen(
            title = "Repair KeyLease",
            message = "Your vault is here, but the connection needs repair.",
            icon = Icons.Filled.Build,
            details = details,
        ) {
            KeyleaseButton("Open Settings", onClick = { app.selectSection(AppSection.SETTINGS) })
        }
        AppPhase.BACKGROUND_APPROVAL_REQUIRED -> StateScreen(
            title = "Allow KeyLease in the background",
            message = "Approve the background item so the vault is ready when you open the app.",
            icon = Icons.Filled.Warning,
        ) {
            val scope = rememberCoroutineScope()
            KeyleaseButton("Try again", outline = true, onClick = { scope.launch { app.refresh() } })
        }
        AppPhase.SERVICE_UNAVAILABLE -> StateScreen(
            title = "Can't reach KeyLease",
            message = "Your vault has not been opened. Make sure the local service is allowed, then try again.",
            icon = Icons.Filled.Monitor,
            details = details,
        ) {
            val scope = rememberCoroutineScope()
            KeyleaseButton(
                "Try again",
                icon = Icons.Filled.Refresh,
                onClick = { scope.launch { app.refresh() } },
            )
        }
        AppPhase.PERMISSION_DENIED -> StateScreen(
            title = "Permission needed",
            message = "This device's access needs to be repaired before KeyLease can read vault items.",
            icon = Icons.Filled.Shield,
            footnote = "Your vault and its existing permissions are unchanged.",
            details = details,
        ) {
            KeyleaseButton("Repair in Settings", onClick = { app.selectSection(AppSection.SETTINGS) })
        }
        AppPhase.LOCKED -> UnlockScreen(app)
        AppPhase.READY -> Unit
    }
}

@Composable
private fun OnboardingScreen(app: AppController) {
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var sourcePassword by remember { mutableStateOf("") }
    var sourcePath by remember { mutableStateOf<String?>(null) }
    var sourceKind by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var differentPassword by remember { mutableStateOf(false) }
    var acknowledgePlaintext by remember { mutableStateOf(false) }
    var creating by remember { mutableStateOf(false) }
    var enableBiometric by remember { mutableStateOf(false) }
    var choosing by remember { mutableStateOf(false) }

    val mobile = app.capabilities.mobileVaultLifecycle
    val importing = sourcePath != null
    val configuring = importing || creating
    val needsSourcePassword = sourceKind == "kdbx"
    val needsTargetPassword = !needsSourcePassword || differentPassword

    fun choose() {
        if (choosing) return
        choosing = true
        scope.launch {
            try {
                val path = app.chooseVaultSource?.invoke()
                if (path != null) {
                    val inspected = app.inspectSource(path)
                    if (inspected["supported"] == false) {
                        error = inspected["reason"]?.toString() ?: "Unsupported vault source"
                    } else {
                        sourcePath = path
                        sourceKind = inspected["kind"] as? String
                        error = null
                    }
                }
            } catch (caught: Throwable) {
                error = "This file is not a supported encrypted KeyLease backup or KDBX vault."
            } finally {
                choosing = false
            }
        }
    }

    fun submit() {
        val targetPassword = if (sourceKind == "kdbx" && !differentPassword) {
            sourcePassword
        } else {
            password
        }
        if (targetPassword.isEmpty() ||
            (sourceKind != "kdbx" || differentPassword) && targetPassword != confirm
        ) {
            error = "Enter matching passwords to continue."
            return
        }
        if (sourceKind == "onepux" && !acknowledgePlaintext) {
            error = "Confirm that this export may contain plaintext secrets."
            return
        }
        val request = mutableMapOf<String, Any?>("password" to targetPassword)
        if (enableBiometric) request["enable_biometric"] = true
        when (sourceKind) {
            null -> request["mode"] = "create"
            "keylease_database" -> {
                request["mode"] = "adopt_keylease_database"
                request["source_path"] = sourcePath
            }
            "keylease_backup" -> {
                request["mode"] = "restore_keylease_backup"
                request["source_path"] = sourcePath
            }
            "kdbx" -> {
                request["mode"] = "import_kdbx"
                request["source_path"] = sourcePath
                request["source_password"] = sourcePassword
            }
            "onepux" -> {
                request["mode"] = "import_onepux"
                request["source_path"] = sourcePath
                request["acknowledge_plaintext"] = true
            }
        }
        scope.launch {
            app.provision(request)
            password = ""
            confirm = ""
            sourcePassword = ""
        }
    }

    StateScreen(
        title = if (importing) "Bring your vault to KeyLease" else "Welcome to KeyLease",
        message = if (importing) {
            "Your original file stays unchanged. KeyLease creates an encrypted managed copy on this device."
        } else if (mobile) {
            "Choose how you want to set up this phone. No vault is assumed yet."
        } else {
            "Create a new encrypted vault, or use one you already have."
        },
        icon = Icons.Filled.Key,
        footnote = if (mobile) {
            "Managed vaults stay in Android app-private storage."
        } else {
            "KeyLease stores its managed files privately."
        },
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            if (error != null) {
                Text(error!!, color = MaterialTheme.colorScheme.error)
                Spacer(Modifier.height(10.dp))
            }
            if (!configuring) {
                if (mobile) {
                    KeyleaseButton(
                        "Pair with nearby desktop — coming soon",
                        enabled = false,
                        icon = Icons.Filled.Wifi,
                        onClick = {},
                    )
                    Spacer(Modifier.height(10.dp))
                }
                KeyleaseButton("Create a new vault", onClick = { creating = true })
                Spacer(Modifier.height(10.dp))
                KeyleaseButton(
                    if (mobile) "Import KeyLease backup or KDBX" else "Use an existing vault",
                    outline = true,
                    enabled = !choosing,
                    onClick = ::choose,
                )
            } else {
                if (sourcePath != null) {
                    Text(sourcePath!!, maxLines = 2, style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(10.dp))
                }
                KeyleaseButton(
                    "Choose another file",
                    outline = true,
                    enabled = !choosing,
                    onClick = {
                        sourcePath = null
                        sourceKind = null
                        creating = false
                        choose()
                    },
                )
            }
            if (configuring) Spacer(Modifier.height(18.dp))
            if (needsSourcePassword) {
                OutlinedTextField(
                    value = sourcePassword,
                    onValueChange = { sourcePassword = it },
                    label = { Text("Existing vault password") },
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(10.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = differentPassword, onCheckedChange = { differentPassword = it })
                    Text("Use a different password in KeyLease")
                }
            }
            if (configuring && needsTargetPassword) {
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text(if (importing) "KeyLease password" else "Master password") },
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                )
                if (mobile) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = enableBiometric, onCheckedChange = { enableBiometric = it })
                        Text("Enable biometric unlock after verifying this password")
                    }
                }
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(
                    value = confirm,
                    onValueChange = { confirm = it },
                    label = { Text("Confirm password") },
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            if (sourceKind == "onepux") {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(
                        checked = acknowledgePlaintext,
                        onCheckedChange = { acknowledgePlaintext = it },
                    )
                    Text("I understand this export may contain plaintext secrets")
                }
            }
            if (configuring) {
                Spacer(Modifier.height(18.dp))
                KeyleaseButton(
                    if (importing) "Import and continue" else "Create vault",
                    onClick = ::submit,
                )
                if (creating) {
                    Spacer(Modifier.height(10.dp))
                    KeyleaseButton("Back", outline = true, onClick = { creating = false })
                }
            }
        }
    }
}

/**
 * The unlock form. The password never leaves this composition except as the
 * argument of `unlock`, and the field is cleared straight after submit.
 */
@Composable
private fun UnlockScreen(app: AppController) {
    val appState by app.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var biometricUnlock by remember { mutableStateOf(false) }
    var enableBiometric by remember { mutableStateOf(false) }
    var switching by remember { mutableStateOf(false) }
    var failure by remember { mutableStateOf<UserMessage?>(null) }

    LaunchedEffect(Unit) {
        biometricUnlock = app.canUnlockWithBiometrics()
        if (biometricUnlock) app.unlockWithBiometrics()
    }

    val busy = appState.isBusy(AppController.unlockKey)
    val activeVault = appState.activeVaultProfile
    // A vault that predates the profile registry has no entry yet — fall back
    // to what the open database itself can report.
    val vaultId = activeVault?.vaultId ?: appState.status?.vaultId
    val shortIdentity = vaultId?.let { if (it.length > 12) it.substring(0, 12) else it }
    val vaultPath = activeVault?.path ?: appState.activeVaultPath

    fun submit() {
        if (password.isEmpty()) return
        val value = password
        password = ""
        scope.launch { app.unlock(value, enableBiometric = enableBiometric) }
    }

    StateScreen(
        title = "Welcome back",
        message = "Unlock your vault to access your items.",
        icon = Icons.Filled.Lock,
        footnote = "The vault locks itself when the app is backgrounded or the screen locks.",
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            // Which vault this password opens — a name alone is ambiguous once
            // the device holds more than one.
            Text(
                activeVault?.name ?: "Vault on this device",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                textAlign = TextAlign.Center,
            )
            if (vaultPath != null) {
                SelectionContainer {
                    Text(
                        vaultPath,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                        maxLines = 2,
                    )
                }
            }
            if (shortIdentity != null) {
                Text(
                    "ID $shortIdentity",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            failure?.let {
                Spacer(Modifier.height(10.dp))
                Text(it.detail, color = MaterialTheme.colorScheme.error)
            }
            Spacer(Modifier.height(14.dp))
            OutlinedTextField(
                value = password,
                onValueChange = {
                    password = it
                    if (it.isNotEmpty()) app.clearUnlockMessage()
                },
                label = { Text("Master password") },
                supportingText = appState.unlockMessage?.let { message ->
                    {
                        Text(
                            if (message.title == "Incorrect master password") {
                                "Incorrect master password. Try again."
                            } else {
                                message.detail
                            },
                        )
                    }
                },
                isError = appState.unlockMessage != null,
                visualTransformation = PasswordVisualTransformation(),
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(10.dp))
            KeyleaseButton(
                if (busy) "Unlocking…" else "Unlock vault",
                icon = Icons.Filled.LockOpen,
                enabled = !busy,
                onClick = ::submit,
                modifier = Modifier.fillMaxWidth(),
            )
            if (app.capabilities.mobileVaultLifecycle && !biometricUnlock) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(
                        checked = enableBiometric,
                        onCheckedChange = { enableBiometric = it },
                        enabled = !busy,
                    )
                    Text("Enable biometric unlock on this device")
                }
            }
            if (biometricUnlock) {
                Spacer(Modifier.height(10.dp))
                KeyleaseButton(
                    "Unlock with biometrics",
                    outline = true,
                    icon = Icons.Filled.Fingerprint,
                    enabled = !busy,
                    onClick = { scope.launch { app.unlockWithBiometrics() } },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            if (app.capabilities.mobileVaultLifecycle) {
                Spacer(Modifier.height(14.dp))
                if (appState.vaultProfiles.size > 1) {
                    KeyleaseButton(
                        "Switch vault",
                        outline = true,
                        icon = Icons.Filled.SwapHoriz,
                        enabled = !busy,
                        onClick = { switching = true },
                    )
                }
                // The vault list — switch, rename, import, create — lives in
                // Settings, which stays reachable while the vault is locked.
                TextButton(
                    onClick = { app.selectSection(AppSection.SETTINGS) },
                    enabled = !busy,
                ) { Text("Manage vaults") }
            }
        }
    }

    if (switching) {
        SwitchVaultDialog(
            profiles = appState.vaultProfiles,
            onSwitch = { profile ->
                scope.launch {
                    try {
                        app.switchManagedVault(profile.id)
                    } catch (caught: Throwable) {
                        failure = UserMessage.from(caught)
                    }
                    switching = false
                }
            },
            onDismiss = { switching = false },
        )
    }
}

@Composable
private fun SwitchVaultDialog(
    profiles: List<LocalVaultProfile>,
    onSwitch: (LocalVaultProfile) -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Switch vault") },
        text = {
            Column {
                Text(
                    "Each vault has its own master password.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(8.dp))
                for (profile in profiles) {
                    ListItem(
                        modifier = Modifier.clickable(enabled = !profile.active) {
                            onSwitch(profile)
                        },
                        leadingContent = {
                            Icon(
                                if (profile.active) {
                                    Icons.Filled.CheckCircle
                                } else {
                                    Icons.Filled.Circle
                                },
                                contentDescription = null,
                                tint = if (profile.active) {
                                    LocalKeyleaseColors.current.success
                                } else {
                                    MaterialTheme.colorScheme.onSurfaceVariant
                                },
                            )
                        },
                        headlineContent = { Text(profile.name) },
                        supportingContent = {
                            Text(
                                listOfNotNull(
                                    profile.path,
                                    profile.vaultId?.let { "ID ${it.take(12)}" },
                                ).joinToString("\n"),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        },
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}
