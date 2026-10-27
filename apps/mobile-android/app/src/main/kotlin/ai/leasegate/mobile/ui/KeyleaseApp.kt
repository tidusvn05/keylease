package ai.leasegate.mobile.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import ai.leasegate.mobile.core.UserMessage
import ai.leasegate.mobile.state.AppController
import ai.leasegate.mobile.state.AppPhase
import ai.leasegate.mobile.state.AppSection
import ai.leasegate.mobile.state.EntryWorkspaceMode
import ai.leasegate.mobile.ui.screens.ApprovalsScreen
import ai.leasegate.mobile.ui.screens.SettingsScreen
import ai.leasegate.mobile.ui.screens.VaultScreen
import kotlinx.coroutines.launch

/**
 * The KeyLease client — single-activity Compose shell.
 *
 * Phone form factor only (compact navigation + list → detail routing): this
 * build targets handsets. Section state, the RPC contract and the security semantics are
 * identical.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyleaseApp(app: AppController) {
    val appState by app.state.collectAsStateWithLifecycle()
    val vaultState by app.vault.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()

    // A freshly created vault drops straight into "add the first item".
    androidx.compose.runtime.LaunchedEffect(appState.phase) {
        if (app.consumeCreateFirstItemRequest()) {
            app.selectSection(AppSection.VAULT)
            app.vault.beginCreate()
        }
    }

    KeyleaseTheme {
        // A pending TOTP camera scan covers everything, including the shell.
        val qrPending by app.qrScan.pending.collectAsStateWithLifecycle()
        if (qrPending != null) {
            QrScanOverlay(onResult = app.qrScan::complete)
            return@KeyleaseTheme
        }
        // Android's back gesture walks back through sections before leaving
        // the app; Vault is the root, so back from there exits.
        BackHandler(enabled = appState.section != AppSection.VAULT) {
            app.selectSection(AppSection.VAULT)
        }
        Scaffold(
            topBar = {
                TopAppBar(
                    title = {
                        when {
                            appState.section != AppSection.VAULT -> Text(appState.section.label)
                            else -> Text(appState.activeVaultProfile?.name ?: "KeyLease")
                        }
                    },
                    actions = {
                        if (appState.section == AppSection.VAULT && appState.isReady) {
                            IconButton(onClick = { app.vault.openPasswordGenerator() }) {
                                Icon(
                                    Icons.Filled.AutoAwesome,
                                    contentDescription = "Password generator",
                                )
                            }
                            IconButton(onClick = { app.vault.beginCreate() }) {
                                Icon(Icons.Filled.Add, contentDescription = "New item")
                            }
                        }
                        IconButton(
                            onClick = { scope.launch { app.refresh() } },
                            enabled = !appState.isBusy(AppController.refreshKey),
                        ) {
                            Icon(Icons.Filled.Refresh, contentDescription = "Refresh")
                        }
                        if (appState.isReady) {
                            IconButton(
                                onClick = { scope.launch { app.lock() } },
                                enabled = !appState.isBusy(AppController.lockKey),
                            ) {
                                Icon(Icons.Filled.Lock, contentDescription = "Lock vault")
                            }
                        }
                    },
                )
            },
            bottomBar = {
                if (appState.isReady || appState.section == AppSection.SETTINGS) {
                    NavigationBar {
                        NavigationBarItem(
                            selected = appState.section == AppSection.VAULT,
                            onClick = { app.selectSection(AppSection.VAULT) },
                            icon = { Icon(Icons.Filled.Key, contentDescription = null) },
                            label = { Text("Vault") },
                        )
                        NavigationBarItem(
                            selected = appState.section == AppSection.APPROVALS,
                            onClick = { app.selectSection(AppSection.APPROVALS) },
                            icon = { Icon(Icons.Filled.Shield, contentDescription = null) },
                            label = { Text("Approvals") },
                        )
                        NavigationBarItem(
                            selected = appState.section == AppSection.SETTINGS,
                            onClick = { app.selectSection(AppSection.SETTINGS) },
                            icon = { Icon(Icons.Filled.Settings, contentDescription = null) },
                            label = { Text("Settings") },
                        )
                    }
                }
            },
        ) { padding ->
            Column(Modifier.fillMaxSize().padding(padding)) {
                if (appState.isReady &&
                    vaultState.migrationStatus?.pending?.isNotEmpty() == true
                ) {
                    MessageBanner(
                        message = UserMessage(
                            title = "Vault migration available",
                            detail = "${vaultState.migrationStatus!!.pending.first().proposals.size} legacy items can be safely reclassified.",
                            actionLabel = "Review migration",
                        ),
                        onAction = { /* migration center is policy-gated on mobile */ },
                    )
                }
                appState.banner?.let { banner ->
                    MessageBanner(
                        message = banner,
                        onDismiss = app::dismissBanner,
                        onAction = { scope.launch { app.refresh() } },
                    )
                }
                val gated = appState.section.requiresReady && !appState.isReady
                when {
                    gated -> PhaseScreen(app, appState.phase)
                    appState.section == AppSection.VAULT -> VaultScreen(app)
                    appState.section == AppSection.APPROVALS -> ApprovalsScreen(app)
                    appState.section == AppSection.SETTINGS -> SettingsScreen(app)
                }
            }
        }
    }
}
