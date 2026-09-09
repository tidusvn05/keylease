import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';

import '../models/models.dart';
import '../platform/local_runtime_adapter.dart';
import '../platform/preferences_store.dart';
import '../platform/security_adapter.dart';
import '../../ui/tokens/keylease_tokens.dart';
import '../rpc/keylease_rpc.dart';
import 'app_phase.dart';
import 'busy_registry.dart';
import 'connection_settings.dart';
import 'password_generator_settings.dart';
import 'section_controllers.dart';
import 'user_message.dart';
import 'vault_controller.dart';

typedef ClientFactory = KeyLeaseClient Function(ConnectionSettings settings);

KeyLeaseClient _socketClient(ConnectionSettings settings) =>
    SocketKeyLeaseClient(
      KeyLeaseRpc(settings.socketPath, settings.agentId, settings.tokenPath),
    );

/// Owns the session: which phase the app is in, the current section and the
/// feature controllers. All security decisions still belong to the daemon;
/// this class only decides what the user is told and shown.
class AppController extends ChangeNotifier with BusyRegistry {
  AppController({
    required this.adapter,
    required this.preferences,
    required this.runtime,
    this.clientFactory = _socketClient,
  }) {
    vault = VaultController(clientOf: () => client);
    connections = ConnectionsController(() => client);
    approvals = ApprovalsController(() => client);
    activity = ActivityController(() => client);
    _lockSubscription = adapter.lockRequests.listen(_onLockRequested);
    _vaultChangeSubscription = runtime.vaultChanges.listen(
      (_) => unawaited(_onExternalVaultChange()),
    );
  }

  static const refreshKey = 'app.refresh';
  static const unlockKey = 'app.unlock';
  static const lockKey = 'app.lock';

  static bool _isAgentContent(EntrySummary entry) =>
      const {'core.prompt', 'core.runbook', 'core.note'}.contains(entry.kind);

  static String agentPromptForEntry(EntrySummary entry) {
    final readInstructions = _isAgentContent(entry)
        ? '''Read its content: `keylease content get ${entry.id} --raw`
If access is denied, ask me to grant this agent read access.'''
        : '''Inspect it: `keylease entries get ${entry.id}`
List its fields: `keylease entries view ${entry.id}`
Reveal only a needed field: `keylease entries reveal ${entry.id} --field <field-id>`
Get its OTP if needed: `keylease entries totp ${entry.id}`''';
    return '''Use KeyLease Vault item ${jsonEncode(entry.title)} (`${entry.id}`) for this task.

Connect to KeyLease directly; do not ask me to paste the item content.
$readInstructions

Keep returned content and secrets private. If the vault is locked, ask me to unlock KeyLease.''';
  }

  static String cliCommandForEntry(EntrySummary entry) => _isAgentContent(entry)
      ? 'keylease content get ${entry.id} --raw'
      : 'keylease entries get ${entry.id}';

  final SecurityAdapter adapter;
  final PreferencesStore preferences;
  final LocalRuntimeAdapter runtime;
  final ClientFactory clientFactory;
  StreamSubscription<LockTrigger>? _lockSubscription;
  StreamSubscription<void>? _vaultChangeSubscription;
  bool _handlingExternalVaultChange = false;

  ConnectionSettings settings = ConnectionSettings.defaults();
  AppPhase phase = AppPhase.checking;
  AppSection section = AppSection.vault;
  VaultStatus? status;
  UserMessage? phaseMessage;
  UserMessage? banner;
  double sidebarWidth = KeyLeaseLayout.sidebarWidth;
  double listWidth = KeyLeaseLayout.listWidth;
  bool legacyAvailable = false;
  String? legacyDatabase;
  String? serviceVersion;
  List<LocalVaultProfile> vaultProfiles = const [];
  bool _createFirstItemRequested = false;
  PasswordGeneratorSettings passwordGeneratorSettings =
      const PasswordGeneratorSettings();
  Map<String, String> _sshKeyBindings = const {};

  late final VaultController vault;
  late final ConnectionsController connections;
  late final ApprovalsController approvals;
  late final ActivityController activity;

  KeyLeaseClient get client => clientFactory(settings);

  bool get isReady => phase == AppPhase.ready;

  /// Loads saved, non-secret preferences and probes the local service.
  Future<void> start() async {
    final stored = await preferences.load();
    settings = ConnectionSettings.defaults();
    sidebarWidth =
        (stored['sidebar_width'] as num?)?.toDouble() ??
        KeyLeaseLayout.sidebarWidth;
    listWidth =
        (stored['list_width'] as num?)?.toDouble() ?? KeyLeaseLayout.listWidth;
    passwordGeneratorSettings = PasswordGeneratorSettings.fromJson(
      stored['password_generator'],
    );
    final storedBindings = stored['ssh_key_bindings'];
    _sshKeyBindings = storedBindings is Map
        ? {
            for (final entry in storedBindings.entries)
              if (entry.value is String) '${entry.key}': entry.value as String,
          }
        : const {};
    notifyListeners();
    try {
      final inspection = await runtime.inspect();
      if (inspection.tokenPath != null) {
        settings = settings.copyWith(tokenPath: inspection.tokenPath);
      }
      vaultProfiles = await runtime.listVaults();
      legacyAvailable = inspection.legacyAvailable;
      legacyDatabase = inspection.legacyDatabase;
      serviceVersion = inspection.serviceVersion;
      switch (inspection.state) {
        case LocalRuntimeState.needsOnboarding:
          _enter(AppPhase.onboarding, null);
          return;
        case LocalRuntimeState.repairRequired:
          _enter(AppPhase.repairRequired, null);
          return;
        case LocalRuntimeState.ready:
          await runtime.ensureService();
          await _waitForService();
      }
    } catch (caught) {
      _enter(
        caught is BackgroundApprovalRequired
            ? AppPhase.backgroundApprovalRequired
            : AppPhase.serviceUnavailable,
        UserMessage.from(caught),
      );
      return;
    }
    await refresh();
  }

  Future<void> persistPreferences() => preferences.save({
    'sidebar_width': sidebarWidth,
    'list_width': listWidth,
    'password_generator': passwordGeneratorSettings.toJson(),
    'ssh_key_bindings': _sshKeyBindings,
  });

  String _sshBindingKey(String itemId, String endpointId) =>
      '${status?.vaultId ?? 'unknown'}/$itemId/$endpointId';

  String? sshKeyBinding(String itemId, String endpointId) =>
      _sshKeyBindings[_sshBindingKey(itemId, endpointId)];

  Future<void> setSshKeyBinding(
    String itemId,
    String endpointId,
    String? path,
  ) async {
    final previous = _sshKeyBindings;
    final next = {..._sshKeyBindings};
    final key = _sshBindingKey(itemId, endpointId);
    if (path == null || path.isEmpty) {
      next.remove(key);
    } else {
      next[key] = path;
    }
    _sshKeyBindings = next;
    notifyListeners();
    await persistPreferences();
    final stored = await preferences.load();
    final bindings = stored['ssh_key_bindings'];
    final persisted = bindings is Map ? bindings[key]?.toString() : null;
    if (persisted != (path == null || path.isEmpty ? null : path)) {
      _sshKeyBindings = previous;
      notifyListeners();
      throw StateError(
        'The SSH private key binding could not be saved on this device.',
      );
    }
  }

  Future<void> removeSshBindingsForItem(String itemId) async {
    final marker = '/$itemId/';
    final next = {
      for (final entry in _sshKeyBindings.entries)
        if (!entry.key.contains(marker)) entry.key: entry.value,
    };
    if (next.length == _sshKeyBindings.length) return;
    _sshKeyBindings = next;
    await persistPreferences();
  }

  Future<void> updatePasswordGeneratorSettings(
    PasswordGeneratorSettings value,
  ) async {
    passwordGeneratorSettings = value;
    notifyListeners();
    await persistPreferences();
  }

  void setPaneWidths({double? sidebar, double? list}) {
    sidebarWidth = sidebar ?? sidebarWidth;
    listWidth = list ?? listWidth;
    notifyListeners();
    unawaited(persistPreferences());
  }

  void selectSection(AppSection value) {
    if (section == value) return;
    section = value;
    notifyListeners();
    unawaited(loadSection());
  }

  void dismissBanner() {
    if (banner == null) return;
    banner = null;
    notifyListeners();
  }

  /// Recomputes [phase] from the daemon, keeping each failure distinguishable.
  Future<void> refresh() async {
    await track(
      refreshKey,
      () async {
        final Map<String, dynamic> raw;
        try {
          raw = Map<String, dynamic>.from(
            await client.unauthenticated({'command': 'status'}) as Map,
          );
        } on KeyLeaseException catch (caught) {
          _enter(
            caught.code == KeyLeaseErrorCode.client
                ? AppPhase.repairRequired
                : AppPhase.serviceUnavailable,
            UserMessage.from(caught),
          );
          return;
        }

        status = VaultStatus.fromJson(raw);
        if (status!.locked) {
          _clearSessionData();
          _enter(
            AppPhase.locked,
            const UserMessage(
              title: 'Welcome back',
              detail: 'Unlock your vault to access your items.',
              actionLabel: 'Unlock vault',
            ),
          );
          return;
        }

        // Unlocked is not the same as allowed: probe one authorized read so a
        // policy denial is reported as a denial and not as a locked vault.
        try {
          await client.authorized({'command': 'groups_list'});
        } on KeyLeaseException catch (caught) {
          _enter(switch (caught.code) {
            KeyLeaseErrorCode.denied => AppPhase.permissionDenied,
            KeyLeaseErrorCode.vaultLocked => AppPhase.locked,
            KeyLeaseErrorCode.transport => AppPhase.serviceUnavailable,
            KeyLeaseErrorCode.client => AppPhase.repairRequired,
            _ => AppPhase.serviceUnavailable,
          }, UserMessage.from(caught));
          return;
        }

        _enter(AppPhase.ready, null);
        await vault.loadMigrations();
        await loadSection();
      },
      onError: (caught) {
        _enter(AppPhase.serviceUnavailable, UserMessage.from(caught));
      },
    );
  }

  Future<String?> chooseVaultSource() => runtime.chooseVaultSource();

  Future<Map<String, dynamic>> inspectSource(String path) =>
      runtime.inspectSource(path);

  Future<bool> provision(Map<String, dynamic> request) async {
    var completed = false;
    _createFirstItemRequested = request['mode'] == 'create';
    _enter(AppPhase.provisioning, null);
    await track(
      'app.provision',
      () async {
        await runtime.provision(request);
        await runtime.ensureService();
        await _waitForService();
        completed = true;
      },
      onError: (caught) {
        _createFirstItemRequested = false;
        banner = UserMessage.from(caught);
        _enter(
          caught is BackgroundApprovalRequired
              ? AppPhase.backgroundApprovalRequired
              : AppPhase.onboarding,
          null,
        );
      },
    );
    if (completed) {
      final password = request['password'] as String?;
      if (password != null) await unlock(password);
    }
    return completed;
  }

  bool consumeCreateFirstItemRequest() {
    if (!_createFirstItemRequested || !isReady) return false;
    _createFirstItemRequested = false;
    return true;
  }

  Future<void> restartService() async {
    await runtime.restartService();
    await refresh();
  }

  Future<void> openLoginItemsSettings() => runtime.openLoginItemsSettings();

  Future<void> openDataFolder() => runtime.openDataFolder();

  /// Uses a dedicated settings window on desktop hosts that provide one, and
  /// retains the in-shell destination as the cross-platform fallback.
  Future<void> openSettings() async {
    if (await adapter.openSettingsWindow()) return;
    selectSection(AppSection.settings);
  }

  Future<void> reloadVaultProfiles() async {
    vaultProfiles = await runtime.listVaults();
    notifyListeners();
  }

  Future<void> createManagedVault(
    String name,
    Map<String, dynamic> request,
  ) async {
    await runtime.createVault(name, request);
    await reloadVaultProfiles();
  }

  Future<void> renameManagedVault(String id, String name) async {
    await runtime.renameVault(id, name);
    await reloadVaultProfiles();
  }

  Future<void> switchManagedVault(String id) async {
    final previous = vaultProfiles
        .where((profile) => profile.active)
        .firstOrNull;
    if (previous?.id == id) return;
    if (isReady) await lock();
    _clearSessionData();
    try {
      await runtime.switchVault(id);
      await runtime.restartService();
      final inspection = await runtime.inspect();
      settings = ConnectionSettings.defaults().copyWith(
        tokenPath: inspection.tokenPath,
      );
      vaultProfiles = await runtime.listVaults();
      await _waitForService();
      await refresh();
      await runtime.publishVaultChange();
    } catch (_) {
      if (previous != null) {
        await runtime.switchVault(previous.id);
        await runtime.restartService();
        final inspection = await runtime.inspect();
        settings = ConnectionSettings.defaults().copyWith(
          tokenPath: inspection.tokenPath,
        );
        vaultProfiles = await runtime.listVaults();
      }
      rethrow;
    }
  }

  Future<void> _onExternalVaultChange() async {
    if (_handlingExternalVaultChange) return;
    _handlingExternalVaultChange = true;
    vault.hideSecrets();
    _clearSessionData();
    status = null;
    _enter(AppPhase.checking, null);
    try {
      final inspection = await runtime.inspect();
      settings = ConnectionSettings.defaults().copyWith(
        tokenPath: inspection.tokenPath,
      );
      vaultProfiles = await runtime.listVaults();
      await _waitForService();
      while (isBusy(refreshKey)) {
        await Future<void>.delayed(const Duration(milliseconds: 20));
      }
      await refresh();
    } catch (caught) {
      _enter(AppPhase.serviceUnavailable, UserMessage.from(caught));
    } finally {
      _handlingExternalVaultChange = false;
    }
  }

  Future<void> _waitForService() async {
    Object? lastError;
    for (var attempt = 0; attempt < 30; attempt++) {
      try {
        await client.unauthenticated({'command': 'status'});
        return;
      } catch (caught) {
        lastError = caught;
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
    }
    throw lastError ?? StateError('KeyLease service did not start');
  }

  Future<void> loadSection() async {
    if (!isReady) return;
    switch (section) {
      case AppSection.vault:
        await vault.load();
      case AppSection.approvals:
        await approvals.load();
      case AppSection.settings:
        await Future.wait([connections.load(), activity.load()]);
    }
  }

  Future<bool> unlock(String password) async {
    var unlocked = false;
    await track(
      unlockKey,
      () async {
        await client.authorized({
          'command': 'unlock',
          'password': password,
          'session_ttl_seconds': 900,
        });
        unlocked = true;
      },
      onError: (caught) {
        banner = UserMessage.from(caught);
      },
    );
    if (unlocked) await refresh();
    return unlocked;
  }

  Future<void> lock() => track(
    lockKey,
    () async {
      await adapter.clearSensitiveClipboard();
      try {
        await client.authorized({'command': 'lock'});
      } finally {
        _clearSessionData();
      }
      await refresh();
    },
    onError: (caught) {
      banner = UserMessage.from(caught);
    },
  );

  Future<void> _onLockRequested(LockTrigger _) async {
    // Sensitive material leaves the screen before the round-trip starts.
    vault.hideSecrets();
    if (phase != AppPhase.ready) return;
    if (isBusy(lockKey)) return;
    await lock();
  }

  void _clearSessionData() {
    vault.clear();
    connections.clear();
    approvals.clear();
    activity.clear();
  }

  void _enter(AppPhase next, UserMessage? message) {
    phase = next;
    phaseMessage = message;
    notifyListeners();
  }

  /// Copies a secret through the native adapter so the conditional clipboard
  /// clear stays in force. The UI never writes secrets to the clipboard.
  Future<bool> copySensitive(
    String value, {
    Duration clearAfter = const Duration(seconds: 30),
  }) async {
    try {
      await adapter.copySensitive(value, clearAfter: clearAfter);
      banner = null;
      notifyListeners();
      return true;
    } catch (caught) {
      banner = UserMessage.from(caught);
      notifyListeners();
      return false;
    }
  }

  Future<bool> copyAgentPrompt(EntrySummary entry) => copySensitive(
    agentPromptForEntry(entry),
    clearAfter: const Duration(seconds: 120),
  );

  Future<bool> copyCliCommand(EntrySummary entry) => copySensitive(
    cliCommandForEntry(entry),
    clearAfter: const Duration(seconds: 120),
  );

  @override
  void dispose() {
    unawaited(_lockSubscription?.cancel());
    unawaited(_vaultChangeSubscription?.cancel());
    unawaited(runtime.dispose());
    unawaited(adapter.dispose());
    vault.dispose();
    connections.dispose();
    approvals.dispose();
    activity.dispose();
    super.dispose();
  }
}
