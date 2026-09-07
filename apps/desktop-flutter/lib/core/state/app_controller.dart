import 'dart:async';

import 'package:flutter/foundation.dart';

import '../models/models.dart';
import '../platform/preferences_store.dart';
import '../platform/security_adapter.dart';
import '../../ui/tokens/keylease_tokens.dart';
import '../rpc/keylease_rpc.dart';
import 'app_phase.dart';
import 'busy_registry.dart';
import 'connection_settings.dart';
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
    this.clientFactory = _socketClient,
  }) {
    vault = VaultController(clientOf: () => client);
    connections = ConnectionsController(() => client);
    approvals = ApprovalsController(() => client);
    activity = ActivityController(() => client);
    _lockSubscription = adapter.lockRequests.listen(_onLockRequested);
  }

  static const refreshKey = 'app.refresh';
  static const unlockKey = 'app.unlock';
  static const lockKey = 'app.lock';

  final SecurityAdapter adapter;
  final PreferencesStore preferences;
  final ClientFactory clientFactory;
  StreamSubscription<LockTrigger>? _lockSubscription;

  ConnectionSettings settings = ConnectionSettings.defaults();
  AppPhase phase = AppPhase.checking;
  AppSection section = AppSection.vault;
  VaultStatus? status;
  UserMessage? phaseMessage;
  UserMessage? banner;
  double sidebarWidth = KeyLeaseLayout.sidebarWidth;
  double listWidth = KeyLeaseLayout.listWidth;

  late final VaultController vault;
  late final ConnectionsController connections;
  late final ApprovalsController approvals;
  late final ActivityController activity;

  KeyLeaseClient get client => clientFactory(settings);

  bool get isReady => phase == AppPhase.ready;

  /// Loads saved, non-secret preferences and probes the local service.
  Future<void> start() async {
    final stored = await preferences.load();
    settings = ConnectionSettings.fromJson(stored);
    sidebarWidth =
        (stored['sidebar_width'] as num?)?.toDouble() ??
        KeyLeaseLayout.sidebarWidth;
    listWidth =
        (stored['list_width'] as num?)?.toDouble() ?? KeyLeaseLayout.listWidth;
    notifyListeners();
    await refresh();
  }

  Future<void> persistPreferences() => preferences.save({
    ...settings.toJson(),
    'sidebar_width': sidebarWidth,
    'list_width': listWidth,
  });

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

  Future<void> applySettings(ConnectionSettings value) async {
    settings = value;
    _clearSessionData();
    notifyListeners();
    await persistPreferences();
    await refresh();
  }

  /// Recomputes [phase] from the daemon, keeping each failure distinguishable.
  Future<void> refresh() async {
    await track(
      refreshKey,
      () async {
        if (!settings.isComplete) {
          _enter(
            AppPhase.setupRequired,
            const UserMessage(
              title: 'Make yourself at home',
              detail:
                  'Point KeyLease at the local service socket and choose the '
                  'client file it issued for this app.',
              actionLabel: 'Open settings',
            ),
          );
          return;
        }

        final Map<String, dynamic> raw;
        try {
          raw = Map<String, dynamic>.from(
            await client.unauthenticated({'command': 'status'}) as Map,
          );
        } on KeyLeaseException catch (caught) {
          _enter(
            caught.code == KeyLeaseErrorCode.client
                ? AppPhase.setupRequired
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
            KeyLeaseErrorCode.client => AppPhase.setupRequired,
            _ => AppPhase.serviceUnavailable,
          }, UserMessage.from(caught));
          return;
        }

        _enter(AppPhase.ready, null);
        await loadSection();
      },
      onError: (caught) {
        _enter(AppPhase.serviceUnavailable, UserMessage.from(caught));
      },
    );
  }

  Future<void> loadSection() async {
    if (!isReady) return;
    switch (section) {
      case AppSection.vault:
        await vault.load();
      case AppSection.connections:
        await connections.load();
      case AppSection.approvals:
        await approvals.load();
      case AppSection.activity:
        await activity.load();
      case AppSection.settings:
        break;
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
  Future<bool> copySensitive(String value) async {
    try {
      await adapter.copySensitive(value);
      banner = null;
      notifyListeners();
      return true;
    } catch (caught) {
      banner = UserMessage.from(caught);
      notifyListeners();
      return false;
    }
  }

  @override
  void dispose() {
    unawaited(_lockSubscription?.cancel());
    vault.dispose();
    connections.dispose();
    approvals.dispose();
    activity.dispose();
    super.dispose();
  }
}
