import 'dart:async';

import 'package:leasegate_vault_ui/core/platform/app_capabilities.dart';
import 'package:leasegate_vault_ui/core/platform/preferences_store.dart';
import 'package:leasegate_vault_ui/core/platform/local_runtime_adapter.dart';
import 'package:leasegate_vault_ui/core/platform/security_adapter.dart';
import 'package:leasegate_vault_ui/core/rpc/keylease_client.dart';
import 'package:leasegate_vault_ui/core/state/app_controller.dart';
import 'package:leasegate_vault_ui/core/state/connection_settings.dart';

/// Records what the UI asked the native layer to do.
class FakeSecurityAdapter implements SecurityAdapter {
  final _lockRequests = StreamController<LockTrigger>.broadcast();
  final _menuActions = StreamController<MenuAction>.broadcast();
  final copied = <String>[];
  final openedUrls = <String>[];

  int clipboardClears = 0;
  String? tokenToReturn;
  String? qrCodeToReturn;
  String? screenQrCodeToReturn;
  Object? screenQrScanError;
  int screenQrScanRequests = 0;
  int cameraQrScanRequests = 0;
  Object? cameraQrScanError;
  int screenRecordingSettingsRequests = 0;
  bool clipboardSupported = true;
  bool browserOpens = true;
  bool settingsWindowOpens = false;
  int settingsWindowRequests = 0;
  List<SshPrivateKeyCandidate> sshKeys = const [];
  String? sshKeyToReturn;

  void requestLock([LockTrigger trigger = LockTrigger.systemSleep]) =>
      _lockRequests.add(trigger);

  void selectMenu(MenuAction action) => _menuActions.add(action);

  @override
  Stream<LockTrigger> get lockRequests => _lockRequests.stream;

  @override
  Stream<MenuAction> get menuActions => _menuActions.stream;

  @override
  Future<void> copySensitive(
    String value, {
    Duration clearAfter = const Duration(seconds: 30),
  }) async {
    if (!clipboardSupported) {
      throw const UnsupportedPlatformCapability('clipboard');
    }
    copied.add(value);
  }

  @override
  Future<void> clearSensitiveClipboard() async => clipboardClears++;

  @override
  Future<String?> selectClientToken() async => tokenToReturn;

  @override
  Future<List<SshPrivateKeyCandidate>> discoverSshPrivateKeys() async =>
      sshKeys;

  @override
  Future<String?> selectSshPrivateKey() async => sshKeyToReturn;

  @override
  Future<String?> scanTotpQrCode() async => qrCodeToReturn;

  @override
  Future<String?> scanTotpQrCodeFromCamera() async {
    cameraQrScanRequests++;
    if (cameraQrScanError case final error?) throw error;
    return qrCodeToReturn;
  }

  @override
  Future<String?> scanTotpQrCodeFromScreen() async {
    screenQrScanRequests++;
    if (screenQrScanError case final error?) throw error;
    return screenQrCodeToReturn;
  }

  @override
  Future<bool> openScreenRecordingSettings() async {
    screenRecordingSettingsRequests++;
    return true;
  }

  @override
  Future<bool> openGoogleAuthorization(String url) async => browserOpens;

  @override
  Future<bool> openExternalUrl(String url) async {
    openedUrls.add(url);
    return browserOpens;
  }

  @override
  Future<bool> openSettingsWindow() async {
    settingsWindowRequests++;
    return settingsWindowOpens;
  }

  @override
  Future<void> dispose() async {
    await _lockRequests.close();
    await _menuActions.close();
  }
}

class FakeLocalRuntimeAdapter implements LocalRuntimeAdapter {
  final _vaultChanges = StreamController<void>.broadcast();
  LocalRuntimeInspection inspection = const LocalRuntimeInspection(
    state: LocalRuntimeState.ready,
    serviceVersion: 'test',
  );
  List<LocalVaultProfile> profiles = const [
    LocalVaultProfile(id: 'primary', name: 'Primary Vault', active: true),
  ];
  int publishedVaultChanges = 0;

  void emitExternalVaultChange() => _vaultChanges.add(null);

  @override
  Stream<void> get vaultChanges => _vaultChanges.stream;

  @override
  Future<LocalRuntimeInspection> inspect() async => inspection;
  @override
  Future<String?> chooseVaultSource() async => null;
  @override
  Future<Map<String, dynamic>> inspectSource(String path) async => {
    'kind': 'keylease_database',
    'path': path,
  };
  @override
  Future<void> provision(Map<String, dynamic> request) async {}
  @override
  Future<void> ensureService() async {}
  @override
  Future<void> restartService() async {}
  @override
  Future<void> openLoginItemsSettings() async {}
  @override
  Future<void> openDataFolder() async {}
  @override
  Future<List<LocalVaultProfile>> listVaults() async => profiles;
  @override
  Future<void> createVault(String name, Map<String, dynamic> request) async {}
  @override
  Future<void> switchVault(String id) async {
    profiles = [
      for (final profile in profiles)
        LocalVaultProfile(
          id: profile.id,
          name: profile.name,
          active: profile.id == id,
        ),
    ];
  }

  @override
  Future<void> publishVaultChange() async => publishedVaultChanges++;
  @override
  Future<void> renameVault(String id, String name) async {}
  @override
  Future<void> dispose() => _vaultChanges.close();
}

/// A scripted daemon.
///
/// Handlers are keyed by command name and may be async, so tests can reorder
/// responses and assert that a stale one is dropped.
class FakeKeyLeaseClient implements KeyLeaseClient {
  FakeKeyLeaseClient({
    Map<String, Future<dynamic> Function(Map<String, dynamic>)>? handlers,
  }) : handlers = handlers ?? {};

  final Map<String, Future<dynamic> Function(Map<String, dynamic>)> handlers;
  final calls = <Map<String, dynamic>>[];

  void on(
    String command,
    Future<dynamic> Function(Map<String, dynamic> request) handler,
  ) => handlers[command] = handler;

  void value(String command, Object? result) =>
      handlers[command] = (_) async => result;

  void fail(String command, KeyLeaseException error) =>
      handlers[command] = (_) async => throw error;

  Future<dynamic> _dispatch(Map<String, dynamic> request) async {
    calls.add(request);
    final command = '${request['command']}';
    final handler = handlers[command];
    if (handler == null) {
      throw KeyLeaseException.fromDaemon({
        'error': 'not_found',
        'resource': command,
      });
    }
    return handler(request);
  }

  @override
  Future<dynamic> unlock(
    String password, {
    int sessionTtlSeconds = 900,
  }) => _dispatch({
    'command': 'unlock',
    'password': password,
    'session_ttl_seconds': sessionTtlSeconds,
  });

  @override
  Future<dynamic> authorized(Map<String, dynamic> request) =>
      _dispatch(request);

  @override
  Future<dynamic> unauthenticated(Map<String, dynamic> request) =>
      _dispatch(request);
}

/// Fixtures matching the daemon's serialised shapes.
abstract final class Fixtures {
  static Map<String, dynamic> get unlockedStatus => {
    'locked': false,
    'vault_id': 'vault-1',
    'idle_expires_at': DateTime.now()
        .add(const Duration(minutes: 15))
        .toUtc()
        .toIso8601String(),
  };

  static Map<String, dynamic> get lockedStatus => {
    'locked': true,
    'requires_user_action': true,
  };

  static List<Map<String, dynamic>> get groups => [
    {
      'id': 'group-work',
      'vault_id': 'vault-1',
      'parent_id': null,
      'name': 'Work',
      'revision': 1,
      'created_at': '2026-09-01T10:00:00Z',
      'updated_at': '2026-09-01T10:00:00Z',
    },
  ];

  static Map<String, dynamic> entry({
    String id = 'entry-github',
    String title = 'GitHub',
    String kind = 'core.login',
    String username = 'alex@northstar.example',
    List<String> urls = const ['https://github.com'],
    bool hasPassword = true,
    bool hasNotes = false,
    bool hasTotp = false,
    bool favorite = false,
    int revision = 3,
  }) => {
    'id': id,
    'group_id': 'group-work',
    'kind': kind,
    'title': title,
    'username': username,
    'urls': urls,
    'has_password': hasPassword,
    'has_notes': hasNotes,
    'has_totp': hasTotp,
    'favorite': favorite,
    'revision': revision,
    'updated_at': '2026-09-05T09:30:00Z',
  };

  static Map<String, dynamic> approval({
    String id = 'approval-1',
    String digest = 'a1b2c3d4e5f6',
    String state = 'pending',
    Duration expiresIn = const Duration(minutes: 5),
  }) => {
    'id': id,
    'request_digest_hex': digest,
    'policy_version': 7,
    'state': state,
    'expires_at': DateTime.now().add(expiresIn).toUtc().toIso8601String(),
    'agent_id': 'agent_ci',
    'action': 'drive:read',
    'resource': 'kl://vault-1/files/report.csv',
    'risk': 'medium',
    'semantic_summary': {
      'operation': 'Read a spreadsheet',
      'target': 'Quarterly report',
      'changed_fields': <String>[],
      'argument_fingerprints': <dynamic>[],
      'blast_radius': 'One file',
    },
  };

  static Map<String, dynamic> get auditEvent => {
    'schema_version': 1,
    'timestamp': DateTime.now().toUtc().toIso8601String(),
    'request_id': 'req-1',
    'agent_id': 'agent_ci',
    'action': 'drive:read',
    'resource': 'kl://vault-1/files/report.csv',
    'decision': 'allow',
    'outcome': 'success',
    'item_count': 1,
    'changed_fields': <String>[],
  };
}

/// A controller wired to fakes, with a happy-path script already installed.
({AppController app, FakeKeyLeaseClient client, FakeSecurityAdapter adapter})
buildController({
  Map<String, dynamic>? preferences,
  LocalRuntimeInspection? runtimeInspection,
  FakeLocalRuntimeAdapter? runtime,
  AppCapabilities capabilities = AppCapabilities.desktop,
  void Function(FakeKeyLeaseClient client)? script,
}) {
  final client = FakeKeyLeaseClient()
    ..value('status', Fixtures.unlockedStatus)
    ..value('groups_list', Fixtures.groups)
    ..value('templates_list', <Map<String, dynamic>>[])
    ..value('projects_list', <Map<String, dynamic>>[])
    ..value('migrations_status', {
      'framework_version': 1,
      'pending': <Map<String, dynamic>>[],
      'history': <Map<String, dynamic>>[],
    })
    ..value('entries_search', [Fixtures.entry()])
    ..on('entries_view', (request) async {
      final entry = Fixtures.entry(id: '${request['id']}');
      return {
        'metadata': entry,
        'template_version': 1,
        'project_id': null,
        'tags': <String>[],
        'sections': <Map<String, dynamic>>[],
        'fields': <Map<String, dynamic>>[],
        'attachments': <String>[],
        'has_notes': entry['has_notes'],
      };
    })
    ..value('connections_list', <Map<String, dynamic>>[])
    ..value('approvals_list', <Map<String, dynamic>>[])
    ..value('audit_query', <Map<String, dynamic>>[])
    ..value('entries_create', {'id': 'entry-new'})
    ..value('entries_update', {'id': 'entry-github'})
    ..value('entries_delete', {'deleted': 'entry-github'})
    ..on('entries_reveal', (request) async {
      final value = request['field'] == 'notes'
          ? 'Recovery instructions\n\nContact the account owner.'
          : 'Demo-only!47-sample';
      return {'value': value};
    })
    ..value('groups_create', {'id': 'group-new'})
    ..value('groups_update', {'id': 'group-work'})
    ..value('groups_delete', {'deleted': 'group-work'})
    ..value('unlock', {'unlocked': true, 'vault_id': 'vault-1'})
    ..value('lock', <String, dynamic>{})
    ..value('generate_password', {
      'password': 'generated-32-characters-long!!',
    });
  script?.call(client);
  final adapter = FakeSecurityAdapter();
  final localRuntime = runtime ?? FakeLocalRuntimeAdapter();
  if (runtimeInspection != null) localRuntime.inspection = runtimeInspection;
  final app = AppController(
    adapter: adapter,
    runtime: localRuntime,
    preferences: InMemoryPreferencesStore(
      preferences ??
          const ConnectionSettings(
            socketPath: '/tmp/keylease-test.sock',
            agentId: 'agent_test',
            tokenPath: '/tmp/keylease-test.token',
          ).toJson(),
    ),
    clientFactory: (_) => client,
    capabilities: capabilities,
  );
  return (app: app, client: client, adapter: adapter);
}
