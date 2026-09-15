import 'dart:async';

import 'package:leasegate_vault_ui/core/platform/local_runtime_adapter.dart';
import 'package:leasegate_vault_ui/core/platform/security_adapter.dart';
import 'package:leasegate_vault_ui/core/rpc/keylease_client.dart';

/// What the app can find out about the vault files on this device.
///
/// An interface so the runtime adapter can be tested without the FFI bridge,
/// and so the bridge can be swapped for the real one in M10 without touching
/// the adapter.
abstract class VaultStorage {
  /// Whether a vault database already exists in app-private storage.
  Future<bool> vaultExists();

  /// The version string the Rust core reports.
  Future<String?> serviceVersion();

  /// The vaults this device holds, and which one is active.
  Future<List<LocalVaultProfile>> listVaults();

  /// Runs a provisioning request against the open vault.
  Future<Map<String, dynamic>> provision(Map<String, dynamic> request);

  /// Makes [id] the active vault.
  Future<void> switchVault(String id);

  /// Creates a new vault file named [name].
  Future<void> createVault(String name, Map<String, dynamic> request);

  Future<void> renameVault(String id, String name);

  /// Copies a user-picked backup into app-private storage and returns its path.
  Future<String?> importBackupFile();
}

/// The Android implementation of [LocalRuntimeAdapter].
///
/// On desktop this interface manages a background daemon: starting it,
/// restarting it after a vault switch, and telling a second Flutter engine that
/// the vault changed. None of that exists here — the vault is opened in process
/// — so several members are legitimately inert, and saying so plainly is better
/// than pretending the concept transferred.
class FfiLocalRuntimeAdapter implements LocalRuntimeAdapter {
  FfiLocalRuntimeAdapter(this._storage);

  final VaultStorage _storage;

  /// There is no second engine to notify: this app runs one.
  ///
  /// On macOS the Settings window is a separate Flutter engine over the same
  /// daemon, which is the only reason this stream exists.
  @override
  Stream<void> get vaultChanges => const Stream<void>.empty();

  @override
  Future<void> publishVaultChange() async {}

  @override
  Future<LocalRuntimeInspection> inspect() async {
    final exists = await _storage.vaultExists();
    return LocalRuntimeInspection(
      state: exists
          ? LocalRuntimeState.ready
          : LocalRuntimeState.needsOnboarding,
      serviceVersion: await _storage.serviceVersion(),
      // No token file: the owner credential never leaves the Rust side.
      // AppController null-checks this and leaves its settings alone.
      tokenPath: null,
    );
  }

  /// No daemon to start. The first `status` call succeeds immediately, which is
  /// why `AppPhase.backgroundApprovalRequired` can never be reached here.
  @override
  Future<void> ensureService() async {}

  @override
  Future<void> restartService() async {}

  @override
  Future<void> provision(Map<String, dynamic> request) =>
      _storage.provision(_mobileProvisionRequest(request)).then((_) {});

  @override
  Future<String?> chooseVaultSource() => _storage.importBackupFile();

  @override
  Future<Map<String, dynamic>> inspectSource(String path) =>
      _storage.provision({'provision': 'inspect_source', 'source_path': path});

  @override
  Future<List<LocalVaultProfile>> listVaults() => _storage.listVaults();

  @override
  Future<void> createVault(String name, Map<String, dynamic> request) =>
      _storage.createVault(name, _mobileProvisionRequest(request));

  @override
  Future<void> switchVault(String id) => _storage.switchVault(id);

  @override
  Future<void> renameVault(String id, String name) =>
      _storage.renameVault(id, name);

  /// Android has no file-manager contract for app-private storage, and the
  /// vault must not be reachable from one.
  @override
  Future<void> openDataFolder() async =>
      throw const UnsupportedPlatformCapability('data folder');

  /// There is no background item to authorise.
  @override
  Future<void> openLoginItemsSettings() async =>
      throw const UnsupportedPlatformCapability('login items');

  @override
  Future<void> dispose() async {}

  Map<String, dynamic> _mobileProvisionRequest(Map<String, dynamic> request) {
    if (request.containsKey('provision')) return request;
    final password = request['password'];
    return switch (request['mode']) {
      'create' => {
        'provision': 'create',
        'password': password,
        'session_ttl_seconds': 900,
        'acknowledge_standalone': true,
      },
      'restore_keylease_backup' => {
        'provision': 'restore_backup',
        'source_path': request['source_path'],
        'password': password,
        'session_ttl_seconds': 900,
      },
      'import_kdbx' => {
        'provision': 'import_kdbx',
        'source_path': request['source_path'],
        'source_password': request['source_password'],
        'password': password,
        'session_ttl_seconds': 900,
      },
      _ => throw const KeyLeaseException(
        'Android supports encrypted KeyLease backups and password-only KDBX files.',
      ),
    };
  }
}
