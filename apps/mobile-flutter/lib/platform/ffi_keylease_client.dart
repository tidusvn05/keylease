import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter/services.dart';
import 'package:leasegate_vault_ui/core/platform/local_runtime_adapter.dart';
import 'package:leasegate_vault_ui/core/rpc/keylease_client.dart';

import 'ffi_bridge.dart';
import 'ffi_local_runtime_adapter.dart';

/// The mobile transport.
///
/// Sends exactly the requests the desktop socket client sends, so everything
/// above it — the whole state and feature layer — is unchanged. What differs is
/// the auth block: on desktop Dart reads a mode-0600 token file on every call,
/// while here the Rust side holds the owner credential and splices it in
/// itself, so no token ever reaches the Dart heap or the filesystem.
class FfiKeyLeaseClient implements KeyLeaseClient {
  const FfiKeyLeaseClient(this._vault, {this.onUnlocked});

  final VaultIsolate _vault;
  final Future<void> Function(Map<String, dynamic> result)? onUnlocked;

  @override
  Future<dynamic> unlock(String password, {int sessionTtlSeconds = 900}) async {
    final response = await _vault.provision({
      'provision': 'unlock_owner',
      'password': password,
      'session_ttl_seconds': sessionTtlSeconds,
    });
    if (response['ok'] == false) {
      throw KeyLeaseException.fromDaemon(response['error']);
    }
    final result = Map<String, dynamic>.from(
      response['result'] as Map? ?? const {},
    );
    await onUnlocked?.call(result);
    return result;
  }

  @override
  Future<dynamic> authorized(Map<String, dynamic> request) => _send(request);

  @override
  Future<dynamic> unauthenticated(Map<String, dynamic> request) =>
      _send(request);

  Future<dynamic> _send(Map<String, dynamic> request) async {
    final response = await _vault.call(request);
    if (response['ok'] == false) {
      throw KeyLeaseException.fromDaemon(response['error']);
    }
    return response['result'];
  }
}

/// Vault files in Android app-private storage, over the FFI.
class FfiVaultStorage implements VaultStorage {
  FfiVaultStorage({
    required VaultIsolate vault,
    required String supportDirectory,
  }) : _vault = vault,
       _supportDirectory = supportDirectory,
       _databasePath = '$supportDirectory/vault.sqlite';

  final VaultIsolate _vault;
  final String _supportDirectory;
  final _runtimeChannel = const MethodChannel('com.keylease/runtime');
  late String _databasePath;
  String? _activeId;
  List<Map<String, dynamic>> _profiles = [];

  String get databasePath => _databasePath;

  File get _registry => File('$_supportDirectory/vault_profiles.json');

  Future<void> initialize() async {
    if (await _registry.exists()) {
      try {
        final raw = jsonDecode(await _registry.readAsString());
        if (raw is Map) {
          _activeId = raw['active_id'] as String?;
          _profiles = (raw['profiles'] as List? ?? const [])
              .whereType<Map>()
              .map((value) => Map<String, dynamic>.from(value))
              .toList();
          final active = _findProfile(_activeId);
          if (active != null) _databasePath = active['path'] as String;
        }
      } catch (_) {
        // A damaged non-secret registry must not hide the legacy vault. The
        // vault database remains authoritative and is never modified here.
      }
    }
    await Directory('$_supportDirectory/vaults').create(recursive: true);
    final opened = await _vault.openVault(_databasePath);
    if (opened['ok'] == false) {
      throw KeyLeaseException.fromDaemon(opened['error']);
    }
  }

  @override
  Future<bool> vaultExists() async {
    final response = await _vault.provision({'provision': 'inspect'});
    if (response['ok'] == false) return false;
    return response['result']?['initialized'] == true;
  }

  @override
  Future<String?> serviceVersion() async {
    final response = await _vault.provision({'provision': 'inspect'});
    return response['result']?['status']?['service_version'] as String?;
  }

  @override
  Future<Map<String, dynamic>> provision(Map<String, dynamic> request) async {
    final response = await _vault.provision(request);
    if (response['ok'] == false) {
      throw KeyLeaseException.fromDaemon(response['error']);
    }
    final result = Map<String, dynamic>.from(
      response['result'] as Map? ?? const {},
    );
    if ({
      'create',
      'restore_backup',
      'import_kdbx',
    }.contains(request['provision'])) {
      await _registerCurrent(result, request['provision'] as String);
      final sourcePath = request['source_path'];
      if (sourcePath is String &&
          sourcePath.startsWith('$_supportDirectory/imports/')) {
        try {
          await File(sourcePath).delete();
        } catch (_) {
          // The managed vault is already committed. A failed cleanup is not
          // allowed to turn a successful import into a second import attempt.
        }
      }
    }
    return result;
  }

  @override
  Future<List<LocalVaultProfile>> listVaults() async => _profiles
      .map(
        (profile) => LocalVaultProfile(
          id: profile['id'] as String,
          name: profile['name'] as String,
          active: profile['id'] == _activeId,
          vaultId: profile['vault_id'] as String?,
          provenance: profile['provenance'] as String?,
        ),
      )
      .toList(growable: false);

  @override
  Future<void> createVault(String name, Map<String, dynamic> request) async {
    final id = _newProfileId();
    final previousPath = _databasePath;
    final previousId = _activeId;
    _databasePath = '$_supportDirectory/vaults/$id.sqlite';
    final opened = await _vault.openVault(_databasePath);
    if (opened['ok'] == false) {
      _databasePath = previousPath;
      _activeId = previousId;
      await _vault.openVault(previousPath);
      throw KeyLeaseException.fromDaemon(opened['error']);
    }
    try {
      await provision(request);
      final index = _profiles.indexWhere(
        (profile) => profile['id'] == _activeId,
      );
      if (index >= 0) _profiles[index]['name'] = _safeName(name);
      await _saveRegistry();
    } catch (_) {
      _databasePath = previousPath;
      _activeId = previousId;
      await _vault.openVault(previousPath);
      rethrow;
    }
  }

  @override
  Future<void> switchVault(String id) async {
    final profile = _findProfile(id);
    if (profile == null) {
      throw const KeyLeaseException(
        'The selected vault is no longer available.',
      );
    }
    final nextPath = profile['path'] as String;
    final opened = await _vault.openVault(nextPath);
    if (opened['ok'] == false) {
      throw KeyLeaseException.fromDaemon(opened['error']);
    }
    _databasePath = nextPath;
    _activeId = id;
    await _saveRegistry();
  }

  @override
  Future<void> renameVault(String id, String name) async {
    final profile = _findProfile(id);
    if (profile == null) return;
    profile['name'] = _safeName(name);
    await _saveRegistry();
  }

  @override
  Future<String?> importBackupFile() =>
      _runtimeChannel.invokeMethod<String>('chooseVaultSource');

  /// Registers a vault created by a pre-registry app version after its first
  /// successful unlock. A rejected password never reaches this callback.
  Future<void> recordUnlocked(Map<String, dynamic> result) async {
    if (_findProfile(_activeId) == null) {
      await _registerCurrent(result, 'existing_keylease_vault');
    }
  }

  Future<void> _registerCurrent(
    Map<String, dynamic> result,
    String sourceKind,
  ) async {
    Map<String, dynamic>? profile;
    for (final candidate in _profiles) {
      if (candidate['path'] == _databasePath) {
        profile = candidate;
        break;
      }
    }
    if (profile == null) {
      final id = _newProfileId();
      profile = {
        'id': id,
        'name': _profiles.isEmpty
            ? 'My Vault'
            : 'Vault ${_profiles.length + 1}',
        'path': _databasePath,
      };
      _profiles.add(profile);
    }
    profile.addAll({
      'vault_id': result['vault_id'],
      'provenance': result['provenance'] ?? sourceKind,
      'source_kind': sourceKind,
    });
    _activeId = profile['id'] as String;
    await _saveRegistry();
  }

  String _newProfileId() {
    final random = Random.secure().nextInt(0x7fffffff).toRadixString(16);
    return 'vault_${DateTime.now().microsecondsSinceEpoch}_$random';
  }

  Map<String, dynamic>? _findProfile(String? id) {
    for (final profile in _profiles) {
      if (profile['id'] == id) return profile;
    }
    return null;
  }

  String _safeName(String value) {
    final trimmed = value.trim();
    return trimmed.isEmpty
        ? 'Vault'
        : trimmed.substring(0, min(80, trimmed.length));
  }

  Future<void> _saveRegistry() async {
    final temporary = File('${_registry.path}.tmp');
    await temporary.writeAsString(
      jsonEncode({'active_id': _activeId, 'profiles': _profiles}),
      flush: true,
    );
    await temporary.rename(_registry.path);
  }
}
