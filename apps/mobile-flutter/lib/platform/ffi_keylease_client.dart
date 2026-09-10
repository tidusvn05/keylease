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
  const FfiKeyLeaseClient(this._vault, this._session);

  final VaultIsolate _vault;
  final MobileSession _session;

  @override
  Future<dynamic> authorized(Map<String, dynamic> request) =>
      _send({...request, if (_session.auth case final auth?) 'auth': auth});

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

/// The owner credential for this device, for the lifetime of one unlock.
///
/// Held in memory only. It is reissued on every unlock — `register_local_owner_client`
/// rotates the token — so there is nothing worth persisting, and persisting it
/// would put a credential on disk for no benefit: the Rust core and this client
/// are the same process.
class MobileSession {
  Map<String, dynamic>? _auth;

  Map<String, dynamic>? get auth => _auth;

  void adopt(Map<String, dynamic> provisionResult) {
    _auth = {
      'agent_id': provisionResult['agent_id'],
      'token': provisionResult['token'],
      'session_id': 'mobile',
    };
  }

  void clear() => _auth = null;
}

/// Vault files in Android app-private storage, over the FFI.
class FfiVaultStorage implements VaultStorage {
  FfiVaultStorage({
    required VaultIsolate vault,
    required MobileSession session,
    required String databasePath,
  }) : _vault = vault,
       _session = session,
       _databasePath = databasePath;

  final VaultIsolate _vault;
  final MobileSession _session;
  final String _databasePath;

  String get databasePath => _databasePath;

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
    // Creating, restoring and unlocking all mint this device's credential.
    if (result['token'] != null) _session.adopt(result);
    return result;
  }

  /// Multi-vault on a phone is a later milestone; one vault per device for now.
  @override
  Future<List<LocalVaultProfile>> listVaults() async => const [];

  @override
  Future<void> createVault(String name, Map<String, dynamic> request) async =>
      throw const KeyLeaseException(
        'Creating a second vault is not available on this device yet',
      );

  @override
  Future<void> switchVault(String id) async {}

  @override
  Future<void> renameVault(String id, String name) async {}

  /// Wired at the composition root, where the file-picker plugin lives.
  @override
  Future<String?> importBackupFile() async => null;
}
