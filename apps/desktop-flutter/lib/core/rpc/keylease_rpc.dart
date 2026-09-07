import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// Stable error codes emitted by the daemon.
///
/// The daemon serialises `KeyLeaseError` as `{"error": "<snake_case>", ...}`,
/// see `crates/keylease-core/src/error.rs`. Anything the UI cannot map is
/// reported as [KeyLeaseErrorCode.unknown] and shown with its raw payload in a
/// diagnostics section, never as the primary message.
enum KeyLeaseErrorCode {
  vaultLocked('vault_locked'),
  denied('denied'),
  approvalRequired('approval_required'),
  revisionConflict('revision_conflict'),
  invalidRequest('invalid_request'),
  unsupportedVersion('unsupported_version'),
  notFound('not_found'),
  leaseExpired('lease_expired'),
  leaseRevoked('lease_revoked'),
  leaseExhausted('lease_exhausted'),
  idempotencyConflict('idempotency_conflict'),
  connectorUnavailable('connector_unavailable'),
  storage('storage'),
  crypto('crypto'),

  /// The client could not reach or speak to the local service at all.
  transport('__transport'),

  /// The client rejected the request before it left the process.
  client('__client'),
  unknown('__unknown');

  const KeyLeaseErrorCode(this.wire);

  final String wire;

  static KeyLeaseErrorCode fromWire(Object? value) {
    for (final code in values) {
      if (code.wire == value) return code;
    }
    return KeyLeaseErrorCode.unknown;
  }
}

/// A failed local IPC call.
///
/// [payload] keeps the exact daemon payload so diagnostics stay faithful;
/// [code] is the routing decision the UI is allowed to make.
class KeyLeaseException implements Exception {
  const KeyLeaseException(this.payload, {this.code = KeyLeaseErrorCode.client});

  const KeyLeaseException.transport(this.payload)
    : code = KeyLeaseErrorCode.transport;

  factory KeyLeaseException.fromDaemon(Object? payload) => KeyLeaseException(
    payload,
    code: KeyLeaseErrorCode.fromWire(payload is Map ? payload['error'] : null),
  );

  final Object? payload;
  final KeyLeaseErrorCode code;

  /// The daemon's structured detail, if it sent one.
  Map<String, dynamic>? get details =>
      payload is Map ? Map<String, dynamic>.from(payload! as Map) : null;

  /// Redacted technical text for a diagnostics disclosure.
  String get diagnostics => jsonEncode(payload);

  @override
  String toString() => 'KeyLease: ${jsonEncode(payload)}';
}

/// Line-delimited JSON client for the local KeyLease unix socket.
///
/// The transport, framing and client-token checks are unchanged from the
/// original single-file client; only the error typing is new.
class KeyLeaseRpc {
  const KeyLeaseRpc(this.socketPath, this.agentId, this.tokenPath);

  static const maxMessageBytes = 4 * 1024 * 1024;
  static const connectTimeout = Duration(seconds: 10);
  static const responseTimeout = Duration(seconds: 30);

  final String socketPath;
  final String agentId;
  final String tokenPath;

  Future<Map<String, dynamic>> auth() async {
    if (agentId.trim().isEmpty || tokenPath.trim().isEmpty) {
      throw const KeyLeaseException('Client ID and token file are required');
    }
    final type = await FileSystemEntity.type(tokenPath, followLinks: false);
    if (type != FileSystemEntityType.file) {
      throw const KeyLeaseException('Client token must be a regular file');
    }
    final stat = await File(tokenPath).stat();
    if (stat.size <= 0 || stat.size > 4096) {
      throw const KeyLeaseException('Client token file has an invalid size');
    }
    if (!Platform.isWindows && stat.mode & 0x3f != 0) {
      throw const KeyLeaseException('Client token file must have mode 0600');
    }
    final token = (await File(tokenPath).readAsString()).trim();
    if (token.isEmpty) throw const KeyLeaseException('Client token is empty');
    return {
      'agent_id': agentId.trim(),
      'token': token,
      'session_id': 'desktop',
    };
  }

  Future<dynamic> call(Map<String, dynamic> request) async {
    final encoded = utf8.encode('${jsonEncode(request)}\n');
    if (encoded.length > maxMessageBytes) {
      throw const KeyLeaseException('Request exceeds the local IPC size limit');
    }
    final Socket connection;
    try {
      connection = await Socket.connect(
        InternetAddress(socketPath, type: InternetAddressType.unix),
        0,
      ).timeout(connectTimeout);
    } on KeyLeaseException {
      rethrow;
    } catch (caught) {
      throw KeyLeaseException.transport('$caught');
    }
    try {
      connection.add(encoded);
      await connection.flush();
      final responseBytes = <int>[];
      var complete = false;
      await for (final chunk in connection.timeout(responseTimeout)) {
        for (final byte in chunk) {
          if (byte == 10) {
            complete = true;
            break;
          }
          responseBytes.add(byte);
          if (responseBytes.length > maxMessageBytes) {
            throw const KeyLeaseException(
              'Response exceeds the local IPC size limit',
            );
          }
        }
        if (complete) break;
      }
      if (!complete) {
        throw const KeyLeaseException.transport(
          'Incomplete local IPC response',
        );
      }
      final response = jsonDecode(utf8.decode(responseBytes));
      if (response is! Map<String, dynamic>) {
        throw const KeyLeaseException('Invalid local IPC response');
      }
      if (response['ok'] == false) {
        throw KeyLeaseException.fromDaemon(response['error']);
      }
      return response['result'];
    } on KeyLeaseException {
      rethrow;
    } on TimeoutException catch (caught) {
      throw KeyLeaseException.transport('$caught');
    } on SocketException catch (caught) {
      throw KeyLeaseException.transport('$caught');
    } finally {
      connection.destroy();
    }
  }
}

/// Indirection so state and feature code can be tested without a daemon.
abstract class KeyLeaseClient {
  /// Sends [request] with a freshly read `auth` block.
  Future<dynamic> authorized(Map<String, dynamic> request);

  /// Sends [request] without an `auth` block. Only `status` qualifies.
  Future<dynamic> unauthenticated(Map<String, dynamic> request);
}

class SocketKeyLeaseClient implements KeyLeaseClient {
  const SocketKeyLeaseClient(this.rpc);

  final KeyLeaseRpc rpc;

  @override
  Future<dynamic> authorized(Map<String, dynamic> request) async =>
      rpc.call({...request, 'auth': await rpc.auth()});

  @override
  Future<dynamic> unauthenticated(Map<String, dynamic> request) =>
      rpc.call(request);
}
