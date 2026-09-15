import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:leasegate_vault_ui/core/rpc/keylease_client.dart';
import 'package:leasegate_vault_ui/core/state/connection_settings.dart';

// The typed errors and the client interface live in keylease_client.dart so
// that state and feature code can depend on them without pulling in dart:io.
// Re-exported so existing imports keep working unchanged.
export 'package:leasegate_vault_ui/core/rpc/keylease_client.dart';

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

class SocketKeyLeaseClient implements KeyLeaseClient {
  const SocketKeyLeaseClient(this.rpc);

  final KeyLeaseRpc rpc;

  @override
  Future<dynamic> unlock(
    String password, {
    int sessionTtlSeconds = 900,
  }) => authorized({
    'command': 'unlock',
    'password': password,
    'session_ttl_seconds': sessionTtlSeconds,
  });

  @override
  Future<dynamic> authorized(Map<String, dynamic> request) async =>
      rpc.call({...request, 'auth': await rpc.auth()});

  @override
  Future<dynamic> unauthenticated(Map<String, dynamic> request) =>
      rpc.call(request);
}

/// The desktop transport, in the shape [ClientFactory] expects.
///
/// Lives here rather than in the shared package because a Unix socket and a
/// mode-0600 token file are desktop concepts; the Android client implements the
/// same [KeyLeaseClient] interface over its in-process FFI bridge instead.
KeyLeaseClient socketClientFactory(ConnectionSettings settings) =>
    SocketKeyLeaseClient(
      KeyLeaseRpc(settings.socketPath, settings.agentId, settings.tokenPath),
    );
