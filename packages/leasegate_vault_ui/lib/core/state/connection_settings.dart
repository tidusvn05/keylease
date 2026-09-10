import 'package:flutter/foundation.dart';

/// Where the local service is and which registered client this app presents.
///
/// None of these values is a secret: the client token itself stays on disk in
/// a mode-0600 file that the daemon validates on every call.
///
/// The defaults are supplied by the host application rather than resolved here,
/// because they are inherently platform-specific — a `$HOME`-relative socket
/// path means nothing inside an Android app sandbox, where the vault is opened
/// in process and there is no socket at all.
@immutable
class ConnectionSettings {
  const ConnectionSettings({
    required this.socketPath,
    required this.agentId,
    required this.tokenPath,
  });

  /// No local service configured.
  ///
  /// The state layer starts here until the host supplies real values, and a
  /// transport that does not use paths (the mobile FFI client) keeps them.
  const ConnectionSettings.unset()
    : socketPath = '',
      agentId = '',
      tokenPath = '';

  final String socketPath;
  final String agentId;
  final String tokenPath;

  bool get isComplete =>
      socketPath.trim().isNotEmpty &&
      agentId.trim().isNotEmpty &&
      tokenPath.trim().isNotEmpty;

  ConnectionSettings copyWith({
    String? socketPath,
    String? agentId,
    String? tokenPath,
  }) => ConnectionSettings(
    socketPath: socketPath ?? this.socketPath,
    agentId: agentId ?? this.agentId,
    tokenPath: tokenPath ?? this.tokenPath,
  );

  /// Deliberately empty: connection settings are never persisted.
  Map<String, dynamic> toJson() => const {};

  @override
  bool operator ==(Object other) =>
      other is ConnectionSettings &&
      other.socketPath == socketPath &&
      other.agentId == agentId &&
      other.tokenPath == tokenPath;

  @override
  int get hashCode => Object.hash(socketPath, agentId, tokenPath);
}
