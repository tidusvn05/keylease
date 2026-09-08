import 'dart:io';

import 'package:flutter/foundation.dart';

/// Where the local service is and which registered client this app presents.
///
/// None of these values is a secret: the client token itself stays on disk in
/// a mode-0600 file that the daemon validates on every call.
@immutable
class ConnectionSettings {
  const ConnectionSettings({
    required this.socketPath,
    required this.agentId,
    required this.tokenPath,
  });

  factory ConnectionSettings.defaults() => ConnectionSettings(
    socketPath:
        '${Platform.environment['HOME'] ?? Directory.systemTemp.path}/.keylease/run/keylease.sock',
    agentId: 'agent_desktop',
    tokenPath:
        '${Platform.environment['HOME'] ?? Directory.systemTemp.path}/.keylease/desktop.token',
  );

  factory ConnectionSettings.fromJson(Map<String, dynamic> json) {
    final fallback = ConnectionSettings.defaults();
    return ConnectionSettings(
      socketPath: json['socket_path'] as String? ?? fallback.socketPath,
      agentId: json['agent_id'] as String? ?? fallback.agentId,
      tokenPath: json['token_path'] as String? ?? fallback.tokenPath,
    );
  }

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
