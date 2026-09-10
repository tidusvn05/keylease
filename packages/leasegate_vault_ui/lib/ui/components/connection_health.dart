import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../core/models/models.dart';
import '../tokens/keylease_tokens.dart';

/// The health of one connection, with the fix when there is one.
///
/// `health`, `health_reason` and `reauthorization_required` all exist on
/// `ConnectionRecord`, so the advice here is the daemon's, not the UI's.
class ConnectionHealthBadge extends StatelessWidget {
  const ConnectionHealthBadge({required this.connection, super.key});

  final ConnectionSummary connection;

  static String describe(ConnectionSummary connection) =>
      switch (connection.health) {
        'connected' => 'Working',
        'degraded' => 'Having trouble',
        'expired' => 'Sign-in expired',
        'revoked' => 'Access revoked',
        'disconnected' => 'Disconnected',
        _ => 'Unknown',
      };

  /// The next step, in the user's language, or null when nothing is wrong.
  static String? remedy(ConnectionSummary connection) {
    if (connection.reauthorizationRequired) {
      return 'Sign in again to restore access.';
    }
    return switch (connection.health) {
      'connected' => null,
      'degraded' => 'Run Test to see whether the provider is reachable.',
      'expired' => 'Refresh this connection to get a new credential.',
      'revoked' => 'The provider revoked this credential. Connect again.',
      'disconnected' => 'Reconnect this account to use it again.',
      _ => 'Run Test to check this connection.',
    };
  }

  @override
  Widget build(BuildContext context) {
    final tokens = KeyLeaseTokens.of(context);
    final color = tokens.statusColor(connection.health);
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          width: 8,
          height: 8,
          decoration: BoxDecoration(color: color, shape: BoxShape.circle),
        ),
        const SizedBox(width: 7),
        Text(
          describe(connection),
          style: context.theme.typography.body.sm.copyWith(color: color),
          semanticsLabel: 'Connection status: ${describe(connection)}',
        ),
      ],
    );
  }
}
