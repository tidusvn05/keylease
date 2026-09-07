import '../rpc/keylease_rpc.dart';
import '../platform/security_adapter.dart';

/// A failure rendered in the user's language, with the technical payload kept
/// for a diagnostics disclosure instead of the headline.
class UserMessage {
  const UserMessage({
    required this.title,
    required this.detail,
    this.actionLabel,
    this.diagnostics,
  });

  final String title;
  final String detail;
  final String? actionLabel;
  final String? diagnostics;

  static UserMessage from(Object error) {
    if (error is UnsupportedPlatformCapability) {
      return UserMessage(
        title: 'Not available in this build',
        detail: '$error',
      );
    }
    if (error is! KeyLeaseException) {
      return UserMessage(
        title: 'Something went wrong',
        detail: 'The app could not finish that action.',
        diagnostics: '$error',
      );
    }
    final details = error.details;
    final reason = details?['reason'];
    return switch (error.code) {
      KeyLeaseErrorCode.transport => UserMessage(
        title: "Can't reach KeyLease",
        detail:
            'The local KeyLease service did not answer. Make sure it is '
            'running, then try connecting again.',
        actionLabel: 'Try again',
        diagnostics: error.diagnostics,
      ),
      KeyLeaseErrorCode.client => UserMessage(
        title: 'Check the connection settings',
        detail: '${error.payload}',
      ),
      KeyLeaseErrorCode.vaultLocked => UserMessage(
        title: 'Vault locked',
        detail: 'Unlock the vault to continue.',
        actionLabel: 'Unlock',
        diagnostics: error.diagnostics,
      ),
      KeyLeaseErrorCode.denied => UserMessage(
        title: 'Permission needed',
        detail: reason is String && reason.isNotEmpty
            ? 'This client is not allowed to do that: $reason'
            : 'This client is not allowed to do that.',
        actionLabel: 'Review connection settings',
        diagnostics: error.diagnostics,
      ),
      KeyLeaseErrorCode.approvalRequired => UserMessage(
        title: 'Approval required',
        detail: 'Someone must approve this exact request before it can run.',
        actionLabel: 'Open Approvals',
        diagnostics: error.diagnostics,
      ),
      KeyLeaseErrorCode.revisionConflict => const UserMessage(
        title: 'This item changed elsewhere',
        detail:
            'Your draft was kept. Reload the item to see the newer version, '
            'then save again.',
        actionLabel: 'Reload',
      ),
      KeyLeaseErrorCode.invalidRequest => UserMessage(
        title: 'Check what you entered',
        detail: reason is String && reason.isNotEmpty
            ? reason
            : 'The service rejected these details.',
        diagnostics: error.diagnostics,
      ),
      KeyLeaseErrorCode.notFound => const UserMessage(
        title: 'Not found',
        detail: 'That item is no longer in the vault.',
      ),
      KeyLeaseErrorCode.idempotencyConflict => const UserMessage(
        title: 'Already submitted',
        detail: 'That change was already sent. Refresh to see the result.',
        actionLabel: 'Refresh',
      ),
      KeyLeaseErrorCode.connectorUnavailable => UserMessage(
        title: 'Provider unavailable',
        detail: 'KeyLease could not reach that provider. Try again shortly.',
        actionLabel: 'Try again',
        diagnostics: error.diagnostics,
      ),
      KeyLeaseErrorCode.leaseExpired ||
      KeyLeaseErrorCode.leaseRevoked ||
      KeyLeaseErrorCode.leaseExhausted => UserMessage(
        title: 'Access window closed',
        detail: 'That access grant is no longer usable. Request a new one.',
        diagnostics: error.diagnostics,
      ),
      KeyLeaseErrorCode.unsupportedVersion => UserMessage(
        title: 'Update needed',
        detail: 'The local service speaks a version this app does not support.',
        diagnostics: error.diagnostics,
      ),
      KeyLeaseErrorCode.storage || KeyLeaseErrorCode.crypto => UserMessage(
        title: 'The vault could not complete that',
        detail: 'KeyLease stopped the action to protect your data.',
        diagnostics: error.diagnostics,
      ),
      KeyLeaseErrorCode.unknown => UserMessage(
        title: 'Something went wrong',
        detail: 'The local service reported an error it could not explain.',
        diagnostics: error.diagnostics,
      ),
    };
  }
}
