import 'dart:convert';

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

/// Indirection so state and feature code can be tested without a daemon.
abstract class KeyLeaseClient {
  /// Sends [request] with a freshly read `auth` block.
  Future<dynamic> authorized(Map<String, dynamic> request);

  /// Sends [request] without an `auth` block. Only `status` qualifies.
  Future<dynamic> unauthenticated(Map<String, dynamic> request);
}
