import Foundation

/// Stable error codes emitted by the daemon.
///
/// Mirrors `KeyLeaseErrorCode` in
/// `packages/leasegate_vault_ui/lib/core/rpc/keylease_client.dart`; the wire
/// values come from `keylease-core/src/error.rs`. The `__`-prefixed codes are
/// client-side only and never appear on the wire.
public enum KeyLeaseErrorCode: String, Sendable {
    case vaultLocked = "vault_locked"
    case denied = "denied"
    case approvalRequired = "approval_required"
    case revisionConflict = "revision_conflict"
    case invalidRequest = "invalid_request"
    case unsupportedVersion = "unsupported_version"
    case notFound = "not_found"
    case leaseExpired = "lease_expired"
    case leaseRevoked = "lease_revoked"
    case leaseExhausted = "lease_exhausted"
    case idempotencyConflict = "idempotency_conflict"
    case connectorUnavailable = "connector_unavailable"
    case storage = "storage"
    case crypto = "crypto"

    /// The client could not reach or speak to the local service at all.
    case transport = "__transport"

    /// The client rejected the request before it left the process.
    case client = "__client"
    case unknown = "__unknown"

    public static func fromWire(_ value: String?) -> KeyLeaseErrorCode {
        guard let value else { return .unknown }
        return KeyLeaseErrorCode(rawValue: value) ?? .unknown
    }
}

/// A failed local IPC call.
///
/// `payload` keeps the exact daemon payload so diagnostics stay faithful;
/// `code` is the routing decision the UI is allowed to make.
public struct KeyLeaseError: Error, Equatable, Sendable {
    public let payload: JSONValue
    public let code: KeyLeaseErrorCode

    public init(_ payload: JSONValue, code: KeyLeaseErrorCode = .client) {
        self.payload = payload
        self.code = code
    }

    public init(_ message: String, code: KeyLeaseErrorCode = .client) {
        self.init(.string(message), code: code)
    }

    public static func transport(_ message: String) -> KeyLeaseError {
        KeyLeaseError(message, code: .transport)
    }

    public static func fromDaemon(_ payload: JSONValue) -> KeyLeaseError {
        KeyLeaseError(
            payload,
            code: .fromWire(payload["error"]?.stringValue)
        )
    }

    /// The daemon's structured detail, if it sent one.
    public var details: [String: JSONValue]? { payload.objectValue }

    /// Redacted technical text for a diagnostics disclosure.
    public var diagnostics: String {
        (try? String(
            data: JSONEncoder().encode(payload),
            encoding: .utf8
        )) ?? "\(payload)"
    }
}
