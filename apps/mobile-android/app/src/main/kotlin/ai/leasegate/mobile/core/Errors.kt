package ai.leasegate.mobile.core

import org.json.JSONObject

/**
 * Stable error codes emitted by the service; the mirror of
 * `KeyLeaseErrorCode` in the shared Dart layer.
 */
enum class KeyLeaseErrorCode(val wire: String) {
    VAULT_LOCKED("vault_locked"),
    DENIED("denied"),
    APPROVAL_REQUIRED("approval_required"),
    REVISION_CONFLICT("revision_conflict"),
    INVALID_REQUEST("invalid_request"),
    UNSUPPORTED_VERSION("unsupported_version"),
    NOT_FOUND("not_found"),
    LEASE_EXPIRED("lease_expired"),
    LEASE_REVOKED("lease_revoked"),
    LEASE_EXHAUSTED("lease_exhausted"),
    IDEMPOTENCY_CONFLICT("idempotency_conflict"),
    CONNECTOR_UNAVAILABLE("connector_unavailable"),
    STORAGE("storage"),
    CRYPTO("crypto"),

    /** The client could not reach or speak to the local service at all. */
    TRANSPORT("__transport"),

    /** The client rejected the request before it left the process. */
    CLIENT("__client"),
    UNKNOWN("__unknown");

    companion object {
        fun fromWire(value: Any?): KeyLeaseErrorCode =
            entries.firstOrNull { it.wire == value } ?: UNKNOWN
    }
}

/**
 * A failed local IPC call. [payload] keeps the exact service payload so
 * diagnostics stay faithful; [code] is the routing decision the UI is
 * allowed to make.
 */
class KeyLeaseException(
    val payload: Any?,
    val code: KeyLeaseErrorCode = KeyLeaseErrorCode.CLIENT,
) : Exception() {
    /** The service's structured detail, if it sent one. */
    val details: JsonMap?
        get() = (payload as? Map<*, *>)?.let {
            @Suppress("UNCHECKED_CAST")
            it as JsonMap
        }

    /** Redacted technical text for a diagnostics disclosure. */
    val diagnostics: String
        get() = when (payload) {
            is Map<*, *>, is List<*> -> JSONObject.wrap(payload)?.toString() ?: "$payload"
            else -> "$payload"
        }

    override fun toString(): String = "KeyLease: ${diagnostics}"

    companion object {
        fun transport(payload: Any?) =
            KeyLeaseException(payload, KeyLeaseErrorCode.TRANSPORT)

        fun fromDaemon(payload: Any?) = KeyLeaseException(
            payload,
            KeyLeaseErrorCode.fromWire((payload as? Map<*, *>)?.get("error")),
        )
    }
}

/** Raised when the library reports it produced no response at all. */
class KeyLeaseNativeFailure(val operation: String) : Exception() {
    override fun toString(): String = "The vault library failed during $operation."
}

/** Raised when this build has no native implementation of a capability. */
class UnsupportedPlatformCapability(val capability: String) : Exception() {
    override fun toString(): String =
        "This build has no native $capability support on android."
}

class TotpQrCodeNotFound(val source: String) : Exception() {
    override fun toString(): String = "No TOTP QR code was found in the $source."
}
