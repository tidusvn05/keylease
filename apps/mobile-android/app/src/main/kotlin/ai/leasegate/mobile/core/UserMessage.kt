package ai.leasegate.mobile.core

/**
 * A failure rendered in the user's language, with the technical payload kept
 * for a diagnostics disclosure instead of the headline. Direct port of
 * `UserMessage` from the shared Dart layer.
 */
data class UserMessage(
    val title: String,
    val detail: String,
    val actionLabel: String? = null,
    val diagnostics: String? = null,
) {
    companion object {
        fun fromUnlock(error: Throwable): UserMessage {
            if (error is KeyLeaseException) {
                val reason = error.details?.get("reason")
                if (error.code == KeyLeaseErrorCode.CRYPTO ||
                    (error.code == KeyLeaseErrorCode.DENIED && reason == "master password rejected")
                ) {
                    return UserMessage(
                        title = "Incorrect master password",
                        detail = "Check your password and try again.",
                        diagnostics = error.diagnostics,
                    )
                }
                if (error.code == KeyLeaseErrorCode.DENIED &&
                    reason is String && reason.contains("unlock rate limit")
                ) {
                    return UserMessage(
                        title = "Too many unlock attempts",
                        detail = "Wait a minute, then try again.",
                        diagnostics = error.diagnostics,
                    )
                }
            }
            return from(error)
        }

        fun from(error: Throwable): UserMessage {
            when (error) {
                is UnsupportedPlatformCapability -> return UserMessage(
                    title = "Not available in this build",
                    detail = "$error",
                )
                is TotpQrCodeNotFound -> return UserMessage(
                    title = "No TOTP QR code found",
                    detail = "Make sure the QR code is visible and unobstructed, then try " +
                        "again. You can also choose an image file.",
                    diagnostics = "$error",
                )
                is SecurityException -> return UserMessage(
                    title = "Permission denied by Android",
                    detail = error.message ?: "The system refused this action.",
                    diagnostics = "$error",
                )
            }
            if (error !is KeyLeaseException) {
                return UserMessage(
                    title = "Something went wrong",
                    detail = "The app could not finish that action.",
                    diagnostics = "$error",
                )
            }
            val reason = error.details?.get("reason")
            return when (error.code) {
                KeyLeaseErrorCode.TRANSPORT -> UserMessage(
                    title = "Can't reach KeyLease",
                    detail = "The local KeyLease service did not answer. Make sure it is " +
                        "running, then try connecting again.",
                    actionLabel = "Try again",
                    diagnostics = error.diagnostics,
                )
                KeyLeaseErrorCode.CLIENT -> UserMessage(
                    title = "Check the connection settings",
                    detail = "${error.payload}",
                )
                KeyLeaseErrorCode.VAULT_LOCKED -> UserMessage(
                    title = "Vault locked",
                    detail = "Unlock the vault to continue.",
                    actionLabel = "Unlock",
                    diagnostics = error.diagnostics,
                )
                KeyLeaseErrorCode.DENIED -> UserMessage(
                    title = "Permission needed",
                    detail = if (reason is String && reason.isNotEmpty()) {
                        "This client is not allowed to do that: $reason"
                    } else {
                        "This client is not allowed to do that."
                    },
                    actionLabel = "Review connection settings",
                    diagnostics = error.diagnostics,
                )
                KeyLeaseErrorCode.APPROVAL_REQUIRED -> UserMessage(
                    title = "Approval required",
                    detail = "Someone must approve this exact request before it can run.",
                    actionLabel = "Open Approvals",
                    diagnostics = error.diagnostics,
                )
                KeyLeaseErrorCode.REVISION_CONFLICT -> UserMessage(
                    title = "This item changed elsewhere",
                    detail = "Your draft was kept. Reload the item to see the newer version, " +
                        "then save again.",
                    actionLabel = "Reload",
                )
                KeyLeaseErrorCode.INVALID_REQUEST -> UserMessage(
                    title = "Check what you entered",
                    detail = if (reason is String && reason.isNotEmpty()) {
                        reason
                    } else {
                        "The service rejected these details."
                    },
                    diagnostics = error.diagnostics,
                )
                KeyLeaseErrorCode.NOT_FOUND -> UserMessage(
                    title = "Not found",
                    detail = "That item is no longer in the vault.",
                )
                KeyLeaseErrorCode.IDEMPOTENCY_CONFLICT -> UserMessage(
                    title = "Already submitted",
                    detail = "That change was already sent. Refresh to see the result.",
                    actionLabel = "Refresh",
                )
                KeyLeaseErrorCode.CONNECTOR_UNAVAILABLE -> UserMessage(
                    title = "Provider unavailable",
                    detail = "KeyLease could not reach that provider. Try again shortly.",
                    actionLabel = "Try again",
                    diagnostics = error.diagnostics,
                )
                KeyLeaseErrorCode.LEASE_EXPIRED,
                KeyLeaseErrorCode.LEASE_REVOKED,
                KeyLeaseErrorCode.LEASE_EXHAUSTED,
                -> UserMessage(
                    title = "Access window closed",
                    detail = "That access grant is no longer usable. Request a new one.",
                    diagnostics = error.diagnostics,
                )
                KeyLeaseErrorCode.UNSUPPORTED_VERSION -> UserMessage(
                    title = "Update needed",
                    detail = "The local service speaks a version this app does not support.",
                    diagnostics = error.diagnostics,
                )
                KeyLeaseErrorCode.STORAGE, KeyLeaseErrorCode.CRYPTO -> UserMessage(
                    title = "The vault could not complete that",
                    detail = "KeyLease stopped the action to protect your data.",
                    diagnostics = error.diagnostics,
                )
                KeyLeaseErrorCode.UNKNOWN -> UserMessage(
                    title = "Something went wrong",
                    detail = "The local service reported an error it could not explain.",
                    diagnostics = error.diagnostics,
                )
            }
        }
    }
}
