package ai.leasegate.mobile.state

import kotlin.coroutines.resume
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * Camera TOTP scan plumbing.
 *
 * `scan()` suspends until the Compose camera overlay decodes a QR code or
 * the user dismisses it — the same shape as the Flutter adapter's
 * `scanTotpQrCodeFromCamera`. Only `otpauth://` codes are accepted; anything
 * else keeps the camera running instead of feeding a stray QR into TOTP.
 */
class QrScanCoordinator {
    private val _pending = MutableStateFlow<CancellableContinuation<String?>?>(null)

    /** Non-null while the camera overlay should be on screen. */
    val pending: StateFlow<CancellableContinuation<String?>?> = _pending.asStateFlow()

    suspend fun scan(): String? = suspendCancellableCoroutine { cont ->
        _pending.value?.resume(null)
        _pending.value = cont
        cont.invokeOnCancellation { _pending.compareAndSet(cont, null) }
    }

    /** Called by the overlay with a decoded `otpauth://` URI, or null. */
    fun complete(uri: String?) {
        val cont = _pending.value ?: return
        _pending.value = null
        cont.resume(uri)
    }
}
