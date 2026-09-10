package ai.leasegate.vault

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

/**
 * The native half of `SecurityAdapter`, for the operations Dart cannot do
 * safely on its own.
 *
 * Only the clipboard lives here. A Dart `Timer` dies with the Flutter engine,
 * so a secret copied and then killed by the OS would stay on the clipboard
 * indefinitely — a real downgrade from the macOS guarantee that the field is
 * cleared after 30 seconds. Scheduling on a `Handler` tied to the application
 * context survives the engine.
 */
class SecurityPlugin(private val context: Context) : MethodChannel.MethodCallHandler {

    private val clipboard: ClipboardManager
        get() = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

    private val handler = Handler(Looper.getMainLooper())

    /** What we last wrote, so a clear cannot discard someone else's clipboard. */
    private var pending: String? = null
    private var pendingClear: Runnable? = null

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "copySensitive" -> {
                val value = call.argument<String>("value")
                val seconds = call.argument<Int>("clear_after_seconds") ?: 30
                if (value == null) {
                    result.error("invalid_request", "value is required", null)
                    return
                }
                copySensitive(value, seconds)
                result.success(true)
            }

            "clearSensitiveClipboard" -> {
                clearIfUnchanged()
                result.success(true)
            }

            else -> result.notImplemented()
        }
    }

    private fun copySensitive(value: String, clearAfterSeconds: Int) {
        val clip = ClipData.newPlainText(null, value).apply {
            // Suppresses the API 33+ "copied" preview toast, which would render
            // the secret on screen, and asks the system not to include it in
            // clipboard history.
            description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        clipboard.setPrimaryClip(clip)
        pending = value

        pendingClear?.let(handler::removeCallbacks)
        val clear = Runnable { clearIfUnchanged() }
        pendingClear = clear
        handler.postDelayed(clear, clearAfterSeconds.toLong() * 1000L)
    }

    /**
     * Clears the clipboard only if it still holds what we put there.
     *
     * Matches the macOS behaviour: if the user has copied something else in the
     * meantime, that is theirs and must not be wiped.
     */
    private fun clearIfUnchanged() {
        val expected = pending ?: return
        val current = clipboard.primaryClip
            ?.takeIf { it.itemCount > 0 }
            ?.getItemAt(0)
            ?.coerceToText(context)
            ?.toString()
        if (current == expected) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                clipboard.clearPrimaryClip()
            } else {
                clipboard.setPrimaryClip(ClipData.newPlainText(null, ""))
            }
        }
        pending = null
        pendingClear?.let(handler::removeCallbacks)
        pendingClear = null
    }

    companion object {
        /** Kept identical to the desktop channel so the Dart side is shared. */
        const val CHANNEL = "com.keylease/security"
    }
}
