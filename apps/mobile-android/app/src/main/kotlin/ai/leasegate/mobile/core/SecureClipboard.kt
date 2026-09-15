package ai.leasegate.mobile.core

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle

/**
 * The conditional secret clipboard. Direct port of `SecurityPlugin.kt` —
 * the clear-after timer is scheduled on a `Handler` tied to the application
 * context so it outlives the composition (and now there is no Flutter engine
 * to outlive, the same guarantee holds across activity recreation).
 *
 * The UI never writes secrets to the clipboard itself: every copy goes
 * through here so the conditional clear stays in force.
 */
class SecureClipboard(context: Context) {
    private val appContext = context.applicationContext
    private val clipboard: ClipboardManager
        get() = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

    private val handler = Handler(Looper.getMainLooper())

    /** What we last wrote, so a clear cannot discard someone else's clipboard. */
    private var pending: String? = null
    private var pendingClear: Runnable? = null

    fun copySensitive(value: String, clearAfterSeconds: Int = 30) {
        val clip = ClipData.newPlainText(null, value).apply {
            // Suppresses the API 33+ "copied" preview toast, which would
            // render the secret on screen, and asks the system not to include
            // it in clipboard history.
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
     * Clears the clipboard only if it still holds what we put there: if the
     * user has copied something else in the meantime, that is theirs and must
     * not be wiped.
     */
    fun clearIfUnchanged() {
        val expected = pending ?: return
        val current = clipboard.primaryClip
            ?.takeIf { it.itemCount > 0 }
            ?.getItemAt(0)
            ?.coerceToText(appContext)
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
}
