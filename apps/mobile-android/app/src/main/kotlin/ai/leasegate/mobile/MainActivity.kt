package ai.leasegate.mobile

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.net.toUri
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import ai.leasegate.mobile.core.BiometricVault
import ai.leasegate.mobile.core.KeyLeaseException
import ai.leasegate.mobile.ui.KeyleaseApp
import java.io.File
import java.util.UUID
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.withContext

/**
 * The vault activity.
 *
 * [FragmentActivity] rather than `ComponentActivity` because biometric
 * prompts are fragment-based. FLAG_SECURE is set before `super.onCreate` so
 * the very first frame is covered: it blocks screenshots and blanks the
 * window in the recents switcher.
 */
class MainActivity : FragmentActivity() {
    private val controller get() = (application as KeyleaseApplication).controller
    private var pendingVaultFile: CancellableContinuation<String?>? = null
    private var pendingQrImage: CancellableContinuation<String?>? = null

    private val pickVaultFile = registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        val pending = pendingVaultFile ?: return@registerForActivityResult
        pendingVaultFile = null
        if (uri == null) {
            pending.resume(null)
            return@registerForActivityResult
        }
        // The copy can be large; keep it off the main thread.
        lifecycleScope.launch {
            try {
                pending.resume(withContext(Dispatchers.IO) { importToPrivate(uri) })
            } catch (error: Exception) {
                pending.resumeWithException(error)
            }
        }
    }

    private val pickQrImage = registerForActivityResult(
        ActivityResultContracts.GetContent(),
    ) { uri ->
        val pending = pendingQrImage ?: return@registerForActivityResult
        pendingQrImage = null
        if (uri == null) {
            pending.resume(null)
            return@registerForActivityResult
        }
        lifecycleScope.launch {
            try {
                pending.resume(withContext(Dispatchers.IO) { decodeQrImage(uri) })
            } catch (error: Exception) {
                pending.resumeWithException(error)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        super.onCreate(savedInstanceState)
        controller.biometric = BiometricVault(this)
        controller.chooseVaultSource = ::chooseVaultSource
        controller.openExternalUrl = ::openExternalUrl
        controller.scanTotpFromImage = ::scanTotpFromImage
        setContent {
            KeyleaseApp(controller)
        }
    }

    /** Any touch defers the foreground idle lock. */
    override fun onUserInteraction() {
        super.onUserInteraction()
        controller.noteActivity()
    }

    private suspend fun chooseVaultSource(): String? = suspendCancellableCoroutine { cont ->
        if (pendingVaultFile != null) {
            cont.resumeWithException(KeyLeaseException("A file chooser is already open"))
            return@suspendCancellableCoroutine
        }
        pendingVaultFile = cont
        cont.invokeOnCancellation { pendingVaultFile = null }
        try {
            pickVaultFile.launch(arrayOf("*/*"))
        } catch (error: ActivityNotFoundException) {
            pendingVaultFile = null
            cont.resumeWithException(KeyLeaseException("No file picker is available"))
        }
    }

    /**
     * Copies a user-picked document into app-private `imports/` — the vault
     * must never be reachable from shared storage. Over-large or unreadable
     * sources are cleaned up rather than left half-written.
     */
    private fun importToPrivate(uri: Uri): String {
        var target: File? = null
        try {
            val importDir = File(filesDir, "imports").apply { mkdirs() }
            val targetFile = File(importDir, "${UUID.randomUUID()}.source")
            target = targetFile
            contentResolver.openInputStream(uri).use { input ->
                requireNotNull(input) { "The selected file cannot be opened" }
                targetFile.outputStream().use { output ->
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    var total = 0L
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        total += count
                        require(total <= MAX_IMPORT_BYTES) { "The selected file exceeds 64 MiB" }
                        output.write(buffer, 0, count)
                    }
                }
            }
            return targetFile.absolutePath
        } catch (error: Exception) {
            target?.delete()
            throw error
        }
    }

    /**
     * The image path of TOTP scanning: the user picks a saved QR screenshot
     * and ML Kit decodes it on-device. Returns the `otpauth://` URI, or null
     * when the pick was cancelled or no usable code was found.
     */
    private suspend fun scanTotpFromImage(): String? = suspendCancellableCoroutine { cont ->
        if (pendingQrImage != null) {
            cont.resumeWithException(KeyLeaseException("A file chooser is already open"))
            return@suspendCancellableCoroutine
        }
        pendingQrImage = cont
        cont.invokeOnCancellation { pendingQrImage = null }
        try {
            pickQrImage.launch("image/*")
        } catch (error: ActivityNotFoundException) {
            pendingQrImage = null
            cont.resumeWithException(KeyLeaseException("No image picker is available"))
        }
    }

    private suspend fun decodeQrImage(uri: Uri): String? {
        val image = com.google.mlkit.vision.common.InputImage.fromFilePath(this, uri)
        val barcodes =
            com.google.mlkit.vision.barcode.BarcodeScanning.getClient().process(image).await()
        return barcodes.firstOrNull { it.rawValue?.startsWith("otpauth://") == true }
            ?.rawValue
    }

    private suspend fun openExternalUrl(url: String): Boolean {
        val intent = Intent(Intent.ACTION_VIEW, url.toUri())
            .addCategory(Intent.CATEGORY_BROWSABLE)
        return try {
            startActivity(intent)
            true
        } catch (_: ActivityNotFoundException) {
            false
        }
    }

    companion object {
        private const val MAX_IMPORT_BYTES = 64L * 1024L * 1024L
    }
}
