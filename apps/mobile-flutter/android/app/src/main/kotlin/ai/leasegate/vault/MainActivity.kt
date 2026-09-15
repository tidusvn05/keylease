package ai.leasegate.vault

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import java.io.File
import java.util.UUID
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * The vault activity.
 *
 * [FlutterFragmentActivity] rather than `FlutterActivity` because biometric
 * prompts and the camera scanner are fragment-based.
 */
class MainActivity : FlutterFragmentActivity() {
    private var pendingVaultFile: MethodChannel.Result? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        // FLAG_SECURE blocks screenshots and screen recording, and blanks the
        // window in the recents switcher — which otherwise keeps a thumbnail of
        // whatever entry was open. Set before super.onCreate so the very first
        // frame is covered.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        super.onCreate(savedInstanceState)
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            SecurityPlugin.CHANNEL,
        ).setMethodCallHandler(SecurityPlugin(applicationContext))

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            BiometricVaultPlugin.CHANNEL,
        ).setMethodCallHandler(BiometricVaultPlugin(this))

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            RUNTIME_CHANNEL,
        ).setMethodCallHandler { call, result ->
            when (call.method) {
                "chooseVaultSource" -> chooseVaultSource(result)
                else -> result.notImplemented()
            }
        }
    }

    private fun chooseVaultSource(result: MethodChannel.Result) {
        if (pendingVaultFile != null) {
            result.error("busy", "A file chooser is already open", null)
            return
        }
        pendingVaultFile = result
        startActivityForResult(
            Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "*/*"
            },
            PICK_VAULT_FILE,
        )
    }

    @Deprecated("Activity result API retained for FlutterFragmentActivity compatibility")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != PICK_VAULT_FILE) return
        val result = pendingVaultFile ?: return
        pendingVaultFile = null
        val uri = data?.data
        if (resultCode != Activity.RESULT_OK || uri == null) {
            result.success(null)
            return
        }
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
            result.success(targetFile.absolutePath)
        } catch (error: Exception) {
            target?.delete()
            result.error("invalid_source", error.message ?: "The selected file could not be imported", null)
        }
    }

    companion object {
        private const val RUNTIME_CHANNEL = "com.keylease/runtime"
        private const val PICK_VAULT_FILE = 7301
        private const val MAX_IMPORT_BYTES = 64L * 1024L * 1024L
    }
}
