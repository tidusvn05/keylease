package ai.leasegate.vault

import android.os.Bundle
import android.view.WindowManager
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
    }
}
