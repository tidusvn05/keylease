package ai.leasegate.mobile

import android.app.Application
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import ai.leasegate.mobile.core.PreferencesStore
import ai.leasegate.mobile.core.SecureClipboard
import ai.leasegate.mobile.core.VaultSession
import ai.leasegate.mobile.core.VaultStorage
import ai.leasegate.mobile.state.AppController

/**
 * The Android composition root — the counterpart of `buildAndroidController`.
 *
 * The whole UI observes [controller]; this class only decides which platform
 * implementations to give it: app-private storage, the in-process vault and
 * the conditional-clear clipboard.
 */
class KeyleaseApplication : Application() {
    lateinit var session: VaultSession
        private set
    lateinit var storage: VaultStorage
        private set
    lateinit var controller: AppController
        private set

    override fun onCreate() {
        super.onCreate()
        val support = filesDir.absolutePath
        session = VaultSession()
        storage = VaultStorage(session, support)
        controller = AppController(
            session = session,
            storage = storage,
            preferences = PreferencesStore(support),
            clipboard = SecureClipboard(this),
        )

        // Process-level lifecycle: any move to the background hides revealed
        // secrets and locks, matching the Flutter observer's paused/hidden
        // handling — screen-off is indistinguishable from a normal pause.
        ProcessLifecycleOwner.get().lifecycle.addObserver(
            object : DefaultLifecycleObserver {
                override fun onStart(owner: LifecycleOwner) =
                    controller.onProcessLifecycle(foregrounded = true)

                override fun onStop(owner: LifecycleOwner) =
                    controller.onProcessLifecycle(foregrounded = false)
            },
        )
        controller.start()
    }
}
