package ai.leasegate.mobile.core

import java.io.File

/**
 * Non-secret UI preferences, in Android app-private storage.
 *
 * Port of `AppPreferencesStore`: the app's own directory is already 0700 and
 * owned by this uid alone, so no permission dance is needed.
 */
class PreferencesStore(directory: String) {
    private val path = "$directory/ui.json"

    suspend fun load(): JsonMap {
        return try {
            val file = File(path)
            if (!file.exists()) return emptyMap()
            jsonDecode(file.readText())
        } catch (_: Exception) {
            // Corrupt or unreadable preferences must never block start-up.
            emptyMap()
        }
    }

    suspend fun save(values: JsonMap) {
        try {
            val file = File(path)
            file.parentFile?.mkdirs()
            file.writeText(jsonEncode(values))
        } catch (_: Exception) {
            // Preferences are a convenience; failing to persist is not fatal.
        }
    }
}
