package ai.leasegate.mobile.core

import ai.leasegate.mobile.bridge.KeyleaseNative
import java.util.concurrent.Executors
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.withContext

/**
 * Owns the vault handle on a single worker thread.
 *
 * Every JNI call blocks its calling thread — `call` runs the Rust dispatch to
 * completion — so calls are confined to one dedicated dispatcher. One
 * long-lived worker also matches the store's real concurrency: `NativeStore`
 * is a single mutex, so there is nothing to gain from more. This is the
 * direct counterpart of `VaultIsolate` in the Flutter client.
 */
class VaultSession {
    private val executor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "keylease-vault").apply { isDaemon = true }
    }
    private val dispatcher: CoroutineDispatcher = executor.asCoroutineDispatcher()

    @Volatile
    private var handle: Long = 0L

    val isOpen: Boolean get() = handle != 0L

    /** Opens the vault at [databasePath] and returns the response envelope. */
    suspend fun openVault(databasePath: String): JsonMap = withContext(dispatcher) {
        // Switching profiles reuses the worker but never the native handle or
        // its decrypted session state.
        closeLocked()
        val raw = KeyleaseNative.open(databasePath)
            ?: throw KeyLeaseNativeFailure("open")
        val envelope = jsonDecode(raw)
        if (envelope["ok"] == true) {
            handle = (envelope.map("result")?.get("handle") as? Number)?.toLong() ?: 0L
        }
        envelope
    }

    suspend fun call(request: JsonMap): JsonMap = send(request, "call", KeyleaseNative::call)

    suspend fun provision(request: JsonMap): JsonMap =
        send(request, "provision", KeyleaseNative::provision)

    suspend fun lock() = withContext(dispatcher) {
        if (handle != 0L) KeyleaseNative.lock(handle)
    }

    /** Closes the vault and shuts the worker down. */
    suspend fun dispose() {
        withContext(dispatcher) { closeLocked() }
        executor.shutdown()
    }

    private suspend fun send(
        request: JsonMap,
        operation: String,
        fn: (Long, String) -> String?,
    ): JsonMap = withContext(dispatcher) {
        // The request may carry a master password; the native side copies it
        // out of the JVM string, and Kotlin cannot zeroise a String — this is
        // the same exposure the Dart heap already has.
        val raw = fn(handle, jsonEncode(request)) ?: throw KeyLeaseNativeFailure(operation)
        try {
            jsonDecode(raw)
        } catch (caught: Throwable) {
            android.util.Log.e("KeyLease", "jsonDecode failed for $operation (${raw.length}B)", caught)
            throw caught
        }
    }

    private fun closeLocked() {
        if (handle == 0L) return
        KeyleaseNative.close(handle)
        handle = 0L
    }
}

/**
 * The mobile transport. Sends exactly the requests the desktop socket client
 * sends; the auth block is spliced in on the Rust side.
 */
class KeyLeaseClient(
    private val vault: VaultSession,
    private val onUnlocked: suspend (JsonMap) -> Unit = {},
) {
    suspend fun unlock(password: String, sessionTtlSeconds: Int = 900): JsonMap {
        val response = vault.provision(
            mapOf(
                "provision" to "unlock_owner",
                "password" to password,
                "session_ttl_seconds" to sessionTtlSeconds,
            ),
        )
        if (response["ok"] == false) throw KeyLeaseException.fromDaemon(response["error"])
        @Suppress("UNCHECKED_CAST")
        val result = (response["result"] as? JsonMap) ?: emptyMap()
        onUnlocked(result)
        return result
    }

    /** Sends [request]; the Rust side attaches the `auth` block. */
    suspend fun authorized(request: JsonMap): Any? = send(request)

    /** Sends [request] without an `auth` block. Only `status` qualifies. */
    suspend fun unauthenticated(request: JsonMap): Any? = send(request)

    private suspend fun send(request: JsonMap): Any? {
        val response = vault.call(request)
        if (response["ok"] == false) throw KeyLeaseException.fromDaemon(response["error"])
        return response["result"]
    }
}
