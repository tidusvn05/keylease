package ai.leasegate.mobile.bridge

/**
 * The JNI surface of `libkeylease_mobile.so` (`crates/keylease-mobile`,
 * `jni` feature). Each call crosses into the same `open_json`/`call_json`/
 * `provision_json` cores the C ABI and the socket transport use.
 *
 * The owner credential never crosses this boundary: the Rust side holds it
 * and splices it into requests itself. A null return means the library
 * produced no output at all (the C ABI's `STATUS_FATAL`); every protocol and
 * policy error still arrives as an ordinary `{"ok":false,...}` envelope.
 */
object KeyleaseNative {
    init {
        System.loadLibrary("keylease_mobile")
    }

    @JvmStatic
    external fun open(path: String): String?

    @JvmStatic
    external fun call(handle: Long, request: String): String?

    @JvmStatic
    external fun provision(handle: Long, request: String): String?

    @JvmStatic
    external fun lock(handle: Long): Int

    @JvmStatic
    external fun close(handle: Long): Int
}
