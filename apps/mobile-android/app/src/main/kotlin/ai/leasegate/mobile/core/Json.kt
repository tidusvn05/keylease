package ai.leasegate.mobile.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * The wire format is the same JSON document the desktop socket carries.
 * Requests are built as `Map<String, Any?>` and responses arrive the same
 * way, matching the dynamic `Map<String, dynamic>` the shared Dart layer
 * uses.
 */

typealias JsonMap = Map<String, Any?>

fun JSONObject.toMap(): JsonMap {
    val out = LinkedHashMap<String, Any?>(length())
    for (key in keys()) {
        out[key] = unwrap(get(key))
    }
    return out
}

fun JSONArray.toList(): List<Any?> {
    val out = ArrayList<Any?>(length())
    for (i in 0 until length()) out.add(unwrap(get(i)))
    return out
}

private fun unwrap(value: Any?): Any? = when (value) {
    JSONObject.NULL -> null
    is JSONObject -> value.toMap()
    is JSONArray -> value.toList()
    else -> value
}

fun jsonEncode(map: JsonMap): String = JSONObject(map).toString()

fun jsonDecode(text: String): JsonMap = JSONObject(text).toMap()

fun JsonMap?.string(key: String): String? =
    this?.get(key)?.let { it as? String ?: it.toString() }

fun JsonMap?.int(key: String): Int? = (this?.get(key) as? Number)?.toInt()

fun JsonMap?.bool(key: String): Boolean? = this?.get(key) as? Boolean

fun JsonMap?.map(key: String): JsonMap? =
    (this?.get(key) as? Map<*, *>)?.let { value ->
        @Suppress("UNCHECKED_CAST")
        value as JsonMap
    }

fun JsonMap?.list(key: String): List<Any?> = this?.get(key) as? List<Any?> ?: emptyList()

fun JsonMap?.strings(key: String): List<String> = list(key).map { it.toString() }

fun JsonMap?.stringList(key: String): List<String> =
    (this?.get(key) as? List<*>)?.map { it.toString() } ?: emptyList()
