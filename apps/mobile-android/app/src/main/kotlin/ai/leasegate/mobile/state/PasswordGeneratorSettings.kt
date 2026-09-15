package ai.leasegate.mobile.state

import ai.leasegate.mobile.core.JsonMap

enum class PasswordPattern(val wire: String) {
    RANDOM("random"),
    WORDS("words"),
    PIN("pin"),
}

/** Port of `PasswordGeneratorSettings` — same defaults, same recipe shape. */
data class PasswordGeneratorSettings(
    val pattern: PasswordPattern = PasswordPattern.RANDOM,
    val length: Int = 24,
    val wordCount: Int = 5,
    val pinLength: Int = 6,
    val separator: String = "-",
    val uppercase: Boolean = true,
    val lowercase: Boolean = true,
    val numbers: Boolean = true,
    val symbols: Boolean = true,
    val avoidAmbiguous: Boolean = true,
    val capitalize: Boolean = false,
    val wordNumber: Boolean = true,
) {
    val requestLength: Int get() = if (pattern == PasswordPattern.PIN) pinLength else length

    val recipe: Map<String, Any?>
        get() = when (pattern) {
            PasswordPattern.RANDOM -> mapOf(
                "type" to "random",
                "length" to length,
                "uppercase" to uppercase,
                "lowercase" to lowercase,
                "numbers" to numbers,
                "symbols" to symbols,
                "avoid_ambiguous" to avoidAmbiguous,
            )
            PasswordPattern.WORDS -> mapOf(
                "type" to "words",
                "count" to wordCount,
                "separator" to separator,
                "capitalize" to capitalize,
                "include_number" to wordNumber,
            )
            PasswordPattern.PIN -> mapOf("type" to "pin", "length" to pinLength)
        }

    fun toJson(): JsonMap = mapOf(
        "pattern" to pattern.wire,
        "length" to length,
        "word_count" to wordCount,
        "pin_length" to pinLength,
        "separator" to separator,
        "uppercase" to uppercase,
        "lowercase" to lowercase,
        "numbers" to numbers,
        "symbols" to symbols,
        "avoid_ambiguous" to avoidAmbiguous,
        "capitalize" to capitalize,
        "word_number" to wordNumber,
    )

    companion object {
        private val lengths = setOf(16, 20, 24, 32, 40, 64)
        private val wordCounts = setOf(3, 4, 5, 6, 7, 8)
        private val pinLengths = setOf(4, 6, 8, 10, 12)
        private val separators = setOf("-", " ", ".", "_")

        fun fromJson(value: Any?): PasswordGeneratorSettings {
            if (value !is Map<*, *>) return PasswordGeneratorSettings()
            val json = value as Map<String, Any?>
            val rawLength = (json["length"] as? Number)?.toInt()
            val rawWordCount = (json["word_count"] as? Number)?.toInt()
            val rawPinLength = (json["pin_length"] as? Number)?.toInt()
            val rawSeparator = json["separator"] as? String
            return PasswordGeneratorSettings(
                pattern = when (json["pattern"]) {
                    "words" -> PasswordPattern.WORDS
                    "pin" -> PasswordPattern.PIN
                    else -> PasswordPattern.RANDOM
                },
                length = if (rawLength in lengths) rawLength!! else 24,
                wordCount = if (rawWordCount in wordCounts) rawWordCount!! else 5,
                pinLength = if (rawPinLength in pinLengths) rawPinLength!! else 6,
                separator = if (rawSeparator in separators) rawSeparator!! else "-",
                uppercase = json["uppercase"] != false,
                lowercase = json["lowercase"] != false,
                numbers = json["numbers"] != false,
                symbols = json["symbols"] != false,
                avoidAmbiguous = json["avoid_ambiguous"] != false,
                capitalize = json["capitalize"] == true,
                wordNumber = json["word_number"] != false,
            )
        }
    }
}
