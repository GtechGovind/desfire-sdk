package com.desfire.ev3.example.domain.model

/** Parse bounded hexadecimal text with spaces, colons, dashes, or underscores. */
internal fun String.hexBytes(
    allowEmpty: Boolean = true,
    maximumBytes: Int = 64 * 1024,
): ByteArray {
    require(maximumBytes >= 0)
    require(length <= maximumBytes * 4L + 1_024L) {
        "Hexadecimal input exceeds the accepted formatted-text bound."
    }
    val compact = filterNot { it.isWhitespace() || it == ':' || it == '-' || it == '_' }
    require(allowEmpty || compact.isNotEmpty()) { "A hexadecimal value is required." }
    require(compact.length <= maximumBytes * 2L) {
        "Hexadecimal input exceeds $maximumBytes bytes."
    }
    require(compact.length % 2 == 0) { "Hexadecimal text must contain complete bytes." }
    require(compact.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
        "Hexadecimal text contains an invalid character."
    }
    return ByteArray(compact.length / 2) { index ->
        val high = compact[index * 2].digitToInt(16)
        val low = compact[index * 2 + 1].digitToInt(16)
        ((high shl 4) or low).toByte()
    }
}
