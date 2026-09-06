import com.desfire.ev3.offline.deriveNxpAes128

/** Decode even-length public hexadecimal test data. */
private fun hex(value: String): ByteArray =
    value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

/** Run the published NXP AES-128 diversification vector through JNI. */
fun main() {
    val derived = deriveNxpAes128(
        hex("00112233445566778899aabbccddeeff"),
        hex("04782e21801d803042f54e585020416275"),
    )
    check(derived.contentEquals(hex("a8dd63a3b89d54b37ca802473fda9175")))
    derived.fill(0)
}
