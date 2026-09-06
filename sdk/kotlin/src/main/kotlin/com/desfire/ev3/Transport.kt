package com.desfire.ev3

/** Encoding of native DESFire commands at the reader boundary. */
public enum class Framing(public val code: Int) {
    NATIVE(0),
    ISO_WRAPPED(1),
}

/** Hard physical-frame bounds checked before native code sends a frame. */
public data class TransportLimits(
    public val framing: Framing = Framing.ISO_WRAPPED,
    public val maxTransmit: Int = 261,
    public val maxReceive: Int = 65_538,
    public val maxNativeFrame: Int = 60,
)

/**
 * One already activated card connection.
 *
 * [exchange] blocks for one physical reader exchange and receives its remaining deadline. It must
 * send the frame exactly once, return the complete physical response, and avoid reconnecting or
 * retrying. Throw [DesfireException] for known evidence; another exception becomes UNKNOWN.
 * [cancel] must be thread-safe and prompt. The owner closes the physical reader after its Card.
 */
public interface CardTransport {
    public val limits: TransportLimits

    /** Send one complete physical frame exactly once. */
    public fun exchange(frame: ByteArray, timeoutMs: Int): ByteArray

    /** Request interruption without waiting for the active exchange lock. */
    public fun cancel()

    /** Reset the activated card explicitly or report UNSUPPORTED. */
    public fun reset()
}
