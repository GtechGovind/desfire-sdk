package com.desfire.ev3

/** Exact native delivery evidence. [UNKNOWN] requires reconciliation before retrying a mutation. */
public enum class Outcome(public val code: Int) {
    NOT_SENT(0),
    REJECTED(1),
    SUCCEEDED(2),
    UNKNOWN(3),
}

/** Stable C ABI error codes exposed without remapping or collapsing failure categories. */
public enum class ErrorCode(public val code: Int) {
    INVALID_ARGUMENT(1),
    TRANSPORT(2),
    CARD_REMOVED(3),
    TIMEOUT(4),
    CANCELLED(5),
    MALFORMED_RESPONSE(6),
    CARD_REJECTED(7),
    AUTHENTICATION(8),
    INTEGRITY(9),
    UNSUPPORTED(10),
    STALE_HANDLE(11),
    BUSY(12),
    SESSION_INVALID(13),
    COUNTER_EXHAUSTED(14),
    BUFFER_TOO_SMALL(15),
    CRYPTO(16),
    INTERNAL(17),
}

/**
 * Redacted failure from exactly one SDK call.
 *
 * [code], [outcome], and [deviceStatus] preserve the C ABI values. The message contains no key
 * bytes, APDU payload, or provider diagnostic supplied by an untrusted callback.
 */
public class DesfireException(
    public val code: Int,
    public val outcome: Int,
    public val deviceStatus: Int,
    message: String,
) : RuntimeException(message) {
    /** Typed error code when this runtime recognizes the returned ABI value. */
    public val errorCode: ErrorCode?
        get() = ErrorCode.entries.firstOrNull { it.code == code }

    /** Typed delivery outcome when this runtime recognizes the returned ABI value. */
    public val deliveryOutcome: Outcome?
        get() = Outcome.entries.firstOrNull { it.code == outcome }
}

/**
 * A native invocation completed successfully, but its returned payload violated the Kotlin ABI
 * shape.
 *
 * For card operations this is post-I/O evidence and must not be reported as a pre-transmission
 * validation failure. Offline operations can raise the same exception without card I/O. Closing
 * and reopening a card is recommended when the malformed result affects card session state.
 */
public class MalformedNativeResultException(message: String) : RuntimeException(message)

/** Reject and clear a returned payload whose exact byte size differs from the ABI contract. */
internal fun requireNativeResultSize(result: ByteArray, expected: Int, message: String) {
    if (result.size != expected) {
        result.fill(0)
        throw MalformedNativeResultException(message)
    }
}

/** Reject a returned payload when the ABI contract requires no result bytes. */
internal fun requireEmptyNativeResult(result: ByteArray, message: String) {
    requireNativeResultSize(result, 0, message)
}
