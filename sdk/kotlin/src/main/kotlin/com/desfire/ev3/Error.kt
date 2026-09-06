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
