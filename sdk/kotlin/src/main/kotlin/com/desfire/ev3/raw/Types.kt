package com.desfire.ev3.raw

import com.desfire.ev3.AuthenticationInfo
import com.desfire.ev3.Communication
import com.desfire.ev3.Framing
import com.desfire.ev3.MalformedNativeResultException

/** Native response with its exact final status byte and deterministically disposable data. */
public class NativeResponse(public val status: Int, data: ByteArray) : AutoCloseable {
    init {
        require(status in 0..0xFF) { "Native status must fit one byte" }
    }

    private var responseBytes = data.copyOf()
    private var closed = false

    /** Status-free response bytes; the caller owns and must clear the returned copy. */
    public val data: ByteArray
        @Synchronized get() {
            check(!closed) { "Native response is closed" }
            return responseBytes.copyOf()
        }

    /** Run one callback with a temporary data copy and overwrite that copy before returning. */
    public fun <T> useData(operation: (ByteArray) -> T): T {
        val snapshot = data
        return try {
            operation(snapshot)
        } finally {
            snapshot.fill(0)
        }
    }

    /** Overwrite the response-owned data; repeated calls are safe. */
    @Synchronized
    override fun close() {
        if (closed) return
        responseBytes.fill(0)
        responseBytes = byteArrayOf()
        closed = true
    }
}

/** ISO/IEC 7816 response with its exact final status word and disposable data. */
public class IsoResponse(public val status: Int, data: ByteArray) : AutoCloseable {
    init {
        require(status in 0..0xFFFF) { "ISO status must fit two bytes" }
    }

    private var responseBytes = data.copyOf()
    private var closed = false

    /** Response data before SW1/SW2; the caller owns and must clear the returned copy. */
    public val data: ByteArray
        @Synchronized get() {
            check(!closed) { "ISO response is closed" }
            return responseBytes.copyOf()
        }

    /** Run one callback with a temporary data copy and overwrite that copy before returning. */
    public fun <T> useData(operation: (ByteArray) -> T): T {
        val snapshot = data
        return try {
            operation(snapshot)
        } finally {
            snapshot.fill(0)
        }
    }

    /** True only for ISO success status 9000. */
    public val successful: Boolean
        get() = status == 0x9000

    /** Overwrite the response-owned data; repeated calls are safe. */
    @Synchronized
    override fun close() {
        if (closed) return
        responseBytes.fill(0)
        responseBytes = byteArrayOf()
        closed = true
    }
}

/** Explicit short, extended, or automatically selected ISO APDU length encoding. */
public enum class LengthEncoding(internal val code: Int) {
    AUTOMATIC(0),
    SHORT(1),
    EXTENDED(2),
}

/** Active raw secure-session family used by an explicit secure request. */
public enum class SecureProfile(internal val code: Int) {
    STANDARD_AES(1),
    EV2(2),
}

/**
 * Unprotected native logical command with explicit chaining and response bounds.
 *
 * [singleContinuation] permits at most one caller-requested additional frame. No continuation is
 * inferred from a command number. Close this descriptor after its admitted operation completes;
 * racing [close] with an active operation is invalid.
 */
public class NativeRequest(
    public val framing: Framing,
    public val command: Int,
    data: ByteArray = byteArrayOf(),
    public val maximumResponse: Long,
    public val firstFrameDataSize: Long? = null,
    public val singleContinuation: Boolean = false,
) : AutoCloseable {
    init {
        require(command in 0..0xFF) { "Native command must fit one byte" }
        require(data.size <= 16 * 1024 * 1024) { "Native data exceeds sixteen MiB" }
        require(maximumResponse in 1..16L * 1024 * 1024) { "Invalid maximum response" }
        require(firstFrameDataSize == null || firstFrameDataSize in 0..data.size.toLong()) {
            "First-frame boundary must be inside the request data"
        }
    }

    private var dataMaterial = data.copyOf()
    private var closed = false

    /** Request-owned data used only by the binding call; concurrent close is invalid. */
    internal val dataBytes: ByteArray
        @Synchronized get() {
            check(!closed) { "Native request is closed" }
            return dataMaterial
        }

    /** Overwrite the request-owned data; repeated calls are safe. */
    @Synchronized
    override fun close() {
        if (closed) return
        dataMaterial.fill(0)
        dataMaterial = byteArrayOf()
        closed = true
    }
}

/**
 * Exact true ISO/IEC 7816 command APDU and continuation policy.
 * Close this descriptor after its admitted operation completes; concurrent close is invalid.
 */
public class IsoApdu(
    public val cla: Int,
    public val ins: Int,
    public val p1: Int,
    public val p2: Int,
    data: ByteArray = byteArrayOf(),
    public val le: Int? = null,
    public val lengthEncoding: LengthEncoding = LengthEncoding.AUTOMATIC,
    public val correctLength: Boolean = false,
    public val maximumResponse: Long = 65_536,
    public val maximumFrames: Long = 256,
) : AutoCloseable {
    init {
        require(cla in 0..0xFF && ins in 0..0xFF && p1 in 0..0xFF && p2 in 0..0xFF) {
            "ISO APDU header fields must fit one byte"
        }
        require(data.size <= 65_535) { "ISO APDU data exceeds 65535 bytes" }
        require(le == null || le in 1..65_536) { "ISO Le must be between one and 65536" }
        require(maximumResponse in 1..16L * 1024 * 1024) { "Invalid maximum response" }
        require(maximumFrames in 1..65_536) { "Invalid maximum frame count" }
    }

    private var dataMaterial = data.copyOf()
    private var closed = false

    /** Request-owned APDU data used only by the binding call; concurrent close is invalid. */
    internal val dataBytes: ByteArray
        @Synchronized get() {
            check(!closed) { "ISO APDU is closed" }
            return dataMaterial
        }

    /** Overwrite the request-owned data; repeated calls are safe. */
    @Synchronized
    override fun close() {
        if (closed) return
        dataMaterial.fill(0)
        dataMaterial = byteArrayOf()
        closed = true
    }
}

/**
 * Explicit secure-native request with no inferred command semantics.
 *
 * The caller declares clear header bytes, protected data bytes, both communication policies,
 * response bounds, chaining boundary, and whether success invalidates the active session.
 * Close this descriptor after its admitted operation completes; concurrent close is invalid.
 */
public class SecureNativeRequest(
    public val profile: SecureProfile,
    public val command: Int,
    header: ByteArray = byteArrayOf(),
    data: ByteArray = byteArrayOf(),
    public val requestCommunication: Communication,
    public val responseCommunication: Communication,
    public val minimumResponse: Long = 0,
    public val maximumResponse: Long,
    public val firstFrameDataSize: Long? = null,
    public val singleContinuation: Boolean = false,
    public val invalidatesSession: Boolean = false,
) : AutoCloseable {
    init {
        require(command in 0..0xFF) { "Native command must fit one byte" }
        require(header.size + data.size <= 16 * 1024 * 1024) {
            "Secure request exceeds sixteen MiB"
        }
        require(minimumResponse >= 0 && maximumResponse >= minimumResponse &&
            maximumResponse <= 16L * 1024 * 1024) { "Invalid secure response bounds" }
        require(firstFrameDataSize == null || firstFrameDataSize >= 0) {
            "First-frame boundary cannot be negative"
        }
    }

    private var headerMaterial = header.copyOf()
    private var dataMaterial = data.copyOf()
    private var closed = false

    /** Request-owned clear header used only by the binding call; concurrent close is invalid. */
    internal val headerBytes: ByteArray
        @Synchronized get() {
            check(!closed) { "Secure native request is closed" }
            return headerMaterial
        }

    /** Request-owned protected data used only by the binding call; concurrent close is invalid. */
    internal val dataBytes: ByteArray
        @Synchronized get() {
            check(!closed) { "Secure native request is closed" }
            return dataMaterial
        }

    /** Overwrite the request-owned header and data; repeated calls are safe. */
    @Synchronized
    override fun close() {
        if (closed) return
        headerMaterial.fill(0)
        dataMaterial.fill(0)
        headerMaterial = byteArrayOf()
        dataMaterial = byteArrayOf()
        closed = true
    }
}

/** Decode a four-byte little-endian status prefix followed by response bytes. */
internal fun decodeNativeResponse(bytes: ByteArray): NativeResponse {
    try {
        if (bytes.size < 4) throw MalformedNativeResultException("Malformed raw native response")
        val status = (bytes[0].toInt() and 0xFF) or
            ((bytes[1].toInt() and 0xFF) shl 8) or
            ((bytes[2].toInt() and 0xFF) shl 16) or
            ((bytes[3].toInt() and 0xFF) shl 24)
        val response = bytes.copyOfRange(4, bytes.size)
        return try {
            NativeResponse(status, response)
        } finally {
            response.fill(0)
        }
    } finally {
        bytes.fill(0)
    }
}

/** Decode a four-byte little-endian ISO status prefix followed by response bytes. */
internal fun decodeIsoResponse(bytes: ByteArray): IsoResponse {
    try {
        if (bytes.size < 4) throw MalformedNativeResultException("Malformed raw ISO response")
        val status = (bytes[0].toInt() and 0xFF) or
            ((bytes[1].toInt() and 0xFF) shl 8) or
            ((bytes[2].toInt() and 0xFF) shl 16) or
            ((bytes[3].toInt() and 0xFF) shl 24)
        val response = bytes.copyOfRange(4, bytes.size)
        return try {
            IsoResponse(status, response)
        } finally {
            response.fill(0)
        }
    } finally {
        bytes.fill(0)
    }
}
