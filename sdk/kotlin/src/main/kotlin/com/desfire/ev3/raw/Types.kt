package com.desfire.ev3.raw

import com.desfire.ev3.AuthenticationInfo
import com.desfire.ev3.Communication
import com.desfire.ev3.Framing

/** Native response with its exact final status byte. */
public class NativeResponse(public val status: Int, data: ByteArray) {
    private val responseBytes = data.copyOf()

    init {
        require(status in 0..0xFF) { "Native status must fit one byte" }
    }

    /** Status-free response bytes. */
    public val data: ByteArray
        get() = responseBytes.copyOf()
}

/** ISO/IEC 7816 response with its exact final status word. */
public class IsoResponse(public val status: Int, data: ByteArray) {
    private val responseBytes = data.copyOf()

    init {
        require(status in 0..0xFFFF) { "ISO status must fit two bytes" }
    }

    /** Response data before SW1/SW2. */
    public val data: ByteArray
        get() = responseBytes.copyOf()

    /** True only for ISO success status 9000. */
    public val successful: Boolean
        get() = status == 0x9000
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
 * inferred from a command number.
 */
public class NativeRequest(
    public val framing: Framing,
    public val command: Int,
    data: ByteArray = byteArrayOf(),
    public val maximumResponse: Long,
    public val firstFrameDataSize: Long? = null,
    public val singleContinuation: Boolean = false,
) {
    internal val dataBytes = data.copyOf()

    init {
        require(command in 0..0xFF) { "Native command must fit one byte" }
        require(dataBytes.size <= 16 * 1024 * 1024) { "Native data exceeds sixteen MiB" }
        require(maximumResponse in 1..16L * 1024 * 1024) { "Invalid maximum response" }
        require(firstFrameDataSize == null || firstFrameDataSize in 0..dataBytes.size.toLong()) {
            "First-frame boundary must be inside the request data"
        }
    }
}

/** Exact true ISO/IEC 7816 command APDU and continuation policy. */
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
) {
    internal val dataBytes = data.copyOf()

    init {
        require(cla in 0..0xFF && ins in 0..0xFF && p1 in 0..0xFF && p2 in 0..0xFF) {
            "ISO APDU header fields must fit one byte"
        }
        require(dataBytes.size <= 65_535) { "ISO APDU data exceeds 65535 bytes" }
        require(le == null || le in 1..65_536) { "ISO Le must be between one and 65536" }
        require(maximumResponse in 1..16L * 1024 * 1024) { "Invalid maximum response" }
        require(maximumFrames in 1..65_536) { "Invalid maximum frame count" }
    }
}

/**
 * Explicit secure-native request with no inferred command semantics.
 *
 * The caller declares clear header bytes, protected data bytes, both communication policies,
 * response bounds, chaining boundary, and whether success invalidates the active session.
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
) {
    internal val headerBytes = header.copyOf()
    internal val dataBytes = data.copyOf()

    init {
        require(command in 0..0xFF) { "Native command must fit one byte" }
        require(headerBytes.size + dataBytes.size <= 16 * 1024 * 1024) {
            "Secure request exceeds sixteen MiB"
        }
        require(minimumResponse >= 0 && maximumResponse >= minimumResponse &&
            maximumResponse <= 16L * 1024 * 1024) { "Invalid secure response bounds" }
        require(firstFrameDataSize == null || firstFrameDataSize >= 0) {
            "First-frame boundary cannot be negative"
        }
    }
}

/** Decode a four-byte little-endian status prefix followed by response bytes. */
internal fun decodeNativeResponse(bytes: ByteArray): NativeResponse {
    check(bytes.size >= 4) { "Malformed raw native response" }
    val status = (bytes[0].toInt() and 0xFF) or
        ((bytes[1].toInt() and 0xFF) shl 8) or
        ((bytes[2].toInt() and 0xFF) shl 16) or
        ((bytes[3].toInt() and 0xFF) shl 24)
    return NativeResponse(status, bytes.copyOfRange(4, bytes.size))
}

/** Decode a four-byte little-endian ISO status prefix followed by response bytes. */
internal fun decodeIsoResponse(bytes: ByteArray): IsoResponse {
    check(bytes.size >= 4) { "Malformed raw ISO response" }
    val status = (bytes[0].toInt() and 0xFF) or
        ((bytes[1].toInt() and 0xFF) shl 8) or
        ((bytes[2].toInt() and 0xFF) shl 16) or
        ((bytes[3].toInt() and 0xFF) shl 24)
    return IsoResponse(status, bytes.copyOfRange(4, bytes.size))
}
