package com.desfire.ev3.raw

/** Reset the raw transport and erase all raw authentication sessions. */
public fun BlockingRawChannel.reset(): Unit = requireEmpty(invoke(0, longArrayOf(), arrayOf()))

/** Report external card replacement and invalidate raw authentication state. */
public fun BlockingRawChannel.notifyStateChange(): Unit =
    requireEmpty(invoke(1, longArrayOf(), arrayOf()))

/** Exchange exactly one physical native frame and preserve its native status. */
public fun BlockingRawChannel.nativeFrame(
    framing: com.desfire.ev3.Framing,
    command: Int,
    data: ByteArray = byteArrayOf(),
    timeoutMs: Long = 5_000,
): NativeResponse = decodeNativeResponse(invoke(2,
    longArrayOf(framing.code.toLong(), command.toLong(), timeoutMs), arrayOf(data)))

/** Exchange one bounded native logical command with explicit chaining policy. */
public fun BlockingRawChannel.nativeExchange(
    request: NativeRequest,
    timeoutMs: Long = 5_000,
): NativeResponse = decodeNativeResponse(invoke(3, longArrayOf(
    request.framing.code.toLong(), request.command.toLong(), request.maximumResponse,
    request.firstFrameDataSize ?: -1, if (request.singleContinuation) 1 else 0, timeoutMs,
), arrayOf(request.dataBytes)))

/** Exchange one true ISO APDU and preserve the final status word. */
public fun BlockingRawChannel.isoExchange(
    request: IsoApdu,
    timeoutMs: Long = 5_000,
): IsoResponse = decodeIsoResponse(invoke(4, longArrayOf(
    request.cla.toLong(), request.ins.toLong(), request.p1.toLong(), request.p2.toLong(),
    if (request.le == null) 0 else 1, (request.le ?: 0).toLong(),
    request.lengthEncoding.code.toLong(), if (request.correctLength) 1 else 0,
    request.maximumResponse, request.maximumFrames, timeoutMs,
), arrayOf(request.dataBytes)))

/** Execute one supported checked ISO data command through the active raw ISO AES session. */
public fun BlockingRawChannel.secureIsoExchange(
    request: IsoApdu,
    timeoutMs: Long = 5_000,
): IsoResponse = decodeIsoResponse(invoke(6, longArrayOf(
    request.cla.toLong(), request.ins.toLong(), request.p1.toLong(), request.p2.toLong(),
    if (request.le == null) 0 else 1, (request.le ?: 0).toLong(),
    request.lengthEncoding.code.toLong(), if (request.correctLength) 1 else 0,
    request.maximumResponse, request.maximumFrames, timeoutMs,
), arrayOf(request.dataBytes)))

/** Execute an explicit secure native command using the selected active raw session. */
public fun BlockingRawChannel.secureNativeExchange(
    request: SecureNativeRequest,
    timeoutMs: Long = 5_000,
): ByteArray = invoke(5, longArrayOf(
    request.profile.code.toLong(), request.command.toLong(),
    request.requestCommunication.value.toLong(), request.responseCommunication.value.toLong(),
    request.minimumResponse, request.maximumResponse, request.firstFrameDataSize ?: -1,
    if (request.singleContinuation) 1 else 0,
    if (request.invalidatesSession) 1 else 0, timeoutMs,
), arrayOf(request.headerBytes, request.dataBytes))

/** Suspend-friendly raw transport reset. */
public suspend fun RawChannel.reset(): Unit = call { reset() }

/** Suspend-friendly card-state replacement notification. */
public suspend fun RawChannel.notifyStateChange(): Unit = call { notifyStateChange() }

/** Suspend-friendly one-frame native exchange. */
public suspend fun RawChannel.nativeFrame(
    framing: com.desfire.ev3.Framing,
    command: Int,
    data: ByteArray = byteArrayOf(),
    timeoutMs: Long = 5_000,
): NativeResponse = call { nativeFrame(framing, command, data, timeoutMs) }

/** Suspend-friendly bounded native logical exchange. */
public suspend fun RawChannel.nativeExchange(
    request: NativeRequest,
    timeoutMs: Long = 5_000,
): NativeResponse = call { nativeExchange(request, timeoutMs) }

/** Suspend-friendly true ISO APDU exchange. */
public suspend fun RawChannel.isoExchange(
    request: IsoApdu,
    timeoutMs: Long = 5_000,
): IsoResponse = call { isoExchange(request, timeoutMs) }

/** Suspend-friendly checked ISO exchange through the active raw ISO AES session. */
public suspend fun RawChannel.secureIsoExchange(
    request: IsoApdu,
    timeoutMs: Long = 5_000,
): IsoResponse = call { secureIsoExchange(request, timeoutMs) }

/** Suspend-friendly secure native exchange. */
public suspend fun RawChannel.secureNativeExchange(
    request: SecureNativeRequest,
    timeoutMs: Long = 5_000,
): ByteArray = call { secureNativeExchange(request, timeoutMs) }

/** Require the empty success result used by lifecycle operations. */
private fun requireEmpty(result: ByteArray) {
    check(result.isEmpty()) { "Unexpected raw lifecycle payload" }
}
