package com.desfire.ev3.android

import android.nfc.TagLostException
import android.nfc.tech.IsoDep
import android.os.Looper
import com.desfire.ev3.CardTransport
import com.desfire.ev3.DesfireException
import com.desfire.ev3.Framing
import com.desfire.ev3.Outcome
import com.desfire.ev3.TransportLimits
import java.io.IOException

/**
 * Android ISO-DEP adapter, separate from the portable Kotlin and JNI SDK.
 * Pass an already connected IsoDep from a foreground NFC discovery callback. ISO-DEP
 * fragmentation belongs to Android; native DESFire additional frames belong to the SDK.
 * Cancellation closes the Android connection. A cancelled/lost card must be rediscovered;
 * this adapter never reconnects or resends a command with uncertain delivery.
 */
class IsoDepTransport(private val isoDep: IsoDep) : CardTransport, AutoCloseable {
    @Volatile
    private var closed = false
    override val limits: TransportLimits

    init {
        require(isoDep.isConnected) { "IsoDep must already be connected" }
        limits = TransportLimits(Framing.ISO_WRAPPED, isoDep.maxTransceiveLength, 65538, 60)
    }

    /** Apply the remaining physical-exchange timeout and send exactly one complete APDU. */
    override fun exchange(frame: ByteArray, timeoutMs: Int): ByteArray {
        if (Looper.myLooper() == Looper.getMainLooper()) throw DesfireException(
            12, Outcome.NOT_SENT.code, 0, "NFC exchange cannot run on the Android main thread")
        if (closed || !isoDep.isConnected) throw DesfireException(3, Outcome.NOT_SENT.code,
            0, "Android NFC connection is closed")
        require(timeoutMs > 0)
        if (frame.size > limits.maxTransmit) throw DesfireException(1, Outcome.NOT_SENT.code,
            0, "APDU exceeds the Android transport capacity")
        try {
            isoDep.timeout = timeoutMs
        } catch (_: IllegalArgumentException) {
            throw DesfireException(1, Outcome.NOT_SENT.code, 0, "Android rejected the exchange timeout")
        }
        try {
            return isoDep.transceive(frame)
        } catch (_: TagLostException) {
            throw closeAfterExchangeFailure(
                DesfireException(3, Outcome.UNKNOWN.code, 0, "NFC tag was lost during exchange"),
            )
        } catch (_: IOException) {
            throw closeAfterExchangeFailure(
                DesfireException(2, Outcome.UNKNOWN.code, 0, "Android NFC exchange failed"),
            )
        }
    }

    /** Closing IsoDep interrupts a blocked transceive; it cannot establish delivery failure. */
    override fun cancel() {
        close()
    }

    /** Android cannot promise an RF reset without rediscovery; never hide a reconnection here. */
    override fun reset() {
        throw DesfireException(10, Outcome.NOT_SENT.code, 0,
            "Rediscover the NFC tag and open a new EV3 card connection")
    }

    /** Idempotently release Android NFC resources; card-operation evidence is returned separately. */
    @Synchronized
    override fun close() {
        if (closed) return
        isoDep.close()
        closed = true
    }

    /** Preserve the primary UNKNOWN outcome while retaining any failed close for diagnostics. */
    private fun closeAfterExchangeFailure(failure: DesfireException): DesfireException {
        try {
            close()
        } catch (closeFailure: IOException) {
            failure.addSuppressed(closeFailure)
        }
        return failure
    }
}
