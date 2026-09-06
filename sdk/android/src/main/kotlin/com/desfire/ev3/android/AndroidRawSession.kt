package com.desfire.ev3.android

import android.nfc.tech.IsoDep
import com.desfire.ev3.raw.RawChannel
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Owns one Android ISO-DEP adapter and its expert raw EV3 channel.
 *
 * A raw session is separate from [AndroidCardSession]. The same connected [IsoDep] must never be
 * shared between managed and raw owners. Callers must supply complete request framing and bounds;
 * this adapter does not infer command semantics.
 */
public class AndroidRawSession private constructor(
    public val channel: RawChannel,
    private val transport: IsoDepTransport,
) {
    private val closeGate = Mutex()
    private var channelClosed = false

    public companion object {
        /**
         * Open a raw channel and transfer the connected ISO-DEP handle only on success.
         *
         * When this function throws, the caller still owns the [IsoDep] object and must retry close
         * if the cleanup failure appears as a suppressed exception.
         */
        public suspend fun open(isoDep: IsoDep): AndroidRawSession {
            val transport = IsoDepTransport(isoDep)
            return try {
                AndroidRawSession(RawChannel.open(transport), transport)
            } catch (failure: Throwable) {
                try {
                    transport.close()
                } catch (closeFailure: Throwable) {
                    failure.addSuppressed(closeFailure)
                }
                throw failure
            }
        }
    }

    /** Request prompt interruption of the active raw exchange without waiting for its queue. */
    public fun requestCancellation() {
        channel.requestCancellation()
    }

    /** Drain admitted raw work, release JNI state, and close the Android reader connection. */
    public suspend fun close(): Unit = closeGate.withLock {
        if (!channelClosed) {
            channel.close()
            channelClosed = true
        }
        transport.close()
    }
}
