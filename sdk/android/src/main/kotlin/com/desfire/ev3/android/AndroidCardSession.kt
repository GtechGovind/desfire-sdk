package com.desfire.ev3.android

import android.nfc.tech.IsoDep
import com.desfire.ev3.Card
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Owns one Android ISO-DEP adapter and its suspend-first managed EV3 card. */
public class AndroidCardSession private constructor(
    public val card: Card,
    private val transport: IsoDepTransport,
) {
    private val closeGate = Mutex()
    private var cardClosed = false

    public companion object {
        /**
         * Open a managed card and transfer the connected ISO-DEP handle only on success.
         *
         * When this function throws, the caller still owns the [IsoDep] object and must retry close
         * if the cleanup failure appears as a suppressed exception.
         */
        public suspend fun open(isoDep: IsoDep): AndroidCardSession {
            val transport = IsoDepTransport(isoDep)
            return try {
                AndroidCardSession(Card.open(transport), transport)
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

    /** Drain card work, release JNI state, and then close the Android reader connection. */
    public suspend fun close(): Unit = closeGate.withLock {
        if (!cardClosed) {
            card.close()
            cardClosed = true
        }
        transport.close()
    }
}
