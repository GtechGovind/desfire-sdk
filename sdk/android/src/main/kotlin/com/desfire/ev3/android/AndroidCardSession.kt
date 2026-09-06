package com.desfire.ev3.android

import android.nfc.tech.IsoDep
import com.desfire.ev3.Card

/** Owns one Android ISO-DEP adapter and its suspend-first managed EV3 card. */
public class AndroidCardSession private constructor(
    public val card: Card,
    private val transport: IsoDepTransport,
) {
    public companion object {
        /** Retain an already connected ISO-DEP tag and open its managed card. */
        public suspend fun open(isoDep: IsoDep): AndroidCardSession {
            val transport = IsoDepTransport(isoDep)
            return try {
                AndroidCardSession(Card.open(transport), transport)
            } catch (failure: Throwable) {
                transport.close()
                throw failure
            }
        }
    }

    /** Drain card work, release JNI state, and then close the Android reader connection. */
    public suspend fun close() {
        card.close()
        transport.close()
    }
}
