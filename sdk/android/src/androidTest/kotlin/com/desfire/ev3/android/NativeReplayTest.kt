package com.desfire.ev3.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.desfire.ev3.Card
import com.desfire.ev3.CardTransport
import com.desfire.ev3.TransportLimits
import com.desfire.ev3.freeMemory
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.runner.RunWith

/** Run a real Android Kotlin -> JNI -> C -> core -> transport exchange from the packaged AAR. */
@RunWith(AndroidJUnit4::class)
class NativeReplayTest {
    /** Exercise real Android dynamic loading and native execution with deterministic transport data. */
    @Test
    fun packagedNativeRuntime(): Unit = runBlocking {
        var calls = 0
        val transport = object : CardTransport {
            override val limits = TransportLimits()
            override fun exchange(frame: ByteArray, timeoutMs: Int): ByteArray {
                check(frame.contentEquals(byteArrayOf(
                    0x90.toByte(), 0x6e, 0, 0, 0,
                )))
                check(timeoutMs > 0)
                calls += 1
                return byteArrayOf(1, 0, 0, 0x91.toByte(), 0)
            }
            override fun cancel() = Unit
            override fun reset() = Unit
        }
        val card = Card.open(transport)
        check(card.freeMemory() == 1L)
        card.close()
        check(calls == 1)
    }
}
