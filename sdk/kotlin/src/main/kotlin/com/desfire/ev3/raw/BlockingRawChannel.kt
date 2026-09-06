package com.desfire.ev3.raw

import com.desfire.ev3.CardTransport
import com.desfire.ev3.DesfireException
import com.desfire.ev3.ErrorCode
import com.desfire.ev3.Outcome
import com.desfire.ev3.ProviderBridge
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** Blocking owner of one independent expert raw C channel. */
public class BlockingRawChannel private constructor(private var handle: Long) : AutoCloseable {
    private enum class State { OPEN, CLOSING, CLOSED }

    private val stateLock = ReentrantLock()
    private val stateChanged = stateLock.newCondition()
    private val invoking = object : ThreadLocal<Boolean>() {
        override fun initialValue(): Boolean = false
    }
    private var state = State.OPEN
    private var admitted = 0
    private var nextTicket = 0L
    private var servingTicket = 0L

    public companion object {
        /** Retain an already activated transport and open a separately owned raw channel. */
        @JvmStatic
        public fun open(transport: CardTransport): BlockingRawChannel {
            val limits = transport.limits
            require(limits.maxTransmit >= 6 && limits.maxReceive >= 2 &&
                limits.maxNativeFrame >= 2) { "Invalid transport limits" }
            return BlockingRawChannel(
                RawNative.open(transport, limits.framing.code, limits.maxTransmit,
                    limits.maxReceive, limits.maxNativeFrame),
            )
        }
    }

    /** Execute one raw operation after fair admission. */
    internal fun invoke(operation: Int, numbers: LongArray, data: Array<ByteArray>): ByteArray =
        withExclusiveHandle { RawNative.invoke(it, operation, numbers, data) }

    /** Execute one specialized JNI operation through the same fair gate. */
    internal fun <T> withExclusiveHandle(operation: (Long) -> T): T {
        rejectReentry()
        val ticket = admit()
        try {
            awaitTurn(ticket)
            val prior = invoking.get()
            invoking.set(true)
            try {
                return operation(handle)
            } finally {
                invoking.set(prior)
            }
        } finally {
            releaseAdmission(ticket)
        }
    }

    /** Request cancellation immediately without waiting behind a raw operation. */
    public fun cancelActive() {
        val current = stateLock.withLock {
            if (state == State.CLOSED || handle == 0L) throw closedError()
            handle
        }
        RawNative.cancel(current)
    }

    /** Reject new work, drain admitted calls, and release native callback ownership once. */
    override fun close() {
        rejectReentry()
        var current = 0L
        stateLock.withLock {
            while (state == State.CLOSING) stateChanged.awaitUninterruptibly()
            if (state == State.CLOSED) return
            state = State.CLOSING
            while (admitted != 0) stateChanged.awaitUninterruptibly()
            current = handle
        }
        try {
            RawNative.close(current)
            stateLock.withLock {
                handle = 0
                state = State.CLOSED
                stateChanged.signalAll()
            }
        } catch (failure: Throwable) {
            stateLock.withLock {
                state = State.OPEN
                stateChanged.signalAll()
            }
            throw failure
        }
    }

    /** Admit one operation before close starts draining the queue. */
    private fun admit(): Long = stateLock.withLock {
            if (state != State.OPEN || handle == 0L) throw closedError()
            if (admitted == 0) {
                nextTicket = 0
                servingTicket = 0
            }
            val ticket = nextTicket++
            admitted += 1
            ticket
        }

    /** Wait uninterruptibly until this admission reaches the raw native boundary. */
    private fun awaitTurn(ticket: Long) {
        stateLock.withLock {
            while (ticket != servingTicket) stateChanged.awaitUninterruptibly()
        }
    }

    /** Complete the active ticket and wake the next operation or a draining close. */
    private fun releaseAdmission(ticket: Long) {
        stateLock.withLock {
            check(ticket == servingTicket) { "Raw-channel ticket order violated" }
            servingTicket += 1
            admitted -= 1
            check(admitted >= 0) { "Raw-channel admission count underflow" }
            stateChanged.signalAll()
        }
    }

    /** Create a stable local stale-handle failure. */
    private fun closedError(): DesfireException = DesfireException(
        ErrorCode.STALE_HANDLE.code, Outcome.NOT_SENT.code, 0, "Raw channel is closing or closed",
    )

    /** Reject recursive raw use from its active transport or provider callback. */
    private fun rejectReentry() {
        if (invoking.get() == true) {
            throw DesfireException(ErrorCode.BUSY.code, Outcome.NOT_SENT.code, 0,
                "Cannot re-enter a raw operation from its callback")
        }
    }
}

/** Private raw JNI surface. */
internal object RawNative {
    init {
        com.desfire.ev3.NativeRuntime.ensureLoaded()
    }

    @JvmStatic external fun open(
        transport: CardTransport,
        framing: Int,
        maxTransmit: Int,
        maxReceive: Int,
        maxNativeFrame: Int,
    ): Long

    @JvmStatic external fun close(handle: Long)
    @JvmStatic external fun cancel(handle: Long)
    @JvmStatic external fun invoke(
        handle: Long,
        operation: Int,
        numbers: LongArray,
        data: Array<ByteArray>,
    ): ByteArray

    @JvmStatic external fun authenticateDirect(
        handle: Long,
        profile: Int,
        keyNumber: Int,
        application: Boolean,
        key: ByteArray,
        pcdCapabilities: ByteArray,
        timeoutMs: Long,
    ): ByteArray

    @JvmStatic external fun authenticateDerived(
        handle: Long,
        profile: Int,
        keyNumber: Int,
        application: Boolean,
        masterKey: ByteArray,
        diversification: ByteArray,
        pcdCapabilities: ByteArray,
        timeoutMs: Long,
    ): ByteArray

    @JvmStatic external fun authenticateProvider(
        handle: Long,
        profile: Int,
        scope: Int,
        keyNumber: Int,
        application: Boolean,
        provider: ProviderBridge,
        reference: ByteArray,
        diversification: ByteArray,
        userContext: ByteArray,
        applicationId: Int,
        keySet: Int,
        pcdCapabilities: ByteArray,
        timeoutMs: Long,
    ): ByteArray
}
