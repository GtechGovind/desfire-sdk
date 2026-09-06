package com.desfire.ev3

import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Blocking facade over one native managed Card.
 *
 * Calls admitted before close execute in FIFO order. Close rejects new calls, drains admitted
 * calls, closes the native handle, and only then releases JNI callback ownership. Cancellation is
 * independent of the FIFO operation lock. The caller retains physical reader ownership.
 */
public class BlockingCard private constructor(private var handle: Long) : AutoCloseable {
    private enum class State { OPEN, CLOSING, CLOSED }

    private val stateLock = ReentrantLock()
    private val stateChanged = stateLock.newCondition()
    private var state = State.OPEN
    private var admitted = 0
    private var nextTicket = 0L
    private var servingTicket = 0L
    private val invoking = object : ThreadLocal<Boolean>() {
        override fun initialValue(): Boolean = false
    }

    public companion object {
        private const val CANCEL_OPERATION = 1

        /** Retain an already activated transport and create one managed EV3 connection. */
        @JvmStatic
        public fun open(transport: CardTransport): BlockingCard {
            val limits = transport.limits
            require(limits.maxTransmit >= 6) { "maxTransmit must be at least six" }
            require(limits.maxReceive >= 2) { "maxReceive must be at least two" }
            require(limits.maxNativeFrame >= 2) { "maxNativeFrame must be at least two" }
            val handle = Native.open(
                transport,
                limits.framing.code,
                limits.maxTransmit,
                limits.maxReceive,
                limits.maxNativeFrame,
            )
            return BlockingCard(handle)
        }
    }

    /** Dispatch one generated operation after fair admission and copy every caller array in JNI. */
    internal fun invoke(operation: Int, numbers: LongArray, data: Array<ByteArray>): ByteArray {
        if (operation == CANCEL_OPERATION) {
            cancelActive()
            return byteArrayOf()
        }
        rejectReentry()
        val ticket = admit()
        try {
            awaitTurn(ticket)
            val before = invoking.get()
            invoking.set(true)
            try {
                return Native.invoke(handle, operation, numbers, data)
            } finally {
                invoking.set(before)
            }
        } finally {
            releaseAdmission(ticket)
        }
    }

    /** Run a specialized JNI call through the same fair per-card operation gate. */
    internal fun <T> withExclusiveHandle(operation: (Long) -> T): T {
        rejectReentry()
        val ticket = admit()
        try {
            awaitTurn(ticket)
            val before = invoking.get()
            invoking.set(true)
            try {
                return operation(handle)
            } finally {
                invoking.set(before)
            }
        } finally {
            releaseAdmission(ticket)
        }
    }

    /** Request transport cancellation without waiting behind the active card operation. */
    public fun cancelActive() {
        val current = stateLock.withLock {
            if (state == State.CLOSED || handle == 0L) {
                throw closedError()
            }
            handle
        }
        Native.cancel(current)
    }

    /**
     * Reject new operations, drain every admitted operation, and close native ownership once.
     *
     * A callback cannot close its own card because that would wait for the callback to return.
     */
    override fun close() {
        rejectReentry()

        var current = 0L
        stateLock.withLock {
            while (state == State.CLOSING) {
                stateChanged.awaitUninterruptibly()
            }
            if (state == State.CLOSED) {
                return
            }
            state = State.CLOSING
            while (admitted != 0) {
                stateChanged.awaitUninterruptibly()
            }
            current = handle
        }

        try {
            Native.close(current)
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

    /** Admit one operation before close can begin draining the queue. */
    private fun admit(): Long = stateLock.withLock {
            if (state != State.OPEN || handle == 0L) {
                throw closedError()
            }
            if (admitted == 0) {
                nextTicket = 0
                servingTicket = 0
            }
            val ticket = nextTicket++
            admitted += 1
            ticket
        }

    /** Wait uninterruptibly for the exact admission ticket to reach the native boundary. */
    private fun awaitTurn(ticket: Long) {
        stateLock.withLock {
            while (ticket != servingTicket) {
                stateChanged.awaitUninterruptibly()
            }
        }
    }

    /** Release the active ticket and wake the next operation or a draining close. */
    private fun releaseAdmission(ticket: Long) {
        stateLock.withLock {
            check(ticket == servingTicket) { "Managed-card ticket order violated" }
            servingTicket += 1
            admitted -= 1
            check(admitted >= 0) { "Managed-card admission count underflow" }
            stateChanged.signalAll()
        }
    }

    /** Construct a stable stale-handle error before JNI or transport access. */
    private fun closedError(): DesfireException = DesfireException(
        ErrorCode.STALE_HANDLE.code,
        Outcome.NOT_SENT.code,
        0,
        "Card is closing or closed",
    )

    /** Reject recursive card use from its active transport or provider callback. */
    private fun rejectReentry() {
        if (invoking.get() == true) {
            throw DesfireException(
                ErrorCode.BUSY.code, Outcome.NOT_SENT.code, 0,
                "Cannot re-enter a card operation from its callback",
            )
        }
    }

}

/** Private JNI entry points; public code uses [Card], [BlockingCard], or the raw package. */
internal object Native {
    init {
        NativeRuntime.ensureLoaded()
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

    @JvmStatic external fun setDefaultAesKeyDirect(
        handle: Long,
        key: ByteArray,
        version: Int,
        timeoutMs: Long,
    )

    @JvmStatic external fun setDefaultAesKeyDerived(
        handle: Long,
        masterKey: ByteArray,
        diversification: ByteArray,
        version: Int,
        timeoutMs: Long,
    )

    @JvmStatic external fun setDefaultAesKeyProvider(
        handle: Long,
        keyNumber: Int,
        provider: ProviderBridge,
        reference: ByteArray,
        diversification: ByteArray,
        userContext: ByteArray,
        applicationId: Int,
        keySet: Int,
        version: Int,
        timeoutMs: Long,
    )

    @JvmStatic external fun createTransactionMacFileProvider(
        handle: Long,
        file: Int,
        accessRights: Int,
        keyNumber: Int,
        provider: ProviderBridge,
        reference: ByteArray,
        diversification: ByteArray,
        userContext: ByteArray,
        applicationId: Int,
        keySet: Int,
        version: Int,
        timeoutMs: Long,
    )

    @JvmStatic external fun changeAesKeyProvider(
        handle: Long,
        number: Int,
        newProvider: ProviderBridge,
        newReference: ByteArray,
        newDiversification: ByteArray,
        newUserContext: ByteArray,
        newApplicationId: Int,
        newKeySet: Int,
        version: Int,
        authenticatedKey: Int,
        oldProvider: ProviderBridge?,
        oldReference: ByteArray,
        oldDiversification: ByteArray,
        oldUserContext: ByteArray,
        oldApplicationId: Int,
        oldKeySet: Int,
        keySet: Int,
        piccMaster: Boolean,
        timeoutMs: Long,
    )

    @JvmStatic external fun invoke(
        handle: Long,
        operation: Int,
        numbers: LongArray,
        data: Array<ByteArray>,
    ): ByteArray
}
