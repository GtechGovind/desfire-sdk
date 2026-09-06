package com.desfire.ev3.raw

import com.desfire.ev3.CardTransport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Suspend-first owner of one independent expert raw channel. */
public class RawChannel private constructor(internal val blocking: BlockingRawChannel) {
    private val operations = Mutex()

    public companion object {
        /** Open a raw channel away from the initiating thread. */
        public suspend fun open(transport: CardTransport): RawChannel {
            var opened: BlockingRawChannel? = null
            try {
                return withContext(Dispatchers.IO) {
                    RawChannel(BlockingRawChannel.open(transport).also { opened = it })
                }
            } catch (failure: Throwable) {
                try {
                    opened?.close()
                } catch (cleanup: Throwable) {
                    failure.addSuppressed(cleanup)
                }
                throw failure
            }
        }
    }

    /** Execute one raw operation through the cancellable per-channel FIFO gate. */
    internal suspend fun <T> call(operation: BlockingRawChannel.() -> T): T = operations.withLock {
        withContext(Dispatchers.IO) { blocking.operation() }
    }

    /** Request cancellation without joining the queued raw operations. */
    public fun requestCancellation(): Unit = blocking.cancelActive()

    /** Drain queued work and release native ownership despite caller cancellation. */
    public suspend fun close() {
        withContext(NonCancellable) {
            operations.withLock { withContext(Dispatchers.IO) { blocking.close() } }
        }
    }
}
