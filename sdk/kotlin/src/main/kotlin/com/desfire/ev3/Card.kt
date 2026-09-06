package com.desfire.ev3

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * Suspend-first owner of one managed EV3 connection.
 *
 * Concurrent callers wait in one cancellable FIFO queue. Cancellation while queued performs no
 * native call. After execution starts, the blocking native call retains all state until the reader
 * returns; coroutine cancellation alone never reports a delivery outcome and never retries.
 */
public class Card private constructor(internal val blocking: BlockingCard) {
    private val operations = Mutex()

    public companion object {
        /** Open a retained native connection away from the caller's thread. */
        public suspend fun open(transport: CardTransport): Card {
            var opened: BlockingCard? = null
            try {
                return withContext(Dispatchers.IO) {
                    Card(BlockingCard.open(transport).also { opened = it })
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

    /** Execute one blocking operation through the cancellable per-card FIFO gate. */
    internal suspend fun <T> call(operation: BlockingCard.() -> T): T = operations.withLock {
        withContext(Dispatchers.IO) { blocking.operation() }
    }

    /** Request cancellation immediately without waiting in the normal operation queue. */
    public fun requestCancellation() {
        blocking.cancelActive()
    }

    /** Drain queued work and release native ownership even when the closing coroutine is cancelled. */
    public suspend fun close() {
        withContext(NonCancellable) {
            operations.withLock {
                withContext(Dispatchers.IO) { blocking.close() }
            }
        }
    }
}
