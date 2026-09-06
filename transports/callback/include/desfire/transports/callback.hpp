/**
 * @file callback.hpp
 * @brief Adapt an application's existing reader connection to the SDK transport contract.
 */
#pragma once

#include <desfire/foundation/transport.hpp>

#include <atomic>
#include <functional>

namespace desfire::transports {

    /**
     * @brief Reader callbacks whose captured resources remain owned by the adapter.
     *
     * Exchange is mandatory. Cancellation may run concurrently with exchange and
     * must not wait on the same operation lock. Callbacks must report delivery
     * uncertainty explicitly and never automatically repeat a mutation.
     */
    struct TransportCallbacks {
        /** Required single-frame exchange callback; inputs remain borrowed only during the call. */
        std::function<Result<Bytes>(ByteView, const ExchangeOptions&)> exchange;

        /** Optional concurrent cancellation callback; exceptions are contained by the adapter. */
        std::function<void()> cancel;

        /** Optional reset callback; errors must preserve delivery and state-change evidence. */
        std::function<Result<void>()> reset;
    };

    /**
     * @brief A platform-independent transport for consumer-supplied reader I/O.
     *
     * The SDK serializes managed commands, not arbitrary direct calls on this object.
     * Callback closures must own their dependencies or outlive the adapter. An
     * exception from exchange is conservatively converted to an unknown outcome.
     */
    class CallbackTransport final : public CardTransport {
    public:

        /**
         * @brief Own callback closures and the declared limits for one activated connection.
         * @param capabilities Exact framing, capacity, cancellation, reset and timing support.
         * @param callbacks Host callbacks whose captured resources outlive this adapter.
         */
        CallbackTransport(TransportCapabilities capabilities, TransportCallbacks callbacks);

        /** @brief Return the immutable limits declared by the host at construction. */
        TransportCapabilities capabilities() const override;

        /** @brief Return the connection generation advanced by reset or state notification. */
        std::uint64_t generation() const noexcept override;

        /**
         * @brief Invoke the host exchange once and contain foreign exceptions.
         * @param frame Borrowed physical request frame, valid only through callback return.
         * @param options Remaining deadline and cancellation state for that physical exchange.
         * @return Owned response or redacted evidence; an exception has unknown delivery.
         */
        Result<Bytes> exchange(ByteView frame, const ExchangeOptions& options) override;

        /** @brief Invoke the optional cancellation callback without taking an operation lock. */
        void cancel() noexcept override;

        /**
         * @brief Invalidate the current generation, then invoke the optional reset callback.
         * @return Callback success, unsupported when absent, or contained exception evidence.
         * @warning Generation advances before the callback because a failed reset may still have
         *          changed card authentication state.
         */
        Result<void> reset() override;

        /**
         * @brief Notify managed handles that removal or external reset changed card state.
         *
         * Safe to call from a reader event thread. It does not perform reader I/O or
         * claim that a pending operation was cancelled successfully.
         */
        void notify_state_change() noexcept;

    private:

        TransportCapabilities capabilities_; ///< Immutable transport capability snapshot.
        TransportCallbacks callbacks_;       ///< Validated callback table.
        std::atomic<std::uint64_t> generation_{
            1}; ///< Card generation captured when this state was created.
    };

} // namespace desfire::transports
