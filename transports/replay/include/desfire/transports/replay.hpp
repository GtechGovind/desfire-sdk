/**
 * @file replay.hpp
 * @brief Deterministic reader exchanges for protocol tests and reproducible examples.
 */
#pragma once

#include <desfire/foundation/transport.hpp>

#include <atomic>
#include <deque>
#include <mutex>

namespace desfire::transports {

    /**
     * @brief One expected frame and the reader result returned for it.
     *
     * Expected bytes are independent test data. The transport does not generate
     * replies from the protocol implementation being tested.
     */
    struct ReplayStep {
        /** Exact request bytes required to consume this script step. */
        Bytes request;

        /** Owned response or failure evidence returned after a matching request. */
        Result<Bytes> response;
    };

    /**
     * @brief Consume a fixed exchange script without physical hardware.
     *
     * A mismatch leaves the step unconsumed and reports not_sent. Simulated reader
     * failures carry the outcome supplied in the script. Reset advances generation
     * but deliberately does not rewind the script or repeat previous operations.
     */
    class ReplayTransport final : public CardTransport {
    public:

        /**
         * @brief Take ownership of an ordered script and declared frame limits.
         * @param steps Expected requests and results in execution order.
         * @param capabilities Limits to expose to the protocol engine.
         */
        explicit ReplayTransport(std::deque<ReplayStep> steps,
                                 TransportCapabilities capabilities = {});

        /** @brief Return the immutable framing and size limits supplied at construction. */
        TransportCapabilities capabilities() const override;

        /** @brief Return the simulated connection generation, advanced only by reset(). */
        std::uint64_t generation() const noexcept override;

        /**
         * @brief Consume exactly one matching replay step.
         * @param frame Borrowed frame that must equal the next independent expectation.
         * @param options Deadline and cancellation controls checked before consuming the step.
         * @return Scripted response or mismatch/cancellation evidence without an implicit retry.
         */
        Result<Bytes> exchange(ByteView frame, const ExchangeOptions& options) override;

        /** @brief Do nothing because replay exchanges complete synchronously without blocking. */
        void cancel() noexcept override;

        /** @brief Advance generation without rewinding or otherwise changing the script. */
        Result<void> reset() override;

        /**
         * @brief Count unconsumed expectations to detect missing protocol exchanges.
         * @return Number of steps remaining in the script.
         */
        std::size_t remaining() const;

    private:

        TransportCapabilities capabilities_; ///< Immutable transport capability snapshot.
        std::deque<ReplayStep> steps_;       ///< Remaining replay exchanges in FIFO order.
        mutable std::mutex mutex_;           ///< Mutex protecting replay steps and lifecycle state.
        std::atomic<std::uint64_t> generation_{
            1}; ///< Card generation captured when this state was created.
    };

} // namespace desfire::transports
