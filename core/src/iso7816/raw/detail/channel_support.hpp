/**
 * @file channel_support.hpp
 * @brief Private raw ISO deadline, delivery-outcome, and generation helpers.
 */
#pragma once

#include <desfire/foundation/transport.hpp>

#include <chrono>

namespace desfire::ev3::iso7816::raw::detail {

    /** @brief One elapsed-time budget and card generation shared by all physical frames. */
    class Budget final {
    public:

        /**
         * @brief Snapshot one transport generation and start the logical-operation clock.
         * @param transport Exclusively owned transport used for every frame.
         * @param options Original operation controls.
         */
        Budget(CardTransport& transport, const ExchangeOptions& options)
            : transport_(transport), options_(options), generation_(transport.generation()) {}

        /**
         * @brief Produce controls with the remaining deadline for the next frame.
         * @param sent True after any earlier frame reached the transport.
         * @return Remaining controls or conservative cancellation/generation/timeout evidence.
         */
        Result<ExchangeOptions> next(bool sent) const {
            const auto outcome = sent ? Outcome::unknown : Outcome::not_sent;
            if (transport_.generation() != generation_) {
                return Error{ErrorCode::card_removed, "Card state changed during ISO command",
                             outcome};
            }
            if (options_.stop.stop_requested()) {
                return Error{ErrorCode::cancelled, "ISO command cancelled", outcome};
            }
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - started_);
            if (options_.timeout.count() <= 0 || elapsed >= options_.timeout) {
                return Error{ErrorCode::timeout, "ISO logical command deadline expired", outcome};
            }
            ExchangeOptions remaining = options_;
            remaining.timeout -= elapsed;
            return remaining;
        }

        /** @brief Report whether the transport still exposes the initial card generation. */
        [[nodiscard]] bool same_card() const noexcept {
            return transport_.generation() == generation_;
        }

    private:

        CardTransport& transport_; ///< Transport used for serialized card exchanges.
        ExchangeOptions options_;  ///< Timeout and cancellation controls shared by the operation.
        std::uint64_t generation_; ///< Card generation captured when this state was created.
        std::chrono::steady_clock::time_point started_{
            std::chrono::steady_clock::now()}; ///< Whether the logical operation has begun card
                                               ///< I/O.
    };

    /**
     * @brief Change a not-sent dependency error to unknown after earlier card delivery.
     * @param error Dependency error to refine.
     * @return Error with conservative delivery evidence.
     */
    inline Error after_send(Error error) {
        if (error.outcome == Outcome::not_sent) {
            error.outcome = Outcome::unknown;
        }
        return error;
    }

} // namespace desfire::ev3::iso7816::raw::detail
