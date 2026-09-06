/**
 * @file callback.cpp
 * @brief Callback-backed transport implementation.
 */
#include <desfire/transports/callback.hpp>

namespace desfire::transports {

    /** @brief Implement `CallbackTransport` to construct callback-backed transport state. */
    CallbackTransport::CallbackTransport(TransportCapabilities capabilities,
                                         TransportCallbacks callbacks)
        : capabilities_(capabilities), callbacks_(std::move(callbacks)) {
        capabilities_.can_cancel = static_cast<bool>(callbacks_.cancel);
        capabilities_.can_reset = static_cast<bool>(callbacks_.reset);
        // This adapter cannot provide RF timing evidence through its ordinary callback.
        capabilities_.hardware_timing = false;
    }

    /**
     * @brief Return callback-adapted reader capabilities.
     *
     * @return Transport limits and cancellation capability bitmask.
     */
    TransportCapabilities CallbackTransport::capabilities() const {
        return capabilities_;
    }

    /** @brief Implement `generation` to report the current card generation. */
    std::uint64_t CallbackTransport::generation() const noexcept {
        return generation_.load();
    }

    /** @brief Implement `exchange` to execute one bounded serialized card exchange. */
    Result<Bytes> CallbackTransport::exchange(ByteView frame, const ExchangeOptions& options) {
        if (!callbacks_.exchange) {
            return invalid("An exchange callback is required");
        }

        if (options.stop.stop_requested()) {
            return Error{ErrorCode::cancelled, "Cancelled before invoking the reader"};
        }

        if (options.timeout.count() <= 0 || frame.size() > capabilities_.max_transmit) {
            return invalid("Callback exchange exceeds configured limits");
        }

        try {
            auto response = callbacks_.exchange(frame, options);

            if (response && response.value().size() > capabilities_.max_receive) {
                return Error{ErrorCode::malformed_response, "Reader response exceeds its limit",
                             Outcome::unknown};
            }

            return response;
        } catch (...) {
            // A callback can throw after sending the command. Neither retry nor
            // a not_sent claim is justified once control has reached user I/O.
            return Error{ErrorCode::transport, "Reader callback threw an exception",
                         Outcome::unknown};
        }
    }

    /**
     * @brief Cancel outstanding exchange if the cancel callback exists.
     *
     * The cancel method is best-effort and never throws across callback boundaries.
     */
    void CallbackTransport::cancel() noexcept {
        try {
            if (callbacks_.cancel) {
                callbacks_.cancel();
            }
        } catch (...) {
            // noexcept cancellation cannot propagate through a stop callback. The
            // ongoing exchange still determines its own result and delivery outcome.
        }
    }

    /**
     * @brief Request reader reset through callback, then advance generation.
     *
     * The generation is advanced before callback return to invalidate stale handles
     * even when reset throws or returns transport-level errors.
     *
     * @return Reset result or unsupported failure.
     */
    Result<void> CallbackTransport::reset() {
        if (!callbacks_.reset) {
            return Error{ErrorCode::unsupported, "Reader reset callback is unavailable"};
        }

        // Invalidate old handles even when reset throws or cannot confirm success.
        // A partially executed reset can already have erased authentication state.
        notify_state_change();

        try {
            return callbacks_.reset();
        } catch (...) {
            return Error{ErrorCode::transport, "Reader reset callback threw an exception",
                         Outcome::unknown};
        }
    }

    /** @brief Implement `notify_state_change` to advance the generation after a reader state
     * change. */
    void CallbackTransport::notify_state_change() noexcept {
        generation_.fetch_add(1);
    }

} // namespace desfire::transports
