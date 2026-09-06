/**
 * @file replay.cpp
 * @brief Deterministic replay transport implementation.
 */
#include <desfire/transports/replay.hpp>

#include <algorithm>

namespace desfire::transports {

    /** @brief Implement `ReplayTransport` to construct deterministic replay transport state. */
    ReplayTransport::ReplayTransport(std::deque<ReplayStep> steps,
                                     TransportCapabilities capabilities)
        : capabilities_(capabilities), steps_(std::move(steps)) {
        // Exchanges are immediate, so no blocked I/O exists to cancel. Reset is a
        // simulated card-state boundary rather than a replay-position change.
        capabilities_.can_cancel = false;
        capabilities_.can_reset = true;
        capabilities_.hardware_timing = false;
    }

    /**
     * @brief Read configured transport capabilities from the transport.
     *
     * @return Copy of limits and capability bits.
     */
    TransportCapabilities ReplayTransport::capabilities() const {
        return capabilities_;
    }

    /** @brief Implement `generation` to report the current card generation. */
    std::uint64_t ReplayTransport::generation() const noexcept {
        return generation_.load();
    }

    /** @brief Implement `exchange` to execute one bounded serialized card exchange. */
    Result<Bytes> ReplayTransport::exchange(ByteView frame, const ExchangeOptions& options) {
        std::lock_guard lock(mutex_);

        if (options.stop.stop_requested()) {
            return Error{ErrorCode::cancelled, "Replay cancelled before transmission"};
        }

        if (options.timeout.count() <= 0 || frame.size() > capabilities_.max_transmit) {
            return invalid("Replay exchange exceeds configured limits");
        }

        if (steps_.empty()) {
            return invalid("Unexpected exchange after the replay script ended");
        }

        const auto& expected = steps_.front().request;

        if (!std::ranges::equal(frame, expected)) {
            // Never include the mismatching frame in the diagnostic: scripts may
            // eventually contain test authentication payloads or secret material.
            return invalid("Exchange does not match the next replay expectation");
        }

        auto response = std::move(steps_.front().response);
        steps_.pop_front();
        return response;
    }

    /**
     * @brief Cancel has no effect because replay exchange is synchronous.
     */
    void ReplayTransport::cancel() noexcept {
        // No pending asynchronous or blocking I/O exists in this immediate transport.
    }

    /**
     * @brief Simulate reset by incrementing generation and keeping script position.
     *
     * A reset does not rewind the script because this would hide unexpected
     * exchanges across host-managed restart boundaries.
     *
     * @return Success.
     */
    Result<void> ReplayTransport::reset() {
        generation_.fetch_add(1);
        return {};
    }

    /**
     * @brief Return remaining script exchanges.
     *
     * Useful for deterministic tests and diagnostics.
     *
     * @return Number of not-yet-consumed replay steps.
     */
    std::size_t ReplayTransport::remaining() const {
        std::lock_guard lock(mutex_);
        return steps_.size();
    }

} // namespace desfire::transports
