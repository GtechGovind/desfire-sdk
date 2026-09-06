/**
 * @file channel.cpp
 * @brief Serialized raw ISO continuation, deadline, and transport execution.
 */
#include "detail/channel_support.hpp"
#include "detail/codec_support.hpp"
#include <desfire/ev3/iso7816/raw/channel.hpp>

#include <utility>

namespace desfire::ev3::iso7816::raw {

    namespace {

        /** @brief Clear one channel activity marker before releasing its operation lock. */
        class ActiveOperation final {
        public:

            /** @brief Mark an already-locked channel operation active. */
            explicit ActiveOperation(bool& active) noexcept : active_(active) {
                active_ = true;
            }

            /** @brief Clear activity on every return and exception path. */
            ~ActiveOperation() {
                active_ = false;
            }

            /** @brief Prevent duplicating ownership of the activity marker. */
            ActiveOperation(const ActiveOperation&) = delete;

            /** @brief Prevent replacing ownership of the activity marker. */
            ActiveOperation& operator=(const ActiveOperation&) = delete;

        private:

            bool& active_; ///< Channel activity marker protected by its recursive mutex.
        };

    } // namespace

    /** @brief Implement `Channel` to bind an ISO APDU channel to its transport. */
    Channel::Channel(std::shared_ptr<CardTransport> transport) : transport_(std::move(transport)) {}

    /** @brief Implement `create` to validate a transport and construct a raw ISO channel. */
    Result<std::unique_ptr<Channel>> Channel::create(std::shared_ptr<CardTransport> transport) {
        if (!transport) {
            return invalid("ISO raw channel requires a non-null transport");
        }
        return std::unique_ptr<Channel>(new Channel(std::move(transport)));
    }

    TransportCapabilities Channel::capabilities() const {
        return transport_->capabilities();
    }

    std::uint64_t Channel::generation() const noexcept {
        return transport_->generation();
    }

    void Channel::cancel() noexcept {
        transport_->cancel();
    }

    Result<void> Channel::reset() {
        const std::scoped_lock lock(operation_mutex_);
        if (operation_active_) {
            return Error{ErrorCode::busy, "ISO transport callback cannot reenter the channel"};
        }
        ActiveOperation operation(operation_active_);
        try {
            return transport_->reset();
        } catch (...) {
            return Error{ErrorCode::internal, "ISO transport reset threw", Outcome::unknown};
        }
    }

    Result<Response> Channel::exchange(const Apdu& apdu, const ExchangeOptions& options,
                                       const Limits& limits) {
        const std::scoped_lock lock(operation_mutex_);
        if (operation_active_) {
            return Error{ErrorCode::busy, "ISO transport callback cannot reenter the channel"};
        }
        ActiveOperation operation(operation_active_);
        bool attempted_io = false;
        try {
            if (options.timeout.count() <= 0 || limits.max_response == 0 ||
                limits.max_frames == 0 || limits.max_frames > 65536) {
                return invalid(
                    "ISO exchange requires positive timeout and bounded byte/frame limits");
            }
            const auto transport_limits = transport_->capabilities();
            if (transport_limits.framing != Framing::iso7816) {
                return Error{ErrorCode::unsupported,
                             "Raw ISO commands require an APDU-capable transport"};
            }
            if (transport_limits.max_receive < 2) {
                return invalid("ISO transport cannot receive a status word");
            }
            auto initial = encode(apdu);
            if (!initial) {
                return initial.error();
            }
            if (initial.value().size() > transport_limits.max_transmit) {
                return invalid("ISO command exceeds transport transmit capacity");
            }
            Bytes request = std::move(initial.value());
            detail::Budget budget(*transport_, options);
            bool sent = false;
            bool continuation = false;
            bool corrected = false;
            Bytes assembled;
            for (std::size_t frame_index = 0; frame_index < limits.max_frames; ++frame_index) {
                auto remaining = budget.next(sent);
                if (!remaining) {
                    return remaining.error();
                }
                if (request.size() > transport_limits.max_transmit) {
                    return Error{ErrorCode::invalid_argument,
                                 "ISO continuation exceeds transport capacity",
                                 sent ? Outcome::unknown : Outcome::not_sent};
                }
                attempted_io = true;
                Result<Bytes> frame = Error{ErrorCode::transport, "ISO transport was not called"};
                try {
                    frame = transport_->exchange(request, remaining.value());
                } catch (...) {
                    return Error{ErrorCode::transport, "ISO transport threw during exchange",
                                 Outcome::unknown};
                }
                if (!frame) {
                    return sent ? detail::after_send(frame.error()) : frame.error();
                }
                sent = true;
                if (!budget.same_card()) {
                    return Error{ErrorCode::card_removed, "Card state changed after ISO response",
                                 Outcome::unknown};
                }
                if (frame.value().size() > transport_limits.max_receive) {
                    return detail::malformed("ISO response exceeds advertised transport capacity");
                }
                auto response = decode(frame.value());
                if (!response) {
                    return response.error();
                }
                const auto status = response.value().status;
                const auto sw1 = static_cast<Byte>(status >> 8U);
                const auto sw2 = static_cast<Byte>(status);
                if (sw1 == 0x6C && !response.value().data.empty()) {
                    return detail::malformed(
                        "ISO length-rejection response unexpectedly contains data", status);
                }
                if (sw1 == 0x6C && limits.correct_length && !continuation && !corrected) {
                    const std::uint32_t adjusted = sw2 == 0 ? 256 : sw2;
                    if (adjusted > limits.max_response) {
                        return detail::malformed(
                            "ISO corrected length exceeds configured response limit", status);
                    }
                    Apdu retry = apdu;
                    retry.le = adjusted;
                    auto encoded = encode(retry);
                    if (!encoded) {
                        return detail::after_send(encoded.error());
                    }
                    request = std::move(encoded.value());
                    corrected = true;
                    continue;
                }
                if (response.value().data.size() > limits.max_response - assembled.size()) {
                    return detail::malformed("ISO response exceeds configured aggregate byte limit",
                                             status);
                }
                append(assembled, response.value().data);
                if (sw1 != 0x61) {
                    return Response{std::move(assembled), status};
                }
                if (assembled.size() == limits.max_response) {
                    return detail::malformed(
                        "ISO continuation would exceed configured aggregate byte limit", status);
                }
                request = Bytes{0x00, 0xC0, 0x00, 0x00, sw2};
                continuation = true;
            }
            return detail::malformed("ISO command exceeded configured physical frame limit");
        } catch (...) {
            return Error{ErrorCode::internal, "ISO exchange dependency failed",
                         attempted_io ? Outcome::unknown : Outcome::not_sent};
        }
    }

} // namespace desfire::ev3::iso7816::raw
