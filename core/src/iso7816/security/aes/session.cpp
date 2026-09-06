/**
 * @file session.cpp
 * @brief ISO AES session lifetime and retained response-CMAC processing.
 */
#include "detail/session_support.hpp"
#include <desfire/ev3/iso7816/security/aes/session.hpp>

#include <algorithm>
#include <utility>

namespace desfire::ev3::iso7816::security::aes {

    /** @copydoc Session::Session */
    Session::Session(checked::KeyReference reference, SecureBuffer key, checked::Channel& channel,
                     std::uint64_t generation)
        : reference_(reference), key_(std::move(key)), channel_(&channel), generation_(generation) {
    }

    /** @copydoc Session::~Session */
    Session::~Session() {
        invalidate();
    }

    /** @copydoc Session::invalidate */
    void Session::invalidate() noexcept {
        key_ = SecureBuffer{};
        wipe(iv_);
        valid_ = false;
    }

    /** @copydoc Session::execute */
    Result<checked::Response> Session::execute(checked::Channel& channel, CryptoProvider& crypto,
                                               const checked::Command& command,
                                               const ExchangeOptions& options,
                                               const checked::Limits& limits) {
        bool attempted_io = false;
        try {
            if (!valid_) {
                return Error{ErrorCode::session_invalid, "ISO AES session is no longer valid"};
            }
            if (&channel != channel_ || channel.generation() != generation_) {
                invalidate();
                return Error{ErrorCode::card_removed,
                             "ISO AES session belongs to an earlier card generation"};
            }
            if (!command.is_read() && !command.is_write() &&
                !(command.is_selection() && !command.resets_authentication())) {
                return Error{ErrorCode::unsupported,
                             "ISO AES session accepts data commands and EF selection only"};
            }
            checked::Limits protected_limits = limits;
            protected_limits.correct_read_length = false;
            if (command.is_read()) {
                if (limits.max_response == 0 ||
                    limits.max_response > detail::maximum_expected_data) {
                    return invalid(
                        "ISO authenticated read requires a response limit from one through 65536");
                }
                protected_limits.max_response += 8;
            }
            attempted_io = true;
            auto response = channel.exchange(command, options, protected_limits);
            if (!response) {
                if (response.error().outcome != Outcome::not_sent) {
                    invalidate();
                }
                return response.error();
            }
            if (!response.value().success()) {
                // No application bytes from an unverified warning/error response escape this
                // session.
                const auto status = response.value().status;
                invalidate();
                return Error{ErrorCode::card_rejected, "ISO authenticated command rejected",
                             Outcome::rejected, status};
            }
            if (!command.is_read()) {
                if (command.is_write() && !response.value().data.empty()) {
                    invalidate();
                    return detail::malformed("ISO write unexpectedly returned response data",
                                             detail::success_status);
                }
                return response;
            }
            if (response.value().data.size() < 8) {
                invalidate();
                return detail::malformed("ISO authenticated read lacks its response CMAC",
                                         detail::success_status);
            }
            const auto payload_size = response.value().data.size() - 8;
            SecureBuffer mac_input(payload_size + 1);
            std::copy_n(response.value().data.begin(), payload_size,
                        mac_input.mutable_view().begin());
            auto mac = detail::retained_cmac(crypto, key_.view(), iv_, mac_input.view());
            if (!mac) {
                invalidate();
                return detail::after_send(mac.error());
            }
            if (!detail::equal_secret(mac.value().view().first(8),
                                      ByteView(response.value().data).last(8))) {
                wipe(response.value().data);
                invalidate();
                return Error{ErrorCode::integrity,
                             "ISO authenticated response CMAC verification failed",
                             Outcome::unknown};
            }
            if (channel.generation() != generation_) {
                invalidate();
                return Error{ErrorCode::card_removed, "Card changed while verifying ISO response",
                             Outcome::unknown};
            }
            std::copy(mac.value().view().begin(), mac.value().view().end(), iv_.begin());
            response.value().data.resize(payload_size);
            return response;
        } catch (...) {
            if (attempted_io) {
                invalidate();
            }
            return Error{ErrorCode::internal, "ISO AES response dependency failed",
                         attempted_io ? Outcome::unknown : Outcome::not_sent};
        }
    }

} // namespace desfire::ev3::iso7816::security::aes
