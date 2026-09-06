/**
 * @file channel.cpp
 * @brief Standard AES and EV2 native secure-message command execution.
 */
#include <desfire/ev3/native/secure/channel.hpp>

#include <desfire/ev3/security/ev2/session.hpp>
#include <desfire/ev3/security/standard_aes/session.hpp>

#include <limits>
#include <string>
#include <string_view>

namespace desfire::ev3::native::secure {

    using model::CommunicationMode;

    namespace {

        /** @brief Largest accepted clear logical response in the managed product contract. */
        constexpr std::size_t maximum_logical_response = 16U * 1024U * 1024U;

        /** @brief Maximum secure-message overhead allowed before clear response validation. */
        constexpr std::size_t response_protection_overhead = 32U;

        /**
         * @brief Validate protection modes and generic response bounds before session mutation.
         * @param request Borrowed checked command view.
         * @return Success or invalid_argument with Outcome::not_sent.
         */
        Result<void> validate(const Request& request) {
            if (request.minimum_response > request.maximum_response ||
                request.maximum_response > maximum_logical_response) {
                return invalid("Invalid secure native response bounds");
            }
            if (request.request_mode != CommunicationMode::plain &&
                request.request_mode != CommunicationMode::mac &&
                request.request_mode != CommunicationMode::full) {
                return invalid("Invalid native request communication mode");
            }
            if (request.response_mode != CommunicationMode::plain &&
                request.response_mode != CommunicationMode::mac &&
                request.response_mode != CommunicationMode::full) {
                return invalid("Invalid native response communication mode");
            }

            return {};
        }

        /**
         * @brief Convert a non-success native status into stable rejected evidence.
         * @param status Native card status byte.
         * @return Card-rejected error retaining the device status.
         */
        Error rejected(Byte status) {
            return Error{ErrorCode::card_rejected, "Native command was rejected by card",
                         Outcome::rejected, status};
        }

        /**
         * @brief Copy borrowed clear fields into one raw command payload.
         * @param request Borrowed secure request.
         * @return Owned concatenated header and data.
         */
        Bytes clear_payload(const Request& request) {
            Bytes payload(request.header.begin(), request.header.end());
            append(payload, request.data);
            return payload;
        }

        /**
         * @brief Build a raw request from prepared secure-message bytes.
         * @param request Borrowed checked command metadata.
         * @param wire_data Owned prepared payload.
         * @return Complete bounded raw request.
         */
        raw::Request raw_request(const Request& request, Bytes wire_data) {
            // Keep a small wire allowance even for exact-empty clear responses so unexpected card
            // data is collected and reported by the checked clear-length boundary.
            std::size_t maximum_response = request.maximum_response + response_protection_overhead;
            return raw::Request{
                .command = request.command,
                .data = std::move(wire_data),
                .maximum_response = maximum_response,
                .first_frame_data_size = request.first_frame_data_size,
                .single_continuation_frame = request.single_continuation_frame,
            };
        }

        /**
         * @brief Check final clear response length after authentication and decryption.
         * @param response Owned clear response bytes.
         * @param request Borrowed checked response bounds.
         * @return The response or malformed_response with unknown execution outcome.
         */
        Result<Bytes> check_response_size(Bytes response, const Request& request) {
            if (response.size() < request.minimum_response ||
                response.size() > request.maximum_response) {
                return Error{ErrorCode::malformed_response,
                             "Native response violates checked command length", Outcome::unknown};
            }

            return response;
        }

        /**
         * @brief Protect, exchange, and verify a command using either supported AES session family.
         * @tparam Session Standard AES or EV2 session implementing the secure-message operations.
         * @param raw_channel Serialized raw channel.
         * @param request Borrowed checked command view.
         * @param session Exclusively borrowed mutable session.
         * @param options Complete logical-command controls.
         * @return Verified clear response or exact failure evidence.
         */
        template <class Session>
        Result<Bytes> exchange_protected(raw::RawNativeChannel& raw_channel, const Request& request,
                                         Session& session, const ExchangeOptions& options) {
            auto valid = validate(request);
            if (!valid) {
                return valid.error();
            }

            auto transaction = raw_channel.begin(options);
            if (!transaction) {
                return transaction.error();
            }

            Result<Bytes> prepared = Bytes{};
            if (request.request_mode == CommunicationMode::plain) {
                prepared = session.prepare_plain(request.command, request.header, request.data);
            } else if (request.request_mode == CommunicationMode::mac) {
                prepared = session.prepare_mac(request.command, request.header, request.data);
            } else {
                prepared = session.prepare_full(request.command, request.header, request.data);
            }
            if (!prepared) {
                session.invalidate();
                return prepared.error();
            }

            auto response =
                transaction.value().exchange(raw_request(request, std::move(prepared.value())));
            if (!response) {
                session.invalidate();
                return response.error();
            }
            if (response.value().status != 0x00) {
                session.invalidate();
                return rejected(response.value().status);
            }

            Result<Bytes> clear = Bytes{};
            if (request.invalidates_session && request.response_mode == CommunicationMode::plain) {
                clear = std::move(response.value().data);
            } else if (request.response_mode == CommunicationMode::plain) {
                clear = session.accept_plain_response(response.value());
            } else if (request.response_mode == CommunicationMode::mac) {
                clear = session.verify_response(response.value());
            } else {
                const auto expected = request.minimum_response == request.maximum_response
                                          ? std::optional<std::size_t>(request.maximum_response)
                                          : std::nullopt;
                clear = session.verify_and_decrypt_full_response(response.value(), expected);
            }
            if (!clear) {
                session.invalidate();
                return clear.error();
            }

            auto checked = check_response_size(std::move(clear.value()), request);
            if (!checked) {
                session.invalidate();
                return checked.error();
            }
            if (request.invalidates_session) {
                session.invalidate();
            }

            return checked;
        }

    } // namespace

    /** @brief Implement `SecureNativeChannel` to construct a secure-messaging facade over the raw
     * channel. */
    SecureNativeChannel::SecureNativeChannel(std::shared_ptr<raw::RawNativeChannel> raw)
        : raw_(std::move(raw)) {}

    /** @brief Implement `~SecureNativeChannel` to release the secure-channel facade. */
    SecureNativeChannel::~SecureNativeChannel() = default;

    /** @brief Implement `connect` to validate dependencies and create a ready channel. */
    Result<std::shared_ptr<SecureNativeChannel>>
    SecureNativeChannel::connect(std::shared_ptr<raw::RawNativeChannel> raw) {
        if (!raw) {
            return invalid("Secure native channel requires a raw channel");
        }

        return std::shared_ptr<SecureNativeChannel>(new SecureNativeChannel(std::move(raw)));
    }

    /** @brief Implement `exchange_unprotected` to execute one checked command without secure
     * messaging. */
    Result<Bytes> SecureNativeChannel::exchange_unprotected(const Request& request,
                                                            const ExchangeOptions& options) {
        auto valid = validate(request);
        if (!valid) {
            return valid.error();
        }

        auto response = raw_->exchange(raw_request(request, clear_payload(request)), options);
        if (!response) {
            return response.error();
        }
        if (response.value().status != 0x00) {
            return rejected(response.value().status);
        }

        return check_response_size(std::move(response.value().data), request);
    }

    /** @brief Implement `exchange` to execute one bounded serialized card exchange. */
    Result<Bytes> SecureNativeChannel::exchange(const Request& request,
                                                security::standard_aes::Session& session,
                                                const ExchangeOptions& options) {
        return exchange_protected(*raw_, request, session, options);
    }

    /** @brief Implement `exchange` to execute one bounded serialized card exchange. */
    Result<Bytes> SecureNativeChannel::exchange(const Request& request,
                                                security::ev2::Session& session,
                                                const ExchangeOptions& options) {
        return exchange_protected(*raw_, request, session, options);
    }

} // namespace desfire::ev3::native::secure
