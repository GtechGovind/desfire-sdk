/**
 * @file message.hpp
 * @brief Unprotected DESFire native request and response messages.
 */
#pragma once

#include <desfire/foundation/bytes.hpp>

#include <cstddef>
#include <optional>

namespace desfire::ev3::native::raw {

    /**
     * @brief Own one complete status-free native command before reader framing.
     *
     * The request is deliberately untyped and applies no authentication, MAC, encryption, or
     * command-specific validation. Use `managed::Card` for checked product operations.
     */
    struct Request {
        Byte command{}; ///< Native instruction byte.
        Bytes data{};   ///< Complete status-free logical command data.

        /** Largest aggregate status-free response accepted from the card, in bytes. */
        std::size_t maximum_response{16U * 1024U * 1024U};

        /** Optional exact data size sent with the initial instruction frame. */
        std::optional<std::size_t> first_frame_data_size{};

        /** Require all data after the first-frame boundary to fit one additional frame. */
        bool single_continuation_frame{};
    };

    /**
     * @brief Own one decoded native response with reader framing removed.
     */
    struct Response {
        Byte status{}; ///< Native status byte, including `AF` continuation.
        Bytes data{};  ///< Status-free response data.

        /**
         * @brief Compare status and response bytes.
         * @param other Decoded response to compare.
         * @return True when both fields are equal.
         */
        bool operator==(const Response& other) const = default;
    };

} // namespace desfire::ev3::native::raw
