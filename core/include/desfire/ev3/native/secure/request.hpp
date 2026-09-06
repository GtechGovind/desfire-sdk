/**
 * @file request.hpp
 * @brief Validated-command view consumed by native secure messaging.
 */
#pragma once

#include <desfire/ev3/model/communication.hpp>
#include <desfire/foundation/bytes.hpp>

#include <cstddef>
#include <optional>

namespace desfire::ev3::native::secure {

    /**
     * @brief Borrow one command's checked fields for synchronous secure execution.
     *
     * Header and data storage must remain alive until `SecureNativeChannel::exchange()` returns.
     * The managed layer creates this view only after command-specific validation. The secure layer
     * validates generic response and chaining bounds but does not assign meaning to raw opcodes.
     */
    struct Request {
        Byte command{};    ///< Native instruction byte.
        ByteView header{}; ///< Clear command header authenticated but not encrypted.
        ByteView data{};   ///< Borrowed command data protected according to `request_mode`.
        model::CommunicationMode request_mode{
            model::CommunicationMode::mac}; ///< Command protection.
        model::CommunicationMode response_mode{
            model::CommunicationMode::mac}; ///< Response protection.
        std::size_t minimum_response{};     ///< Minimum clear response bytes after verification.
        std::size_t maximum_response{};     ///< Maximum clear response bytes after verification.
        std::optional<std::size_t> first_frame_data_size{}; ///< Prepared-wire first frame boundary.
        bool single_continuation_frame{};                   ///< Require one remaining upload frame.
        bool invalidates_session{}; ///< Successful command erases the supplied native session.
    };

} // namespace desfire::ev3::native::secure
