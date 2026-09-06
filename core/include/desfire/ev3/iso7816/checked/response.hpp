/**
 * @file response.hpp
 * @brief Semantically checked ISO response and logical-exchange limits.
 */
#pragma once

#include <desfire/foundation/bytes.hpp>

namespace desfire::ev3::iso7816::checked {

    /** @brief Complete checked response retaining application data and the original status word. */
    struct Response final {
        std::uint16_t status{}; ///< Complete SW1/SW2 in host order.
        Bytes data{};           ///< Owned response bytes before SW1/SW2.

        /** @brief Report confirmed ISO success only for status 0x9000. */
        [[nodiscard]] bool success() const noexcept {
            return status == 0x9000;
        }

        /**
         * @brief Compare complete response data and status.
         * @return True when both values are equal; false otherwise.
         */
        bool operator==(const Response&) const = default;
    };

    /** @brief Checked aggregate response, frame, and safe read-correction bounds. */
    struct Limits final {
        std::size_t max_response{65536}; ///< Maximum aggregate response-data bytes.
        std::size_t max_frames{1024};    ///< Maximum physical frames in one logical exchange.
        bool correct_read_length{true};  ///< Permit one checked read-only 6Cxx correction.
    };

} // namespace desfire::ev3::iso7816::checked
