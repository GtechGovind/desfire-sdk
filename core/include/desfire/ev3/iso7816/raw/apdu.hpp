/**
 * @file apdu.hpp
 * @brief Owned raw ISO/IEC 7816-4 command and response APDU models.
 */
#pragma once

#include <desfire/foundation/bytes.hpp>

#include <cstdint>
#include <optional>

namespace desfire::ev3::iso7816::raw {

    /** @brief APDU length representation; automatic selects the shortest valid form. */
    enum class LengthEncoding { automatic, short_apdu, extended };

    /**
     * @brief One owned raw command APDU before byte encoding.
     *
     * Raw commands preserve caller-supplied ISO fields. The codec validates structural lengths but
     * does not claim that an instruction, parameter, or retry is valid for a card application.
     */
    struct Apdu final {
        Byte cla{};                        ///< Class byte.
        Byte ins{};                        ///< Instruction byte.
        Byte p1{};                         ///< First instruction parameter.
        Byte p2{};                         ///< Second instruction parameter.
        Bytes data{};                      ///< Owned command data.
        std::optional<std::uint32_t> le{}; ///< Literal expected length from 1 through 65,536.
        LengthEncoding encoding{LengthEncoding::automatic}; ///< Requested length representation.
    };

    /** @brief One decoded raw response APDU retaining response data and the complete status word.
     */
    struct Response final {
        Bytes data{};           ///< Owned bytes before SW1/SW2.
        std::uint16_t status{}; ///< Complete SW1/SW2 in host order.

        /** @brief Report confirmed ISO success only for status 0x9000. */
        [[nodiscard]] bool success() const noexcept {
            return status == 0x9000;
        }

        /**
         * @brief Compare response data and status.
         * @return True when both values are equal; false otherwise.
         */
        bool operator==(const Response&) const = default;
    };

} // namespace desfire::ev3::iso7816::raw
