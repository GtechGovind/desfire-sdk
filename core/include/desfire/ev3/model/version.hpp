/**
 * @file version.hpp
 * @brief DESFire EV3 GetVersion models and checked response parser.
 */
#pragma once

#include <desfire/foundation/bytes.hpp>

#include <array>

namespace desfire::ev3::model {

    /** @brief One unmodified seven-byte DESFire hardware or software descriptor. */
    struct VersionPart {
        Byte vendor{};   ///< Hardware vendor identifier.
        Byte type{};     ///< Product type identifier.
        Byte subtype{};  ///< Product subtype identifier.
        Byte major{};    ///< Major version number.
        Byte minor{};    ///< Minor version number.
        Byte storage{};  ///< Storage-size descriptor.
        Byte protocol{}; ///< Protocol identifier.

        /**
         * @brief Compare all descriptor bytes without inferring a product generation.
         * @param other Descriptor to compare.
         * @return True when every transmitted byte is equal.
         */
        constexpr bool operator==(const VersionPart& other) const = default;
    };

    /** @brief Complete fixed-length payload returned by the native GetVersion command. */
    struct VersionInfo {
        VersionPart hardware{};      ///< Hardware version record returned by the card.
        VersionPart software{};      ///< Software version record returned by the card.
        std::array<Byte, 7> uid{};   ///< Card UID returned in the version response.
        std::array<Byte, 5> batch{}; ///< Five-byte manufacturing batch identifier.
        Byte production_week{};      ///< BCD production week reported by the card.
        Byte production_year{};      ///< BCD production year reported by the card.

        /**
         * @brief Compare complete decoded version information.
         * @param other Version information to compare.
         * @return True when all fixed wire fields match.
         */
        constexpr bool operator==(const VersionInfo& other) const = default;
    };

    /**
     * @brief Parse an assembled status-free GetVersion payload.
     * @param payload Exact response data collected across additional frames.
     * @return Decoded version information, or malformed_response for any non-28-byte payload.
     */
    Result<VersionInfo> parse_version(ByteView payload);

} // namespace desfire::ev3::model
