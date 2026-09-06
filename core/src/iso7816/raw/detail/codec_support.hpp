/**
 * @file codec_support.hpp
 * @brief Private ISO APDU structural validation and length encoding.
 */
#pragma once

#include <desfire/ev3/iso7816/raw/apdu.hpp>

#include <cstdint>
#include <string>
#include <utility>

namespace desfire::ev3::iso7816::raw::detail {

    /** @brief Largest data field representable by an extended APDU Lc. */
    inline constexpr std::size_t maximum_command_data = 65535;
    /** @brief Largest literal Le represented by the extended zero value. */
    inline constexpr std::uint32_t maximum_expected_data = 65536;

    /**
     * @brief Construct malformed-response evidence with an optional ISO status word.
     * @param message Non-sensitive structural failure description.
     * @param status Status observed before the structural failure, or zero when unavailable.
     * @return Malformed-response error with unknown delivery outcome.
     */
    inline Error malformed(std::string message, std::uint16_t status = 0) {
        return Error{ErrorCode::malformed_response, std::move(message), Outcome::unknown, status};
    }

    /**
     * @brief Report whether an APDU length policy is a supported enumerator.
     * @param encoding Candidate policy.
     * @return True for automatic, short, or extended representation.
     */
    inline bool valid_encoding(LengthEncoding encoding) noexcept {
        return encoding == LengthEncoding::automatic || encoding == LengthEncoding::short_apdu ||
               encoding == LengthEncoding::extended;
    }

    /**
     * @brief Encode one APDU after checking all representable lengths.
     * @param apdu Borrowed owned fields to encode.
     * @return Encoded bytes or invalid_argument before I/O.
     */
    inline Result<Bytes> encode_fields(const Apdu& apdu) {
        if (!valid_encoding(apdu.encoding) || apdu.data.size() > maximum_command_data ||
            (apdu.le && (*apdu.le == 0 || *apdu.le > maximum_expected_data))) {
            return invalid("ISO command has an invalid data or expected length");
        }
        const bool needs_extended = apdu.data.size() > 255 || (apdu.le && *apdu.le > 256);
        if (apdu.encoding == LengthEncoding::short_apdu && needs_extended) {
            return invalid("ISO command exceeds short APDU length capacity");
        }
        const bool extended = apdu.encoding == LengthEncoding::extended || needs_extended;
        Bytes encoded{apdu.cla, apdu.ins, apdu.p1, apdu.p2};
        encoded.reserve(apdu.data.size() + 9);
        if (!apdu.data.empty()) {
            if (extended) {
                encoded.push_back(0x00);
                encoded.push_back(static_cast<Byte>(apdu.data.size() >> 8U));
            }
            encoded.push_back(static_cast<Byte>(apdu.data.size()));
            append(encoded, apdu.data);
        }
        if (apdu.le) {
            if (extended) {
                if (apdu.data.empty()) {
                    encoded.push_back(0x00);
                }
                encoded.push_back(static_cast<Byte>(*apdu.le >> 8U));
            }
            encoded.push_back(static_cast<Byte>(*apdu.le));
        }
        return encoded;
    }

} // namespace desfire::ev3::iso7816::raw::detail
