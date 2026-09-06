/**
 * @file codec.hpp
 * @brief Structural ISO/IEC 7816-4 APDU byte encoding and decoding.
 */
#pragma once

#include "apdu.hpp"

namespace desfire::ev3::iso7816::raw {

    /**
     * @brief Encode one owned APDU using its explicit short, extended, or automatic policy.
     * @param apdu Structurally validated at this boundary; semantic instruction checks are absent.
     * @return Encoded APDU bytes or invalid_argument before I/O.
     */
    Result<Bytes> encode(const Apdu& apdu);

    /**
     * @brief Decode response data followed by SW1/SW2 without interpreting card semantics.
     * @param frame Complete borrowed transport response.
     * @return Owned response data and status, or malformed_response for fewer than two bytes.
     */
    Result<Response> decode(ByteView frame);

} // namespace desfire::ev3::iso7816::raw
