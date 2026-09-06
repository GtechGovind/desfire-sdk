/**
 * @file codec.hpp
 * @brief Direct and ISO-wrapped codecs for one DESFire native frame.
 */
#pragma once

#include "../framing.hpp"
#include "message.hpp"

namespace desfire::ev3::native::raw {

    /**
     * @brief Encode one direct native reader frame.
     * @param command Native instruction byte.
     * @param data Status-free frame data borrowed for this call.
     * @return `command || data` as owned bytes.
     */
    Result<Bytes> encode_direct(Byte command, ByteView data);

    /**
     * @brief Decode one direct native reader response.
     * @param frame Complete reader response whose first byte is the native status.
     * @return Decoded status and data, or malformed_response for an empty frame.
     */
    Result<Response> decode_direct(ByteView frame);

    /**
     * @brief Encode one proprietary short ISO-wrapped native frame.
     * @param command Native instruction placed in the APDU INS byte.
     * @param data Status-free frame data borrowed for this call; at most 255 bytes.
     * @return Owned `90 INS 00 00 [Lc Data] 00` APDU, or invalid_argument before I/O.
     */
    Result<Bytes> encode_iso_wrapped(Byte command, ByteView data);

    /**
     * @brief Decode one proprietary ISO-wrapped native response.
     * @param frame Complete reader response ending in native status word `91xx`.
     * @return Decoded `xx` status and preceding data, or malformed_response.
     */
    Result<Response> decode_iso_wrapped(ByteView frame);

    /**
     * @brief Encode one native frame using an explicit reader presentation.
     * @param command Native instruction byte.
     * @param data Status-free frame data borrowed for this call.
     * @param framing Direct or proprietary ISO-wrapped presentation.
     * @return Owned reader frame, or an encoding failure before transmission.
     */
    Result<Bytes> encode(Byte command, ByteView data, native::Framing framing);

    /**
     * @brief Decode one reader response using an explicit native presentation.
     * @param frame Complete reader response.
     * @param framing Direct or proprietary ISO-wrapped presentation.
     * @return Native status and data with reader framing removed.
     */
    Result<Response> decode(ByteView frame, native::Framing framing);

} // namespace desfire::ev3::native::raw
