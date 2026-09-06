/**
 * @file codec.cpp
 * @brief Strict ISO APDU serialization and response decoding.
 */
#include "detail/codec_support.hpp"
#include <desfire/ev3/iso7816/raw/codec.hpp>

namespace desfire::ev3::iso7816::raw {

    /** @brief Implement `encode` to serialize a validated protocol request. */
    Result<Bytes> encode(const Apdu& apdu) {
        return detail::encode_fields(apdu);
    }

    /** @brief Implement `decode` to decode and validate a complete protocol response. */
    Result<Response> decode(ByteView frame) {
        if (frame.size() < 2) {
            return detail::malformed("ISO response lacks SW1 and SW2");
        }
        const auto status = static_cast<std::uint16_t>(
            (static_cast<unsigned>(frame[frame.size() - 2]) << 8U) | frame.back());
        return Response{Bytes(frame.begin(), frame.end() - 2), status};
    }

} // namespace desfire::ev3::iso7816::raw
