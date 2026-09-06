/**
 * @file codec.cpp
 * @brief Direct and ISO-wrapped native frame serialization and response decoding.
 */
#include <desfire/ev3/native/raw/codec.hpp>

#include <limits>

namespace desfire::ev3::native::raw {

    /** @brief Implement `encode_direct` to serialize a direct native command frame. */
    Result<Bytes> encode_direct(Byte command, ByteView data) {
        Bytes frame{command};
        append(frame, data);
        return frame;
    }

    /** @brief Implement `decode_direct` to decode a direct native response. */
    Result<Response> decode_direct(ByteView frame) {
        if (frame.empty()) {
            return Error{ErrorCode::malformed_response, "Direct native response has no status",
                         Outcome::unknown};
        }

        return Response{frame.front(), Bytes(frame.begin() + 1, frame.end())};
    }

    /** @brief Implement `encode_iso_wrapped` to serialize a native command in ISO-wrapped framing.
     */
    Result<Bytes> encode_iso_wrapped(Byte command, ByteView data) {
        if (data.size() > std::numeric_limits<Byte>::max()) {
            return invalid("ISO-wrapped native frame exceeds short APDU capacity");
        }

        Bytes frame{0x90, command, 0x00, 0x00};
        if (!data.empty()) {
            frame.push_back(static_cast<Byte>(data.size()));
            append(frame, data);
        }
        frame.push_back(0x00);
        return frame;
    }

    /** @brief Implement `decode_iso_wrapped` to decode an ISO-wrapped native response. */
    Result<Response> decode_iso_wrapped(ByteView frame) {
        if (frame.size() < 2 || frame[frame.size() - 2] != 0x91) {
            return Error{ErrorCode::malformed_response,
                         "ISO-wrapped native response lacks 91xx status", Outcome::unknown};
        }

        return Response{frame.back(), Bytes(frame.begin(), frame.end() - 2)};
    }

    /** @brief Implement `encode` to serialize a validated protocol request. */
    Result<Bytes> encode(Byte command, ByteView data, native::Framing framing) {
        if (framing == native::Framing::direct) {
            return encode_direct(command, data);
        }

        return encode_iso_wrapped(command, data);
    }

    /** @brief Implement `decode` to decode and validate a complete protocol response. */
    Result<Response> decode(ByteView frame, native::Framing framing) {
        if (framing == native::Framing::direct) {
            return decode_direct(frame);
        }

        return decode_iso_wrapped(frame);
    }

} // namespace desfire::ev3::native::raw
