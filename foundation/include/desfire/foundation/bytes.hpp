/**
 * @file bytes.hpp
 * @brief Shared byte representations and binary utility contracts.
 *
 * Defines owned and borrowed byte sequences together with conversion, wire-integer,
 * CRC, and comparison helpers. Secret material that must persist belongs in
 * SecureBuffer rather than ordinary Bytes storage.
 */

#pragma once

#include "result.hpp"

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace desfire {

    /**
     * @brief An unsigned wire byte, avoiding signed-character interpretation.
     */
    using Byte = std::uint8_t;

    /**
     * @brief Owned binary storage for ordinary payloads and responses.
     */
    using Bytes = std::vector<Byte>;

    /**
     * @brief Borrowed read-only bytes; the backing allocation must outlive the view.
     */
    using ByteView = std::span<const Byte>;

    /**
     * @brief Append a borrowed sequence to owned output storage.
     *
     * @param output Destination that may grow during this operation.
     * @param data Bytes to copy into the destination.
     * @pre The source does not alias the destination allocation.
     */
    inline void append(Bytes& output, ByteView data) {
        output.insert(output.end(), data.begin(), data.end());
    }

    /**
     * @brief Append the requested low-order bytes in little-endian wire order.
     *
     * @param output Destination that receives the encoded bytes.
     * @param value Integer whose low-order bytes are encoded.
     * @param count Number of bytes to append, from zero through four.
     * @pre The caller has checked that value fits the intended protocol field.
     *
     * @note This low-level helper deliberately narrows values. Range validation
     * belongs to typed command construction, before serialization begins.
     */
    inline void put_le(Bytes& output, std::uint32_t value, std::size_t count) {
        for (std::size_t index = 0; index < count; ++index) {
            output.push_back(static_cast<Byte>(value >> (8 * index)));
        }
    }

    /**
     * @brief Decode up to four little-endian bytes into an unsigned integer.
     *
     * @param input Borrowed wire field; bytes after the fourth are ignored.
     * @return The decoded integer, or zero for an empty field.
     * @pre The parser has validated the required length of the protocol field.
     */
    inline std::uint32_t get_le(ByteView input) {
        std::uint32_t value = 0;

        for (std::size_t index = 0; index < input.size() && index < 4; ++index) {
            value |= static_cast<std::uint32_t>(input[index]) << (8 * index);
        }

        return value;
    }

    /**
     * @brief Decode strict, case-insensitive hexadecimal text.
     *
     * @param text Input with no separators, whitespace, or incomplete byte pairs.
     * @return Owned bytes, or an invalid_argument error for malformed input.
     *
     * Example usage:
     * @code{.cpp}
     * const auto decoded = from_hex("1a2B");
     * // On success: decoded.value() == Bytes{0x1A, 0x2B}.
     * @endcode
     */
    Result<Bytes> from_hex(std::string_view text);

    /**
     * @brief Encode bytes as lowercase hexadecimal text.
     *
     * @param data Borrowed input that is not modified.
     * @return Two characters for each input byte, without separators.
     * @warning This helper does not redact secrets and must not be used to log keys.
     */
    std::string to_hex(ByteView data);

    /**
     * @brief Calculate CRC-A with initial value 0x6363 and polynomial 0x8408.
     *
     * @param data Bytes covered by the checksum in wire order.
     * @return The reflected 16-bit accumulator without a final XOR.
     */
    std::uint16_t crc16(ByteView data);

    /**
     * @brief Calculate the uncomplemented DESFire CRC-32 accumulator.
     *
     * @param data Bytes covered by the checksum in wire order.
     * @return The accumulator using initial 0xFFFFFFFF and polynomial 0xEDB88320.
     * @note No final XOR is applied; common file-checksum APIs differ here.
     */
    std::uint32_t crc32(ByteView data);

    /**
     * @brief Compare all bytes of equal-length sequences without an early mismatch return.
     *
     * @param left First borrowed sequence.
     * @param right Second borrowed sequence.
     * @return True if lengths and contents match; false otherwise.
     * @note Length is public. Source-level fixed work is not a platform-independent
     * timing certification; see the implementation for the exact guarantees.
     */
    bool constant_time_equal(ByteView left, ByteView right) noexcept;

} // namespace desfire
