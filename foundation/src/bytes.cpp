/**
 * @file bytes.cpp
 * @brief Byte conversion, CRC calculation, and binary comparison utilities.
 *
 * Implements shared binary helpers without reader or cryptographic provider
 * dependencies. CRC parameters are explicit because similarly named variants
 * can produce different results for the same input.
 */

#include <desfire/foundation/bytes.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace desfire {

    namespace {

        /** @brief Implement `make_hex_digit_table` to build the compile-time hexadecimal decoding
         * table. */
        constexpr auto make_hex_digit_table() {
            std::array<int, 256> table{};
            table.fill(-1);

            for (int digit = 0; digit < 10; ++digit) {
                const auto index = static_cast<std::size_t>(static_cast<unsigned char>('0')) +
                                   static_cast<std::size_t>(digit);
                table[index] = digit;
            }

            for (int digit = 0; digit < 6; ++digit) {
                const auto lower_index = static_cast<std::size_t>(static_cast<unsigned char>('a')) +
                                         static_cast<std::size_t>(digit);
                const auto upper_index = static_cast<std::size_t>(static_cast<unsigned char>('A')) +
                                         static_cast<std::size_t>(digit);
                table[lower_index] = 10 + digit;
                table[upper_index] = 10 + digit;
            }

            return table;
        }

        constexpr auto hex_digit_table = make_hex_digit_table();
        constexpr std::string_view hex_digits = "0123456789abcdef";

    } // namespace

    /** @brief Implement `from_hex` to decode validated hexadecimal text. */
    Result<Bytes> from_hex(std::string_view text) {
        // A trailing nibble cannot represent a byte. Reject it before allocation so
        // malformed traces cannot be mistaken for complete protocol messages.
        if (text.size() % 2 != 0) {
            return invalid("Hexadecimal input must have an even length");
        }

        Bytes decoded;
        decoded.reserve(text.size() / 2);

        for (std::size_t offset = 0; offset < text.size(); offset += 2) {
            // Plain char can be signed. Unsigned indexing safely rejects non-ASCII
            // input instead of accessing memory before the lookup table.
            const auto high_character = static_cast<unsigned char>(text[offset]);
            const auto low_character = static_cast<unsigned char>(text[offset + 1]);
            const int high_nibble = hex_digit_table[high_character];
            const int low_nibble = hex_digit_table[low_character];

            if (high_nibble < 0 || low_nibble < 0) {
                return invalid("Invalid hexadecimal input");
            }

            // The checked nibbles are converted to an unsigned fixed-width domain before
            // combining them, so no signed shift or bitwise promotion enters the wire byte.
            const auto high_bits = static_cast<std::uint32_t>(high_nibble);
            const auto low_bits = static_cast<std::uint32_t>(low_nibble);
            const auto byte = static_cast<Byte>((high_bits << 4U) | low_bits);
            decoded.push_back(byte);
        }

        return decoded;
    }

    /** @brief Implement `to_hex` to encode bytes as lowercase hexadecimal text. */
    std::string to_hex(ByteView data) {
        std::string encoded;
        encoded.reserve(data.size() * 2);

        for (const Byte byte : data) {
            // Emit the most-significant nibble first to preserve normal hex order.
            const auto index = static_cast<std::size_t>(byte);
            encoded.push_back(hex_digits[index >> std::size_t{4}]);
            encoded.push_back(hex_digits[index & std::size_t{0x0F}]);
        }

        return encoded;
    }

    /** @brief Implement `crc16` to calculate the DESFire CRC16 value. */
    std::uint16_t crc16(ByteView data) {
        constexpr std::uint32_t initial_value = 0x6363U;
        constexpr std::uint32_t reflected_polynomial = 0x8408U;
        std::uint32_t checksum = initial_value;

        for (const Byte byte : data) {
            checksum ^= static_cast<std::uint32_t>(byte);

            for (unsigned bit = 0; bit < 8; ++bit) {
                // The outgoing low bit determines whether polynomial reduction
                // is needed after shifting this reflected CRC register.
                if ((checksum & 0x0001U) != 0U) {
                    checksum = (checksum >> 1U) ^ reflected_polynomial;
                } else {
                    checksum >>= 1U;
                }
            }
        }

        return static_cast<std::uint16_t>(checksum);
    }

    /** @brief Implement `crc32` to calculate the DESFire CRC32 value. */
    std::uint32_t crc32(ByteView data) {
        constexpr std::uint32_t initial_value = 0xFFFFFFFFU;
        constexpr std::uint32_t reflected_polynomial = 0xEDB88320U;
        std::uint32_t checksum = initial_value;

        for (const Byte byte : data) {
            checksum ^= static_cast<std::uint32_t>(byte);

            for (unsigned bit = 0; bit < 8; ++bit) {
                if ((checksum & 0x00000001U) != 0U) {
                    checksum = (checksum >> 1U) ^ reflected_polynomial;
                } else {
                    checksum >>= 1U;
                }
            }
        }

        return checksum;
    }

    /** @brief Implement `constant_time_equal` to compare equal-length byte sequences without an
     * early mismatch return. */
    bool constant_time_equal(ByteView left, ByteView right) noexcept {
        if (left.size() != right.size()) {
            return false;
        }

        volatile unsigned differences = 0;

        for (std::size_t index = 0; index < left.size(); ++index) {
            const auto byte_difference = static_cast<unsigned>(left[index] ^ right[index]);
            differences = differences | byte_difference;
        }

        return differences == 0;
    }

} // namespace desfire