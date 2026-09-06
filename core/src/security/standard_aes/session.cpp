/**
 * @file session.cpp
 * @brief DESFire standard AES chained-IV secure messaging implementation.
 */
#include <desfire/ev3/security/standard_aes/session.hpp>

#include <algorithm>
#include <array>
#include <limits>

namespace desfire::ev3::security::standard_aes {

    namespace {

        /** @brief AES block width used by standard AES authentication and secure messaging. */
        constexpr std::size_t aes_block_size = 16;
        /** @brief Number of leading full-CMAC bytes transmitted by standard AES messaging. */
        constexpr std::size_t transmitted_mac_size = 8;
        /** @brief Width of a DESFire little-endian CRC-32 field. */
        constexpr std::size_t crc_size = 4;

        /**
         * @brief Adopt provider bytes into secret storage and enforce their exact length.
         * @param result Primitive result to consume.
         * @param expected Required byte count.
         * @return Protected output or unchanged provider evidence.
         */
        Result<SecureBuffer> secret_output(Result<Bytes> result, std::size_t expected) {
            if (!result) {
                return result.error();
            }
            SecureBuffer output(std::move(result.value()));
            if (output.size() != expected) {
                return Error{ErrorCode::crypto,
                             "Standard AES primitive returned an unexpected output length"};
            }
            return output;
        }

        /**
         * @brief Double one AES-CMAC subkey in the big-endian GF(2^128) representation.
         * @param block Sixteen-byte block changed in place.
         */
        void double_cmac_subkey(std::span<Byte, aes_block_size> block) noexcept {
            const bool reduce = (block.front() & 0x80U) != 0;
            Byte carry = 0;
            for (std::size_t index = block.size(); index > 0; --index) {
                const Byte current = block[index - 1];
                block[index - 1] = static_cast<Byte>((current << 1U) | carry);
                carry = static_cast<Byte>(current >> 7U);
            }
            if (reduce) {
                block.back() ^= 0x87U;
            }
        }

        /**
         * @brief Compare a stored little-endian CRC field with a calculated accumulator.
         * @param stored Four-byte wire field.
         * @param calculated DESFire CRC-32 accumulator.
         * @return True only when all four bytes match.
         */
        bool crc_matches(ByteView stored, std::uint32_t calculated) noexcept {
            if (stored.size() != crc_size) {
                return false;
            }
            std::array<Byte, crc_size> expected{};
            for (std::size_t index = 0; index < expected.size(); ++index) {
                expected[index] = static_cast<Byte>(calculated >> (index * 8U));
            }
            return constant_time_equal(stored, expected);
        }

    } // namespace

    Session::Session(std::shared_ptr<CryptoProvider> crypto, AuthenticationMaterial material)
        : crypto_(std::move(crypto)), session_key_(std::move(material.session_key)),
          iv_(aes_block_size) {}

    /** @copydoc Session::create */
    Result<std::unique_ptr<Session>> Session::create(std::shared_ptr<CryptoProvider> crypto,
                                                     AuthenticationMaterial material) {
        if (!crypto || material.session_key.size() != aes_block_size) {
            return invalid("Standard AES session requires a provider and sixteen-byte session key");
        }
        return std::unique_ptr<Session>(new Session(std::move(crypto), std::move(material)));
    }

    /** @copydoc Session::calculate_cmac */
    Result<SecureBuffer> Session::calculate_cmac(ByteView input) {
        try {
            const std::array<Byte, aes_block_size> zero{};
            auto encrypted_zero =
                secret_output(crypto_->cbc(Cipher::aes128, session_key_.view(), zero, zero, true),
                              aes_block_size);
            if (!encrypted_zero) {
                return encrypted_zero.error();
            }
            auto first_subkey = std::move(encrypted_zero.value());
            double_cmac_subkey(std::span<Byte, aes_block_size>{first_subkey.mutable_view().data(),
                                                               aes_block_size});

            const bool complete = !input.empty() && input.size() % aes_block_size == 0;
            const std::size_t block_count =
                input.empty() ? 1 : (input.size() + aes_block_size - 1) / aes_block_size;
            if (block_count > std::numeric_limits<std::size_t>::max() / aes_block_size) {
                return invalid("Standard AES CMAC input is too large");
            }
            SecureBuffer blocks(block_count * aes_block_size);
            std::ranges::copy(input, blocks.mutable_view().begin());
            auto last = blocks.mutable_view().last(aes_block_size);
            if (complete) {
                for (std::size_t index = 0; index < aes_block_size; ++index) {
                    last[index] ^= first_subkey.view()[index];
                }
            } else {
                const std::size_t used = input.size() % aes_block_size;
                last[used] = 0x80;
                double_cmac_subkey(std::span<Byte, aes_block_size>{
                    first_subkey.mutable_view().data(), aes_block_size});
                for (std::size_t index = 0; index < aes_block_size; ++index) {
                    last[index] ^= first_subkey.view()[index];
                }
            }

            auto encrypted = secret_output(
                crypto_->cbc(Cipher::aes128, session_key_.view(), iv_.view(), blocks.view(), true),
                blocks.size());
            if (!encrypted) {
                return encrypted.error();
            }
            SecureBuffer mac(aes_block_size);
            std::ranges::copy(encrypted.value().view().last(aes_block_size),
                              mac.mutable_view().begin());
            return mac;
        } catch (...) {
            return Error{ErrorCode::internal, "Standard AES CMAC calculation failed"};
        }
    }

    /** @copydoc Session::prepare_cmac_command */
    Result<Bytes> Session::prepare_cmac_command(Byte command, ByteView header, ByteView data,
                                                bool transmit_mac) {
        if (phase_ != Phase::ready) {
            return Error{ErrorCode::session_invalid, "Standard AES session is not ready"};
        }
        constexpr auto maximum = std::numeric_limits<std::size_t>::max();
        const std::size_t mac_bytes = transmit_mac ? transmitted_mac_size : 0;
        if (header.size() > maximum - 1 || data.size() > maximum - 1 - header.size() ||
            data.size() > maximum - header.size() ||
            data.size() + header.size() > maximum - mac_bytes) {
            return invalid("Standard AES command is too large");
        }
        try {
            SecureBuffer input(1 + header.size() + data.size());
            auto writable = input.mutable_view();
            writable.front() = command;
            std::ranges::copy(header, writable.subspan(1).begin());
            std::ranges::copy(data, writable.subspan(1 + header.size()).begin());
            auto mac = calculate_cmac(input.view());
            if (!mac) {
                invalidate();
                return mac.error();
            }

            Bytes output;
            output.reserve(header.size() + data.size() + mac_bytes);
            append(output, header);
            append(output, data);
            if (transmit_mac) {
                append(output, mac.value().view().first(transmitted_mac_size));
            }
            std::ranges::copy(mac.value().view(), iv_.mutable_view().begin());
            phase_ = Phase::awaiting_response;
            return output;
        } catch (...) {
            invalidate();
            return Error{ErrorCode::internal, "Standard AES command preparation failed"};
        }
    }

    /** @copydoc Session::prepare_plain */
    Result<Bytes> Session::prepare_plain(Byte command, ByteView header, ByteView data) {
        return prepare_cmac_command(command, header, data, false);
    }

    /** @copydoc Session::accept_plain_response */
    Result<Bytes> Session::accept_plain_response(const native::raw::Response& response) {
        return verify_response(response);
    }

    /** @copydoc Session::prepare_mac */
    Result<Bytes> Session::prepare_mac(Byte command, ByteView header, ByteView data) {
        return prepare_cmac_command(command, header, data, !data.empty());
    }

    /** @copydoc Session::prepare_full */
    Result<Bytes> Session::prepare_full(Byte command, ByteView header, ByteView data) {
        if (data.empty()) {
            return prepare_cmac_command(command, header, data, false);
        }
        if (phase_ != Phase::ready) {
            return Error{ErrorCode::session_invalid, "Standard AES session is not ready"};
        }
        constexpr auto maximum = std::numeric_limits<std::size_t>::max();
        if (header.size() > maximum - 1 || data.size() > maximum - 1 - header.size() ||
            data.size() > maximum - crc_size ||
            data.size() + crc_size > maximum - (aes_block_size - 1)) {
            return invalid("Standard AES Full command is too large");
        }

        try {
            const bool changes_another_aes_key =
                (command == 0xC4 || command == 0xC6) && data.size() == 21;
            const std::size_t command_data_size =
                changes_another_aes_key ? data.size() - crc_size : data.size();
            SecureBuffer crc_input(1 + header.size() + command_data_size);
            auto crc_writable = crc_input.mutable_view();
            crc_writable.front() = command;
            std::ranges::copy(header, crc_writable.subspan(1).begin());
            std::ranges::copy(data.first(command_data_size),
                              crc_writable.subspan(1 + header.size()).begin());
            const std::uint32_t checksum = crc32(crc_input.view());

            const std::size_t clear_size = data.size() + crc_size;
            const std::size_t padded_size =
                ((clear_size + aes_block_size - 1) / aes_block_size) * aes_block_size;
            if (header.size() > maximum - padded_size) {
                return invalid("Standard AES Full command is too large");
            }
            SecureBuffer padded(padded_size);
            std::ranges::copy(data.first(command_data_size), padded.mutable_view().begin());
            for (std::size_t index = 0; index < crc_size; ++index) {
                padded.mutable_view()[command_data_size + index] =
                    static_cast<Byte>(checksum >> (index * 8U));
            }
            if (changes_another_aes_key) {
                // ChangeKey case 1 carries a second CRC over the new key. Its command CRC
                // precedes that existing trailer even though the typed command retains the
                // trailer beside its key material for EV2 secure messaging.
                std::ranges::copy(
                    data.last(crc_size),
                    padded.mutable_view().subspan(command_data_size + crc_size).begin());
            }
            auto ciphertext = secret_output(
                crypto_->cbc(Cipher::aes128, session_key_.view(), iv_.view(), padded.view(), true),
                padded.size());
            if (!ciphertext) {
                invalidate();
                return ciphertext.error();
            }

            Bytes output;
            output.reserve(header.size() + ciphertext.value().size());
            append(output, header);
            append(output, ciphertext.value().view());
            std::ranges::copy(ciphertext.value().view().last(aes_block_size),
                              iv_.mutable_view().begin());
            phase_ = Phase::awaiting_response;
            return output;
        } catch (...) {
            invalidate();
            return Error{ErrorCode::internal, "Standard AES Full command preparation failed"};
        }
    }

    /** @copydoc Session::verify_response */
    Result<Bytes> Session::verify_response(const native::raw::Response& response) {
        if (phase_ != Phase::awaiting_response) {
            return Error{ErrorCode::session_invalid,
                         "Standard AES session is not awaiting a response"};
        }
        if (response.status != 0x00) {
            invalidate();
            if (response.status == 0xAF) {
                return Error{ErrorCode::malformed_response,
                             "Standard AES protected response is not terminal", Outcome::unknown,
                             response.status};
            }
            return Error{ErrorCode::card_rejected, "Card rejected standard AES command",
                         Outcome::rejected, response.status};
        }
        if (response.data.size() < transmitted_mac_size) {
            invalidate();
            return Error{ErrorCode::integrity, "Standard AES response has no complete CMAC",
                         Outcome::unknown};
        }

        try {
            const std::size_t data_size = response.data.size() - transmitted_mac_size;
            const auto data = ByteView{response.data}.first(data_size);
            const auto received_mac = ByteView{response.data}.subspan(data_size);
            SecureBuffer input(data.size() + 1);
            std::ranges::copy(data, input.mutable_view().begin());
            input.mutable_view().back() = response.status;
            auto mac = calculate_cmac(input.view());
            if (!mac) {
                invalidate();
                auto error = mac.error();
                error.outcome = Outcome::unknown;
                return error;
            }
            if (!constant_time_equal(received_mac,
                                     mac.value().view().first(transmitted_mac_size))) {
                invalidate();
                return Error{ErrorCode::integrity, "Standard AES response CMAC verification failed",
                             Outcome::unknown};
            }

            Bytes output(data.begin(), data.end());
            std::ranges::copy(mac.value().view(), iv_.mutable_view().begin());
            phase_ = Phase::ready;
            return output;
        } catch (...) {
            invalidate();
            return Error{ErrorCode::internal, "Standard AES response verification failed",
                         Outcome::unknown};
        }
    }

    /** @copydoc Session::verify_and_decrypt_full_response */
    Result<Bytes>
    Session::verify_and_decrypt_full_response(const native::raw::Response& response,
                                              std::optional<std::size_t> expected_size) {
        if (phase_ != Phase::awaiting_response) {
            return Error{ErrorCode::session_invalid,
                         "Standard AES session is not awaiting a response"};
        }
        if (response.status != 0x00) {
            invalidate();
            if (response.status == 0xAF) {
                return Error{ErrorCode::malformed_response,
                             "Standard AES encrypted response is not terminal", Outcome::unknown,
                             response.status};
            }
            return Error{ErrorCode::card_rejected, "Card rejected standard AES command",
                         Outcome::rejected, response.status};
        }
        if (response.data.empty() || response.data.size() % aes_block_size != 0) {
            invalidate();
            return Error{ErrorCode::integrity, "Standard AES encrypted response has invalid length",
                         Outcome::unknown};
        }

        try {
            auto clear = secret_output(
                crypto_->cbc(Cipher::aes128, session_key_.view(), iv_.view(), response.data, false),
                response.data.size());
            if (!clear) {
                invalidate();
                auto error = clear.error();
                error.outcome = Outcome::unknown;
                return error;
            }

            std::optional<std::size_t> verified_size;
            /** @brief Validate one candidate clear-data boundary against padding and response CRC.
             */
            const auto verifies = [&](std::size_t data_size) {
                if (data_size > clear.value().size() - crc_size) {
                    return false;
                }
                const std::size_t padding_size = clear.value().size() - data_size - crc_size;
                if (padding_size >= aes_block_size ||
                    !std::ranges::all_of(clear.value().view().subspan(data_size + crc_size),
                                         [](Byte value) { return value == 0; })) {
                    return false;
                }
                SecureBuffer crc_input(data_size + 1);
                std::ranges::copy(clear.value().view().first(data_size),
                                  crc_input.mutable_view().begin());
                crc_input.mutable_view().back() = response.status;
                return crc_matches(clear.value().view().subspan(data_size, crc_size),
                                   crc32(crc_input.view()));
            };

            if (expected_size) {
                if (verifies(*expected_size)) {
                    verified_size = *expected_size;
                }
            } else {
                const std::size_t maximum_padding =
                    std::min(aes_block_size - 1, clear.value().size() - crc_size);
                for (std::size_t padding = 0; padding <= maximum_padding; ++padding) {
                    const std::size_t candidate = clear.value().size() - crc_size - padding;
                    if (verifies(candidate)) {
                        if (verified_size) {
                            invalidate();
                            return Error{ErrorCode::integrity,
                                         "Standard AES response has ambiguous CRC boundary",
                                         Outcome::unknown};
                        }
                        verified_size = candidate;
                    }
                }
            }
            if (!verified_size) {
                invalidate();
                return Error{ErrorCode::integrity,
                             "Standard AES response CRC or zero padding is invalid",
                             Outcome::unknown};
            }

            const auto verified_data = clear.value().view().first(*verified_size);
            Bytes output(verified_data.begin(), verified_data.end());
            std::ranges::copy(ByteView{response.data}.last(aes_block_size),
                              iv_.mutable_view().begin());
            phase_ = Phase::ready;
            return output;
        } catch (...) {
            invalidate();
            return Error{ErrorCode::internal, "Standard AES response decryption failed",
                         Outcome::unknown};
        }
    }

    /** @copydoc Session::invalidate */
    void Session::invalidate() noexcept {
        wipe(session_key_.mutable_view());
        wipe(iv_.mutable_view());
        phase_ = Phase::invalid;
    }

} // namespace desfire::ev3::security::standard_aes
