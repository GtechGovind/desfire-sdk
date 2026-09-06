/**
 * @file authentication.cpp
 * @brief Standard DESFire AES mutual authentication using native command 0xAA.
 */
#include <desfire/ev3/security/standard_aes/authentication.hpp>

#include <algorithm>
#include <array>
#include <string>

namespace desfire::ev3::security::standard_aes {

    namespace {

        /** @brief AES block width required by standard AES authentication fields. */
        constexpr std::size_t aes_block_size = 16;

        /**
         * @brief Adopt primitive bytes into protected storage and require an exact output size.
         * @param result Primitive operation result.
         * @param expected Required output size in bytes.
         * @return Protected output, or unchanged provider evidence.
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
         * @brief Validate an authentication phase before decrypting peer-controlled data.
         * @param response Parsed response frame from the card.
         * @param expected_status Required native phase status.
         * @param expected_size Required encrypted data size.
         * @return Success only for the exact expected standard AES phase.
         */
        Result<void> require_phase(const native::raw::Response& response, Byte expected_status,
                                   std::size_t expected_size) {
            if (response.status != expected_status) {
                if (response.status != 0x00 && response.status != 0xAF) {
                    return Error{ErrorCode::card_rejected,
                                 "Standard AES authentication was rejected by card",
                                 Outcome::rejected, response.status};
                }
                return Error{ErrorCode::malformed_response,
                             "Standard AES authentication returned an unexpected phase status",
                             Outcome::unknown, response.status};
            }
            if (response.data.size() != expected_size) {
                return Error{
                    ErrorCode::malformed_response,
                    "Standard AES authentication returned an invalid encrypted field length",
                    Outcome::unknown};
            }
            return {};
        }

        /**
         * @brief Rotate a sixteen-byte nonce one byte left in transmitted byte order.
         * @param input Verified nonce from either party.
         * @return Rotated nonce used by the reciprocal authentication proof.
         * @pre input contains exactly one AES block.
         */
        std::array<Byte, aes_block_size> rotate_left(ByteView input) {
            std::array<Byte, aes_block_size> output{};
            std::rotate_copy(input.begin(), input.begin() + 1, input.end(), output.begin());
            return output;
        }

    } // namespace

    /** @brief Implement the verified Standard AES mutual-authentication exchange. */
    Result<AuthenticationMaterial> authenticate(CryptoProvider& crypto, Byte key_number,
                                                ByteView key,
                                                const AuthenticationExchange& exchange) {
        if (key.size() != aes_block_size || key_number > 0x3F || !exchange) {
            return invalid("Standard AES authentication requires a 16-byte key and an exchange");
        }

        try {
            auto random_a = secret_output(crypto.random(aes_block_size), aes_block_size);
            if (!random_a) {
                return random_a.error();
            }

            const std::array<Byte, 1> payload{key_number};
            auto initial = exchange(0xAA, payload);
            if (!initial) {
                return initial.error();
            }
            auto initial_phase = require_phase(initial.value(), 0xAF, aes_block_size);
            if (!initial_phase) {
                return initial_phase.error();
            }

            const std::array<Byte, aes_block_size> zero_iv{};
            auto random_b =
                secret_output(crypto.cbc(Cipher::aes128, key, zero_iv, initial.value().data, false),
                              aes_block_size);
            if (!random_b) {
                auto error = random_b.error();
                error.outcome = Outcome::unknown;
                return error;
            }

            SecureBuffer proof(aes_block_size * 2);
            std::ranges::copy(random_a.value().view(), proof.mutable_view().begin());
            const auto rotated_b = rotate_left(random_b.value().view());
            std::ranges::copy(rotated_b, proof.mutable_view().begin() + aes_block_size);
            auto encrypted_proof = secret_output(
                crypto.cbc(Cipher::aes128, key, initial.value().data, proof.view(), true),
                proof.size());
            if (!encrypted_proof) {
                auto error = encrypted_proof.error();
                error.outcome = Outcome::unknown;
                return error;
            }

            auto terminal = exchange(0xAF, encrypted_proof.value().view());
            if (!terminal) {
                auto error = terminal.error();
                if (error.outcome == Outcome::not_sent) {
                    error.outcome = Outcome::unknown;
                }
                return error;
            }
            auto terminal_phase = require_phase(terminal.value(), 0x00, aes_block_size);
            if (!terminal_phase) {
                return terminal_phase.error();
            }

            const auto response_iv = encrypted_proof.value().view().last(aes_block_size);
            auto card_proof = secret_output(
                crypto.cbc(Cipher::aes128, key, response_iv, terminal.value().data, false),
                aes_block_size);
            if (!card_proof) {
                auto error = card_proof.error();
                error.outcome = Outcome::unknown;
                return error;
            }
            const auto expected_a = rotate_left(random_a.value().view());
            if (!constant_time_equal(card_proof.value().view(), expected_a)) {
                return Error{ErrorCode::authentication,
                             "Standard AES card proof did not match the host nonce",
                             Outcome::unknown};
            }

            SecureBuffer session_key(aes_block_size);
            auto output = session_key.mutable_view();
            std::ranges::copy(random_a.value().view().first(4), output.begin());
            std::ranges::copy(random_b.value().view().first(4), output.begin() + 4);
            std::ranges::copy(random_a.value().view().subspan(12, 4), output.begin() + 8);
            std::ranges::copy(random_b.value().view().subspan(12, 4), output.begin() + 12);
            return AuthenticationMaterial{std::move(session_key)};
        } catch (...) {
            return Error{ErrorCode::internal, "Standard AES dependency threw an exception",
                         Outcome::unknown};
        }
    }

} // namespace desfire::ev3::security::standard_aes
