/**
 * @file authentication.cpp
 * @brief DESFire EV2 First and NonFirst mutual authentication available on EV3.
 */
#include <desfire/ev3/security/ev2/authentication.hpp>

#include <algorithm>
#include <array>
#include <functional>
#include <string>
#include <tuple>

namespace desfire::ev3::security::ev2 {

    using model::AuthenticationInfo;

    namespace {

        /** @brief AES block width required by EV2 AES authentication fields. */
        constexpr std::size_t aes_block_size = 16;
        /** @brief Size of the normalized PCD and PICC capability records. */
        constexpr std::size_t capability_size = 6;

        /**
         * @brief Adopt primitive bytes into protected storage and require the exact output size.
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
                             "EV2 AES primitive returned an unexpected output length"};
            }
            return output;
        }

        /**
         * @brief Validate an authentication phase before decrypting peer-controlled data.
         * @param response Parsed response frame from the card.
         * @param expected_status Required native phase status.
         * @param expected_size Required encrypted data size.
         * @param operation Stable operation name for redacted diagnostics.
         * @return Success only for the exact expected authenticated phase.
         */
        Result<void> require_phase(const native::raw::Response& response, Byte expected_status,
                                   std::size_t expected_size, std::string_view operation) {
            if (response.status != expected_status) {
                if (response.status != 0x00 && response.status != 0xAF) {
                    return Error{ErrorCode::card_rejected,
                                 std::string(operation) + " was rejected by card",
                                 Outcome::rejected, response.status};
                }
                return Error{ErrorCode::malformed_response,
                             std::string(operation) + " returned an unexpected phase status",
                             Outcome::unknown, response.status};
            }
            if (response.data.size() != expected_size) {
                return Error{ErrorCode::malformed_response,
                             std::string(operation) + " returned an invalid encrypted field length",
                             Outcome::unknown};
            }
            return {};
        }

        /**
         * @brief Rotate a 16-byte nonce one byte left in transmitted byte order.
         * @param input Verified nonce from either party.
         * @return Rotated nonce used by the reciprocal mutual-authentication proof.
         */
        std::array<Byte, aes_block_size> rotate_left(ByteView input) {
            std::array<Byte, aes_block_size> output{};
            std::rotate_copy(input.begin(), input.begin() + 1, input.end(), output.begin());
            return output;
        }

        /**
         * @brief Fill the 26-byte nonce context shared by EV2 ENC and MAC session-key vectors.
         * @param output Tail of one 32-byte CMAC derivation vector.
         * @param random_a Verified host nonce.
         * @param random_b Verified card nonce.
         */
        void write_session_context(std::span<Byte, 26> output, ByteView random_a,
                                   ByteView random_b) noexcept {
            output[0] = random_a[0];
            output[1] = random_a[1];
            for (std::size_t index = 0; index < 6; ++index) {
                output[2 + index] = static_cast<Byte>(random_a[2 + index] ^ random_b[index]);
            }
            for (std::size_t index = 0; index < 10; ++index) {
                output[8 + index] = random_b[6 + index];
            }
            for (std::size_t index = 0; index < 8; ++index) {
                output[18 + index] = random_a[8 + index];
            }
        }

        /**
         * @brief Derive one AES session key after both nonce proofs have verified.
         * @param crypto AES-CMAC provider.
         * @param key Verified static AES key.
         * @param label EV2-defined selector for ENC or MAC derivation.
         * @param random_a Verified host nonce.
         * @param random_b Verified card nonce.
         * @return One protected 16-byte session key.
         */
        Result<SecureBuffer> derive_key(CryptoProvider& crypto, ByteView key,
                                        std::array<Byte, 6> label, ByteView random_a,
                                        ByteView random_b) {
            SecureBuffer vector(32);
            std::ranges::copy(label, vector.mutable_view().begin());
            write_session_context(
                std::span<Byte, 26>{vector.mutable_view().data() + label.size(), 26}, random_a,
                random_b);
            return secret_output(crypto.cmac(Cipher::aes128, key, vector.view()), aes_block_size);
        }

        /**
         * @brief Build both private session keys only after a complete mutual-authentication proof.
         * @param crypto AES-CMAC provider.
         * @param key Verified static AES key.
         * @param random_a Verified host nonce.
         * @param random_b Verified card nonce.
         * @param information Public verified transaction metadata.
         * @return Complete move-only EV2 authenticated session material.
         */
        Result<AuthenticationMaterial> derive_material(CryptoProvider& crypto, ByteView key,
                                                       ByteView random_a, ByteView random_b,
                                                       AuthenticationInfo information) {
            auto encryption =
                derive_key(crypto, key, {0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80}, random_a, random_b);
            if (!encryption) {
                return encryption.error();
            }
            auto mac =
                derive_key(crypto, key, {0x5A, 0xA5, 0x00, 0x01, 0x00, 0x80}, random_a, random_b);
            if (!mac) {
                return mac.error();
            }
            return AuthenticationMaterial{std::move(encryption.value()), std::move(mac.value()),
                                          information};
        }

        /**
         * @brief Execute the nonce exchange shared by First and NonFirst authentication.
         * @param crypto AES and random source provider.
         * @param initial_command EV2 First or NonFirst command code.
         * @param initial_payload Command-specific initial request payload.
         * @param key Static AES-128 key.
         * @param terminal_size Required terminal encrypted field size.
         * @param operation Redacted command name for diagnostics.
         * @param exchange Serialized card exchange callback.
         * @return Verified nonces plus terminal decrypted bytes, or failure evidence.
         */
        Result<std::tuple<SecureBuffer, SecureBuffer, SecureBuffer>>
        exchange_nonces(CryptoProvider& crypto, Byte initial_command, ByteView initial_payload,
                        ByteView key, std::size_t terminal_size, std::string_view operation,
                        const AuthenticationExchange& exchange) {
            auto random_a = secret_output(crypto.random(aes_block_size), aes_block_size);
            if (!random_a) {
                return random_a.error();
            }

            auto initial = exchange(initial_command, initial_payload);
            if (!initial) {
                return initial.error();
            }
            auto initial_phase = require_phase(initial.value(), 0xAF, aes_block_size, operation);
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
                crypto.cbc(Cipher::aes128, key, zero_iv, proof.view(), true), proof.size());
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
            auto terminal_phase = require_phase(terminal.value(), 0x00, terminal_size, operation);
            if (!terminal_phase) {
                return terminal_phase.error();
            }
            auto plaintext = secret_output(
                crypto.cbc(Cipher::aes128, key, zero_iv, terminal.value().data, false),
                terminal_size);
            if (!plaintext) {
                auto error = plaintext.error();
                error.outcome = Outcome::unknown;
                return error;
            }
            return std::make_tuple(std::move(random_a.value()), std::move(random_b.value()),
                                   std::move(plaintext.value()));
        }

    } // namespace

    /** @brief Implement `authenticate_first` to complete EV2 First authentication and verify card
     * proof. */
    Result<AuthenticationMaterial> authenticate_first(CryptoProvider& crypto, Byte key_number,
                                                      ByteView key,
                                                      const AuthenticationExchange& exchange) {
        return authenticate_first(crypto, key_number, key, ByteView{}, exchange);
    }

    /** @brief Implement `authenticate_first` to complete EV2 First authentication and verify card
     * proof. */
    Result<AuthenticationMaterial> authenticate_first(CryptoProvider& crypto, Byte key_number,
                                                      ByteView key, ByteView pcd_capabilities,
                                                      const AuthenticationExchange& exchange) {
        if (key.size() != aes_block_size || key_number > 0x3F ||
            pcd_capabilities.size() > capability_size || !exchange) {
            return invalid(
                "EV2 AES First authentication requires a 16-byte key, zero through six PCD "
                "capability bytes, and an exchange");
        }
        try {
            Bytes payload{key_number, static_cast<Byte>(pcd_capabilities.size())};
            append(payload, pcd_capabilities);
            auto exchange_result = exchange_nonces(crypto, 0x71, payload, key, 32,
                                                   "EV2 AES First authentication", exchange);
            if (!exchange_result) {
                return exchange_result.error();
            }
            const auto& [random_a, random_b, terminal] = exchange_result.value();
            const auto expected_a = rotate_left(random_a.view());
            const auto terminal_data = terminal.view();
            if (!constant_time_equal(terminal_data.subspan(4, aes_block_size), expected_a)) {
                return Error{ErrorCode::authentication,
                             "EV2 AES First card proof did not match the host nonce",
                             Outcome::unknown};
            }
            const std::array<Byte, capability_size> expected_capabilities{};
            auto expected_capabilities_with_input = expected_capabilities;
            std::ranges::copy(pcd_capabilities, expected_capabilities_with_input.begin());
            if (!constant_time_equal(terminal_data.subspan(26, capability_size),
                                     expected_capabilities_with_input)) {
                return Error{ErrorCode::authentication,
                             "EV2 AES First card capability echo did not match the request",
                             Outcome::unknown};
            }
            AuthenticationInfo information{};
            std::ranges::copy(terminal_data.first(4), information.transaction_identifier.begin());
            std::ranges::copy(terminal_data.subspan(20, capability_size),
                              information.picc_capabilities.begin());
            std::ranges::copy(terminal_data.subspan(26, capability_size),
                              information.pcd_capabilities.begin());
            auto material =
                derive_material(crypto, key, random_a.view(), random_b.view(), information);
            if (!material) {
                auto error = material.error();
                error.outcome = Outcome::unknown;
                return error;
            }
            return material;
        } catch (...) {
            return Error{ErrorCode::internal, "EV2 AES First dependency threw an exception",
                         Outcome::unknown};
        }
    }

    /** @brief Implement `authenticate_nonfirst` to replace EV2 session keys while retaining
     * First-session metadata. */
    Result<AuthenticationMaterial> authenticate_nonfirst(CryptoProvider& crypto, Byte key_number,
                                                         ByteView key, AuthenticationInfo previous,
                                                         const AuthenticationExchange& exchange) {
        if (key.size() != aes_block_size || key_number > 0x3F || !exchange) {
            return invalid("EV2 AES NonFirst authentication requires a 16-byte key and exchange");
        }
        try {
            const std::array<Byte, 1> payload{key_number};
            auto exchange_result = exchange_nonces(crypto, 0x77, payload, key, aes_block_size,
                                                   "EV2 AES NonFirst authentication", exchange);
            if (!exchange_result) {
                return exchange_result.error();
            }
            const auto& [random_a, random_b, terminal] = exchange_result.value();
            const auto expected_a = rotate_left(random_a.view());
            if (!constant_time_equal(terminal.view(), expected_a)) {
                return Error{ErrorCode::authentication,
                             "EV2 AES NonFirst card proof did not match the host nonce",
                             Outcome::unknown};
            }
            auto material =
                derive_material(crypto, key, random_a.view(), random_b.view(), previous);
            if (!material) {
                auto error = material.error();
                error.outcome = Outcome::unknown;
                return error;
            }
            return material;
        } catch (...) {
            return Error{ErrorCode::internal, "EV2 AES NonFirst dependency threw an exception",
                         Outcome::unknown};
        }
    }

} // namespace desfire::ev3::security::ev2
