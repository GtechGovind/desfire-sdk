/**
 * @file session.hpp
 * @brief Standard DESFire AES chained-IV secure-messaging state.
 */
#pragma once

#include <desfire/ev3/security/standard_aes/authentication.hpp>

#include <memory>
#include <optional>

namespace desfire::ev3::security::standard_aes {

    /**
     * @brief Own the session key and chained IV established by standard AES authentication.
     *
     * Card serializes access. Every successful cryptographic operation advances the shared IV;
     * every transport, integrity, or protocol failure invalidates the complete session.
     */
    class Session final {
    public:

        /**
         * @brief Create a ready standard AES session from verified authentication material.
         * @param crypto Shared AES primitive provider.
         * @param material Move-only sixteen-byte session key.
         * @return Session ownership, or a local argument error.
         */
        static Result<std::unique_ptr<Session>> create(std::shared_ptr<CryptoProvider> crypto,
                                                       AuthenticationMaterial material);

        /** @brief Destroy the session after its move-only key and IV storage are erased. */
        ~Session() = default;

        /**
         * @brief Update the chained CMAC IV and emit an unmodified Plain-mode command.
         * @param command Native command byte covered by CMAC.
         * @param header Clear command parameters covered by CMAC.
         * @param data Clear user data covered by CMAC.
         * @return Header and data without the calculated CMAC.
         */
        Result<Bytes> prepare_plain(Byte command, ByteView header, ByteView data);

        /**
         * @brief Verify the mandatory response CMAC for authenticated Plain communication.
         * @param response Terminal response containing clear data and an eight-byte CMAC.
         * @return Verified clear data.
         */
        Result<Bytes> accept_plain_response(const native::raw::Response& response);

        /**
         * @brief Calculate chained CMAC and append it only when user data is present.
         * @param command Native command byte covered by CMAC.
         * @param header Clear command parameters covered by CMAC.
         * @param data Clear user data; an empty field updates the IV without transmitting CMAC.
         * @return Header, data, and when required the first eight bytes of the CMAC.
         */
        Result<Bytes> prepare_mac(Byte command, ByteView header, ByteView data);

        /**
         * @brief Encrypt data with DESFire CRC-32 and zero padding using the chained IV.
         * @param command Native command byte included in the CRC.
         * @param header Clear command parameters included in the CRC but not encrypted.
         * @param data User data to encrypt; empty data performs the read-command CMAC update.
         * @return Clear header followed by encrypted data, CRC, and zero padding.
         */
        Result<Bytes> prepare_full(Byte command, ByteView header, ByteView data);

        /**
         * @brief Verify a response's first-eight-byte CMAC and advance the chained IV.
         * @param response Terminal clear response data followed by its CMAC.
         * @return Verified response data without its CMAC.
         */
        Result<Bytes> verify_response(const native::raw::Response& response);

        /**
         * @brief Decrypt and verify a CRC-protected Fully Enciphered response.
         * @param response Terminal ciphertext; status is included in CRC validation.
         * @param expected_size Exact clear-data size when known; otherwise a unique valid CRC split
         * is required.
         * @return Verified clear response data without CRC or zero padding.
         */
        Result<Bytes>
        verify_and_decrypt_full_response(const native::raw::Response& response,
                                         std::optional<std::size_t> expected_size = std::nullopt);

        /**
         * @brief Wipe the key and IV, then reject further operations.
         */
        void invalidate() noexcept;

    private:

        /** @brief Internal state that prevents chained-IV reuse after preparation. */
        enum class Phase { ready, awaiting_response, invalid };

        /**
         * @brief Retain validated dependencies after create() completes local checks.
         * @param crypto AES primitive provider retained for the session lifetime.
         * @param material Verified move-only session key.
         */
        Session(std::shared_ptr<CryptoProvider> crypto, AuthenticationMaterial material);

        /**
         * @brief Calculate AES-CMAC starting with this session's current chained IV.
         * @param input Complete command or response input.
         * @return Full sixteen-byte CMAC without changing session state.
         */
        Result<SecureBuffer> calculate_cmac(ByteView input);

        /**
         * @brief Prepare common command bytes and chained-CMAC state.
         * @param command Native command byte.
         * @param header Clear command parameters.
         * @param data Clear user data.
         * @param transmit_mac Whether to append the first eight CMAC bytes.
         * @return Complete status-free native command payload.
         */
        Result<Bytes> prepare_cmac_command(Byte command, ByteView header, ByteView data,
                                           bool transmit_mac);

        std::shared_ptr<CryptoProvider> crypto_; ///< AES primitives retained for session lifetime.
        SecureBuffer session_key_;               ///< Verified standard AES session key.
        SecureBuffer iv_;           ///< Current chained CMAC/CBC initialization vector.
        Phase phase_{Phase::ready}; ///< Current preparation/response state.
    };

} // namespace desfire::ev3::security::standard_aes
