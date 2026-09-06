/**
 * @file session.hpp
 * @brief Counter-based DESFire EV2 secure-messaging state available on EV3.
 */
#pragma once

#include <desfire/ev3/security/ev2/authentication.hpp>

#include <memory>
#include <optional>

namespace desfire::ev3::security::ev2 {

    /**
     * @brief Own EV2 AES session keys, transaction metadata, and the command counter.
     *
     * Card serializes access. Preparing a message reserves one counter value; transport failure or
     * an invalid response must invalidate the session instead of reusing that counter.
     */
    class Session final {
    public:

        /**
         * @brief Create a ready session from verified EV2 authentication output.
         * @param crypto Shared AES primitive provider.
         * @param material Move-only authenticated session material.
         * @param counter Verified current counter; First authentication starts at zero.
         * @return Session ownership, or a pre-I/O argument failure.
         */
        static Result<std::unique_ptr<Session>> create(std::shared_ptr<CryptoProvider> crypto,
                                                       AuthenticationMaterial material,
                                                       std::uint16_t counter = 0);

        /** @brief Destroy the session after move-only key buffers erase their storage. */
        ~Session() = default;

        /**
         * @brief Reserve the counter for one authenticated Plain-mode command.
         * @param command Native command byte; it is not included in the returned payload.
         * @param header Clear command-specific header.
         * @param data Clear command data.
         * @return Header and data without a MAC; a terminal response must follow.
         */
        Result<Bytes> prepare_plain(Byte command, ByteView header, ByteView data);

        /**
         * @brief Accept the terminal response to a prepared Plain-mode command.
         * @param response Terminal native response whose data is not authenticated.
         * @return Unauthenticated response data, or a failure that invalidates the session.
         */
        Result<Bytes> accept_plain_response(const native::raw::Response& response);

        /**
         * @brief Protect a MAC-mode command and reserve its terminal response.
         * @param command Native command byte.
         * @param header Clear command-specific header bytes.
         * @param data Clear data bytes sent without encryption.
         * @return Header, data, and eight-byte transmitted CMAC.
         */
        Result<Bytes> prepare_mac(Byte command, ByteView header, ByteView data);

        /**
         * @brief Protect one Fully Enciphered command and reserve its terminal response.
         * @param command Native command byte.
         * @param clear_header Command bytes intentionally left outside ciphertext.
         * @param clear_data Plain data encoded with method-2 padding before AES-CBC encryption.
         * @return Header, ciphertext, and eight-byte transmitted CMAC.
         */
        Result<Bytes> prepare_full(Byte command, ByteView clear_header, ByteView clear_data);

        /**
         * @brief Verify a protected terminal response before exposing its non-MAC bytes.
         * @param response Terminal native response containing data and an eight-byte MAC.
         * @return Authenticated data with its trailing MAC removed.
         */
        Result<Bytes> verify_response(const native::raw::Response& response);

        /**
         * @brief Verify and decrypt a Fully Enciphered terminal response.
         * @param response Terminal native response containing ciphertext and response MAC.
         * @param expected_size Optional exact application-level plaintext length.
         * @return Authenticated, AES-decrypted, unpadded data.
         */
        Result<Bytes>
        verify_and_decrypt_full_response(const native::raw::Response& response,
                                         std::optional<std::size_t> expected_size = std::nullopt);

        /**
         * @brief Return the counter reserved for the next protected command.
         * @return Current verified 16-bit EV2 command counter.
         */
        [[nodiscard]] std::uint16_t command_counter() const noexcept;

        /**
         * @brief Return public metadata verified during authentication.
         * @return Immutable transaction identifier and capability records.
         */
        [[nodiscard]] const model::AuthenticationInfo& authentication() const noexcept;

        /**
         * @brief Wipe session keys and reject all future protected operations.
         */
        void invalidate() noexcept;

    private:

        /** @brief Internal state that prevents counter reuse between preparation and verification.
         */
        enum class Phase { ready, awaiting_response, awaiting_plain_response, invalid };

        /**
         * @brief Retain validated material after create() finishes local checks.
         * @param crypto AES primitive provider retained for the session lifetime.
         * @param material Move-only key material and public metadata.
         * @param counter Current verified EV2 counter.
         */
        Session(std::shared_ptr<CryptoProvider> crypto, AuthenticationMaterial material,
                std::uint16_t counter);

        std::shared_ptr<CryptoProvider> crypto_; ///< AES primitives retained for session lifetime.
        SecureBuffer encryption_key_;            ///< Current EV2 session encryption key.
        SecureBuffer mac_key_;                   ///< Current EV2 session authentication key.
        model::AuthenticationInfo
            authentication_{};      ///< Verified transaction and capability metadata.
        std::uint16_t counter_{};   ///< Counter reserved for the next command.
        Phase phase_{Phase::ready}; ///< Current preparation/response state.
    };

} // namespace desfire::ev3::security::ev2
