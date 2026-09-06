/**
 * @file session.hpp
 * @brief Verified ISO mutual AES session and response-integrity state.
 */
#pragma once

#include "authentication.hpp"

#include <array>

namespace desfire::ev3::iso7816::security::aes {

    /** @brief ISO AES session bound to one checked channel identity and card generation. */
    class Session final {
    public:

        /** @brief Erase the session key and retained response-CMAC state. */
        ~Session();

        /** @brief Prevent copying secret session state. */
        Session(const Session&) = delete;
        /** @brief Prevent copy assignment of secret session state. */
        Session& operator=(const Session&) = delete;
        /** @brief Prevent moving state bound to a stable channel identity. */
        Session(Session&&) = delete;
        /** @brief Prevent moving state bound to a stable channel identity. */
        Session& operator=(Session&&) = delete;

        /**
         * @brief Execute an ISO data command or EF selection with retained CMAC state.
         * @param channel Same checked channel used by authenticate().
         * @param crypto AES provider used for response verification.
         * @param command Checked data or EF-selection command.
         * @param options Logical operation timeout and cancellation controls.
         * @param limits Aggregate byte and frame bounds.
         * @return Verified response, or failure that may permanently invalidate this session.
         */
        Result<checked::Response> execute(checked::Channel& channel, CryptoProvider& crypto,
                                          const checked::Command& command,
                                          const ExchangeOptions& options = {},
                                          const checked::Limits& limits = {});

        /** @brief Report whether all delivery and integrity checks preserved the session. */
        [[nodiscard]] bool valid() const noexcept {
            return valid_;
        }

        /** @brief Return the non-secret key reference authenticated by this session. */
        [[nodiscard]] checked::KeyReference key_reference() const noexcept {
            return reference_;
        }

        /** @brief Erase secrets and permanently invalidate the session. */
        void invalidate() noexcept;

    private:

        /** @brief Permit the verified authentication factory to install derived session state. */
        friend Result<std::unique_ptr<Session>>
        authenticate(checked::Channel& channel, CryptoProvider& crypto, checked::KeyReference key,
                     ByteView derived_key, const ExchangeOptions& options,
                     raw::LengthEncoding encoding);

        /**
         * @brief Adopt a private derived key bound to one checked channel generation.
         * @param reference Validated ISO card key reference.
         * @param key Validated card key selector or key material.
         * @param channel Channel identity to compare.
         * @param generation Card generation captured for lifecycle validation.
         */
        Session(checked::KeyReference reference, SecureBuffer key, checked::Channel& channel,
                std::uint64_t generation);

        checked::KeyReference reference_; ///< Authenticated ISO key reference.
        SecureBuffer key_;                ///< Derived ISO AES session key.
        std::array<Byte, 16> iv_{};       ///< Retained response-CMAC initialization vector.
        const checked::Channel* channel_; ///< Channel identity to which this state is bound.
        std::uint64_t generation_;        ///< Card generation captured when this state was created.
        bool valid_{true};                ///< Whether this object still owns valid protocol state.
    };

} // namespace desfire::ev3::iso7816::security::aes
