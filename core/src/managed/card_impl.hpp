/**
 * @file card_impl.hpp
 * @brief Private state for one managed DESFire EV3 Card.
 */
#pragma once

#include <desfire/ev3/iso7816/checked/channel.hpp>
#include <desfire/ev3/iso7816/raw/channel.hpp>
#include <desfire/ev3/iso7816/security/aes/session.hpp>
#include <desfire/ev3/managed/card.hpp>
#include <desfire/ev3/native/raw/channel.hpp>
#include <desfire/ev3/native/secure/channel.hpp>
#include <desfire/ev3/security/ev2/session.hpp>
#include <desfire/ev3/security/standard_aes/session.hpp>

#include <memory>
#include <mutex>
#include <optional>

namespace desfire::ev3::managed {

    /**
     * @brief Own transport, channels, mutually exclusive session families, and managed state.
     */
    class CardImpl final {
    public:

        /**
         * @brief Retain fully validated dependencies and capture the activated-card generation.
         * @param transport Activated transport used for actual ISO operations.
         * @param crypto AES provider used for authentication and ISO session operations.
         * @param raw Serialized direct-or-wrapped native channel over `transport`.
         * @param secure Secure-message executor over `raw`.
         * @param iso_raw Serialized raw ISO channel over the same managed transport.
         * @param iso_checked Checked actual-ISO facade bound to `iso_raw`.
         */
        CardImpl(std::shared_ptr<CardTransport> transport, std::shared_ptr<CryptoProvider> crypto,
                 std::shared_ptr<native::raw::RawNativeChannel> raw,
                 std::shared_ptr<native::secure::SecureNativeChannel> secure,
                 std::unique_ptr<iso7816::raw::Channel> iso_raw,
                 std::unique_ptr<iso7816::checked::Channel> iso_checked)
            : transport(std::move(transport)), crypto(std::move(crypto)), raw(std::move(raw)),
              secure(std::move(secure)), iso_raw(std::move(iso_raw)),
              iso_checked(std::move(iso_checked)), generation(this->transport->generation()) {}

        /** @brief Erase owned sessions through their RAII destructors. */
        ~CardImpl() = default;

        /** @brief Private live state cannot be copied. */
        CardImpl(const CardImpl&) = delete;

        /** @brief Private live state cannot be copy-assigned. */
        CardImpl& operator=(const CardImpl&) = delete;

        /** @brief Private live state remains at a stable address and cannot move. */
        CardImpl(CardImpl&&) = delete;

        /** @brief Private live state remains at a stable address and cannot move-assign. */
        CardImpl& operator=(CardImpl&&) = delete;

        /**
         * @brief Report whether either native AES session family is active.
         * @return True for exactly one Standard AES or EV2 session.
         */
        [[nodiscard]] bool has_native_session() const noexcept {
            return static_cast<bool>(standard_aes_session) || static_cast<bool>(ev2_session);
        }

        /**
         * @brief Wipe and release either active native AES session.
         */
        void clear_native_session() noexcept {
            if (standard_aes_session) {
                standard_aes_session->invalidate();
                standard_aes_session.reset();
            }
            if (ev2_session) {
                ev2_session->invalidate();
                ev2_session.reset();
            }
        }

        std::shared_ptr<CardTransport> transport; ///< Activated card transport.
        std::shared_ptr<CryptoProvider> crypto;   ///< Cryptographic primitive provider.
        std::shared_ptr<native::raw::RawNativeChannel>
            raw; ///< Native raw channel sharing the card transport.
        std::shared_ptr<native::secure::SecureNativeChannel>
            secure; ///< Native secure-messaging channel.
        std::unique_ptr<iso7816::raw::Channel>
            iso_raw; ///< ISO APDU channel sharing the card transport.
        std::unique_ptr<iso7816::checked::Channel> iso_checked; ///< Checked ISO command channel.
        std::unique_ptr<security::standard_aes::Session>
            standard_aes_session; ///< Active Standard AES session, when authenticated.
        std::unique_ptr<security::ev2::Session>
            ev2_session;                       ///< Active EV2 AES session, when authenticated.
        std::optional<Byte> authenticated_key; ///< Authenticated native key selector, when known.
        std::unique_ptr<iso7816::security::aes::Session>
            iso_session;                      ///< Active ISO AES session, when authenticated.
        std::recursive_mutex operation_mutex; ///< Mutex serializing operations for this card.
        bool operation_active{};    ///< Whether a managed operation currently owns admission.
        std::uint64_t generation{}; ///< Card generation captured for lifecycle checks.
        bool usable{true};          ///< Whether card state remains safe for further commands.
        bool authentication_reset_pending{}; ///< Whether ISO authentication requires selection or
                                             ///< reset first.
        std::optional<std::uint32_t> selected_application{
            0}; ///< Currently tracked native application selection.
    };

} // namespace desfire::ev3::managed
