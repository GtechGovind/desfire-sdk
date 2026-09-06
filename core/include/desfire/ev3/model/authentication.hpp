/**
 * @file authentication.hpp
 * @brief Non-secret key-resolution context and verified EV2 authentication metadata.
 */
#pragma once

#include "identifiers.hpp"

#include <array>
#include <optional>
#include <stop_token>
#include <utility>

namespace desfire::ev3::security::key_derivation {

    /** @brief General key-policy purpose shared by authentication, mutation, and offline paths. */
    enum class KeyPurpose {
        authentication,
        current_key,
        replacement_key,
        delegated_application,
        transaction_mac,
        offline_operation,
    };

    /** @brief Authentication protocol profile, separate from the general policy purpose. */
    enum class AuthenticationProfile {
        standard_aes,
        ev2_first,
        ev2_non_first,
        iso_aes,
    };

    /** @brief Card-side namespace associated with a provider key request. */
    enum class KeyScope {
        native,
        iso_picc,
        iso_application,
    };

    /**
     * @brief Own a bounded, non-secret opaque identifier understood by a key provider.
     *
     * The identifier is metadata such as an alias, vault object ID, or key-service handle. It must
     * never contain key bytes. The SDK compares or forwards it without interpreting its format.
     */
    class KeyReference final {
    public:

        /**
         * @brief Copy a provider identifier after bounding its allocation.
         * @param identifier One through 1024 non-secret opaque bytes.
         * @return Owned reference or invalid_argument before provider/card access.
         */
        static Result<KeyReference> make(ByteView identifier) {
            if (identifier.empty() || identifier.size() > 1024) {
                return invalid("Key reference must contain 1 through 1024 bytes");
            }
            return KeyReference(Bytes(identifier.begin(), identifier.end()));
        }

        /**
         * @brief Borrow the provider identifier.
         * @return View valid until this object is moved, replaced, or destroyed.
         */
        [[nodiscard]] ByteView value() const noexcept {
            return identifier_;
        }

        /** @brief Compare opaque provider identifiers byte for byte. */
        bool operator==(const KeyReference&) const = default;

    private:

        /**
         * @brief Retain an identifier already accepted by `make()`.
         * @param identifier Owned non-secret bytes.
         */
        explicit KeyReference(Bytes identifier) : identifier_(std::move(identifier)) {}

        Bytes identifier_; ///< Opaque key identifier owned by this reference.
    };

    /**
     * @brief Own bounded, non-secret policy and diversification inputs for one AES-128 key.
     *
     * Custom derivers decide how the fields affect their construction. The SDK does not infer byte
     * order, prepend a UID/AID, or silently combine fields. The optional application identifies
     * policy context; absence means the caller intentionally supplied no native AID.
     */
    class Aes128DerivationContext final {
    public:

        /**
         * @brief Validate and own one general-purpose derivation context.
         * @param purpose Intended authentication use.
         * @param key_number Native-width card key number used by the authentication command.
         * @param application Optional native application identity for host policy.
         * @param key_set Optional key-set number from zero through 15.
         * @param diversification_input Zero through 65,536 construction-specific bytes.
         * @param user_context Zero through 65,536 application/provider routing bytes.
         * @return Owned context, or invalid_argument before derivation or card I/O.
         */
        static Result<Aes128DerivationContext> make(KeyPurpose purpose, model::KeyNumber key_number,
                                                    std::optional<model::ApplicationId> application,
                                                    std::optional<Byte> key_set,
                                                    ByteView diversification_input,
                                                    ByteView user_context = {}) {
            constexpr std::size_t maximum_context_size = 64U * 1024U;
            switch (purpose) {
            case KeyPurpose::authentication:
            case KeyPurpose::current_key:
            case KeyPurpose::replacement_key:
            case KeyPurpose::delegated_application:
            case KeyPurpose::transaction_mac:
            case KeyPurpose::offline_operation:
                break;
            default:
                return invalid("Unknown AES-128 key purpose");
            }
            if (key_set && *key_set > 15) {
                return invalid("AES-128 derivation key set must be zero through 15");
            }
            if (diversification_input.size() > maximum_context_size ||
                user_context.size() > maximum_context_size ||
                diversification_input.size() > maximum_context_size - user_context.size()) {
                return invalid("AES-128 derivation context exceeds 65536 bytes");
            }

            return Aes128DerivationContext(
                purpose, key_number, application, key_set,
                Bytes(diversification_input.begin(), diversification_input.end()),
                Bytes(user_context.begin(), user_context.end()));
        }

        /** @brief Return the caller-declared intended key use. */
        [[nodiscard]] KeyPurpose purpose() const noexcept {
            return purpose_;
        }

        /** @brief Return the checked card key number. */
        [[nodiscard]] model::KeyNumber key_number() const noexcept {
            return key_number_;
        }

        /** @brief Return optional native application policy context. */
        [[nodiscard]] std::optional<model::ApplicationId> application() const noexcept {
            return application_;
        }

        /** @brief Return optional key-set number zero through 15. */
        [[nodiscard]] std::optional<Byte> key_set() const noexcept {
            return key_set_;
        }

        /** @brief Borrow construction-specific diversification bytes. */
        [[nodiscard]] ByteView diversification_input() const noexcept {
            return diversification_input_;
        }

        /** @brief Borrow application/provider routing context bytes. */
        [[nodiscard]] ByteView user_context() const noexcept {
            return user_context_;
        }

    private:

        /**
         * @brief Retain context fields already accepted by `make()`.
         * @param purpose Intended key use.
         * @param key_number Checked card key number.
         * @param application Optional application identity.
         * @param key_set Optional checked key set.
         * @param diversification_input Owned construction input.
         * @param user_context Owned routing input.
         */
        Aes128DerivationContext(KeyPurpose purpose, model::KeyNumber key_number,
                                std::optional<model::ApplicationId> application,
                                std::optional<Byte> key_set, Bytes diversification_input,
                                Bytes user_context)
            : purpose_(purpose), key_number_(key_number), application_(application),
              key_set_(key_set), diversification_input_(std::move(diversification_input)),
              user_context_(std::move(user_context)) {}

        KeyPurpose purpose_;          ///< Approved purpose for the derived key.
        model::KeyNumber key_number_; ///< Native key selector included in derivation context.
        std::optional<model::ApplicationId>
            application_; ///< Optional application identifier included in derivation context.
        std::optional<Byte>
            key_set_; ///< Optional EV2 key-set selector included in derivation context.
        Bytes diversification_input_; ///< Caller-defined bytes supplied to key diversification.
        Bytes user_context_;          ///< Opaque non-secret context forwarded to key providers.
    };

    /**
     * @brief Own the non-secret metadata supplied to one synchronous key-provider resolution.
     */
    class KeyRequest final {
    public:

        /**
         * @brief Create one provider request.
         * @param reference Opaque provider key identifier.
         * @param context Full purpose, card selector, and bounded caller context.
         * @param scope Native, ISO PICC, or ISO application card-side scope.
         * @param authentication_profile Authentication family when purpose is authentication.
         * @param cancellation Cooperative cancellation observed before the first card frame.
         * @return Owned provider request, or invalid_argument for inconsistent purpose/profile or
         * scope/profile combinations.
         */
        static Result<KeyRequest>
        make(KeyReference reference, Aes128DerivationContext context,
             KeyScope scope = KeyScope::native,
             std::optional<AuthenticationProfile> authentication_profile = {},
             std::stop_token cancellation = {}) {
            switch (scope) {
            case KeyScope::native:
            case KeyScope::iso_picc:
            case KeyScope::iso_application:
                break;
            default:
                return invalid("Unknown key-provider scope");
            }
            if (authentication_profile) {
                switch (*authentication_profile) {
                case AuthenticationProfile::standard_aes:
                case AuthenticationProfile::ev2_first:
                case AuthenticationProfile::ev2_non_first:
                case AuthenticationProfile::iso_aes:
                    break;
                default:
                    return invalid("Unknown authentication profile");
                }
            }
            const bool authentication = context.purpose() == KeyPurpose::authentication;
            if (authentication != authentication_profile.has_value()) {
                return invalid(
                    "Key request authentication purpose and profile must be supplied together");
            }
            if (authentication_profile) {
                const bool iso = *authentication_profile == AuthenticationProfile::iso_aes;
                if (iso == (scope == KeyScope::native)) {
                    return invalid("Key request authentication profile does not match its scope");
                }
            }

            return KeyRequest(std::move(reference), std::move(context), scope,
                              authentication_profile, cancellation);
        }

        /** @brief Borrow the non-secret opaque provider reference. */
        [[nodiscard]] const KeyReference& reference() const noexcept {
            return reference_;
        }

        /** @brief Borrow the complete derivation and policy context. */
        [[nodiscard]] const Aes128DerivationContext& context() const noexcept {
            return context_;
        }

        /** @brief Return the card-side namespace expected by this request. */
        [[nodiscard]] KeyScope scope() const noexcept {
            return scope_;
        }

        /** @brief Return the authentication family, or no value for non-authentication purposes. */
        [[nodiscard]] std::optional<AuthenticationProfile> authentication_profile() const noexcept {
            return authentication_profile_;
        }

        /**
         * @brief Return the cooperative provider-resolution cancellation token.
         * @return Token observed by synchronous key providers.
         */
        [[nodiscard]] std::stop_token cancellation() const noexcept {
            return cancellation_;
        }

    private:

        /**
         * @brief Retain an already validated provider request.
         * @param reference Opaque provider key identifier.
         * @param context Owned key policy context.
         * @param scope Card-side key namespace.
         * @param authentication_profile Optional authentication protocol family.
         * @param cancellation Cooperative cancellation token.
         */
        KeyRequest(KeyReference reference, Aes128DerivationContext context, KeyScope scope,
                   std::optional<AuthenticationProfile> authentication_profile,
                   std::stop_token cancellation)
            : reference_(std::move(reference)), context_(std::move(context)), scope_(scope),
              authentication_profile_(authentication_profile), cancellation_(cancellation) {}

        KeyReference reference_;          ///< Authenticated ISO key reference.
        Aes128DerivationContext context_; ///< Validated derivation context for this request.
        KeyScope scope_;                  ///< Card key scope for this request.
        std::optional<AuthenticationProfile>
            authentication_profile_;   ///< Authentication family requesting the key.
        std::stop_token cancellation_; ///< Cancellation token forwarded to the provider.
    };

} // namespace desfire::ev3::security::key_derivation

namespace desfire::ev3::model {

    /** @brief Non-secret metadata verified by EV2 First and retained by NonFirst. */
    struct AuthenticationInfo {
        std::array<Byte, 4> transaction_identifier{}; ///< Transaction identifier established by EV2
                                                      ///< First authentication.
        std::array<Byte, 6>
            picc_capabilities{}; ///< PICC capability bytes authenticated by the session.
        std::array<Byte, 6>
            pcd_capabilities{}; ///< PCD capability bytes echoed and authenticated by the card.

        /**
         * @brief Compare verified public authentication metadata.
         * @param other Metadata to compare.
         * @return True when transaction and capability fields match.
         */
        constexpr bool operator==(const AuthenticationInfo& other) const = default;
    };

} // namespace desfire::ev3::model
