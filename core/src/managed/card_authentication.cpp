/**
 * @file card_authentication.cpp
 * @brief Managed Standard AES, EV2 AES, and ISO AES authentication.
 */
#include <desfire/ev3/managed/card.hpp>

#include "card_impl.hpp"
#include "operation_guard.hpp"

#include <desfire/ev3/iso7816/security/aes/authentication.hpp>
#include <desfire/ev3/security/ev2/authentication.hpp>
#include <desfire/ev3/security/standard_aes/authentication.hpp>

#include <stop_token>
#include <utility>

namespace desfire::ev3::managed {

    namespace {

        /**
         * @brief Replace untrusted resolver diagnostics with local pre-I/O evidence.
         * @param code Stable resolver failure category.
         * @param message Fixed secret-free managed diagnostic.
         * @return Failure that proves no authentication frame was sent.
         */
        Error local_resolution_error(ErrorCode code, const char* message) {
            return Error{code, message, Outcome::not_sent, 0};
        }

        /**
         * @brief Validate derivation metadata before invoking application code.
         * @param context Caller-owned bounded derivation context.
         * @return Success only for an authentication-purpose context.
         */
        Result<void> validate_derivation_context(
            const security::key_derivation::Aes128DerivationContext& context) {
            if (context.purpose() != security::key_derivation::KeyPurpose::authentication) {
                return invalid(
                    "Managed authentication requires authentication-purpose key context");
            }
            return {};
        }

        /**
         * @brief Match an ISO card selector to the approved derivation-context key number.
         * @param context Caller-owned derivation context.
         * @param key Validated PICC or application ISO key reference.
         * @return Success only when both selectors name the same card key.
         */
        Result<void>
        validate_iso_context_key(const security::key_derivation::Aes128DerivationContext& context,
                                 iso7816::checked::KeyReference key) {
            const std::uint32_t selected_key = key.value() == 0 ? 0U : (key.value() & 0x0FU);
            if (context.key_number().value() != selected_key) {
                return invalid(
                    "ISO derivation context key number does not match card key reference");
            }
            return {};
        }

        /**
         * @brief Validate one provider request against a managed authentication entry point.
         * @param request Validated non-secret provider request.
         * @param expected_profile Authentication family selected by the called method.
         * @param iso_key Optional actual ISO key selector; absence selects native authentication.
         * @return Success only when profile, scope, and card selector agree.
         */
        Result<void>
        validate_provider_request(const security::key_derivation::KeyRequest& request,
                                  security::key_derivation::AuthenticationProfile expected_profile,
                                  std::optional<iso7816::checked::KeyReference> iso_key = {}) {
            auto context = validate_derivation_context(request.context());
            if (!context) {
                return context.error();
            }
            if (request.authentication_profile() != expected_profile) {
                return invalid("Key provider request authentication profile does not match method");
            }

            if (!iso_key) {
                if (request.scope() != security::key_derivation::KeyScope::native) {
                    return invalid("Native authentication requires a native key-provider scope");
                }
                return {};
            }

            const bool picc_key = iso_key->value() == 0;
            const auto expected_scope = picc_key
                                            ? security::key_derivation::KeyScope::iso_picc
                                            : security::key_derivation::KeyScope::iso_application;
            if (request.scope() != expected_scope) {
                return invalid("ISO key-provider scope does not match the card key reference");
            }
            const std::uint32_t selected_key = picc_key ? 0U : (iso_key->value() & 0x0FU);
            if (request.context().key_number().value() != selected_key) {
                return invalid("ISO provider context key number does not match card key reference");
            }
            return {};
        }

        /**
         * @brief Invoke a caller deriver exactly once and contain all local failures.
         * @param deriver Caller-owned synchronous deriver.
         * @param master_key Exact master key borrowed only for the call.
         * @param context Bounded authentication-purpose derivation context.
         * @param options Managed cancellation controls checked around the call.
         * @return Independent exact key or redacted not-sent evidence.
         */
        Result<security::key_derivation::Aes128Key>
        derive_once(security::key_derivation::Aes128KeyDeriver& deriver,
                    const security::key_derivation::Aes128Key& master_key,
                    const security::key_derivation::Aes128DerivationContext& context,
                    const ExchangeOptions& options) {
            if (!master_key.valid()) {
                return invalid("Managed authentication master key was moved from");
            }
            if (options.stop.stop_requested()) {
                return local_resolution_error(ErrorCode::cancelled,
                                              "Authentication cancelled before key derivation");
            }

            try {
                auto derived = deriver.derive(master_key, context);
                if (!derived) {
                    return local_resolution_error(derived.error().code,
                                                  "AES-128 key derivation failed");
                }
                if (options.stop.stop_requested()) {
                    return local_resolution_error(ErrorCode::cancelled,
                                                  "Authentication cancelled after key derivation");
                }
                if (!derived.value().valid()) {
                    return local_resolution_error(ErrorCode::crypto,
                                                  "AES-128 deriver returned no exact key");
                }
                return std::move(derived).value();
            } catch (...) {
                return local_resolution_error(ErrorCode::internal,
                                              "AES-128 key deriver threw an exception");
            }
        }

        /**
         * @brief Invoke a caller provider exactly once with combined cooperative cancellation.
         * @param provider Caller-owned synchronous exportable-key provider.
         * @param request Validated non-secret request and caller cancellation token.
         * @param options Managed operation cancellation checked and forwarded to the provider.
         * @return Independent exact key or redacted not-sent evidence.
         */
        Result<security::key_derivation::Aes128Key>
        resolve_once(security::key_derivation::Aes128KeyProvider& provider,
                     const security::key_derivation::KeyRequest& request,
                     const ExchangeOptions& options) {
            if (request.cancellation().stop_requested() || options.stop.stop_requested()) {
                return local_resolution_error(ErrorCode::cancelled,
                                              "Authentication cancelled before key resolution");
            }

            try {
                std::stop_source combined;
                const auto request_stop = [&combined]() noexcept {
                    static_cast<void>(combined.request_stop());
                };
                const auto operation_stop = [&combined]() noexcept {
                    static_cast<void>(combined.request_stop());
                };
                std::stop_callback request_callback(request.cancellation(), request_stop);
                std::stop_callback operation_callback(options.stop, operation_stop);
                auto effective = security::key_derivation::KeyRequest::make(
                    request.reference(), request.context(), request.scope(),
                    request.authentication_profile(), combined.get_token());
                if (!effective) {
                    return local_resolution_error(ErrorCode::internal,
                                                  "Validated key request could not be copied");
                }

                auto resolved = provider.resolve(effective.value());
                if (!resolved) {
                    return local_resolution_error(resolved.error().code,
                                                  "AES-128 key provider failed");
                }
                if (combined.stop_requested()) {
                    return local_resolution_error(ErrorCode::cancelled,
                                                  "Authentication cancelled after key resolution");
                }
                if (!resolved.value().valid()) {
                    return local_resolution_error(ErrorCode::crypto,
                                                  "AES-128 key provider returned no exact key");
                }
                return std::move(resolved).value();
            } catch (...) {
                return local_resolution_error(ErrorCode::internal,
                                              "AES-128 key provider threw an exception");
            }
        }

    } // namespace

    /** @brief Implement `authentication_preflight_locked` to validate managed lifecycle state
     * before authentication. */
    Result<void> Card::authentication_preflight_locked(bool require_ev2_session,
                                                       const ExchangeOptions& options) {
        if (options.timeout.count() <= 0) {
            return invalid("Authentication requires a positive timeout");
        }
        if (options.stop.stop_requested()) {
            return Error{ErrorCode::cancelled, "Authentication cancelled before card I/O"};
        }
        if (!impl_->usable) {
            return Error{ErrorCode::session_invalid,
                         "Managed session is uncertain; reset before authentication"};
        }
        if (require_ev2_session && !impl_->ev2_session) {
            return Error{ErrorCode::session_invalid,
                         "EV2 NonFirst requires an active verified EV2 First session"};
        }
        if (impl_->raw->generation() != impl_->generation) {
            invalidate_locked();
            return Error{ErrorCode::card_removed, "Card state changed before authentication"};
        }
        return {};
    }

    /** @brief Implement `authenticate_ev2_locked` to complete EV2 authentication under managed
     * admission. */
    Result<model::AuthenticationInfo>
    Card::authenticate_ev2_locked(bool first, model::KeyNumber key_number,
                                  const security::key_derivation::Aes128Key& key,
                                  ByteView pcd_capabilities, const ExchangeOptions& options) {
        try {
            if (!key.valid()) {
                return invalid("EV2 AES key was moved from");
            }
            if (pcd_capabilities.size() > 6 || (!first && !pcd_capabilities.empty())) {
                return invalid(
                    "PCD capabilities must contain zero through six bytes and require EV2 First");
            }

            auto transaction = impl_->raw->begin(options);
            if (!transaction) {
                return transaction.error();
            }

            auto previous_iso_session = std::move(impl_->iso_session);
            const model::AuthenticationInfo previous_information =
                impl_->ev2_session ? impl_->ev2_session->authentication()
                                   : model::AuthenticationInfo{};
            const std::uint16_t previous_counter =
                impl_->ev2_session ? impl_->ev2_session->command_counter() : 0;
            // Adapt the admitted transaction to the authentication frame-exchange callback.
            const auto exchange = [&transaction](Byte command, ByteView data) {
                return transaction.value().exchange_frame(command, data);
            };

            Result<security::ev2::AuthenticationMaterial> material =
                first ? security::ev2::authenticate_first(*impl_->crypto,
                                                          static_cast<Byte>(key_number.value()),
                                                          key.view(), pcd_capabilities, exchange)
                      : security::ev2::authenticate_nonfirst(
                            *impl_->crypto, static_cast<Byte>(key_number.value()), key.view(),
                            previous_information, exchange);
            if (!material) {
                if (material.error().outcome == Outcome::not_sent) {
                    impl_->iso_session = std::move(previous_iso_session);
                } else {
                    invalidate_locked();
                }
                return material.error();
            }
            if (impl_->raw->generation() != impl_->generation) {
                invalidate_locked();
                return Error{ErrorCode::card_removed, "Card state changed after EV2 authentication",
                             Outcome::unknown};
            }

            auto session = security::ev2::Session::create(
                impl_->crypto, std::move(material.value()), first ? 0 : previous_counter);
            if (!session) {
                auto error = session.error();
                error.outcome = Outcome::unknown;
                invalidate_locked();
                return error;
            }

            const model::AuthenticationInfo information = session.value()->authentication();
            impl_->clear_native_session();
            impl_->ev2_session = std::move(session.value());
            impl_->authenticated_key = static_cast<Byte>(key_number.value());
            impl_->authentication_reset_pending = false;
            return information;
        } catch (...) {
            invalidate_locked();
            return Error{ErrorCode::internal, "EV2 authentication failed", Outcome::unknown};
        }
    }

    /** @brief Implement `authenticate_standard_aes_locked` to complete Standard AES authentication
     * under managed admission. */
    Result<void>
    Card::authenticate_standard_aes_locked(model::KeyNumber key_number,
                                           const security::key_derivation::Aes128Key& key,
                                           const ExchangeOptions& options) {
        try {
            if (!key.valid()) {
                return invalid("Standard AES key was moved from");
            }

            auto transaction = impl_->raw->begin(options);
            if (!transaction) {
                return transaction.error();
            }

            auto previous_iso_session = std::move(impl_->iso_session);
            /** @brief Exchange authentication frames inside one raw transaction lease. */
            const auto exchange = [&transaction](Byte command, ByteView data) {
                return transaction.value().exchange_frame(command, data);
            };
            auto material = security::standard_aes::authenticate(
                *impl_->crypto, static_cast<Byte>(key_number.value()), key.view(), exchange);
            if (!material) {
                if (material.error().outcome == Outcome::not_sent) {
                    impl_->iso_session = std::move(previous_iso_session);
                } else {
                    invalidate_locked();
                }
                return material.error();
            }
            if (impl_->raw->generation() != impl_->generation) {
                invalidate_locked();
                return Error{ErrorCode::card_removed,
                             "Card state changed after Standard AES authentication",
                             Outcome::unknown};
            }

            auto session =
                security::standard_aes::Session::create(impl_->crypto, std::move(material.value()));
            if (!session) {
                auto error = session.error();
                error.outcome = Outcome::unknown;
                invalidate_locked();
                return error;
            }

            impl_->clear_native_session();
            impl_->standard_aes_session = std::move(session.value());
            impl_->authenticated_key = static_cast<Byte>(key_number.value());
            impl_->authentication_reset_pending = false;
            return {};
        } catch (...) {
            invalidate_locked();
            return Error{ErrorCode::internal, "Standard AES authentication failed",
                         Outcome::unknown};
        }
    }

    /** @brief Implement `authenticate_standard_aes` to establish managed Standard AES session
     * state. */
    Result<void> Card::authenticate_standard_aes(model::KeyNumber key_number,
                                                 security::key_derivation::Aes128Key key,
                                                 const ExchangeOptions& options) {
        OperationGuard operation(impl_->operation_mutex, impl_->operation_active);
        if (!operation) {
            return Error{ErrorCode::busy, "Card callback cannot reenter an active operation"};
        }
        auto preflight = authentication_preflight_locked(false, options);
        if (!preflight) {
            return preflight.error();
        }
        return authenticate_standard_aes_locked(key_number, key, options);
    }

    /** @brief Derive once and authenticate Standard AES under one managed admission. */
    Result<void> Card::authenticate_standard_aes(
        security::key_derivation::Aes128Key master_key,
        security::key_derivation::Aes128KeyDeriver& deriver,
        const security::key_derivation::Aes128DerivationContext& context,
        const ExchangeOptions& options) {
        OperationGuard operation(impl_->operation_mutex, impl_->operation_active);
        if (!operation) {
            return Error{ErrorCode::busy, "Card callback cannot reenter an active operation"};
        }
        auto preflight = authentication_preflight_locked(false, options);
        if (!preflight) {
            return preflight.error();
        }
        auto valid = validate_derivation_context(context);
        if (!valid) {
            return valid.error();
        }
        auto key = derive_once(deriver, master_key, context, options);
        if (!key) {
            return key.error();
        }
        return authenticate_standard_aes_locked(context.key_number(), key.value(), options);
    }

    /** @brief Resolve once and authenticate Standard AES under one managed admission. */
    Result<void>
    Card::authenticate_standard_aes(security::key_derivation::Aes128KeyProvider& provider,
                                    const security::key_derivation::KeyRequest& request,
                                    const ExchangeOptions& options) {
        OperationGuard operation(impl_->operation_mutex, impl_->operation_active);
        if (!operation) {
            return Error{ErrorCode::busy, "Card callback cannot reenter an active operation"};
        }
        auto preflight = authentication_preflight_locked(false, options);
        if (!preflight) {
            return preflight.error();
        }
        auto valid = validate_provider_request(
            request, security::key_derivation::AuthenticationProfile::standard_aes);
        if (!valid) {
            return valid.error();
        }
        auto key = resolve_once(provider, request, options);
        if (!key) {
            return key.error();
        }
        return authenticate_standard_aes_locked(request.context().key_number(), key.value(),
                                                options);
    }

    /** @brief Establish EV2 First with an empty capability prefix and one direct exact key. */
    Result<model::AuthenticationInfo>
    Card::authenticate_ev2_first_aes(model::KeyNumber key_number,
                                     security::key_derivation::Aes128Key key,
                                     const ExchangeOptions& options) {
        return authenticate_ev2_first_aes_with_capabilities(key_number, std::move(key), {},
                                                            options);
    }

    /** @brief Establish EV2 First with explicit capabilities and one direct exact key. */
    Result<model::AuthenticationInfo> Card::authenticate_ev2_first_aes_with_capabilities(
        model::KeyNumber key_number, security::key_derivation::Aes128Key key,
        ByteView pcd_capabilities, const ExchangeOptions& options) {
        OperationGuard operation(impl_->operation_mutex, impl_->operation_active);
        if (!operation) {
            return Error{ErrorCode::busy, "Card callback cannot reenter an active operation"};
        }
        auto preflight = authentication_preflight_locked(false, options);
        if (!preflight) {
            return preflight.error();
        }
        return authenticate_ev2_locked(true, key_number, key, pcd_capabilities, options);
    }

    /** @brief Derive once and establish EV2 First with an empty capability prefix. */
    Result<model::AuthenticationInfo> Card::authenticate_ev2_first_aes(
        security::key_derivation::Aes128Key master_key,
        security::key_derivation::Aes128KeyDeriver& deriver,
        const security::key_derivation::Aes128DerivationContext& context,
        const ExchangeOptions& options) {
        return authenticate_ev2_first_aes_with_capabilities(std::move(master_key), deriver, context,
                                                            {}, options);
    }

    /** @brief Derive once and establish EV2 First with explicit capabilities. */
    Result<model::AuthenticationInfo> Card::authenticate_ev2_first_aes_with_capabilities(
        security::key_derivation::Aes128Key master_key,
        security::key_derivation::Aes128KeyDeriver& deriver,
        const security::key_derivation::Aes128DerivationContext& context, ByteView pcd_capabilities,
        const ExchangeOptions& options) {
        OperationGuard operation(impl_->operation_mutex, impl_->operation_active);
        if (!operation) {
            return Error{ErrorCode::busy, "Card callback cannot reenter an active operation"};
        }
        auto preflight = authentication_preflight_locked(false, options);
        if (!preflight) {
            return preflight.error();
        }
        if (pcd_capabilities.size() > 6) {
            return invalid("EV2 First PCD capabilities cannot exceed six bytes");
        }
        auto valid = validate_derivation_context(context);
        if (!valid) {
            return valid.error();
        }
        auto key = derive_once(deriver, master_key, context, options);
        if (!key) {
            return key.error();
        }
        return authenticate_ev2_locked(true, context.key_number(), key.value(), pcd_capabilities,
                                       options);
    }

    /** @brief Resolve once and establish EV2 First with an empty capability prefix. */
    Result<model::AuthenticationInfo>
    Card::authenticate_ev2_first_aes(security::key_derivation::Aes128KeyProvider& provider,
                                     const security::key_derivation::KeyRequest& request,
                                     const ExchangeOptions& options) {
        return authenticate_ev2_first_aes_with_capabilities(provider, request, {}, options);
    }

    /** @brief Resolve once and establish EV2 First with explicit capabilities. */
    Result<model::AuthenticationInfo> Card::authenticate_ev2_first_aes_with_capabilities(
        security::key_derivation::Aes128KeyProvider& provider,
        const security::key_derivation::KeyRequest& request, ByteView pcd_capabilities,
        const ExchangeOptions& options) {
        OperationGuard operation(impl_->operation_mutex, impl_->operation_active);
        if (!operation) {
            return Error{ErrorCode::busy, "Card callback cannot reenter an active operation"};
        }
        auto preflight = authentication_preflight_locked(false, options);
        if (!preflight) {
            return preflight.error();
        }
        if (pcd_capabilities.size() > 6) {
            return invalid("EV2 First PCD capabilities cannot exceed six bytes");
        }
        auto valid = validate_provider_request(
            request, security::key_derivation::AuthenticationProfile::ev2_first);
        if (!valid) {
            return valid.error();
        }
        auto key = resolve_once(provider, request, options);
        if (!key) {
            return key.error();
        }
        return authenticate_ev2_locked(true, request.context().key_number(), key.value(),
                                       pcd_capabilities, options);
    }

    /** @brief Establish EV2 NonFirst using one direct exact key. */
    Result<model::AuthenticationInfo>
    Card::authenticate_ev2_non_first_aes(model::KeyNumber key_number,
                                         security::key_derivation::Aes128Key key,
                                         const ExchangeOptions& options) {
        OperationGuard operation(impl_->operation_mutex, impl_->operation_active);
        if (!operation) {
            return Error{ErrorCode::busy, "Card callback cannot reenter an active operation"};
        }
        auto preflight = authentication_preflight_locked(true, options);
        if (!preflight) {
            return preflight.error();
        }
        return authenticate_ev2_locked(false, key_number, key, {}, options);
    }

    /** @brief Derive once and establish EV2 NonFirst under one managed admission. */
    Result<model::AuthenticationInfo> Card::authenticate_ev2_non_first_aes(
        security::key_derivation::Aes128Key master_key,
        security::key_derivation::Aes128KeyDeriver& deriver,
        const security::key_derivation::Aes128DerivationContext& context,
        const ExchangeOptions& options) {
        OperationGuard operation(impl_->operation_mutex, impl_->operation_active);
        if (!operation) {
            return Error{ErrorCode::busy, "Card callback cannot reenter an active operation"};
        }
        auto preflight = authentication_preflight_locked(true, options);
        if (!preflight) {
            return preflight.error();
        }
        auto valid = validate_derivation_context(context);
        if (!valid) {
            return valid.error();
        }
        auto key = derive_once(deriver, master_key, context, options);
        if (!key) {
            return key.error();
        }
        return authenticate_ev2_locked(false, context.key_number(), key.value(), {}, options);
    }

    /** @brief Implement `authenticate_ev2_non_first_aes` to replace managed EV2 session keys. */
    Result<model::AuthenticationInfo>
    Card::authenticate_ev2_non_first_aes(security::key_derivation::Aes128KeyProvider& provider,
                                         const security::key_derivation::KeyRequest& request,
                                         const ExchangeOptions& options) {
        OperationGuard operation(impl_->operation_mutex, impl_->operation_active);
        if (!operation) {
            return Error{ErrorCode::busy, "Card callback cannot reenter an active operation"};
        }
        auto preflight = authentication_preflight_locked(true, options);
        if (!preflight) {
            return preflight.error();
        }
        auto valid = validate_provider_request(
            request, security::key_derivation::AuthenticationProfile::ev2_non_first);
        if (!valid) {
            return valid.error();
        }
        auto key = resolve_once(provider, request, options);
        if (!key) {
            return key.error();
        }
        return authenticate_ev2_locked(false, request.context().key_number(), key.value(), {},
                                       options);
    }

    /** @brief Implement `authenticate_iso_aes_locked` to complete ISO AES authentication under
     * managed admission. */
    Result<void>
    Card::authenticate_iso_aes_locked(iso7816::checked::KeyReference key,
                                      const security::key_derivation::Aes128Key& aes_key,
                                      const ExchangeOptions& options) {
        if (impl_->authentication_reset_pending) {
            return Error{ErrorCode::session_invalid,
                         "Select an ISO file or reset before ISO authentication after local reset"};
        }
        if (!aes_key.valid()) {
            return invalid("ISO AES key was moved from");
        }

        auto previous_standard = std::move(impl_->standard_aes_session);
        auto previous_ev2 = std::move(impl_->ev2_session);
        auto previous_iso = std::move(impl_->iso_session);
        const auto previous_key = impl_->authenticated_key;
        impl_->authenticated_key.reset();
        try {
            auto authenticated = iso7816::security::aes::authenticate(
                *impl_->iso_checked, *impl_->crypto, key, aes_key.view(), options);
            if (!authenticated) {
                if (authenticated.error().outcome == Outcome::not_sent) {
                    impl_->standard_aes_session = std::move(previous_standard);
                    impl_->ev2_session = std::move(previous_ev2);
                    impl_->iso_session = std::move(previous_iso);
                    impl_->authenticated_key = previous_key;
                } else {
                    invalidate_locked();
                }
                return authenticated.error();
            }
            if (impl_->iso_checked->generation() != impl_->generation) {
                invalidate_locked();
                return Error{ErrorCode::card_removed, "Card state changed after ISO authentication",
                             Outcome::unknown};
            }

            impl_->iso_session = std::move(authenticated.value());
            impl_->authentication_reset_pending = false;
            return {};
        } catch (...) {
            invalidate_locked();
            return Error{ErrorCode::internal, "ISO authentication failed", Outcome::unknown};
        }
    }

    /** @brief Establish ISO AES using one consumed direct exact key. */
    Result<void> Card::authenticate_iso_aes(iso7816::checked::KeyReference key,
                                            security::key_derivation::Aes128Key aes_key,
                                            const ExchangeOptions& options) {
        OperationGuard operation(impl_->operation_mutex, impl_->operation_active);
        if (!operation) {
            return Error{ErrorCode::busy, "Card callback cannot reenter an active operation"};
        }
        auto preflight = authentication_preflight_locked(false, options);
        if (!preflight) {
            return preflight.error();
        }
        return authenticate_iso_aes_locked(key, aes_key, options);
    }

    /** @brief Derive once and establish ISO AES under one managed admission. */
    Result<void>
    Card::authenticate_iso_aes(iso7816::checked::KeyReference key,
                               security::key_derivation::Aes128Key master_key,
                               security::key_derivation::Aes128KeyDeriver& deriver,
                               const security::key_derivation::Aes128DerivationContext& context,
                               const ExchangeOptions& options) {
        OperationGuard operation(impl_->operation_mutex, impl_->operation_active);
        if (!operation) {
            return Error{ErrorCode::busy, "Card callback cannot reenter an active operation"};
        }
        auto preflight = authentication_preflight_locked(false, options);
        if (!preflight) {
            return preflight.error();
        }
        auto valid = validate_derivation_context(context);
        if (!valid) {
            return valid.error();
        }
        valid = validate_iso_context_key(context, key);
        if (!valid) {
            return valid.error();
        }
        auto derived = derive_once(deriver, master_key, context, options);
        if (!derived) {
            return derived.error();
        }
        return authenticate_iso_aes_locked(key, derived.value(), options);
    }

    /** @brief Resolve once and establish ISO AES under one managed admission. */
    Result<void> Card::authenticate_iso_aes(iso7816::checked::KeyReference key,
                                            security::key_derivation::Aes128KeyProvider& provider,
                                            const security::key_derivation::KeyRequest& request,
                                            const ExchangeOptions& options) {
        OperationGuard operation(impl_->operation_mutex, impl_->operation_active);
        if (!operation) {
            return Error{ErrorCode::busy, "Card callback cannot reenter an active operation"};
        }
        auto preflight = authentication_preflight_locked(false, options);
        if (!preflight) {
            return preflight.error();
        }
        auto valid = validate_provider_request(
            request, security::key_derivation::AuthenticationProfile::iso_aes, key);
        if (!valid) {
            return valid.error();
        }
        auto resolved = resolve_once(provider, request, options);
        if (!resolved) {
            return resolved.error();
        }
        return authenticate_iso_aes_locked(key, resolved.value(), options);
    }

} // namespace desfire::ev3::managed
