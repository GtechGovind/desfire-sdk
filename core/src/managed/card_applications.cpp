/**
 * @file card_applications.cpp
 * @brief Managed application selection, enumeration, creation, and deletion.
 */
#include <desfire/ev3/managed/card.hpp>

#include "card_impl.hpp"
#include "model_names.hpp"
#include "operation_guard.hpp"

#include <array>

namespace desfire::ev3::managed {

    namespace {

        /**
         * @brief Encode a validated three-byte application ID in native little-endian order.
         * @param id Validated application identifier.
         * @return Fixed three-byte command data.
         */
        std::array<Byte, 3> application_data(model::ApplicationId id) {
            return {static_cast<Byte>(id.value()), static_cast<Byte>(id.value() >> 8U),
                    static_cast<Byte>(id.value() >> 16U)};
        }

        /**
         * @brief Execute one successfully built application command.
         * @param card Managed card.
         * @param command Checked command result or preflight error.
         * @param options Complete operation controls.
         * @return Status-free response or preserved preflight/execution failure.
         */
        Result<Bytes> run(Card& card, Result<native::checked::Command> command,
                          const ExchangeOptions& options) {
            if (!command) {
                return command.error();
            }

            return card.execute(command.value(), options);
        }

        /**
         * @brief Execute one application mutation and discard its checked empty response.
         * @param card Managed card.
         * @param command Checked command result or preflight error.
         * @param options Complete operation controls.
         * @return Success or preserved failure evidence.
         */
        Result<void> run_void(Card& card, Result<native::checked::Command> command,
                              const ExchangeOptions& options) {
            auto result = run(card, std::move(command), options);
            if (!result) {
                return result.error();
            }

            return {};
        }

    } // namespace

    /** @brief Select an application after erasing authentication bound to the old selection. */
    Result<void> Card::select_application(model::ApplicationId id, const ExchangeOptions& options) {
        OperationGuard operation(impl_->operation_mutex, impl_->operation_active);
        if (!operation) {
            return Error{ErrorCode::busy, "Card callback cannot reenter an active operation"};
        }
        if (options.timeout.count() <= 0) {
            return invalid("Application selection timeout must be positive");
        }
        if (options.stop.stop_requested()) {
            return Error{ErrorCode::cancelled, "Application selection cancelled before I/O"};
        }

        const bool was_authenticated =
            impl_->has_native_session() || static_cast<bool>(impl_->iso_session);
        const bool reset_was_pending = impl_->authentication_reset_pending;
        impl_->clear_native_session();
        impl_->iso_session.reset();
        impl_->authenticated_key.reset();
        impl_->authentication_reset_pending = false;

        const auto data = application_data(id);
        auto response = execute_plain_locked(0x5A, data, options, "SelectApplication");
        if (!response) {
            if (was_authenticated) {
                invalidate_locked();
            } else if (reset_was_pending && impl_->usable) {
                if (response.error().outcome == Outcome::unknown) {
                    invalidate_locked();
                } else {
                    impl_->authentication_reset_pending = true;
                }
            }
            return response.error();
        }
        if (!response.value().empty()) {
            invalidate_locked();
            return Error{ErrorCode::malformed_response,
                         "SelectApplication response must contain no data", Outcome::unknown};
        }

        impl_->selected_application = id.value();
        return {};
    }

    /** @brief List and strictly parse native application identifiers. */
    Result<std::vector<model::ApplicationId>>
    Card::application_ids(const ExchangeOptions& options) {
        auto result = run(*this, native::checked::get_application_ids(), options);
        if (!result) {
            return result.error();
        }

        return native::checked::parse_application_ids(result.value());
    }

    /** @brief Create one checked AES application. */
    Result<void> Card::create_application(const model::ApplicationConfiguration& configuration,
                                          const ExchangeOptions& options) {
        return run_void(*this, native::checked::create_application(configuration), options);
    }

    /** @brief Permanently delete one checked nonzero application. */
    Result<void> Card::delete_application(model::ApplicationId id, const ExchangeOptions& options) {
        return run_void(*this, native::checked::delete_application(id), options);
    }

    /** @brief Create one checked delegated AES application with caller-supplied authorization. */
    Result<void> Card::create_delegated_application(
        const model::DelegatedApplicationConfiguration& configuration,
        ByteView encrypted_default_key, ByteView dam_mac, const ExchangeOptions& options) {
        return run_void(*this,
                        native::checked::create_delegated_application(
                            configuration, encrypted_default_key, dam_mac),
                        options);
    }

    /** @brief Read and decode one delegated-application slot. */
    Result<native::checked::DelegatedApplicationInfo>
    Card::delegated_application_info(std::uint16_t slot, const ExchangeOptions& options) {
        auto result = run(*this, native::checked::get_delegated_application_info(slot), options);
        if (!result) {
            return result.error();
        }

        return native::checked::parse_delegated_application_info(result.value());
    }

    /** @brief Delete one delegated application using issuer-produced authorization bytes. */
    Result<void> Card::delete_delegated_application(model::ApplicationId id, ByteView dam_mac,
                                                    const ExchangeOptions& options) {
        return run_void(*this, native::checked::delete_delegated_application(id, dam_mac), options);
    }

} // namespace desfire::ev3::managed
