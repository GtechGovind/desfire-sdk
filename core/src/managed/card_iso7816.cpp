/**
 * @file card_iso7816.cpp
 * @brief Managed actual ISO/IEC 7816 command execution and session transitions.
 */
#include <desfire/ev3/managed/card.hpp>

#include "card_impl.hpp"
#include "model_names.hpp"
#include "operation_guard.hpp"

namespace desfire::ev3::managed {

    /** @brief Execute one actual ISO command while preserving native/ISO session separation. */
    Result<iso7816::checked::Response> Card::iso_command(const iso7816::checked::Command& command,
                                                         const ExchangeOptions& options) {
        OperationGuard operation(impl_->operation_mutex, impl_->operation_active);
        if (!operation) {
            return Error{ErrorCode::busy, "Card callback cannot reenter an active operation"};
        }
        if (!impl_->usable) {
            return Error{ErrorCode::session_invalid, "Reset or reconnect before ISO operation"};
        }
        if (impl_->authentication_reset_pending && !command.resets_authentication()) {
            return Error{ErrorCode::session_invalid,
                         "Select an application or reset before ISO operation after local reset"};
        }
        if (impl_->raw->generation() != impl_->generation) {
            invalidate_locked();
            return Error{ErrorCode::card_removed, "Card changed before ISO operation"};
        }
        if (impl_->has_native_session() && !command.resets_authentication()) {
            return Error{ErrorCode::session_invalid,
                         "ISO operation cannot reuse a native secure session"};
        }

        std::unique_ptr<security::standard_aes::Session> previous_standard;
        std::unique_ptr<security::ev2::Session> previous_ev2;
        std::unique_ptr<iso7816::security::aes::Session> previous_iso;
        const auto previous_key = impl_->authenticated_key;
        const bool previous_reset_pending = impl_->authentication_reset_pending;
        const auto previous_selection = impl_->selected_application;
        const bool had_previous_authentication =
            impl_->has_native_session() || static_cast<bool>(impl_->iso_session);
        if (command.resets_authentication()) {
            previous_standard = std::move(impl_->standard_aes_session);
            previous_ev2 = std::move(impl_->ev2_session);
            previous_iso = std::move(impl_->iso_session);
            impl_->authenticated_key.reset();
            impl_->authentication_reset_pending = false;
        }

        try {
            auto response = impl_->iso_session
                                ? impl_->iso_session->execute(*impl_->iso_checked, *impl_->crypto,
                                                              command, options)
                                : impl_->iso_checked->exchange(command, options);
            if (!response) {
                if (response.error().outcome == Outcome::not_sent &&
                    command.resets_authentication()) {
                    impl_->standard_aes_session = std::move(previous_standard);
                    impl_->ev2_session = std::move(previous_ev2);
                    impl_->iso_session = std::move(previous_iso);
                    impl_->authenticated_key = previous_key;
                    impl_->authentication_reset_pending = previous_reset_pending;
                    impl_->selected_application = previous_selection;
                } else if (had_previous_authentication || previous_reset_pending ||
                           impl_->iso_session || response.error().outcome == Outcome::unknown) {
                    invalidate_locked();
                }
                return response.error();
            }
            if (impl_->raw->generation() != impl_->generation) {
                invalidate_locked();
                return Error{ErrorCode::card_removed, "Card changed during ISO operation",
                             Outcome::unknown};
            }
            if (impl_->iso_session && !impl_->iso_session->valid()) {
                invalidate_locked();
            }
            if (command.resets_authentication()) {
                if (response.value().status == 0x9000) {
                    impl_->authentication_reset_pending = false;
                    impl_->selected_application.reset();
                } else {
                    impl_->standard_aes_session = std::move(previous_standard);
                    impl_->ev2_session = std::move(previous_ev2);
                    impl_->iso_session = std::move(previous_iso);
                    impl_->authenticated_key = previous_key;
                    impl_->authentication_reset_pending = previous_reset_pending;
                    impl_->selected_application = previous_selection;
                }
            }

            return response;
        } catch (...) {
            invalidate_locked();
            return Error{ErrorCode::internal, "ISO operation failed", Outcome::unknown};
        }
    }

} // namespace desfire::ev3::managed
