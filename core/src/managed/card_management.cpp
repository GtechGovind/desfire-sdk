/**
 * @file card_management.cpp
 * @brief Managed UID, originality, formatting, and PICC configuration operations.
 */
#include <desfire/ev3/managed/card.hpp>

#include "card_impl.hpp"
#include "model_names.hpp"
#include "operation_guard.hpp"

namespace desfire::ev3::managed {

    namespace {

        /**
         * @brief Execute one successfully built management command.
         * @param card Managed card.
         * @param command Checked command or preflight error.
         * @param options Complete operation controls.
         * @return Status-free response or preserved failure evidence.
         */
        Result<Bytes> run(Card& card, Result<native::checked::Command> command,
                          const ExchangeOptions& options) {
            if (!command) {
                return command.error();
            }

            return card.execute(command.value(), options);
        }

        /**
         * @brief Execute one management mutation and discard its checked empty response.
         * @param card Managed card.
         * @param command Checked command or preflight error.
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

    /** @brief Implement `execute` to execute one checked command through managed state policy. */
    Result<Bytes> Card::execute(const native::checked::Command& command,
                                const ExchangeOptions& options) {
        OperationGuard operation(impl_->operation_mutex, impl_->operation_active);
        if (!operation) {
            return Error{ErrorCode::busy, "Card callback cannot reenter an active operation"};
        }

        return execute_locked(command, options);
    }

    /** @brief Implement `execute_locked` to execute one checked command while holding operation
     * admission. */
    Result<Bytes> Card::execute_locked(const native::checked::Command& command,
                                       const ExchangeOptions& options) {
        try {
            if (!impl_->usable) {
                return Error{ErrorCode::session_invalid,
                             "Reset or reconnect before further card I/O"};
            }
            if (impl_->authentication_reset_pending) {
                return Error{ErrorCode::session_invalid,
                             "Select an application, authenticate EV2 First, or reset after "
                             "local authentication reset"};
            }
            if (!command.valid()) {
                return invalid("Cannot execute a moved-from command");
            }
            if (command.opcode() == 0x6D) {
                return invalid("Use df_names() to preserve physical response boundaries");
            }
            if (impl_->raw->generation() != impl_->generation) {
                invalidate_locked();
                return Error{ErrorCode::card_removed, "Card changed before managed command"};
            }
            if (impl_->iso_session) {
                return Error{ErrorCode::session_invalid,
                             "Native command requires native authentication or selection"};
            }
            if (!impl_->has_native_session() && command.requires_authentication()) {
                return Error{ErrorCode::authentication,
                             "This command requires native authentication"};
            }
            if (command.requires_ev2_session() && !impl_->ev2_session) {
                return Error{ErrorCode::authentication,
                             "This command requires EV2 AES authentication"};
            }
            if (command.requires_picc_selection() &&
                (!impl_->selected_application || *impl_->selected_application != 0)) {
                return Error{ErrorCode::authentication,
                             "This command requires PICC application selection"};
            }
            if (command.current_authenticated_key() &&
                command.current_authenticated_key() != impl_->authenticated_key) {
                return Error{
                    ErrorCode::authentication,
                    "native::checked::Command key selector differs from verified authentication"};
            }
            if (command.restricts_authenticated_key() &&
                (!impl_->authenticated_key ||
                 !command.accepts_authenticated_key(*impl_->authenticated_key))) {
                return Error{ErrorCode::authentication,
                             "Authenticated key is not authorized for this command"};
            }

            const bool protected_session = impl_->has_native_session();
            const native::secure::Request request{
                .command = command.opcode(),
                .header = command.header(),
                .data = command.data(),
                .request_mode = command.request_mode(),
                .response_mode = command.response_mode(),
                .minimum_response = command.minimum_response(),
                .maximum_response = command.maximum_response(),
                .first_frame_data_size = command.first_frame_payload_size(),
                .single_continuation_frame = command.requires_single_continuation_frame(),
                .invalidates_session = command.invalidates_session(),
            };

            Result<Bytes> result = Bytes{};
            if (impl_->ev2_session) {
                result = impl_->secure->exchange(request, *impl_->ev2_session, options);
            } else if (impl_->standard_aes_session) {
                result = impl_->secure->exchange(request, *impl_->standard_aes_session, options);
            } else {
                result = impl_->secure->exchange_unprotected(request, options);
            }
            if (!result) {
                if (protected_session || result.error().outcome == Outcome::unknown) {
                    invalidate_locked();
                }
                return result.error();
            }
            if (impl_->raw->generation() != impl_->generation) {
                invalidate_locked();
                return Error{ErrorCode::card_removed, "Card changed during managed command",
                             Outcome::unknown};
            }

            Result<void> parsed;
            if (command.opcode() == 0x60) {
                auto value = model::parse_version(result.value());
                if (!value) {
                    parsed = value.error();
                }
            } else if (command.opcode() == 0x6A) {
                auto value = native::checked::parse_application_ids(result.value());
                if (!value) {
                    parsed = value.error();
                }
            } else if (command.opcode() == 0x61) {
                auto value = native::checked::parse_iso_file_ids(result.value());
                if (!value) {
                    parsed = value.error();
                }
            } else if (command.opcode() == 0x45) {
                auto value = native::checked::parse_key_settings(result.value());
                if (!value) {
                    parsed = value.error();
                }
            } else if (command.opcode() == 0xF5) {
                auto value = native::checked::parse_file_settings(result.value());
                if (!value) {
                    parsed = value.error();
                }
            } else if (command.opcode() == 0xF6) {
                auto value = native::checked::parse_file_counters(result.value());
                if (!value) {
                    parsed = value.error();
                }
            } else if (command.opcode() == 0x6C) {
                auto value = native::checked::parse_value(result.value());
                if (!value) {
                    parsed = value.error();
                }
            } else if (command.opcode() == 0x51) {
                Result<native::checked::CardUid> value =
                    Error{ErrorCode::malformed_response, "GetCardUID command header is invalid",
                          Outcome::unknown};
                if (command.header().empty()) {
                    value = native::checked::parse_card_uid(
                        result.value(), native::checked::CardUidRequest::omit_option);
                } else if (command.header().size() == 1 && command.header().front() == 0x00) {
                    value = native::checked::parse_card_uid(
                        result.value(), native::checked::CardUidRequest::without_nuid);
                } else if (command.header().size() == 1 && command.header().front() == 0x01) {
                    value = native::checked::parse_card_uid(
                        result.value(), native::checked::CardUidRequest::with_nuid);
                }
                if (!value) {
                    parsed = value.error();
                }
            } else if (command.opcode() == 0x69) {
                auto value = native::checked::parse_delegated_application_info(result.value());
                if (!value) {
                    parsed = value.error();
                }
            } else if (command.opcode() == 0x3C) {
                auto value = native::checked::parse_originality_signature(result.value());
                if (!value) {
                    parsed = value.error();
                }
            } else if (command.opcode() == 0xC7 && !result.value().empty()) {
                auto value = native::checked::parse_transaction_mac(result.value());
                if (!value) {
                    parsed = value.error();
                }
            }
            if (!parsed) {
                invalidate_locked();
                return parsed.error();
            }
            if (command.invalidates_session()) {
                impl_->clear_native_session();
                impl_->authenticated_key.reset();
            }

            return result;
        } catch (...) {
            invalidate_locked();
            return Error{ErrorCode::internal, "Managed native command failed", Outcome::unknown};
        }
    }

    /** @brief Read the authenticated UID using the option-omitted form. */
    Result<native::checked::CardUid> Card::card_uid(const ExchangeOptions& options) {
        return card_uid(native::checked::CardUidRequest::omit_option, options);
    }

    /** @brief Read and parse the authenticated UID using an explicit request variant. */
    Result<native::checked::CardUid> Card::card_uid(native::checked::CardUidRequest request,
                                                    const ExchangeOptions& options) {
        auto result = run(*this, native::checked::get_card_uid(request), options);
        if (!result) {
            return result.error();
        }

        return native::checked::parse_card_uid(result.value(), request);
    }

    /** @brief Read exactly 56 originality-signature bytes. */
    Result<std::array<Byte, 56>> Card::originality_signature(const ExchangeOptions& options) {
        auto result = run(*this, native::checked::read_originality_signature(), options);
        if (!result) {
            return result.error();
        }

        return native::checked::parse_originality_signature(result.value());
    }

    /** @brief Permanently format the PICC after checked authenticated execution. */
    Result<void> Card::format_picc(const ExchangeOptions& options) {
        return run_void(*this, native::checked::format_picc(), options);
    }

    /** @brief Set documented PICC option-zero flags. */
    Result<void> Card::set_picc_configuration(const model::PiccConfiguration& configuration,
                                              const ExchangeOptions& options) {
        return run_void(*this, native::checked::set_picc_configuration(configuration), options);
    }

    /** @brief Set the exact option-five capability record. */
    Result<void>
    Card::set_capability_configuration(const model::CapabilityConfiguration& configuration,
                                       const ExchangeOptions& options) {
        return run_void(*this, native::checked::set_capability_configuration(configuration),
                        options);
    }

    /** @brief Replace the default PICC AES key and key version. */
    Result<void> Card::set_default_aes_key(ByteView aes_key, Byte key_version,
                                           const ExchangeOptions& options) {
        return run_void(*this, native::checked::set_default_aes_key(aes_key, key_version), options);
    }

    /** @brief Set one complete checked ATS byte sequence. */
    Result<void> Card::set_ats(ByteView ats, const ExchangeOptions& options) {
        return run_void(*this, native::checked::set_ats(ats), options);
    }

    /** @brief Set the checked two-byte ATQA field. */
    Result<void> Card::set_atqa(std::uint16_t atqa, const ExchangeOptions& options) {
        return run_void(*this, native::checked::set_atqa(atqa), options);
    }

} // namespace desfire::ev3::managed
