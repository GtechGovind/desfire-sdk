/**
 * @file card_lifecycle.cpp
 * @brief Managed Card construction, reset, cancellation, and invalidation boundaries.
 */
#include <desfire/ev3/managed/card.hpp>

#include "card_impl.hpp"
#include "model_names.hpp"
#include "operation_guard.hpp"

#include <string>

namespace desfire::ev3::managed {

    namespace {

        /**
         * @brief Convert a non-success native status into stable rejected evidence.
         * @param status Native status byte.
         * @param operation Redacted operation name.
         * @return Card-rejected error retaining the status byte.
         */
        Error rejected(Byte status, std::string_view operation) {
            return Error{ErrorCode::card_rejected, std::string(operation) + " was rejected by card",
                         Outcome::rejected, status};
        }

    } // namespace

    /** @brief Implement `Card` to construct or transfer managed card ownership. */
    Card::Card(std::unique_ptr<CardImpl> impl) : impl_(std::move(impl)) {}

    /** @brief Implement `connect` to validate dependencies and create a ready channel. */
    Result<std::shared_ptr<Card>> Card::connect(std::shared_ptr<CardTransport> transport,
                                                std::shared_ptr<CryptoProvider> crypto) {
        if (!transport || !crypto) {
            return invalid("Managed Card requires transport and cryptographic provider");
        }

        auto raw = native::raw::RawNativeChannel::connect(transport);
        if (!raw) {
            return raw.error();
        }
        auto secure = native::secure::SecureNativeChannel::connect(raw.value());
        if (!secure) {
            return secure.error();
        }

        auto iso_raw = iso7816::raw::Channel::create(transport);
        if (!iso_raw) {
            return iso_raw.error();
        }
        auto iso_checked = std::make_unique<iso7816::checked::Channel>(*iso_raw.value());

        auto impl = std::make_unique<CardImpl>(std::move(transport), std::move(crypto),
                                               std::move(raw.value()), std::move(secure.value()),
                                               std::move(iso_raw.value()), std::move(iso_checked));
        return std::shared_ptr<Card>(new Card(std::move(impl)));
    }

    /** @brief Implement `~Card` to cancel active work before releasing managed card state. */
    Card::~Card() {
        std::lock_guard lock(impl_->operation_mutex);
        invalidate_locked();
    }

    /** @brief Implement `execute_plain_locked` to execute an allowed unauthenticated discovery
     * command. */
    Result<Bytes> Card::execute_plain_locked(Byte command, ByteView data,
                                             const ExchangeOptions& options,
                                             std::string_view operation) {
        try {
            if (!impl_->usable) {
                return Error{ErrorCode::session_invalid,
                             "Managed session is uncertain; reconnect before further I/O"};
            }
            if (impl_->authentication_reset_pending) {
                return Error{ErrorCode::session_invalid,
                             "Select an application, authenticate EV2 First, or reset after "
                             "local authentication reset"};
            }
            if (impl_->iso_session) {
                return Error{ErrorCode::session_invalid,
                             "Select an application before switching ISO to native commands"};
            }
            if (impl_->has_native_session()) {
                Result<native::checked::Command> checked =
                    invalid("Unsupported authenticated discovery command");
                if (command == 0x60) {
                    checked = native::checked::get_version();
                } else if (command == 0x6E) {
                    checked = native::checked::free_memory();
                } else if (command == 0x6F) {
                    checked = native::checked::get_file_ids();
                }
                if (!checked) {
                    return checked.error();
                }

                return execute_locked(checked.value(), options);
            }
            if (impl_->raw->generation() != impl_->generation) {
                invalidate_locked();
                return Error{ErrorCode::card_removed, "Card state changed before native command"};
            }

            native::raw::Request request{
                .command = command,
                .data = Bytes(data.begin(), data.end()),
            };
            auto response = impl_->raw->exchange(request, options);
            if (!response) {
                if (response.error().outcome == Outcome::unknown) {
                    invalidate_locked();
                }
                return response.error();
            }
            if (impl_->raw->generation() != impl_->generation) {
                invalidate_locked();
                return Error{ErrorCode::card_removed, "Card state changed after native command",
                             Outcome::unknown};
            }
            if (response.value().status != 0x00) {
                return rejected(response.value().status, operation);
            }

            return std::move(response.value().data);
        } catch (...) {
            invalidate_locked();
            return Error{ErrorCode::internal, "Managed native command failed", Outcome::unknown};
        }
    }

    /** @brief Erase local authentication and require an explicit re-synchronization operation. */
    Result<void> Card::reset_authentication() {
        OperationGuard operation(impl_->operation_mutex, impl_->operation_active);
        if (!operation) {
            return Error{ErrorCode::busy, "Card callback cannot reenter an active operation"};
        }

        const bool had_authentication =
            impl_->has_native_session() || static_cast<bool>(impl_->iso_session);
        impl_->authenticated_key.reset();
        impl_->iso_session.reset();
        impl_->clear_native_session();
        impl_->authentication_reset_pending =
            impl_->authentication_reset_pending || had_authentication;
        return {};
    }

    /** @brief Invalidate local state before resetting the activated transport. */
    Result<void> Card::reset() {
        OperationGuard operation(impl_->operation_mutex, impl_->operation_active);
        if (!operation) {
            return Error{ErrorCode::busy, "Card callback cannot reenter an active operation"};
        }

        invalidate_locked();
        auto result = impl_->raw->reset();
        if (!result) {
            return result.error();
        }

        impl_->generation = impl_->raw->generation();
        impl_->usable = true;
        impl_->authentication_reset_pending = false;
        impl_->selected_application = 0;
        return {};
    }

    /** @brief Forward cancellation without waiting for managed or raw operation locks. */
    void Card::cancel() noexcept {
        impl_->raw->cancel();
    }

    /** @brief Wipe every session and mark managed state unusable until reset or reconnect. */
    void Card::invalidate_locked() noexcept {
        impl_->authenticated_key.reset();
        impl_->iso_session.reset();
        impl_->clear_native_session();
        impl_->authentication_reset_pending = false;
        impl_->selected_application.reset();
        impl_->usable = false;
    }

} // namespace desfire::ev3::managed
