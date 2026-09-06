/**
 * @file internal.hpp
 * @brief Shared ownership, validation, and exception-containment support for the C ABI.
 */
#pragma once

#include <desfire.h>
#include <desfire/crypto/openssl.hpp>
#include <desfire/ev3/iso7816/checked/channel.hpp>
#include <desfire/ev3/iso7816/checked/command.hpp>
#include <desfire/ev3/iso7816/raw/channel.hpp>
#include <desfire/ev3/iso7816/security/aes/authentication.hpp>
#include <desfire/ev3/iso7816/security/aes/session.hpp>
#include <desfire/ev3/managed/card.hpp>
#include <desfire/ev3/model/authentication.hpp>
#include <desfire/ev3/model/communication.hpp>
#include <desfire/ev3/model/identifiers.hpp>
#include <desfire/ev3/model/settings.hpp>
#include <desfire/ev3/native/checked/applications.hpp>
#include <desfire/ev3/native/checked/card_management.hpp>
#include <desfire/ev3/native/checked/files.hpp>
#include <desfire/ev3/native/checked/keys.hpp>
#include <desfire/ev3/native/checked/transactions.hpp>
#include <desfire/ev3/native/raw/channel.hpp>
#include <desfire/ev3/native/secure/channel.hpp>
#include <desfire/ev3/offline/delegated_application.hpp>
#include <desfire/ev3/offline/mifare_classic_license.hpp>
#include <desfire/ev3/offline/originality_signature.hpp>
#include <desfire/ev3/offline/transaction_mac.hpp>
#include <desfire/ev3/security/ev2/authentication.hpp>
#include <desfire/ev3/security/ev2/session.hpp>
#include <desfire/ev3/security/key_derivation/aes128.hpp>
#include <desfire/ev3/security/key_derivation/nxp_aes128.hpp>
#include <desfire/ev3/security/standard_aes/authentication.hpp>
#include <desfire/ev3/security/standard_aes/session.hpp>
#include <desfire/transports/callback.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <utility>

/** @brief Own immutable command output allocated by the C ABI. */
struct df_buffer {
    desfire::Bytes bytes; ///< Bytes released and wiped by df_buffer_free.
};

namespace desfire::c_api::detail {

    /** @brief Managed-card implementation exposed only through opaque C handles. */
    using Card = ev3::managed::Card;
    using ev3::model::AccessRights;
    using ev3::model::ApplicationConfiguration;
    using ev3::model::ApplicationId;
    using ev3::model::AuthenticationInfo;
    using ev3::model::ByteCount;
    using ev3::model::CommunicationMode;
    using ev3::model::DataFileConfiguration;
    using ev3::model::FileNumber;
    using ev3::model::FileSettingsChange;
    using ev3::model::KeyNumber;
    using ev3::model::KeySetConfiguration;
    using ev3::model::Offset;
    using ev3::model::RecordFileConfiguration;
    using ev3::model::ValueFileConfiguration;
    namespace commands = ev3::native::checked;
    namespace iso7816 = ev3::iso7816::checked;
    namespace key_derivation = ev3::security::key_derivation;

    static_assert(sizeof(df_error) == 256);
    static_assert(static_cast<std::uint32_t>(ErrorCode::invalid_argument) == DF_INVALID_ARGUMENT);
    static_assert(static_cast<std::uint32_t>(ErrorCode::transport) == DF_TRANSPORT);
    static_assert(static_cast<std::uint32_t>(ErrorCode::card_removed) == DF_CARD_REMOVED);
    static_assert(static_cast<std::uint32_t>(ErrorCode::timeout) == DF_TIMEOUT);
    static_assert(static_cast<std::uint32_t>(ErrorCode::cancelled) == DF_CANCELLED);
    static_assert(static_cast<std::uint32_t>(ErrorCode::malformed_response) ==
                  DF_MALFORMED_RESPONSE);
    static_assert(static_cast<std::uint32_t>(ErrorCode::card_rejected) == DF_CARD_REJECTED);
    static_assert(static_cast<std::uint32_t>(ErrorCode::authentication) == DF_AUTHENTICATION);
    static_assert(static_cast<std::uint32_t>(ErrorCode::integrity) == DF_INTEGRITY);
    static_assert(static_cast<std::uint32_t>(ErrorCode::unsupported) == DF_UNSUPPORTED);
    static_assert(static_cast<std::uint32_t>(ErrorCode::stale_handle) == DF_STALE_HANDLE);
    static_assert(static_cast<std::uint32_t>(ErrorCode::busy) == DF_BUSY);
    static_assert(static_cast<std::uint32_t>(ErrorCode::session_invalid) == DF_SESSION_INVALID);
    static_assert(static_cast<std::uint32_t>(ErrorCode::counter_exhausted) == DF_COUNTER_EXHAUSTED);
    static_assert(static_cast<std::uint32_t>(ErrorCode::buffer_too_small) == DF_BUFFER_TOO_SMALL);
    static_assert(static_cast<std::uint32_t>(ErrorCode::crypto) == DF_CRYPTO);
    static_assert(static_cast<std::uint32_t>(ErrorCode::internal) == DF_INTERNAL);
    static_assert(static_cast<std::uint32_t>(Outcome::not_sent) == DF_NOT_SENT);
    static_assert(static_cast<std::uint32_t>(Outcome::rejected) == DF_REJECTED);
    static_assert(static_cast<std::uint32_t>(Outcome::succeeded) == DF_SUCCEEDED);
    static_assert(static_cast<std::uint32_t>(Outcome::unknown) == DF_UNKNOWN);

    /** @brief Retain one foreign callback context exactly once for an SDK-owned lease. */
    class TransportLease final {
    public:

        /**
         * @brief Copy a validated descriptor and invoke its optional retain callback.
         * @param descriptor Validated foreign transport descriptor to retain.
         */
        explicit TransportLease(const df_transport_v1& descriptor);

        /** @brief Invoke the matching optional release callback after every closure is gone. */
        ~TransportLease();

        /** @brief Prevent duplicate ownership of one foreign retain. */
        TransportLease(const TransportLease&) = delete;

        /** @brief Prevent replacing one foreign retain lease by copy assignment. */
        TransportLease& operator=(const TransportLease&) = delete;

        /**
         * @brief Borrow the stable descriptor copy retained by this lease.
         * @return Descriptor whose callback context remains retained for this lease's lifetime.
         */
        [[nodiscard]] const df_transport_v1& descriptor() const noexcept;

    private:

        df_transport_v1 descriptor_{}; ///< Stable descriptor copy paired with one optional retain.
    };

    /** @brief Managed handle entry retained across registry lookup and concurrent close. */
    struct Entry final {
        std::shared_ptr<Card> card; ///< Managed card retained while a registry lookup is in flight.
        std::shared_ptr<transports::CallbackTransport> transport; ///< Retained callback transport.
        std::recursive_mutex operation; ///< Serializes complete logical card operations.
        bool active{};                  ///< True while a callback-reentry-sensitive call runs.
        bool closed{};                  ///< True after close removes the public handle.
    };

    /** @brief Raw channel state for exactly one declared transport framing. */
    struct RawEntry final {
        std::shared_ptr<transports::CallbackTransport> transport; ///< Retained raw transport.
        std::shared_ptr<CryptoProvider> crypto; ///< Crypto provider shared by raw secure sessions.
        std::shared_ptr<ev3::native::raw::RawNativeChannel> native; ///< Native raw framing layer.
        std::shared_ptr<ev3::native::secure::SecureNativeChannel> secure; ///< Secure native layer.
        std::unique_ptr<ev3::iso7816::raw::Channel> iso;             ///< True ISO raw APDU channel.
        std::unique_ptr<ev3::iso7816::checked::Channel> iso_checked; ///< Checked ISO command layer.
        std::unique_ptr<ev3::iso7816::security::aes::Session>
            iso_session; ///< Active ISO AES state.
        std::unique_ptr<ev3::security::standard_aes::Session>
            standard_session; ///< Active native Standard AES state.
        std::unique_ptr<ev3::security::ev2::Session> ev2_session; ///< Active native EV2 state.
        std::uint64_t session_generation{}; ///< Transport generation bound to secure state.
        std::recursive_mutex operation;     ///< Serializes complete raw logical operations.
        bool active{};                      ///< True during a callback-reentry-sensitive call.
        bool closed{};                      ///< True after close removes the public handle.
    };

    /** @brief Set and clear one handle's reentry marker while its operation lock is owned. */
    template <class EntryType> class ActiveEntry final {
    public:

        /**
         * @brief Mark the entry active.
         * @param entry Registry entry protected by its already-held operation lock.
         */
        explicit ActiveEntry(EntryType& entry) : entry_(entry) {
            entry_.active = true;
        }

        /** @brief Clear the marker before the operation lock is released. */
        ~ActiveEntry() {
            entry_.active = false;
        }

        /** @brief Prevent duplicate ownership of the activity marker. */
        ActiveEntry(const ActiveEntry&) = delete;

        /** @brief Prevent replacing an active marker by copy assignment. */
        ActiveEntry& operator=(const ActiveEntry&) = delete;

    private:

        EntryType& entry_; ///< Entry whose active marker is cleared on scope exit.
    };

    inline std::mutex registry_mutex; ///< Protects managed handle allocation and lookup.
    inline std::unordered_map<df_card, std::shared_ptr<Entry>>
        registry;                         ///< Live managed handles and their retained state.
    inline df_card next_handle{1};        ///< Next monotonic managed handle; zero is never valid.
    inline std::mutex raw_registry_mutex; ///< Protects raw handle allocation and lookup.
    inline std::unordered_map<df_raw_channel, std::shared_ptr<RawEntry>>
        raw_registry;                         ///< Live raw handles and their retained state.
    inline df_raw_channel next_raw_handle{1}; ///< Next monotonic raw handle; zero is never valid.

    /**
     * @brief Copy redacted failure evidence to caller storage and return its stable code.
     * @param output Optional caller-owned error destination.
     * @param error Internal error containing status and delivery outcome.
     * @return Stable C ABI error code matching error.code.
     */
    int32_t failure(df_error* output, const Error& error) noexcept;

    /**
     * @brief Report an exception that reached the C ABI without allocating memory.
     * @param output Optional caller-owned error destination.
     * @return DF_INTERNAL with unknown delivery evidence.
     * @note This path must remain allocation-free because it can run after std::bad_alloc.
     */
    int32_t unexpected_failure(df_error* output) noexcept;

    /**
     * @brief Contain every C++ exception at one C call boundary.
     * @tparam Function Callable returning Result<void>.
     * @param output Optional caller-owned error destination cleared before invocation.
     * @param function Operation to invoke under the exception boundary.
     * @return DF_OK on success or a stable translated error code.
     */
    template <class Function> int32_t boundary(df_error* output, Function&& function) noexcept {
        if (output) {
            *output = {};
        }
        try {
            auto result = function();
            if (!result) {
                return failure(output, result.error());
            }
            if (output) {
                output->outcome = DF_SUCCEEDED;
            }
            return DF_OK;
        } catch (...) {
            return unexpected_failure(output);
        }
    }

    /**
     * @brief Resolve a live managed handle while retaining its entry.
     * @param handle Managed handle received from the C caller.
     * @return Retained entry, or stale_handle when no live handle exists.
     */
    Result<std::shared_ptr<Entry>> lookup(df_card handle);

    /**
     * @brief Resolve a live raw handle while retaining its entry.
     * @param handle Raw-channel handle received from the C caller.
     * @return Retained entry, or stale_handle when no live handle exists.
     */
    Result<std::shared_ptr<RawEntry>> lookup_raw(df_raw_channel handle);

    /**
     * @brief Serialize one managed operation and reject callback reentry.
     * @tparam Function Callable accepting Card and ExchangeOptions.
     * @param handle Managed handle to resolve and lock.
     * @param timeout Positive complete-operation timeout in milliseconds.
     * @param function Checked managed operation to invoke exactly once.
     * @return Success or validation, lifetime, busy, transport, or card failure evidence.
     */
    template <class Function>
    Result<void> invoke(df_card handle, std::uint32_t timeout, Function&& function) {
        if (timeout == 0) {
            return invalid("Timeout must be positive milliseconds");
        }
        auto entry = lookup(handle);
        if (!entry) {
            return entry.error();
        }
        std::unique_lock lock(entry.value()->operation, std::try_to_lock);
        if (!lock.owns_lock()) {
            return Error{ErrorCode::busy, "Another card operation is active"};
        }
        if (entry.value()->active) {
            return Error{ErrorCode::busy, "Callback cannot reenter the active operation"};
        }
        if (entry.value()->closed) {
            return Error{ErrorCode::stale_handle, "Card is closed"};
        }
        ActiveEntry operation(*entry.value());
        return function(*entry.value()->card,
                        ExchangeOptions{std::chrono::milliseconds(timeout), {}});
    }

    /**
     * @brief Serialize one raw operation and reject callback reentry.
     * @tparam Function Callable accepting RawEntry and ExchangeOptions.
     * @param handle Raw-channel handle to resolve and lock.
     * @param timeout Positive complete-operation timeout in milliseconds.
     * @param function Raw operation to invoke exactly once.
     * @return Success or validation, lifetime, busy, transport, or card failure evidence.
     */
    template <class Function>
    Result<void> invoke_raw(df_raw_channel handle, std::uint32_t timeout, Function&& function) {
        if (timeout == 0) {
            return invalid("Timeout must be positive milliseconds");
        }
        auto entry = lookup_raw(handle);
        if (!entry) {
            return entry.error();
        }
        std::unique_lock lock(entry.value()->operation, std::try_to_lock);
        if (!lock.owns_lock()) {
            return Error{ErrorCode::busy, "Another raw operation is active"};
        }
        if (entry.value()->active) {
            return Error{ErrorCode::busy, "Callback cannot reenter the active raw operation"};
        }
        if (entry.value()->closed) {
            return Error{ErrorCode::stale_handle, "Raw channel is closed"};
        }
        ActiveEntry operation(*entry.value());
        return function(*entry.value(), ExchangeOptions{std::chrono::milliseconds(timeout), {}});
    }

    /**
     * @brief Allocate one result buffer before the supplied operation performs I/O.
     * @tparam Function Callable returning Result<Bytes>.
     * @param output Destination that must point to a null buffer handle.
     * @param function Operation producing bytes to transfer to C ownership.
     * @return Success after ownership transfer, or the operation's exact failure.
     */
    template <class Function> Result<void> output_bytes(df_buffer** output, Function&& function) {
        if (!output || *output) {
            return invalid("Output must point to a null buffer handle");
        }
        auto owned = std::make_unique<df_buffer>();
        auto result = function();
        if (!result) {
            return result.error();
        }
        owned->bytes = std::move(result.value());
        *output = owned.release();
        return {};
    }

    /**
     * @brief Validate a foreign byte range before making a borrowed C++ view.
     * @param data Borrowed first byte, or null only when length is zero.
     * @param length Number of bytes, bounded before constructing the view.
     * @return Valid borrowed view or invalid_argument.
     */
    Result<ByteView> bytes(const std::uint8_t* data, std::size_t length);

    /**
     * @brief Decode a public C communication selector.
     * @param value DF_PLAIN, DF_MAC, or DF_FULL.
     * @return Checked communication mode or invalid_argument.
     */
    Result<CommunicationMode> mode(std::uint32_t value);

    /**
     * @brief Decode the ABI's packed four-selector access-right value.
     * @param packed Unsigned value that must fit exactly in sixteen bits.
     * @return Decoded access rights or invalid_argument.
     */
    Result<AccessRights> access_rights_from_c(std::uint32_t packed);

    /**
     * @brief Validate the C ISO key-number and scope pair.
     * @param key ISO key selector.
     * @param application Zero for PICC master scope or one for application scope.
     * @return Checked ISO key reference or invalid_argument.
     */
    Result<iso7816::KeyReference> iso_key(std::uint32_t key, std::uint32_t application);

    /**
     * @brief Build one retained callback transport from a validated descriptor.
     * @param descriptor Foreign callback descriptor to validate, copy, and retain.
     * @return Callback transport or a stable descriptor-validation error.
     */
    Result<std::shared_ptr<transports::CallbackTransport>>
    make_transport(const df_transport_v1* descriptor);

    /**
     * @brief Validate an exact direct AES-128 key and copy it to move-only storage.
     * @param key Borrowed key bytes.
     * @param length Number of key bytes; must be sixteen.
     * @return Move-only AES-128 key or a validation error.
     */
    Result<key_derivation::Aes128Key> aes128_key(const std::uint8_t* key, std::size_t length);

    /**
     * @brief Validate and write EV2 public authentication metadata.
     * @param output Initialized caller-owned ABI-v1 destination.
     * @param information Verified internal authentication metadata.
     * @return Success or invalid_argument for an invalid destination descriptor.
     */
    Result<void> write_authentication_info(df_authentication_info_v1* output,
                                           const AuthenticationInfo& information);

    /**
     * @brief Build a checked key-provider request for one exact authentication entrypoint.
     * @param request Borrowed C ABI request descriptor.
     * @param expected_profile Required authentication profile.
     * @param expected_scope Required native or ISO key scope.
     * @param expected_key Required key selector.
     * @return Owned checked request or exact validation and cancellation evidence.
     */
    Result<key_derivation::KeyRequest>
    make_key_request(const df_key_request_v1* request,
                     key_derivation::AuthenticationProfile expected_profile,
                     key_derivation::KeyScope expected_scope, std::uint32_t expected_key);

    /**
     * @brief Build a checked provider request for an exact non-authentication purpose.
     * @param request Borrowed C ABI request descriptor.
     * @param expected_purpose Required non-authentication key purpose.
     * @param expected_scope Required native or ISO key scope.
     * @param expected_key Required key selector.
     * @return Owned checked request or exact validation and cancellation evidence.
     */
    Result<key_derivation::KeyRequest> make_key_request(const df_key_request_v1* request,
                                                        key_derivation::KeyPurpose expected_purpose,
                                                        key_derivation::KeyScope expected_scope,
                                                        std::uint32_t expected_key);

    /** @brief Retain and invoke one C key provider through the C++ provider interface. */
    class KeyProviderAdapter final : public key_derivation::Aes128KeyProvider {
    public:

        /**
         * @brief Validate, copy, and retain one provider descriptor for this operation.
         * @param provider Foreign provider descriptor to validate and retain.
         * @param request Request descriptor copied for the adapter's single resolution.
         * @return Owned adapter or invalid_argument.
         */
        static Result<std::unique_ptr<KeyProviderAdapter>>
        create(const df_key_provider_v1* provider, const df_key_request_v1* request);

        /** @brief Release the provider context after resolution and card authentication finish. */
        ~KeyProviderAdapter() override;

        /**
         * @brief Resolve one scoped AES-128 key through the foreign provider.
         * @param request Validated non-secret key request and derivation context.
         * @return A move-only AES-128 key, or a provider, cancellation, or validation error.
         */
        Result<key_derivation::Aes128Key>
        resolve(const key_derivation::KeyRequest& request) override;

        /** @brief Prevent duplicating one provider retain and exactly-once state. */
        KeyProviderAdapter(const KeyProviderAdapter&) = delete;

        /** @brief Prevent replacing one provider retain by copy assignment. */
        KeyProviderAdapter& operator=(const KeyProviderAdapter&) = delete;

    private:

        /**
         * @brief Retain descriptors already validated by create().
         * @param provider Validated provider descriptor copied into this adapter.
         * @param request Validated request descriptor copied into this adapter.
         */
        KeyProviderAdapter(df_key_provider_v1 provider, df_key_request_v1 request);

        df_key_provider_v1 provider_{}; ///< Retained foreign provider descriptor.
        df_key_request_v1 request_{};   ///< Stable request copy for exactly one resolution.
        bool resolved_{};               ///< Guards the provider's exactly-once contract.
    };

} // namespace desfire::c_api::detail
