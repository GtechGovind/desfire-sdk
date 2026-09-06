/**
 * @file runtime.cpp
 * @brief C ABI errors, buffers, managed handles, and lifecycle operations.
 */
#include "detail/internal.hpp"
#include "detail/manifest.hpp"

namespace desfire::c_api::detail {
    namespace {
        /**
         * @brief Report whether every authentication-info reserved word is zero.
         * @param output Authentication output descriptor to inspect.
         * @return True only when every reserved word is zero.
         */
        bool authentication_reserved_is_zero(const df_authentication_info_v1& output) noexcept {
            return std::all_of(std::begin(output.reserved), std::end(output.reserved),
                               [](std::uint64_t value) { return value == 0; });
        }

        /**
         * @brief Report whether every key-request reserved word is zero.
         * @param request Key request descriptor to inspect.
         * @return True only when every reserved word is zero.
         */
        bool request_reserved_is_zero(const df_key_request_v1& request) noexcept {
            return std::all_of(std::begin(request.reserved), std::end(request.reserved),
                               [](std::uint64_t value) { return value == 0; });
        }
    } // namespace

    /** @brief Implement the documented `failure` helper. */
    int32_t failure(df_error* output, const Error& error) noexcept {
        if (output) {
            *output = {};
            output->code = static_cast<std::uint32_t>(error.code);
            output->outcome = static_cast<std::uint32_t>(error.outcome);
            output->device_status = error.device_status;
            const auto length = std::min(error.message.size(), sizeof(output->message) - 1U);
            std::memcpy(output->message, error.message.data(), length);
        }
        return static_cast<std::int32_t>(error.code);
    }

    /** @brief Implement the documented allocation-free unexpected-exception boundary. */
    int32_t unexpected_failure(df_error* output) noexcept {
        if (output) {
            *output = {};
            output->code = DF_INTERNAL;
            output->outcome = DF_UNKNOWN;
            constexpr char message[] = "Native operation failed";
            static_assert(sizeof(message) <= sizeof(output->message));
            std::memcpy(output->message, message, sizeof(message));
        }
        return DF_INTERNAL;
    }

    /** @brief Implement the documented `lookup` helper. */
    Result<std::shared_ptr<Entry>> lookup(df_card handle) {
        std::lock_guard lock(registry_mutex);
        const auto found = registry.find(handle);
        if (found == registry.end()) {
            return Error{ErrorCode::stale_handle, "Closed or unknown card handle"};
        }
        return found->second;
    }

    /** @brief Implement the documented `lookup_raw` helper. */
    Result<std::shared_ptr<RawEntry>> lookup_raw(df_raw_channel handle) {
        std::lock_guard lock(raw_registry_mutex);
        const auto found = raw_registry.find(handle);
        if (found == raw_registry.end()) {
            return Error{ErrorCode::stale_handle, "Closed or unknown raw-channel handle"};
        }
        return found->second;
    }

    /** @brief Implement the documented `bytes` helper. */
    Result<ByteView> bytes(const std::uint8_t* data, std::size_t length) {
        constexpr std::size_t maximum_buffer = 16U * 1024U * 1024U;
        if ((length != 0 && !data) || length > maximum_buffer) {
            return invalid("Invalid byte buffer");
        }
        return ByteView(data, length);
    }

    /** @brief Implement the documented `mode` helper. */
    Result<CommunicationMode> mode(std::uint32_t value) {
        if (value != DF_PLAIN && value != DF_MAC && value != DF_FULL) {
            return invalid("Communication must be Plain, MAC, or Full");
        }
        return static_cast<CommunicationMode>(value);
    }

    /** @brief Implement the documented `access_rights_from_c` helper. */
    Result<AccessRights> access_rights_from_c(std::uint32_t packed) {
        if (packed > 0xFFFFU) {
            return invalid("Access rights exceed sixteen bits");
        }
        return AccessRights{
            static_cast<Byte>((packed >> 4U) & 0x0FU), static_cast<Byte>(packed & 0x0FU),
            static_cast<Byte>((packed >> 12U) & 0x0FU), static_cast<Byte>((packed >> 8U) & 0x0FU)};
    }

    /** @brief Implement the documented `iso_key` helper. */
    Result<iso7816::KeyReference> iso_key(std::uint32_t key, std::uint32_t application) {
        if (application > 1U || (application == 0U && key != 0U)) {
            return invalid("Invalid ISO key scope");
        }
        if (application != 0U) {
            return iso7816::KeyReference::application(key);
        }
        return iso7816::KeyReference::picc_master();
    }

    /** @brief Implement the documented `aes128_key` helper. */
    Result<key_derivation::Aes128Key> aes128_key(const std::uint8_t* key, std::size_t length) {
        auto input = bytes(key, length);
        if (!input) {
            return input.error();
        }
        return key_derivation::Aes128Key::import(input.value());
    }

    /** @brief Implement the documented `write_authentication_info` helper. */
    Result<void> write_authentication_info(df_authentication_info_v1* output,
                                           const AuthenticationInfo& information) {
        if (!output || output->struct_size != sizeof(df_authentication_info_v1) ||
            output->abi_version != DF_ABI_VERSION || !authentication_reserved_is_zero(*output)) {
            return invalid("Invalid authentication-info output descriptor");
        }
        std::copy(information.transaction_identifier.begin(),
                  information.transaction_identifier.end(), output->transaction_identifier);
        std::copy(information.picc_capabilities.begin(), information.picc_capabilities.end(),
                  output->picc_capabilities);
        std::copy(information.pcd_capabilities.begin(), information.pcd_capabilities.end(),
                  output->pcd_capabilities);
        return {};
    }

    /** @brief Implement the documented `make_key_request` helper. */
    Result<key_derivation::KeyRequest>
    make_key_request(const df_key_request_v1* request,
                     key_derivation::AuthenticationProfile expected_profile,
                     key_derivation::KeyScope expected_scope, std::uint32_t expected_key) {
        if (!request || request->struct_size != sizeof(df_key_request_v1) ||
            request->abi_version != DF_ABI_VERSION ||
            request->purpose != DF_KEY_PURPOSE_AUTHENTICATION ||
            request->authentication_profile != static_cast<std::uint32_t>(expected_profile) ||
            request->scope != static_cast<std::uint32_t>(expected_scope) ||
            request->key_number != expected_key || !request_reserved_is_zero(*request)) {
            return invalid("Key request does not match the authentication entrypoint");
        }
        if (request->reference_size == 0 || request->reference_size > 1024U ||
            !request->reference || request->diversification_size > 65536U ||
            request->user_context_size > 65536U ||
            request->diversification_size > 65536U - request->user_context_size ||
            (request->diversification_size != 0 && !request->diversification) ||
            (request->user_context_size != 0 && !request->user_context)) {
            return invalid("Invalid key reference or provider context bytes");
        }
        if (request->is_cancelled && request->is_cancelled(request->cancellation_context) != 0) {
            return Error{ErrorCode::cancelled, "Key resolution cancelled before provider access"};
        }

        auto key_number = KeyNumber::make(request->key_number);
        if (!key_number) {
            return key_number.error();
        }
        std::optional<ApplicationId> application;
        if (request->application_id != DF_OPTION_ABSENT) {
            auto parsed = ApplicationId::make(request->application_id);
            if (!parsed) {
                return parsed.error();
            }
            application = parsed.value();
        }
        std::optional<Byte> key_set;
        if (request->key_set != DF_OPTION_ABSENT) {
            if (request->key_set > 15U) {
                return invalid("Key-set selector must be zero through fifteen");
            }
            key_set = static_cast<Byte>(request->key_set);
        }
        auto reference = key_derivation::KeyReference::make(
            ByteView(request->reference, request->reference_size));
        if (!reference) {
            return reference.error();
        }
        auto context = key_derivation::Aes128DerivationContext::make(
            key_derivation::KeyPurpose::authentication, key_number.value(), application, key_set,
            ByteView(request->diversification, request->diversification_size),
            ByteView(request->user_context, request->user_context_size));
        if (!context) {
            return context.error();
        }
        return key_derivation::KeyRequest::make(std::move(reference.value()),
                                                std::move(context.value()), expected_scope,
                                                expected_profile);
    }

    /** @brief Implement non-authentication key-request validation and conversion. */
    Result<key_derivation::KeyRequest> make_key_request(const df_key_request_v1* request,
                                                        key_derivation::KeyPurpose expected_purpose,
                                                        key_derivation::KeyScope expected_scope,
                                                        std::uint32_t expected_key) {
        if (!request || request->struct_size != sizeof(df_key_request_v1) ||
            request->abi_version != DF_ABI_VERSION ||
            request->purpose != static_cast<std::uint32_t>(expected_purpose) ||
            request->authentication_profile != DF_OPTION_ABSENT ||
            request->scope != static_cast<std::uint32_t>(expected_scope) ||
            request->key_number != expected_key || !request_reserved_is_zero(*request) ||
            request->reference_size == 0 || request->reference_size > 1024U ||
            !request->reference || request->diversification_size > 65536U ||
            request->user_context_size > 65536U ||
            request->diversification_size > 65536U - request->user_context_size ||
            (request->diversification_size != 0 && !request->diversification) ||
            (request->user_context_size != 0 && !request->user_context)) {
            return invalid("Invalid non-authentication key request");
        }
        if (request->is_cancelled && request->is_cancelled(request->cancellation_context) != 0) {
            return Error{ErrorCode::cancelled, "Key resolution cancelled before provider access"};
        }
        auto key_number = KeyNumber::make(request->key_number);
        if (!key_number) {
            return key_number.error();
        }
        std::optional<ApplicationId> application;
        if (request->application_id != DF_OPTION_ABSENT) {
            auto parsed = ApplicationId::make(request->application_id);
            if (!parsed) {
                return parsed.error();
            }
            application = parsed.value();
        }
        std::optional<Byte> key_set;
        if (request->key_set != DF_OPTION_ABSENT) {
            if (request->key_set > 15U) {
                return invalid("Key-set selector must be zero through fifteen");
            }
            key_set = static_cast<Byte>(request->key_set);
        }
        auto reference = key_derivation::KeyReference::make(
            ByteView(request->reference, request->reference_size));
        if (!reference) {
            return reference.error();
        }
        auto context = key_derivation::Aes128DerivationContext::make(
            expected_purpose, key_number.value(), application, key_set,
            ByteView(request->diversification, request->diversification_size),
            ByteView(request->user_context, request->user_context_size));
        if (!context) {
            return context.error();
        }
        return key_derivation::KeyRequest::make(std::move(reference.value()),
                                                std::move(context.value()), expected_scope);
    }

} // namespace desfire::c_api::detail

extern "C" {

/** @brief Implement the documented `df_abi_version` C ABI operation. */
uint32_t df_abi_version(void) {
    return DF_ABI_VERSION;
}

/** @brief Implement the documented `df_manifest_sha256` C ABI operation. */
const char* df_manifest_sha256(void) {
    return desfire::c_api::detail::manifest_sha256;
}

/** @brief Implement the documented `df_open` C ABI operation. */
int32_t df_open(const df_transport_v1* transport, df_card* out, df_error* error) {
    using namespace desfire;
    using namespace desfire::c_api::detail;
    return boundary(error, [&]() -> Result<void> {
        if (!out || *out != 0) {
            return invalid("Output handle must point to zero");
        }
        auto transport_result = make_transport(transport);
        if (!transport_result) {
            return transport_result.error();
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        auto card = Card::connect(transport_result.value(), crypto.value());
        if (!card) {
            return card.error();
        }
        auto entry = std::make_shared<Entry>();
        entry->transport = std::move(transport_result.value());
        entry->card = std::move(card.value());
        std::lock_guard lock(registry_mutex);
        if (next_handle == UINT64_MAX) {
            return Error{ErrorCode::internal, "Card handle space exhausted"};
        }
        const auto handle = next_handle++;
        registry.emplace(handle, std::move(entry));
        *out = handle;
        return {};
    });
}

/** @brief Implement the documented `df_close` C ABI operation. */
int32_t df_close(df_card card, df_error* error) {
    using namespace desfire;
    using namespace desfire::c_api::detail;
    return boundary(error, [&]() -> Result<void> {
        auto entry = lookup(card);
        if (!entry) {
            return entry.error();
        }
        std::unique_lock operation(entry.value()->operation, std::try_to_lock);
        if (!operation.owns_lock() || entry.value()->active) {
            return Error{ErrorCode::busy, "Cancel or wait for the active operation before close"};
        }
        std::lock_guard registry_lock(registry_mutex);
        entry.value()->closed = true;
        if (registry.erase(card) != 1U) {
            return Error{ErrorCode::stale_handle, "Card is already closed"};
        }
        return {};
    });
}

/** @brief Implement the documented `df_reset` C ABI operation. */
int32_t df_reset(df_card card, df_error* error) {
    using namespace desfire::c_api::detail;
    return boundary(error, [&] {
        return invoke(card, 5000U,
                      [](Card& card, const desfire::ExchangeOptions&) { return card.reset(); });
    });
}

/** @brief Implement the documented `df_cancel` C ABI operation. */
int32_t df_cancel(df_card card, df_error* error) {
    using namespace desfire;
    using namespace desfire::c_api::detail;
    return boundary(error, [&]() -> Result<void> {
        auto entry = lookup(card);
        if (!entry) {
            return entry.error();
        }
        entry.value()->card->cancel();
        return {};
    });
}

/** @brief Implement the documented `df_notify_state_change` C ABI operation. */
int32_t df_notify_state_change(df_card card, df_error* error) {
    using namespace desfire;
    using namespace desfire::c_api::detail;
    return boundary(error, [&]() -> Result<void> {
        auto entry = lookup(card);
        if (!entry) {
            return entry.error();
        }
        entry.value()->transport->notify_state_change();
        return {};
    });
}

/** @brief Implement the documented `df_buffer_size` C ABI operation. */
size_t df_buffer_size(const df_buffer* buffer) {
    return buffer ? buffer->bytes.size() : 0;
}

/** @brief Implement the documented `df_buffer_data` C ABI operation. */
const uint8_t* df_buffer_data(const df_buffer* buffer) {
    return buffer ? buffer->bytes.data() : nullptr;
}

/** @brief Implement the documented `df_buffer_free` C ABI operation. */
void df_buffer_free(df_buffer* buffer) {
    if (buffer) {
        desfire::wipe(buffer->bytes);
        delete buffer;
    }
}

} // extern "C"
