/**
 * @file offline.cpp
 * @brief Stateless NXP AES derivation, transaction-MAC, and originality helpers.
 */
#include "detail/internal.hpp"

using namespace desfire;
using namespace desfire::c_api::detail;

namespace {
    /**
     * @brief Report whether every versioned-descriptor reserved word is zero.
     * @tparam Size Compile-time number of reserved words.
     * @param reserved Fixed reserved-word array to inspect.
     * @return True only when every reserved word is zero.
     */
    template <std::size_t Size>
    bool reserved_is_zero(const std::uint64_t (&reserved)[Size]) noexcept {
        return std::all_of(std::begin(reserved), std::end(reserved),
                           [](std::uint64_t value) { return value == 0; });
    }

    /**
     * @brief Copy one fixed-size public result into C-owned output storage.
     * @tparam Size Compile-time byte count.
     * @param value Public fixed-size result to copy.
     * @return Owned ordinary byte vector suitable for df_buffer.
     */
    template <std::size_t Size> Bytes public_bytes(const std::array<Byte, Size>& value) {
        return Bytes(value.begin(), value.end());
    }

    /**
     * @brief Copy a move-only secret result into caller-owned ABI storage.
     * @param value Secure result whose bytes are exported explicitly by this ABI operation.
     * @return Owned ordinary byte vector transferred to df_buffer ownership.
     */
    Bytes exported_secret(const SecureBuffer& value) {
        return Bytes(value.view().begin(), value.view().end());
    }

    /**
     * @brief Validate one C owned-buffer output slot before invoking a key provider.
     * @param output Destination that must be non-null and point to a null buffer handle.
     * @return Success or invalid_argument before provider resolution begins.
     */
    Result<void> validate_output_slot(df_buffer** output) {
        if (!output || *output) {
            return invalid("Output must point to a null buffer handle");
        }
        return {};
    }

    /**
     * @brief Resolve exactly one AES key for a stateless offline operation.
     * @param provider Foreign provider descriptor retained during resolution.
     * @param request Non-secret key request validated against the operation.
     * @param purpose Exact offline key purpose expected by the entry point.
     * @return Move-only AES-128 key or validation, cancellation, or provider failure.
     */
    Result<ev3::security::key_derivation::Aes128Key>
    resolve_offline_key(const df_key_provider_v1* provider, const df_key_request_v1* request,
                        key_derivation::KeyPurpose purpose) {
        const auto expected_key = request ? request->key_number : 0U;
        auto checked =
            make_key_request(request, purpose, key_derivation::KeyScope::native, expected_key);
        if (!checked) {
            return checked.error();
        }
        auto adapter = KeyProviderAdapter::create(provider, request);
        if (!adapter) {
            return adapter.error();
        }
        return adapter.value()->resolve(checked.value());
    }

    /**
     * @brief Decode and validate one delegated-application ABI descriptor.
     * @param value Borrowed versioned descriptor with zeroed reserved fields.
     * @return Owned checked configuration or invalid_argument.
     */
    Result<ev3::model::DelegatedApplicationConfiguration>
    delegated_configuration(const df_delegated_application_configuration_v1* value) {
        if (!value || value->struct_size != sizeof(*value) ||
            value->abi_version != DF_ABI_VERSION || value->key_settings > 0xFFU ||
            value->number_of_keys > 0xFFU || value->slot > 0xFFFFU || value->slot_version > 0xFFU ||
            value->quota_limit > 0xFFFFU || value->iso_file_identifiers > 1U ||
            value->key_settings3 < -1 || value->key_settings3 > 0xFF || value->iso_id < -1 ||
            value->iso_id > 0xFFFF || value->has_key_sets > 1U ||
            value->active_key_set_version > 0xFFU || value->number_of_key_sets > 0xFFU ||
            value->maximum_key_size > 0xFFU || value->key_set_settings > 0xFFU ||
            !reserved_is_zero(value->reserved)) {
            return invalid("Invalid delegated-application offline descriptor");
        }
        if (value->has_key_sets == 0U &&
            (value->active_key_set_version != 0U || value->number_of_key_sets != 0U ||
             value->maximum_key_size != 0U || value->key_set_settings != 0U)) {
            return invalid("Absent delegated key-set fields must be zero");
        }
        auto name = bytes(value->df_name, value->df_name_size);
        auto application = ApplicationId::make(value->application_id);
        if (!name || !application) {
            return !name ? name.error() : application.error();
        }
        std::optional<ev3::model::KeySetConfiguration> key_sets;
        if (value->has_key_sets != 0U) {
            key_sets = ev3::model::KeySetConfiguration{
                .active_version = static_cast<Byte>(value->active_key_set_version),
                .number_of_sets = static_cast<Byte>(value->number_of_key_sets),
                .maximum_key_size = static_cast<Byte>(value->maximum_key_size),
                .settings = static_cast<Byte>(value->key_set_settings),
            };
        }
        ev3::model::ApplicationConfiguration application_configuration{
            .id = application.value(),
            .key_settings = static_cast<Byte>(value->key_settings),
            .number_of_keys = static_cast<Byte>(value->number_of_keys),
            .iso_file_identifiers = value->iso_file_identifiers != 0U,
            .key_settings3 = value->key_settings3 < 0
                                 ? std::nullopt
                                 : std::optional<Byte>(static_cast<Byte>(value->key_settings3)),
            .key_sets = key_sets,
            .iso_id = value->iso_id < 0
                          ? std::nullopt
                          : std::optional<std::uint16_t>(static_cast<std::uint16_t>(value->iso_id)),
            .df_name = Bytes(name.value().begin(), name.value().end()),
        };
        return ev3::model::DelegatedApplicationConfiguration{
            .application = std::move(application_configuration),
            .slot = static_cast<std::uint16_t>(value->slot),
            .slot_version = static_cast<Byte>(value->slot_version),
            .quota_limit = static_cast<std::uint16_t>(value->quota_limit),
        };
    }

    /**
     * @brief Derive both transaction session keys and concatenate MAC then encryption key.
     * @param crypto Cryptographic provider used for AES-CMAC derivation.
     * @param transaction_key Borrowed sixteen-byte application transaction key.
     * @param counter Committed transaction counter.
     * @param uid Borrowed real card UID.
     * @return Thirty-two owned bytes containing MAC key followed by encryption key.
     */
    Result<Bytes> transaction_keys(CryptoProvider& crypto, ByteView transaction_key,
                                   std::uint32_t counter, ByteView uid) {
        auto keys =
            ev3::offline::derive_transaction_mac_keys_aes(crypto, transaction_key, uid, counter);
        if (!keys) {
            return keys.error();
        }
        Bytes output;
        output.reserve(32);
        append(output, keys.value().mac_key.view());
        append(output, keys.value().encryption_key.view());
        return output;
    }

    /**
     * @brief Derive and calculate one eight-byte transaction MAC.
     * @param crypto Cryptographic provider used for derivation and AES-CMAC.
     * @param transaction_key Borrowed sixteen-byte application transaction key.
     * @param counter Committed transaction counter.
     * @param uid Borrowed real card UID.
     * @param transaction_input Exact transaction input accumulated by the application.
     * @return Owned eight-byte transaction MAC or cryptographic failure.
     */
    Result<Bytes> transaction_mac(CryptoProvider& crypto, ByteView transaction_key,
                                  std::uint32_t counter, ByteView uid, ByteView transaction_input) {
        auto keys =
            ev3::offline::derive_transaction_mac_keys_aes(crypto, transaction_key, uid, counter);
        if (!keys) {
            return keys.error();
        }
        auto mac = ev3::offline::calculate_transaction_mac_aes(crypto, keys.value().mac_key.view(),
                                                               transaction_input);
        if (!mac) {
            return mac.error();
        }
        return Bytes(mac.value().begin(), mac.value().end());
    }
} // namespace

extern "C" {

/** @brief Implement the documented `df_offline_derive_nxp_aes128` C ABI operation. */
int32_t df_offline_derive_nxp_aes128(const uint8_t* master_key, size_t master_key_size,
                                     const uint8_t* diversification, size_t diversification_size,
                                     df_buffer** output, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto key = aes128_key(master_key, master_key_size);
        auto input = bytes(diversification, diversification_size);
        if (!key || !input) {
            return !key ? key.error() : input.error();
        }
        auto number = KeyNumber::make(0);
        auto context = key_derivation::Aes128DerivationContext::make(
            key_derivation::KeyPurpose::offline_operation, number.value(), {}, {}, input.value());
        if (!context) {
            return context.error();
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        return output_bytes(output, [&]() -> Result<Bytes> {
            auto derived = ev3::security::key_derivation::nxp_aes128::derive(
                *crypto.value(), key.value(), context.value());
            if (!derived) {
                return derived.error();
            }
            const auto view = derived.value().view();
            return Bytes(view.begin(), view.end());
        });
    });
}

/** @brief Implement the documented `df_offline_derive_nxp_aes128_provider` C ABI operation. */
int32_t df_offline_derive_nxp_aes128_provider(const df_key_provider_v1* provider,
                                              const df_key_request_v1* request, df_buffer** output,
                                              df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (auto valid = validate_output_slot(output); !valid) {
            return valid.error();
        }
        const auto expected_key = request ? request->key_number : 0U;
        auto checked = make_key_request(request, key_derivation::KeyPurpose::offline_operation,
                                        key_derivation::KeyScope::native, expected_key);
        if (!checked) {
            return checked.error();
        }
        auto adapter = KeyProviderAdapter::create(provider, request);
        if (!adapter) {
            return adapter.error();
        }
        auto resolved = adapter.value()->resolve(checked.value());
        if (!resolved) {
            return resolved.error();
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        return output_bytes(output, [&]() -> Result<Bytes> {
            auto derived = ev3::security::key_derivation::nxp_aes128::derive(
                *crypto.value(), resolved.value(), checked.value().context());
            if (!derived) {
                return derived.error();
            }
            const auto view = derived.value().view();
            return Bytes(view.begin(), view.end());
        });
    });
}

/** @brief Implement the documented `df_offline_encrypt_delegated_default_key_aes` C ABI operation.
 */
int32_t df_offline_encrypt_delegated_default_key_aes(const uint8_t* dam_encryption_key,
                                                     size_t dam_encryption_key_size,
                                                     const uint8_t* application_default_key,
                                                     size_t application_default_key_size,
                                                     uint32_t application_default_key_version,
                                                     df_buffer** output, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto dam_key = aes128_key(dam_encryption_key, dam_encryption_key_size);
        auto application_key = aes128_key(application_default_key, application_default_key_size);
        if (!dam_key || !application_key || application_default_key_version > 0xFFU) {
            if (!dam_key) {
                return dam_key.error();
            }
            if (!application_key) {
                return application_key.error();
            }
            return invalid("Delegated default-key version exceeds one byte");
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        return output_bytes(output, [&]() -> Result<Bytes> {
            auto result = ev3::offline::encrypt_delegated_default_key_aes(
                *crypto.value(), dam_key.value().view(), application_key.value().view(),
                static_cast<Byte>(application_default_key_version));
            if (!result) {
                return result.error();
            }
            return exported_secret(result.value());
        });
    });
}

/** @brief Implement the documented `df_offline_encrypt_delegated_default_key_aes_provider` C ABI
 * operation. */
int32_t df_offline_encrypt_delegated_default_key_aes_provider(
    const df_key_provider_v1* provider, const df_key_request_v1* request,
    const uint8_t* application_default_key, size_t application_default_key_size,
    uint32_t application_default_key_version, df_buffer** output, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (auto valid = validate_output_slot(output); !valid) {
            return valid.error();
        }
        auto application_key = aes128_key(application_default_key, application_default_key_size);
        if (!application_key || application_default_key_version > 0xFFU) {
            return !application_key ? application_key.error()
                                    : invalid("Delegated default-key version exceeds one byte");
        }
        auto dam_key = resolve_offline_key(provider, request,
                                           key_derivation::KeyPurpose::delegated_application);
        if (!dam_key) {
            return dam_key.error();
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        return output_bytes(output, [&]() -> Result<Bytes> {
            auto result = ev3::offline::encrypt_delegated_default_key_aes(
                *crypto.value(), dam_key.value().view(), application_key.value().view(),
                static_cast<Byte>(application_default_key_version));
            if (!result) {
                return result.error();
            }
            return exported_secret(result.value());
        });
    });
}

/** @brief Implement the documented `df_offline_calculate_delegated_application_mac_aes` C ABI
 * operation. */
int32_t df_offline_calculate_delegated_application_mac_aes(
    const uint8_t* dam_mac_key, size_t dam_mac_key_size,
    const df_delegated_application_configuration_v1* configuration,
    const uint8_t* encrypted_default_key, size_t encrypted_default_key_size, df_buffer** output,
    df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto key = aes128_key(dam_mac_key, dam_mac_key_size);
        auto config = delegated_configuration(configuration);
        auto encrypted = bytes(encrypted_default_key, encrypted_default_key_size);
        if (!key || !config || !encrypted) {
            if (!key) {
                return key.error();
            }
            return !config ? config.error() : encrypted.error();
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        return output_bytes(output, [&]() -> Result<Bytes> {
            auto result = ev3::offline::calculate_delegated_application_mac_aes(
                *crypto.value(), key.value().view(), config.value(), encrypted.value());
            return result ? Result<Bytes>(public_bytes(result.value())) : result.error();
        });
    });
}

/** @brief Implement the documented `df_offline_calculate_delegated_application_mac_aes_provider` C
 * ABI operation. */
int32_t df_offline_calculate_delegated_application_mac_aes_provider(
    const df_key_provider_v1* provider, const df_key_request_v1* request,
    const df_delegated_application_configuration_v1* configuration,
    const uint8_t* encrypted_default_key, size_t encrypted_default_key_size, df_buffer** output,
    df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (auto valid = validate_output_slot(output); !valid) {
            return valid.error();
        }
        auto config = delegated_configuration(configuration);
        auto encrypted = bytes(encrypted_default_key, encrypted_default_key_size);
        if (!config || !encrypted) {
            return !config ? config.error() : encrypted.error();
        }
        auto key = resolve_offline_key(provider, request,
                                       key_derivation::KeyPurpose::delegated_application);
        if (!key) {
            return key.error();
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        return output_bytes(output, [&]() -> Result<Bytes> {
            auto result = ev3::offline::calculate_delegated_application_mac_aes(
                *crypto.value(), key.value().view(), config.value(), encrypted.value());
            return result ? Result<Bytes>(public_bytes(result.value())) : result.error();
        });
    });
}

/** @brief Implement the documented `df_offline_calculate_delegated_application_delete_mac_aes` C
 * ABI operation. */
int32_t df_offline_calculate_delegated_application_delete_mac_aes(const uint8_t* dam_mac_key,
                                                                  size_t dam_mac_key_size,
                                                                  uint32_t application_id,
                                                                  df_buffer** output,
                                                                  df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto key = aes128_key(dam_mac_key, dam_mac_key_size);
        auto application = ApplicationId::make(application_id);
        if (!key || !application) {
            return !key ? key.error() : application.error();
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        return output_bytes(output, [&]() -> Result<Bytes> {
            auto result = ev3::offline::calculate_delegated_application_delete_mac_aes(
                *crypto.value(), key.value().view(), application.value());
            return result ? Result<Bytes>(public_bytes(result.value())) : result.error();
        });
    });
}

/** @brief Implement the documented
 * `df_offline_calculate_delegated_application_delete_mac_aes_provider` C ABI operation. */
int32_t df_offline_calculate_delegated_application_delete_mac_aes_provider(
    const df_key_provider_v1* provider, const df_key_request_v1* request, uint32_t application_id,
    df_buffer** output, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (auto valid = validate_output_slot(output); !valid) {
            return valid.error();
        }
        auto application = ApplicationId::make(application_id);
        if (!application) {
            return application.error();
        }
        auto key = resolve_offline_key(provider, request,
                                       key_derivation::KeyPurpose::delegated_application);
        if (!key) {
            return key.error();
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        return output_bytes(output, [&]() -> Result<Bytes> {
            auto result = ev3::offline::calculate_delegated_application_delete_mac_aes(
                *crypto.value(), key.value().view(), application.value());
            return result ? Result<Bytes>(public_bytes(result.value())) : result.error();
        });
    });
}

/** @brief Implement the documented `df_offline_calculate_delegated_configuration_mac_aes` C ABI
 * operation. */
int32_t df_offline_calculate_delegated_configuration_mac_aes(
    const uint8_t* dam_mac_key, size_t dam_mac_key_size, const uint8_t* old_df_name,
    size_t old_df_name_size, const uint8_t* new_df_name, size_t new_df_name_size,
    df_buffer** output, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto key = aes128_key(dam_mac_key, dam_mac_key_size);
        auto old_name = bytes(old_df_name, old_df_name_size);
        auto new_name = bytes(new_df_name, new_df_name_size);
        if (!key || !old_name || !new_name) {
            if (!key) {
                return key.error();
            }
            return !old_name ? old_name.error() : new_name.error();
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        return output_bytes(output, [&]() -> Result<Bytes> {
            auto result = ev3::offline::calculate_delegated_configuration_mac_aes(
                *crypto.value(), key.value().view(), old_name.value(), new_name.value());
            return result ? Result<Bytes>(public_bytes(result.value())) : result.error();
        });
    });
}

/** @brief Implement the documented `df_offline_calculate_delegated_configuration_mac_aes_provider`
 * C ABI operation. */
int32_t df_offline_calculate_delegated_configuration_mac_aes_provider(
    const df_key_provider_v1* provider, const df_key_request_v1* request,
    const uint8_t* old_df_name, size_t old_df_name_size, const uint8_t* new_df_name,
    size_t new_df_name_size, df_buffer** output, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (auto valid = validate_output_slot(output); !valid) {
            return valid.error();
        }
        auto old_name = bytes(old_df_name, old_df_name_size);
        auto new_name = bytes(new_df_name, new_df_name_size);
        if (!old_name || !new_name) {
            return !old_name ? old_name.error() : new_name.error();
        }
        auto key = resolve_offline_key(provider, request,
                                       key_derivation::KeyPurpose::delegated_application);
        if (!key) {
            return key.error();
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        return output_bytes(output, [&]() -> Result<Bytes> {
            auto result = ev3::offline::calculate_delegated_configuration_mac_aes(
                *crypto.value(), key.value().view(), old_name.value(), new_name.value());
            return result ? Result<Bytes>(public_bytes(result.value())) : result.error();
        });
    });
}

/** @brief Implement the documented `df_offline_calculate_mfc_license_mac_aes` C ABI operation. */
int32_t df_offline_calculate_mfc_license_mac_aes(
    const uint8_t* license_mac_key, size_t license_mac_key_size, const uint8_t* mfc_license,
    size_t mfc_license_size, const uint8_t* mfc_sector_secrets, size_t mfc_sector_secrets_size,
    df_buffer** output, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto key = aes128_key(license_mac_key, license_mac_key_size);
        auto license = bytes(mfc_license, mfc_license_size);
        auto secrets = bytes(mfc_sector_secrets, mfc_sector_secrets_size);
        if (!key || !license || !secrets) {
            if (!key) {
                return key.error();
            }
            return !license ? license.error() : secrets.error();
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        return output_bytes(output, [&]() -> Result<Bytes> {
            auto result = ev3::offline::calculate_mfc_license_mac_aes(
                *crypto.value(), key.value().view(), license.value(), secrets.value());
            return result ? Result<Bytes>(public_bytes(result.value())) : result.error();
        });
    });
}

/** @brief Implement the documented `df_offline_calculate_mfc_license_mac_aes_provider` C ABI
 * operation. */
int32_t df_offline_calculate_mfc_license_mac_aes_provider(
    const df_key_provider_v1* provider, const df_key_request_v1* request,
    const uint8_t* mfc_license, size_t mfc_license_size, const uint8_t* mfc_sector_secrets,
    size_t mfc_sector_secrets_size, df_buffer** output, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (auto valid = validate_output_slot(output); !valid) {
            return valid.error();
        }
        auto license = bytes(mfc_license, mfc_license_size);
        auto secrets = bytes(mfc_sector_secrets, mfc_sector_secrets_size);
        if (!license || !secrets) {
            return !license ? license.error() : secrets.error();
        }
        auto key =
            resolve_offline_key(provider, request, key_derivation::KeyPurpose::offline_operation);
        if (!key) {
            return key.error();
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        return output_bytes(output, [&]() -> Result<Bytes> {
            auto result = ev3::offline::calculate_mfc_license_mac_aes(
                *crypto.value(), key.value().view(), license.value(), secrets.value());
            return result ? Result<Bytes>(public_bytes(result.value())) : result.error();
        });
    });
}

/** @brief Implement the documented `df_offline_derive_transaction_mac_keys_aes` C ABI operation. */
int32_t df_offline_derive_transaction_mac_keys_aes(const uint8_t* transaction_key,
                                                   size_t transaction_key_size,
                                                   uint32_t transaction_counter, const uint8_t* uid,
                                                   size_t uid_size, df_buffer** output,
                                                   df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto key = aes128_key(transaction_key, transaction_key_size);
        auto uid_view = bytes(uid, uid_size);
        if (!key || !uid_view) {
            return !key ? key.error() : uid_view.error();
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        return output_bytes(output, [&] {
            return transaction_keys(*crypto.value(), key.value().view(), transaction_counter,
                                    uid_view.value());
        });
    });
}

/** @brief Implement the documented `df_offline_derive_transaction_mac_keys_aes_provider` C ABI
 * operation. */
int32_t df_offline_derive_transaction_mac_keys_aes_provider(const df_key_provider_v1* provider,
                                                            const df_key_request_v1* request,
                                                            uint32_t transaction_counter,
                                                            const uint8_t* uid, size_t uid_size,
                                                            df_buffer** output, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (auto valid = validate_output_slot(output); !valid) {
            return valid.error();
        }
        auto uid_view = bytes(uid, uid_size);
        if (!uid_view) {
            return uid_view.error();
        }
        auto key =
            resolve_offline_key(provider, request, key_derivation::KeyPurpose::transaction_mac);
        if (!key) {
            return key.error();
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        return output_bytes(output, [&] {
            return transaction_keys(*crypto.value(), key.value().view(), transaction_counter,
                                    uid_view.value());
        });
    });
}

/** @brief Implement the documented `df_offline_calculate_transaction_mac_session_aes` C ABI
 * operation. */
int32_t df_offline_calculate_transaction_mac_session_aes(const uint8_t* session_mac_key,
                                                         size_t session_mac_key_size,
                                                         const uint8_t* transaction_input,
                                                         size_t transaction_input_size,
                                                         df_buffer** output, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto key = aes128_key(session_mac_key, session_mac_key_size);
        auto input = bytes(transaction_input, transaction_input_size);
        if (!key || !input) {
            return !key ? key.error() : input.error();
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        return output_bytes(output, [&]() -> Result<Bytes> {
            auto result = ev3::offline::calculate_transaction_mac_aes(
                *crypto.value(), key.value().view(), input.value());
            return result ? Result<Bytes>(public_bytes(result.value())) : result.error();
        });
    });
}

/** @brief Implement the documented `df_offline_calculate_transaction_mac_aes` C ABI operation. */
int32_t df_offline_calculate_transaction_mac_aes(const uint8_t* transaction_mac_key,
                                                 size_t key_size, uint32_t transaction_counter,
                                                 const uint8_t* uid, size_t uid_size,
                                                 const uint8_t* transaction_input,
                                                 size_t transaction_input_size, df_buffer** output,
                                                 df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto key = bytes(transaction_mac_key, key_size);
        auto uid_view = bytes(uid, uid_size);
        auto input = bytes(transaction_input, transaction_input_size);
        if (!key || !uid_view || !input) {
            if (!key) {
                return key.error();
            }
            return !uid_view ? uid_view.error() : input.error();
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        return output_bytes(output, [&] {
            return transaction_mac(*crypto.value(), key.value(), transaction_counter,
                                   uid_view.value(), input.value());
        });
    });
}

/** @brief Implement the documented `df_offline_calculate_transaction_mac_aes_provider` C ABI
 * operation. */
int32_t df_offline_calculate_transaction_mac_aes_provider(const df_key_provider_v1* provider,
                                                          const df_key_request_v1* request,
                                                          uint32_t transaction_counter,
                                                          const uint8_t* uid, size_t uid_size,
                                                          const uint8_t* transaction_input,
                                                          size_t transaction_input_size,
                                                          df_buffer** output, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (auto valid = validate_output_slot(output); !valid) {
            return valid.error();
        }
        const auto expected_key = request ? request->key_number : 0U;
        auto checked = make_key_request(request, key_derivation::KeyPurpose::transaction_mac,
                                        key_derivation::KeyScope::native, expected_key);
        if (!checked) {
            return checked.error();
        }
        auto adapter = KeyProviderAdapter::create(provider, request);
        if (!adapter) {
            return adapter.error();
        }
        auto uid_view = bytes(uid, uid_size);
        auto input = bytes(transaction_input, transaction_input_size);
        if (!uid_view || !input) {
            return !uid_view ? uid_view.error() : input.error();
        }
        auto resolved = adapter.value()->resolve(checked.value());
        if (!resolved) {
            return resolved.error();
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        return output_bytes(output, [&] {
            return transaction_mac(*crypto.value(), resolved.value().view(), transaction_counter,
                                   uid_view.value(), input.value());
        });
    });
}

/** @brief Implement the documented `df_offline_verify_transaction_mac_aes` C ABI operation. */
int32_t df_offline_verify_transaction_mac_aes(
    const uint8_t* transaction_key, size_t transaction_key_size, uint32_t transaction_counter,
    const uint8_t* uid, size_t uid_size, const uint8_t* transaction_input,
    size_t transaction_input_size, const uint8_t* transaction_mac, size_t transaction_mac_size,
    uint32_t* verified, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto key = aes128_key(transaction_key, transaction_key_size);
        auto uid_view = bytes(uid, uid_size);
        auto input = bytes(transaction_input, transaction_input_size);
        auto mac = bytes(transaction_mac, transaction_mac_size);
        if (!key || !uid_view || !input || !mac || !verified) {
            if (!key) {
                return key.error();
            }
            if (!uid_view) {
                return uid_view.error();
            }
            if (!input) {
                return input.error();
            }
            return !mac ? mac.error() : invalid("Transaction verification output is null");
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        auto result = ev3::offline::verify_transaction_mac_aes(
            *crypto.value(), key.value().view(), uid_view.value(), transaction_counter,
            input.value(), mac.value());
        if (!result) {
            return result.error();
        }
        *verified = result.value() ? 1U : 0U;
        return {};
    });
}

/** @brief Implement the documented `df_offline_verify_transaction_mac_aes_provider` C ABI
 * operation. */
int32_t df_offline_verify_transaction_mac_aes_provider(
    const df_key_provider_v1* provider, const df_key_request_v1* request,
    uint32_t transaction_counter, const uint8_t* uid, size_t uid_size,
    const uint8_t* transaction_input, size_t transaction_input_size, const uint8_t* transaction_mac,
    size_t transaction_mac_size, uint32_t* verified, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto uid_view = bytes(uid, uid_size);
        auto input = bytes(transaction_input, transaction_input_size);
        auto mac = bytes(transaction_mac, transaction_mac_size);
        if (!uid_view || !input || !mac || !verified) {
            if (!uid_view) {
                return uid_view.error();
            }
            if (!input) {
                return input.error();
            }
            return !mac ? mac.error() : invalid("Transaction verification output is null");
        }
        auto key =
            resolve_offline_key(provider, request, key_derivation::KeyPurpose::transaction_mac);
        if (!key) {
            return key.error();
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        auto result = ev3::offline::verify_transaction_mac_aes(
            *crypto.value(), key.value().view(), uid_view.value(), transaction_counter,
            input.value(), mac.value());
        if (!result) {
            return result.error();
        }
        *verified = result.value() ? 1U : 0U;
        return {};
    });
}

/** @brief Implement the documented `df_offline_decrypt_transaction_reader_id_aes` C ABI operation.
 */
int32_t df_offline_decrypt_transaction_reader_id_aes(const uint8_t* session_encryption_key,
                                                     size_t session_encryption_key_size,
                                                     const uint8_t* encrypted_reader_id,
                                                     size_t encrypted_reader_id_size,
                                                     df_buffer** output, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto key = aes128_key(session_encryption_key, session_encryption_key_size);
        auto encrypted = bytes(encrypted_reader_id, encrypted_reader_id_size);
        if (!key || !encrypted) {
            return !key ? key.error() : encrypted.error();
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        return output_bytes(output, [&]() -> Result<Bytes> {
            auto result = ev3::offline::decrypt_transaction_reader_id_aes(
                *crypto.value(), key.value().view(), encrypted.value());
            if (!result) {
                return result.error();
            }
            return exported_secret(result.value());
        });
    });
}

/** @brief Implement the documented `df_offline_verify_originality_uid_signature` C ABI operation.
 */
int32_t df_offline_verify_originality_uid_signature(const char* curve, const uint8_t* public_key,
                                                    size_t public_key_size, const uint8_t* uid,
                                                    size_t uid_size, const uint8_t* signature,
                                                    size_t signature_size, uint32_t* verified,
                                                    df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (!curve || std::strcmp(curve, "secp224r1") != 0 || !verified) {
            return invalid("Only the documented secp224r1 UID construction is supported");
        }
        auto public_key_view = bytes(public_key, public_key_size);
        auto uid_view = bytes(uid, uid_size);
        auto signature_view = bytes(signature, signature_size);
        if (!public_key_view || !uid_view || !signature_view) {
            if (!public_key_view) {
                return public_key_view.error();
            }
            return !uid_view ? uid_view.error() : signature_view.error();
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        auto result = ev3::offline::verify_originality_uid_signature(
            *crypto.value(), public_key_view.value(), uid_view.value(), signature_view.value());
        if (!result) {
            return result.error();
        }
        *verified = result.value() ? 1U : 0U;
        return {};
    });
}

} // extern "C"
