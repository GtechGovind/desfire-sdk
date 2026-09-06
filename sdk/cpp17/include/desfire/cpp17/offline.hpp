/**
 * @file offline.hpp
 * @brief Result-based C++17 wrappers for every stateless offline C ABI operation.
 */
#pragma once

#include <desfire/cpp17/raw.hpp>

namespace desfire::cpp17::offline {

    /** @brief Optional four-byte delegated application key-set configuration. */
    struct DelegatedKeySetConfiguration final {
        std::uint8_t active_version{}; /**< Version of the key set active when the delegated
                                          application is created. */
        std::uint8_t
            number_of_sets{}; /**< Number of key sets provisioned for the delegated application. */
        std::uint8_t maximum_key_size{}; /**< Maximum key width encoded in the delegated key-set
                                            configuration. */
        std::uint8_t settings{};         /**< Documented delegated key-set settings byte. */
    };

    /** @brief Named fields authenticated by delegated-application creation MAC generation. */
    struct DelegatedApplicationConfiguration final {
        ApplicationId
            application_id;          /**< Native application identifier authenticated by the MAC. */
        std::uint8_t key_settings{}; /**< Documented application key-settings byte. */
        std::uint8_t number_of_keys{}; /**< Encoded AES key-count and type byte. */
        std::uint16_t slot{};          /**< Delegated application slot number. */
        std::uint8_t slot_version{};   /**< Version byte required for the delegated slot. */
        std::uint16_t
            quota_limit{}; /**< Maximum delegated storage blocks allocated to the application. */
        bool iso_file_identifiers{}; /**< Whether the delegated application includes ISO file
                                        identifiers. */
        std::optional<std::uint8_t>
            key_settings3;                   /**< Optional third application key-settings byte. */
        std::optional<std::uint16_t> iso_id; /**< Optional ISO dedicated-file identifier. */
        Bytes df_name;                       /**< Optional ISO dedicated-file name. */
        std::optional<DelegatedKeySetConfiguration> key_set; /**< Optional EV3 key-set scope. */
    };

    /** @brief Owned transaction MAC and ReaderID session-key bytes. */
    struct TransactionMacKeys final {
        Bytes mac_key;        /**< Derived sixteen-byte SesTMMACKey. */
        Bytes encryption_key; /**< Derived sixteen-byte SesTMENCKey. */
    };

    /**
     * @brief Invoke one caller-defined derivation for an explicit offline purpose.
     * @param master_key Live exportable AES-128 master key.
     * @param deriver Caller-owned nonthrowing derivation implementation.
     * @param context Non-secret scope and diversification inputs.
     * @param expected_purpose Purpose required by the operation that will consume the result.
     * @return Fresh move-only AES key, or local not-sent failure evidence.
     */
    inline Result<Aes128Key> derive_aes128_key(const Aes128Key& master_key,
                                               Aes128KeyDeriver& deriver,
                                               const Aes128DerivationContext& context,
                                               KeyPurpose expected_purpose) {
        if (!master_key.valid() || context.purpose != expected_purpose ||
            context.diversification_input.size() > 65536 || context.user_context.size() > 65536 ||
            context.diversification_input.size() > 65536 - context.user_context.size()) {
            return Result<Aes128Key>::failure(cpp17::detail::invalid_argument(
                "invalid offline derivation key, purpose or context"));
        }
        auto result = deriver.derive(master_key, context);
        if (!result) {
            auto error = std::move(result).error();
            error.outcome = Outcome::not_sent;
            error.device_status = 0;
            return Result<Aes128Key>::failure(std::move(error));
        }
        if (result.value().valid()) {
            return result;
        }
        return Result<Aes128Key>::failure(Error{ErrorCode::crypto, Outcome::not_sent, 0,
                                                "AES-128 deriver returned an invalid key"});
    }

    namespace offline_detail {

        /**
         * @brief Convert one C owned-buffer result into C++17 byte ownership.
         * @param status Stable status returned by the matching C ABI invocation.
         * @param buffer Native owned buffer to adopt or inspect.
         * @param error Per-call C error storage paired with the returned status.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        inline Result<Bytes> buffer_result(std::int32_t status, df_buffer* buffer,
                                           const df_error& error) {
            raw::Buffer owned = raw::Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Bytes>::failure(cpp17::detail::native_error(status, error));
            }
            return Result<Bytes>::success(owned.copy());
        }

        /**
         * @brief Reject moved-from direct keys before crossing the C boundary.
         * @param key Live AES-128 key borrowed only until the operation returns.
         * @param message Secret-free diagnostic used when the direct key is invalid.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        inline Result<void> require_key(const Aes128Key& key, const char* message) {
            auto identity = raw::validate_native_identity();
            if (!identity) {
                return identity;
            }
            return key.valid() ? Result<void>::success()
                               : Result<void>::failure(cpp17::detail::invalid_argument(message));
        }

        /**
         * @brief Validate provider metadata for one exact offline key purpose.
         * @param request Non-secret key lookup request borrowed for the synchronous provider call.
         * @param purpose Exact key purpose required from the provider request.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        inline Result<void> require_request(const KeyRequest& request, KeyPurpose purpose) {
            auto identity = raw::validate_native_identity();
            if (!identity) {
                return identity;
            }
            auto checked = cpp17::detail::validate_key_request(request);
            if (!checked) {
                return checked;
            }
            if (request.context.purpose != purpose) {
                return Result<void>::failure(cpp17::detail::invalid_argument(
                    "key request purpose does not match operation"));
            }
            return Result<void>::success();
        }

        /**
         * @brief Build a borrowed ABI descriptor from one live C++ configuration.
         * @param value Live delegated configuration whose byte fields remain borrowed by the
         * result.
         * @return A versioned descriptor borrowing storage from the supplied configuration.
         */
        inline df_delegated_application_configuration_v1
        delegated_descriptor(const DelegatedApplicationConfiguration& value) {
            df_delegated_application_configuration_v1 result{};
            result.struct_size = sizeof(result);
            result.abi_version = DF_ABI_VERSION;
            result.application_id = value.application_id.value();
            result.key_settings = value.key_settings;
            result.number_of_keys = value.number_of_keys;
            result.slot = value.slot;
            result.slot_version = value.slot_version;
            result.quota_limit = value.quota_limit;
            result.iso_file_identifiers = value.iso_file_identifiers ? 1U : 0U;
            result.key_settings3 = value.key_settings3 ? *value.key_settings3 : -1;
            result.iso_id = value.iso_id ? *value.iso_id : -1;
            result.df_name = cpp17::detail::byte_data(value.df_name);
            result.df_name_size = value.df_name.size();
            if (value.key_set) {
                result.has_key_sets = 1;
                result.active_key_set_version = value.key_set->active_version;
                result.number_of_key_sets = value.key_set->number_of_sets;
                result.maximum_key_size = value.key_set->maximum_key_size;
                result.key_set_settings = value.key_set->settings;
            }
            return result;
        }

    } // namespace offline_detail

    /**
     * @brief Derive one AES-128 key with the C ABI AN10922 implementation.
     * @param master_key Live AES-128 master key borrowed only for derivation.
     * @param diversification Explicit non-secret diversification input bytes.
     * @return The owned success value or failure evidence with the exact delivery outcome.
     */
    inline Result<Bytes> derive_nxp_aes128(const Aes128Key& master_key,
                                           const Bytes& diversification) {
        auto identity = raw::validate_native_identity();
        if (!identity) {
            return Result<Bytes>::failure(std::move(identity).error());
        }
        if (!master_key.valid()) {
            return Result<Bytes>::failure(
                detail::invalid_argument("AES-128 master key ownership is empty"));
        }
        df_buffer* buffer{};
        df_error error{};
        const auto status = df_offline_derive_nxp_aes128(master_key.data(), master_key.size(),
                                                         detail::byte_data(diversification),
                                                         diversification.size(), &buffer, &error);
        return offline_detail::buffer_result(status, buffer, error);
    }

    /**
     * @brief Resolve one master key exactly once and derive AES-128 through AN10922.
     * @param provider Synchronous key provider invoked once before the offline calculation.
     * @param request Non-secret key lookup request borrowed for the synchronous provider call.
     * @return The owned success value or failure evidence with the exact delivery outcome.
     */
    inline Result<Bytes> derive_nxp_aes128(Aes128KeyProvider& provider, const KeyRequest& request) {
        auto checked = offline_detail::require_request(request, KeyPurpose::offline_operation);
        if (!checked) {
            return Result<Bytes>::failure(std::move(checked).error());
        }
        detail::ProviderCall call(provider, request);
        df_buffer* buffer{};
        df_error error{};
        const auto status =
            df_offline_derive_nxp_aes128_provider(call.provider(), call.request(), &buffer, &error);
        return offline_detail::buffer_result(status, buffer, error);
    }

    /**
     * @brief Encrypt one delegated application default key into a 32-byte EncK.
     * @param dam_encryption_key Live DAMEncKey used to protect the delegated application default
     * key.
     * @param application_default_key Application AES key encrypted into the delegated EncK record.
     * @param application_default_key_version Version byte stored with the delegated application
     * default key.
     * @return The owned success value or failure evidence with the exact delivery outcome.
     */
    inline Result<Bytes>
    encrypt_delegated_default_key_aes(const Aes128Key& dam_encryption_key,
                                      const Aes128Key& application_default_key,
                                      std::uint8_t application_default_key_version) {
        auto dam_valid = offline_detail::require_key(dam_encryption_key, "DAMEncKey is empty");
        auto application_valid = offline_detail::require_key(
            application_default_key, "delegated application default key is empty");
        if (!dam_valid || !application_valid) {
            return Result<Bytes>::failure(!dam_valid ? std::move(dam_valid).error()
                                                     : std::move(application_valid).error());
        }
        df_buffer* buffer{};
        df_error error{};
        const auto status = df_offline_encrypt_delegated_default_key_aes(
            dam_encryption_key.data(), dam_encryption_key.size(), application_default_key.data(),
            application_default_key.size(), application_default_key_version, &buffer, &error);
        return offline_detail::buffer_result(status, buffer, error);
    }

    /**
     * @brief Resolve DAMEncKey once before encrypting a direct delegated default key.
     * @param provider Synchronous key provider invoked once before the offline calculation.
     * @param request Non-secret key lookup request borrowed for the synchronous provider call.
     * @param application_default_key Application AES key encrypted into the delegated EncK record.
     * @param application_default_key_version Version byte stored with the delegated application
     * default key.
     * @return The owned success value or failure evidence with the exact delivery outcome.
     */
    inline Result<Bytes>
    encrypt_delegated_default_key_aes(Aes128KeyProvider& provider, const KeyRequest& request,
                                      const Aes128Key& application_default_key,
                                      std::uint8_t application_default_key_version) {
        auto checked = offline_detail::require_request(request, KeyPurpose::delegated_application);
        auto application_valid = offline_detail::require_key(
            application_default_key, "delegated application default key is empty");
        if (!checked || !application_valid) {
            return Result<Bytes>::failure(!checked ? std::move(checked).error()
                                                   : std::move(application_valid).error());
        }
        detail::ProviderCall call(provider, request);
        df_buffer* buffer{};
        df_error error{};
        const auto status = df_offline_encrypt_delegated_default_key_aes_provider(
            call.provider(), call.request(), application_default_key.data(),
            application_default_key.size(), application_default_key_version, &buffer, &error);
        return offline_detail::buffer_result(status, buffer, error);
    }

    /**
     * @brief Calculate the eight-byte issuer MAC for delegated-application creation.
     * @param dam_mac_key Live DAMMACKey used to authorize the delegated operation.
     * @param configuration Named configuration whose fields are encoded by the matching command.
     * @param encrypted_default_key Documented encrypted delegated default-key record.
     * @return The owned success value or failure evidence with the exact delivery outcome.
     */
    inline Result<Bytes>
    calculate_delegated_application_mac_aes(const Aes128Key& dam_mac_key,
                                            const DelegatedApplicationConfiguration& configuration,
                                            const Bytes& encrypted_default_key) {
        auto valid = offline_detail::require_key(dam_mac_key, "DAMMACKey is empty");
        if (!valid) {
            return Result<Bytes>::failure(std::move(valid).error());
        }
        auto native = offline_detail::delegated_descriptor(configuration);
        df_buffer* buffer{};
        df_error error{};
        const auto status = df_offline_calculate_delegated_application_mac_aes(
            dam_mac_key.data(), dam_mac_key.size(), &native,
            detail::byte_data(encrypted_default_key), encrypted_default_key.size(), &buffer,
            &error);
        return offline_detail::buffer_result(status, buffer, error);
    }

    /**
     * @brief Resolve DAMMACKey once before delegated-application creation MAC calculation.
     * @param provider Synchronous key provider invoked once before the offline calculation.
     * @param request Non-secret key lookup request borrowed for the synchronous provider call.
     * @param configuration Named configuration whose fields are encoded by the matching command.
     * @param encrypted_default_key Documented encrypted delegated default-key record.
     * @return The owned success value or failure evidence with the exact delivery outcome.
     */
    inline Result<Bytes>
    calculate_delegated_application_mac_aes(Aes128KeyProvider& provider, const KeyRequest& request,
                                            const DelegatedApplicationConfiguration& configuration,
                                            const Bytes& encrypted_default_key) {
        auto checked = offline_detail::require_request(request, KeyPurpose::delegated_application);
        if (!checked) {
            return Result<Bytes>::failure(std::move(checked).error());
        }
        auto native = offline_detail::delegated_descriptor(configuration);
        detail::ProviderCall call(provider, request);
        df_buffer* buffer{};
        df_error error{};
        const auto status = df_offline_calculate_delegated_application_mac_aes_provider(
            call.provider(), call.request(), &native, detail::byte_data(encrypted_default_key),
            encrypted_default_key.size(), &buffer, &error);
        return offline_detail::buffer_result(status, buffer, error);
    }

    /**
     * @brief Calculate the eight-byte issuer MAC for delegated-application deletion.
     * @param dam_mac_key Live DAMMACKey used to authorize the delegated operation.
     * @param application_id Native application identifier included in the deletion MAC.
     * @return The owned success value or failure evidence with the exact delivery outcome.
     */
    inline Result<Bytes>
    calculate_delegated_application_delete_mac_aes(const Aes128Key& dam_mac_key,
                                                   ApplicationId application_id) {
        auto valid = offline_detail::require_key(dam_mac_key, "DAMMACKey is empty");
        if (!valid) {
            return Result<Bytes>::failure(std::move(valid).error());
        }
        df_buffer* buffer{};
        df_error error{};
        const auto status = df_offline_calculate_delegated_application_delete_mac_aes(
            dam_mac_key.data(), dam_mac_key.size(), application_id.value(), &buffer, &error);
        return offline_detail::buffer_result(status, buffer, error);
    }

    /**
     * @brief Resolve DAMMACKey once before delegated-application deletion MAC calculation.
     * @param provider Synchronous key provider invoked once before the offline calculation.
     * @param request Non-secret key lookup request borrowed for the synchronous provider call.
     * @param application_id Native application identifier included in the deletion MAC.
     * @return The owned success value or failure evidence with the exact delivery outcome.
     */
    inline Result<Bytes> calculate_delegated_application_delete_mac_aes(
        Aes128KeyProvider& provider, const KeyRequest& request, ApplicationId application_id) {
        auto checked = offline_detail::require_request(request, KeyPurpose::delegated_application);
        if (!checked) {
            return Result<Bytes>::failure(std::move(checked).error());
        }
        detail::ProviderCall call(provider, request);
        df_buffer* buffer{};
        df_error error{};
        const auto status = df_offline_calculate_delegated_application_delete_mac_aes_provider(
            call.provider(), call.request(), application_id.value(), &buffer, &error);
        return offline_detail::buffer_result(status, buffer, error);
    }

    /**
     * @brief Calculate the delegated DF-name configuration authorization MAC.
     * @param dam_mac_key Live DAMMACKey used to authorize the delegated operation.
     * @param old_df_name Current ISO dedicated-file name included in the authorization MAC.
     * @param new_df_name Replacement ISO dedicated-file name included in the authorization MAC.
     * @return The owned success value or failure evidence with the exact delivery outcome.
     */
    inline Result<Bytes> calculate_delegated_configuration_mac_aes(const Aes128Key& dam_mac_key,
                                                                   const Bytes& old_df_name,
                                                                   const Bytes& new_df_name) {
        auto valid = offline_detail::require_key(dam_mac_key, "DAMMACKey is empty");
        if (!valid) {
            return Result<Bytes>::failure(std::move(valid).error());
        }
        df_buffer* buffer{};
        df_error error{};
        const auto status = df_offline_calculate_delegated_configuration_mac_aes(
            dam_mac_key.data(), dam_mac_key.size(), detail::byte_data(old_df_name),
            old_df_name.size(), detail::byte_data(new_df_name), new_df_name.size(), &buffer,
            &error);
        return offline_detail::buffer_result(status, buffer, error);
    }

    /**
     * @brief Resolve DAMMACKey once before delegated DF-name MAC calculation.
     * @param provider Synchronous key provider invoked once before the offline calculation.
     * @param request Non-secret key lookup request borrowed for the synchronous provider call.
     * @param old_df_name Current ISO dedicated-file name included in the authorization MAC.
     * @param new_df_name Replacement ISO dedicated-file name included in the authorization MAC.
     * @return The owned success value or failure evidence with the exact delivery outcome.
     */
    inline Result<Bytes> calculate_delegated_configuration_mac_aes(Aes128KeyProvider& provider,
                                                                   const KeyRequest& request,
                                                                   const Bytes& old_df_name,
                                                                   const Bytes& new_df_name) {
        auto checked = offline_detail::require_request(request, KeyPurpose::delegated_application);
        if (!checked) {
            return Result<Bytes>::failure(std::move(checked).error());
        }
        detail::ProviderCall call(provider, request);
        df_buffer* buffer{};
        df_error error{};
        const auto status = df_offline_calculate_delegated_configuration_mac_aes_provider(
            call.provider(), call.request(), detail::byte_data(old_df_name), old_df_name.size(),
            detail::byte_data(new_df_name), new_df_name.size(), &buffer, &error);
        return offline_detail::buffer_result(status, buffer, error);
    }

    /**
     * @brief Calculate the MIFARE Classic compatibility-license AES MAC.
     * @param license_mac_key Live MFCLicenseMACKey used to authenticate the license record.
     * @param license Complete MIFARE Classic compatibility license record.
     * @param sector_secrets Complete MIFARE Classic sector-secret bytes covered by the license MAC.
     * @return The owned success value or failure evidence with the exact delivery outcome.
     */
    inline Result<Bytes> calculate_mfc_license_mac_aes(const Aes128Key& license_mac_key,
                                                       const Bytes& license,
                                                       const Bytes& sector_secrets) {
        auto valid = offline_detail::require_key(license_mac_key, "MFCLicenseMACKey is empty");
        if (!valid) {
            return Result<Bytes>::failure(std::move(valid).error());
        }
        df_buffer* buffer{};
        df_error error{};
        const auto status = df_offline_calculate_mfc_license_mac_aes(
            license_mac_key.data(), license_mac_key.size(), detail::byte_data(license),
            license.size(), detail::byte_data(sector_secrets), sector_secrets.size(), &buffer,
            &error);
        return offline_detail::buffer_result(status, buffer, error);
    }

    /**
     * @brief Resolve MFCLicenseMACKey once before calculating its authorization MAC.
     * @param provider Synchronous key provider invoked once before the offline calculation.
     * @param request Non-secret key lookup request borrowed for the synchronous provider call.
     * @param license Complete MIFARE Classic compatibility license record.
     * @param sector_secrets Complete MIFARE Classic sector-secret bytes covered by the license MAC.
     * @return The owned success value or failure evidence with the exact delivery outcome.
     */
    inline Result<Bytes> calculate_mfc_license_mac_aes(Aes128KeyProvider& provider,
                                                       const KeyRequest& request,
                                                       const Bytes& license,
                                                       const Bytes& sector_secrets) {
        auto checked = offline_detail::require_request(request, KeyPurpose::offline_operation);
        if (!checked) {
            return Result<Bytes>::failure(std::move(checked).error());
        }
        detail::ProviderCall call(provider, request);
        df_buffer* buffer{};
        df_error error{};
        const auto status = df_offline_calculate_mfc_license_mac_aes_provider(
            call.provider(), call.request(), detail::byte_data(license), license.size(),
            detail::byte_data(sector_secrets), sector_secrets.size(), &buffer, &error);
        return offline_detail::buffer_result(status, buffer, error);
    }

    /**
     * @brief Derive independent transaction MAC and ReaderID encryption session keys.
     * @param transaction_key Application transaction-MAC key borrowed until return.
     * @param transaction_counter Committed transaction counter used in session-key derivation.
     * @param uid Real card UID bytes used in the documented calculation.
     * @return The owned success value or failure evidence with the exact delivery outcome.
     */
    inline Result<TransactionMacKeys>
    derive_transaction_mac_keys_aes(const Aes128Key& transaction_key,
                                    std::uint32_t transaction_counter, const Bytes& uid) {
        auto valid = offline_detail::require_key(transaction_key, "transaction key is empty");
        if (!valid) {
            return Result<TransactionMacKeys>::failure(std::move(valid).error());
        }
        df_buffer* buffer{};
        df_error error{};
        const auto status = df_offline_derive_transaction_mac_keys_aes(
            transaction_key.data(), transaction_key.size(), transaction_counter,
            detail::byte_data(uid), uid.size(), &buffer, &error);
        auto bytes = offline_detail::buffer_result(status, buffer, error);
        if (!bytes) {
            return Result<TransactionMacKeys>::failure(std::move(bytes).error());
        }
        if (bytes.value().size() != 32) {
            return Result<TransactionMacKeys>::failure(
                detail::invalid_argument("native transaction keys have an invalid length"));
        }
        return Result<TransactionMacKeys>::success(
            TransactionMacKeys{Bytes(bytes.value().begin(), bytes.value().begin() + 16),
                               Bytes(bytes.value().begin() + 16, bytes.value().end())});
    }

    /**
     * @brief Resolve AppTransactionMACKey once before deriving both session keys.
     * @param provider Synchronous key provider invoked once before the offline calculation.
     * @param request Non-secret key lookup request borrowed for the synchronous provider call.
     * @param transaction_counter Committed transaction counter used in session-key derivation.
     * @param uid Real card UID bytes used in the documented calculation.
     * @return The owned success value or failure evidence with the exact delivery outcome.
     */
    inline Result<TransactionMacKeys>
    derive_transaction_mac_keys_aes(Aes128KeyProvider& provider, const KeyRequest& request,
                                    std::uint32_t transaction_counter, const Bytes& uid) {
        auto checked = offline_detail::require_request(request, KeyPurpose::transaction_mac);
        if (!checked) {
            return Result<TransactionMacKeys>::failure(std::move(checked).error());
        }
        detail::ProviderCall call(provider, request);
        df_buffer* buffer{};
        df_error error{};
        const auto status = df_offline_derive_transaction_mac_keys_aes_provider(
            call.provider(), call.request(), transaction_counter, detail::byte_data(uid),
            uid.size(), &buffer, &error);
        auto bytes = offline_detail::buffer_result(status, buffer, error);
        if (!bytes) {
            return Result<TransactionMacKeys>::failure(std::move(bytes).error());
        }
        if (bytes.value().size() != 32) {
            return Result<TransactionMacKeys>::failure(
                detail::invalid_argument("native transaction keys have an invalid length"));
        }
        return Result<TransactionMacKeys>::success(
            TransactionMacKeys{Bytes(bytes.value().begin(), bytes.value().begin() + 16),
                               Bytes(bytes.value().begin() + 16, bytes.value().end())});
    }

    /**
     * @brief Calculate a TMV from one already-derived transaction MAC session key.
     * @param session_mac_key Already-derived SesTMMACKey used to calculate the TMV.
     * @param transaction_input Exact transaction-MAC input bytes.
     * @return The owned success value or failure evidence with the exact delivery outcome.
     */
    inline Result<Bytes> calculate_transaction_mac_session_aes(const Aes128Key& session_mac_key,
                                                               const Bytes& transaction_input) {
        auto valid =
            offline_detail::require_key(session_mac_key, "transaction session key is empty");
        if (!valid) {
            return Result<Bytes>::failure(std::move(valid).error());
        }
        df_buffer* buffer{};
        df_error error{};
        const auto status = df_offline_calculate_transaction_mac_session_aes(
            session_mac_key.data(), session_mac_key.size(), detail::byte_data(transaction_input),
            transaction_input.size(), &buffer, &error);
        return offline_detail::buffer_result(status, buffer, error);
    }

    /**
     * @brief Calculate an eight-byte AES transaction MAC from explicit transaction input.
     * @param transaction_mac_key Live application transaction-MAC key used to derive the session
     * MAC key.
     * @param transaction_counter Committed transaction counter used in session-key derivation.
     * @param uid Real card UID bytes used in the documented calculation.
     * @param transaction_input Exact transaction-MAC input bytes.
     * @return The owned success value or failure evidence with the exact delivery outcome.
     */
    inline Result<Bytes> calculate_transaction_mac_aes(const Aes128Key& transaction_mac_key,
                                                       std::uint32_t transaction_counter,
                                                       const Bytes& uid,
                                                       const Bytes& transaction_input) {
        auto valid = offline_detail::require_key(transaction_mac_key,
                                                 "AES-128 transaction-MAC key ownership is empty");
        if (!valid) {
            return Result<Bytes>::failure(std::move(valid).error());
        }
        df_buffer* buffer{};
        df_error error{};
        const auto status = df_offline_calculate_transaction_mac_aes(
            transaction_mac_key.data(), transaction_mac_key.size(), transaction_counter,
            detail::byte_data(uid), uid.size(), detail::byte_data(transaction_input),
            transaction_input.size(), &buffer, &error);
        return offline_detail::buffer_result(status, buffer, error);
    }

    /**
     * @brief Resolve one transaction-MAC key exactly once before calculating its MAC.
     * @param provider Synchronous key provider invoked once before the offline calculation.
     * @param request Non-secret key lookup request borrowed for the synchronous provider call.
     * @param transaction_counter Committed transaction counter used in session-key derivation.
     * @param uid Real card UID bytes used in the documented calculation.
     * @param transaction_input Exact transaction-MAC input bytes.
     * @return The owned success value or failure evidence with the exact delivery outcome.
     */
    inline Result<Bytes> calculate_transaction_mac_aes(Aes128KeyProvider& provider,
                                                       const KeyRequest& request,
                                                       std::uint32_t transaction_counter,
                                                       const Bytes& uid,
                                                       const Bytes& transaction_input) {
        auto checked = offline_detail::require_request(request, KeyPurpose::transaction_mac);
        if (!checked) {
            return Result<Bytes>::failure(std::move(checked).error());
        }
        detail::ProviderCall call(provider, request);
        df_buffer* buffer{};
        df_error error{};
        const auto status = df_offline_calculate_transaction_mac_aes_provider(
            call.provider(), call.request(), transaction_counter, detail::byte_data(uid),
            uid.size(), detail::byte_data(transaction_input), transaction_input.size(), &buffer,
            &error);
        return offline_detail::buffer_result(status, buffer, error);
    }

    /**
     * @brief Verify one transaction MAC with explicit backend key, UID, counter, and TMI.
     * @param transaction_key Application transaction-MAC key borrowed until return.
     * @param transaction_counter Committed transaction counter used in session-key derivation.
     * @param uid Real card UID bytes used in the documented calculation.
     * @param transaction_input Exact transaction-MAC input bytes.
     * @param transaction_mac Eight-byte transaction MAC to verify.
     * @return The owned success value or failure evidence with the exact delivery outcome.
     */
    inline Result<bool> verify_transaction_mac_aes(const Aes128Key& transaction_key,
                                                   std::uint32_t transaction_counter,
                                                   const Bytes& uid, const Bytes& transaction_input,
                                                   const Bytes& transaction_mac) {
        auto valid = offline_detail::require_key(transaction_key, "transaction key is empty");
        if (!valid) {
            return Result<bool>::failure(std::move(valid).error());
        }
        std::uint32_t verified{};
        df_error error{};
        const auto status = df_offline_verify_transaction_mac_aes(
            transaction_key.data(), transaction_key.size(), transaction_counter,
            detail::byte_data(uid), uid.size(), detail::byte_data(transaction_input),
            transaction_input.size(), detail::byte_data(transaction_mac), transaction_mac.size(),
            &verified, &error);
        if (status != DF_OK) {
            return Result<bool>::failure(detail::native_error(status, error));
        }
        return Result<bool>::success(verified != 0U);
    }

    /**
     * @brief Resolve AppTransactionMACKey once before verifying one transaction MAC.
     * @param provider Synchronous key provider invoked once before the offline calculation.
     * @param request Non-secret key lookup request borrowed for the synchronous provider call.
     * @param transaction_counter Committed transaction counter used in session-key derivation.
     * @param uid Real card UID bytes used in the documented calculation.
     * @param transaction_input Exact transaction-MAC input bytes.
     * @param transaction_mac Eight-byte transaction MAC to verify.
     * @return The owned success value or failure evidence with the exact delivery outcome.
     */
    inline Result<bool> verify_transaction_mac_aes(Aes128KeyProvider& provider,
                                                   const KeyRequest& request,
                                                   std::uint32_t transaction_counter,
                                                   const Bytes& uid, const Bytes& transaction_input,
                                                   const Bytes& transaction_mac) {
        auto checked = offline_detail::require_request(request, KeyPurpose::transaction_mac);
        if (!checked) {
            return Result<bool>::failure(std::move(checked).error());
        }
        detail::ProviderCall call(provider, request);
        std::uint32_t verified{};
        df_error error{};
        const auto status = df_offline_verify_transaction_mac_aes_provider(
            call.provider(), call.request(), transaction_counter, detail::byte_data(uid),
            uid.size(), detail::byte_data(transaction_input), transaction_input.size(),
            detail::byte_data(transaction_mac), transaction_mac.size(), &verified, &error);
        if (status != DF_OK) {
            return Result<bool>::failure(detail::native_error(status, error));
        }
        return Result<bool>::success(verified != 0U);
    }

    /**
     * @brief Decrypt one authenticated EncTMRI with an already-derived session encryption key.
     * @param session_encryption_key Already-derived SesTMENCKey used to decrypt EncTMRI.
     * @param encrypted_reader_id Authenticated encrypted ReaderID value to decrypt.
     * @return The owned success value or failure evidence with the exact delivery outcome.
     */
    inline Result<Bytes> decrypt_transaction_reader_id_aes(const Aes128Key& session_encryption_key,
                                                           const Bytes& encrypted_reader_id) {
        auto valid = offline_detail::require_key(session_encryption_key,
                                                 "transaction encryption key is empty");
        if (!valid) {
            return Result<Bytes>::failure(std::move(valid).error());
        }
        df_buffer* buffer{};
        df_error error{};
        const auto status = df_offline_decrypt_transaction_reader_id_aes(
            session_encryption_key.data(), session_encryption_key.size(),
            detail::byte_data(encrypted_reader_id), encrypted_reader_id.size(), &buffer, &error);
        return offline_detail::buffer_result(status, buffer, error);
    }

    /**
     * @brief Verify a UID originality signature with one explicit trusted public key and curve.
     * @param curve NUL-terminated supported curve name understood by the native verifier.
     * @param public_key Trusted public key bytes for originality verification.
     * @param uid Real card UID bytes used in the documented calculation.
     * @param signature Originality signature bytes to verify.
     * @return The owned success value or failure evidence with the exact delivery outcome.
     */
    inline Result<bool> verify_originality_uid_signature(const std::string& curve,
                                                         const Bytes& public_key, const Bytes& uid,
                                                         const Bytes& signature) {
        auto identity = raw::validate_native_identity();
        if (!identity) {
            return Result<bool>::failure(std::move(identity).error());
        }
        std::uint32_t verified{};
        df_error error{};
        const auto status = df_offline_verify_originality_uid_signature(
            curve.c_str(), detail::byte_data(public_key), public_key.size(), detail::byte_data(uid),
            uid.size(), detail::byte_data(signature), signature.size(), &verified, &error);
        if (status != DF_OK) {
            return Result<bool>::failure(detail::native_error(status, error));
        }
        return Result<bool>::success(verified != 0);
    }
} // namespace desfire::cpp17::offline
