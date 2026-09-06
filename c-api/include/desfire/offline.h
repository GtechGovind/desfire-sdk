/**
 * @file offline.h
 * @brief Stateless host-side AES and originality helpers exposed through C99.
 */
#ifndef DESFIRE_OFFLINE_H
#define DESFIRE_OFFLINE_H

#include <desfire/key_provider.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief ABI-v1 application fields authenticated by a delegated-application creation MAC.
 *
 * Optional key_settings3 and iso_id use -1 when absent. has_key_sets is zero or one; when zero,
 * every key-set field must be zero. The DF name is borrowed for the duration of the call and may
 * contain zero through sixteen bytes. Reserved words must be zero.
 */
typedef struct df_delegated_application_configuration_v1 {
    uint32_t struct_size;            /**< sizeof(df_delegated_application_configuration_v1). */
    uint32_t abi_version;            /**< DF_ABI_VERSION. */
    uint32_t application_id;         /**< Nonzero 24-bit delegated AID. */
    uint32_t key_settings;           /**< Application key-settings byte. */
    uint32_t number_of_keys;         /**< Application AES key-count/type byte. */
    uint32_t slot;                   /**< Sixteen-bit delegated slot. */
    uint32_t slot_version;           /**< Delegated slot version byte. */
    uint32_t quota_limit;            /**< Sixteen-bit delegated quota. */
    uint32_t iso_file_identifiers;   /**< Zero or one. */
    int32_t key_settings3;           /**< Optional third key-settings byte, or -1. */
    int32_t iso_id;                  /**< Optional ISO DF identifier, or -1. */
    const uint8_t* df_name;          /**< Optional ISO DF name. */
    size_t df_name_size;             /**< Zero through sixteen bytes. */
    uint32_t has_key_sets;           /**< Whether the following key-set fields are present. */
    uint32_t active_key_set_version; /**< Initially active key-set version. */
    uint32_t number_of_key_sets;     /**< Total key sets. */
    uint32_t maximum_key_size;       /**< Maximum application key width. */
    uint32_t key_set_settings;       /**< Documented key-set settings byte. */
    uint64_t reserved[DF_ABI_RESERVED_WORDS]; /**< Must be zero. */
} df_delegated_application_configuration_v1;

/**
 * @brief Derive one AES-128 key with NXP AN10922 from one through 31 explicit bytes.
 * @param master_key Borrowed AES-128 master key.
 * @param master_key_size Size of master_key; must be sixteen.
 * @param diversification Borrowed AN10922 diversification input.
 * @param diversification_size Diversification size from one through 31 bytes.
 * @param output Receives an owned result buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_offline_derive_nxp_aes128(const uint8_t* master_key, size_t master_key_size,
                                            const uint8_t* diversification,
                                            size_t diversification_size, df_buffer** output,
                                            df_error* error);

/**
 * @brief Resolve one master key and derive AES-128 from the request's diversification bytes.
 * @param provider Validated synchronous AES-128 provider descriptor borrowed for this operation.
 * @param request Validated non-secret key reference, scope, purpose, and derivation context.
 * @param output Receives an owned result buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_offline_derive_nxp_aes128_provider(const df_key_provider_v1* provider,
                                                     const df_key_request_v1* request,
                                                     df_buffer** output, df_error* error);

/**
 * @brief Encrypt a delegated AES default key into the documented 32-byte EncK record.
 * @param dam_encryption_key Borrowed sixteen-byte delegated-application encryption key.
 * @param dam_encryption_key_size Size of dam_encryption_key; must be sixteen.
 * @param application_default_key Borrowed sixteen-byte application default key.
 * @param application_default_key_size Size of application_default_key; must be sixteen.
 * @param application_default_key_version Application default-key version byte.
 * @param output Receives an owned result buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_offline_encrypt_delegated_default_key_aes(
    const uint8_t* dam_encryption_key, size_t dam_encryption_key_size,
    const uint8_t* application_default_key, size_t application_default_key_size,
    uint32_t application_default_key_version, df_buffer** output, df_error* error);

/**
 * @brief Resolve DAMEncKey before encrypting a caller-supplied delegated default key.
 * @param provider Validated synchronous AES-128 provider descriptor borrowed for this operation.
 * @param request Validated non-secret key reference, scope, purpose, and derivation context.
 * @param application_default_key Borrowed sixteen-byte application default key.
 * @param application_default_key_size Size of application_default_key; must be sixteen.
 * @param application_default_key_version Application default-key version byte.
 * @param output Receives an owned result buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_offline_encrypt_delegated_default_key_aes_provider(
    const df_key_provider_v1* provider, const df_key_request_v1* request,
    const uint8_t* application_default_key, size_t application_default_key_size,
    uint32_t application_default_key_version, df_buffer** output, df_error* error);

/**
 * @brief Calculate the eight-byte creation DAM MAC from an exact versioned configuration.
 * @param dam_mac_key Borrowed sixteen-byte delegated-application MAC key.
 * @param dam_mac_key_size Size of dam_mac_key; must be sixteen.
 * @param configuration Validated versioned configuration descriptor borrowed for this call.
 * @param encrypted_default_key Borrowed issuer-generated encrypted default-key record.
 * @param encrypted_default_key_size Size of the encrypted default-key record required by the
 * command.
 * @param output Receives an owned result buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_offline_calculate_delegated_application_mac_aes(
    const uint8_t* dam_mac_key, size_t dam_mac_key_size,
    const df_delegated_application_configuration_v1* configuration,
    const uint8_t* encrypted_default_key, size_t encrypted_default_key_size, df_buffer** output,
    df_error* error);

/**
 * @brief Resolve DAMMACKey before calculating the delegated-application creation MAC.
 * @param provider Validated synchronous AES-128 provider descriptor borrowed for this operation.
 * @param request Validated non-secret key reference, scope, purpose, and derivation context.
 * @param configuration Validated versioned configuration descriptor borrowed for this call.
 * @param encrypted_default_key Borrowed issuer-generated encrypted default-key record.
 * @param encrypted_default_key_size Size of the encrypted default-key record required by the
 * command.
 * @param output Receives an owned result buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_offline_calculate_delegated_application_mac_aes_provider(
    const df_key_provider_v1* provider, const df_key_request_v1* request,
    const df_delegated_application_configuration_v1* configuration,
    const uint8_t* encrypted_default_key, size_t encrypted_default_key_size, df_buffer** output,
    df_error* error);

/**
 * @brief Calculate the eight-byte issuer MAC authorizing delegated-application deletion.
 * @param dam_mac_key Borrowed sixteen-byte delegated-application MAC key.
 * @param dam_mac_key_size Size of dam_mac_key; must be sixteen.
 * @param application_id Nonzero 24-bit delegated application identifier.
 * @param output Receives an owned result buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_offline_calculate_delegated_application_delete_mac_aes(const uint8_t* dam_mac_key,
                                                                         size_t dam_mac_key_size,
                                                                         uint32_t application_id,
                                                                         df_buffer** output,
                                                                         df_error* error);

/**
 * @brief Resolve DAMMACKey before calculating the delegated-application deletion MAC.
 * @param provider Validated synchronous AES-128 provider descriptor borrowed for this operation.
 * @param request Validated non-secret key reference, scope, purpose, and derivation context.
 * @param application_id Nonzero 24-bit delegated application identifier.
 * @param output Receives an owned result buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_offline_calculate_delegated_application_delete_mac_aes_provider(
    const df_key_provider_v1* provider, const df_key_request_v1* request, uint32_t application_id,
    df_buffer** output, df_error* error);

/**
 * @brief Calculate the eight-byte DAM MAC for an explicit old and replacement DF name.
 * @param dam_mac_key Borrowed sixteen-byte delegated-application MAC key.
 * @param dam_mac_key_size Size of dam_mac_key; must be sixteen.
 * @param old_df_name Borrowed current ISO DF name.
 * @param old_df_name_size Current ISO DF-name size in bytes.
 * @param new_df_name Borrowed replacement ISO DF name.
 * @param new_df_name_size Replacement ISO DF-name size in bytes.
 * @param output Receives an owned result buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_offline_calculate_delegated_configuration_mac_aes(
    const uint8_t* dam_mac_key, size_t dam_mac_key_size, const uint8_t* old_df_name,
    size_t old_df_name_size, const uint8_t* new_df_name, size_t new_df_name_size,
    df_buffer** output, df_error* error);

/**
 * @brief Resolve DAMMACKey before calculating the delegated DF-name configuration MAC.
 * @param provider Validated synchronous AES-128 provider descriptor borrowed for this operation.
 * @param request Validated non-secret key reference, scope, purpose, and derivation context.
 * @param old_df_name Borrowed current ISO DF name.
 * @param old_df_name_size Current ISO DF-name size in bytes.
 * @param new_df_name Borrowed replacement ISO DF name.
 * @param new_df_name_size Replacement ISO DF-name size in bytes.
 * @param output Receives an owned result buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_offline_calculate_delegated_configuration_mac_aes_provider(
    const df_key_provider_v1* provider, const df_key_request_v1* request,
    const uint8_t* old_df_name, size_t old_df_name_size, const uint8_t* new_df_name,
    size_t new_df_name_size, df_buffer** output, df_error* error);

/**
 * @brief Calculate the eight-byte AES MAC for a complete MIFARE Classic license record.
 * @param license_mac_key Borrowed sixteen-byte MIFARE Classic license MAC key.
 * @param license_mac_key_size Size of license_mac_key; must be sixteen.
 * @param mfc_license Borrowed complete documented MIFARE Classic license record.
 * @param mfc_license_size Size of mfc_license in bytes.
 * @param mfc_sector_secrets Borrowed documented MIFARE Classic sector-secret record.
 * @param mfc_sector_secrets_size Size of mfc_sector_secrets in bytes.
 * @param output Receives an owned result buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_offline_calculate_mfc_license_mac_aes(
    const uint8_t* license_mac_key, size_t license_mac_key_size, const uint8_t* mfc_license,
    size_t mfc_license_size, const uint8_t* mfc_sector_secrets, size_t mfc_sector_secrets_size,
    df_buffer** output, df_error* error);

/**
 * @brief Resolve MFCLicenseMACKey before calculating the compatibility-license MAC.
 * @param provider Validated synchronous AES-128 provider descriptor borrowed for this operation.
 * @param request Validated non-secret key reference, scope, purpose, and derivation context.
 * @param mfc_license Borrowed complete documented MIFARE Classic license record.
 * @param mfc_license_size Size of mfc_license in bytes.
 * @param mfc_sector_secrets Borrowed documented MIFARE Classic sector-secret record.
 * @param mfc_sector_secrets_size Size of mfc_sector_secrets in bytes.
 * @param output Receives an owned result buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_offline_calculate_mfc_license_mac_aes_provider(
    const df_key_provider_v1* provider, const df_key_request_v1* request,
    const uint8_t* mfc_license, size_t mfc_license_size, const uint8_t* mfc_sector_secrets,
    size_t mfc_sector_secrets_size, df_buffer** output, df_error* error);

/**
 * @brief Derive SesTMMACKey followed by SesTMENCKey into one exact 32-byte result.
 * @param transaction_key Borrowed sixteen-byte application transaction-MAC key.
 * @param transaction_key_size Size of transaction_key; must be sixteen.
 * @param transaction_counter Committed transaction counter used for session-key derivation.
 * @param uid Borrowed real card UID used by the documented derivation or verification.
 * @param uid_size UID size accepted by the documented operation.
 * @param output Receives an owned result buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_offline_derive_transaction_mac_keys_aes(const uint8_t* transaction_key,
                                                          size_t transaction_key_size,
                                                          uint32_t transaction_counter,
                                                          const uint8_t* uid, size_t uid_size,
                                                          df_buffer** output, df_error* error);

/**
 * @brief Resolve AppTransactionMACKey before deriving both transaction session keys.
 * @param provider Validated synchronous AES-128 provider descriptor borrowed for this operation.
 * @param request Validated non-secret key reference, scope, purpose, and derivation context.
 * @param transaction_counter Committed transaction counter used for session-key derivation.
 * @param uid Borrowed real card UID used by the documented derivation or verification.
 * @param uid_size UID size accepted by the documented operation.
 * @param output Receives an owned result buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_offline_derive_transaction_mac_keys_aes_provider(
    const df_key_provider_v1* provider, const df_key_request_v1* request,
    uint32_t transaction_counter, const uint8_t* uid, size_t uid_size, df_buffer** output,
    df_error* error);

/**
 * @brief Calculate an eight-byte TMV from an already-derived SesTMMACKey and complete TMI.
 * @param session_mac_key Borrowed already-derived sixteen-byte transaction session MAC key.
 * @param session_mac_key_size Size of session_mac_key; must be sixteen.
 * @param transaction_input Borrowed exact transaction input accumulated by the application.
 * @param transaction_input_size Size of transaction_input in bytes.
 * @param output Receives an owned result buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_offline_calculate_transaction_mac_session_aes(
    const uint8_t* session_mac_key, size_t session_mac_key_size, const uint8_t* transaction_input,
    size_t transaction_input_size, df_buffer** output, df_error* error);

/**
 * @brief Calculate an eight-byte AES transaction MAC from explicit counter, UID, and TMI.
 * @param transaction_mac_key Borrowed sixteen-byte application transaction-MAC key.
 * @param key_size Size of key in bytes; AES entry points require exactly sixteen.
 * @param transaction_counter Committed transaction counter used for session-key derivation.
 * @param uid Borrowed real card UID used by the documented derivation or verification.
 * @param uid_size UID size accepted by the documented operation.
 * @param transaction_input Borrowed exact transaction input accumulated by the application.
 * @param transaction_input_size Size of transaction_input in bytes.
 * @param output Receives an owned result buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_offline_calculate_transaction_mac_aes(
    const uint8_t* transaction_mac_key, size_t key_size, uint32_t transaction_counter,
    const uint8_t* uid, size_t uid_size, const uint8_t* transaction_input,
    size_t transaction_input_size, df_buffer** output, df_error* error);

/**
 * @brief Resolve one transaction key and calculate the eight-byte AES transaction MAC.
 * @param provider Validated synchronous AES-128 provider descriptor borrowed for this operation.
 * @param request Validated non-secret key reference, scope, purpose, and derivation context.
 * @param transaction_counter Committed transaction counter used for session-key derivation.
 * @param uid Borrowed real card UID used by the documented derivation or verification.
 * @param uid_size UID size accepted by the documented operation.
 * @param transaction_input Borrowed exact transaction input accumulated by the application.
 * @param transaction_input_size Size of transaction_input in bytes.
 * @param output Receives an owned result buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_offline_calculate_transaction_mac_aes_provider(
    const df_key_provider_v1* provider, const df_key_request_v1* request,
    uint32_t transaction_counter, const uint8_t* uid, size_t uid_size,
    const uint8_t* transaction_input, size_t transaction_input_size, df_buffer** output,
    df_error* error);

/**
 * @brief Verify an eight-byte TMV from the backend key, real UID, committed TMC, and exact TMI.
 * @param transaction_key Borrowed sixteen-byte application transaction-MAC key.
 * @param transaction_key_size Size of transaction_key; must be sixteen.
 * @param transaction_counter Committed transaction counter used for session-key derivation.
 * @param uid Borrowed real card UID used by the documented derivation or verification.
 * @param uid_size UID size accepted by the documented operation.
 * @param transaction_input Borrowed exact transaction input accumulated by the application.
 * @param transaction_input_size Size of transaction_input in bytes.
 * @param transaction_mac Borrowed eight-byte transaction MAC to verify.
 * @param transaction_mac_size Size of transaction_mac; must be eight.
 * @param verified Non-NULL destination set to one for a valid signature or MAC and zero otherwise.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_offline_verify_transaction_mac_aes(
    const uint8_t* transaction_key, size_t transaction_key_size, uint32_t transaction_counter,
    const uint8_t* uid, size_t uid_size, const uint8_t* transaction_input,
    size_t transaction_input_size, const uint8_t* transaction_mac, size_t transaction_mac_size,
    uint32_t* verified, df_error* error);

/**
 * @brief Resolve AppTransactionMACKey before verifying an eight-byte TMV.
 * @param provider Validated synchronous AES-128 provider descriptor borrowed for this operation.
 * @param request Validated non-secret key reference, scope, purpose, and derivation context.
 * @param transaction_counter Committed transaction counter used for session-key derivation.
 * @param uid Borrowed real card UID used by the documented derivation or verification.
 * @param uid_size UID size accepted by the documented operation.
 * @param transaction_input Borrowed exact transaction input accumulated by the application.
 * @param transaction_input_size Size of transaction_input in bytes.
 * @param transaction_mac Borrowed eight-byte transaction MAC to verify.
 * @param transaction_mac_size Size of transaction_mac; must be eight.
 * @param verified Non-NULL destination set to one for a valid signature or MAC and zero otherwise.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_offline_verify_transaction_mac_aes_provider(
    const df_key_provider_v1* provider, const df_key_request_v1* request,
    uint32_t transaction_counter, const uint8_t* uid, size_t uid_size,
    const uint8_t* transaction_input, size_t transaction_input_size, const uint8_t* transaction_mac,
    size_t transaction_mac_size, uint32_t* verified, df_error* error);

/**
 * @brief Decrypt one exact 16-byte EncTMRI with an already-derived SesTMENCKey.
 * @param session_encryption_key Borrowed already-derived sixteen-byte transaction session
 * encryption key.
 * @param session_encryption_key_size Size of session_encryption_key; must be sixteen.
 * @param encrypted_reader_id Borrowed exact sixteen-byte encrypted transaction-reader identifier.
 * @param encrypted_reader_id_size Size of encrypted_reader_id; must be sixteen.
 * @param output Receives an owned result buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_offline_decrypt_transaction_reader_id_aes(const uint8_t* session_encryption_key,
                                                            size_t session_encryption_key_size,
                                                            const uint8_t* encrypted_reader_id,
                                                            size_t encrypted_reader_id_size,
                                                            df_buffer** output, df_error* error);

/**
 * @brief Verify one UID originality signature using a caller-selected supported curve.
 * @param curve NUL-terminated identifier for one supported originality-signature curve.
 * @param public_key Borrowed encoded originality-signature public key.
 * @param public_key_size Size of public_key in bytes.
 * @param uid Borrowed real card UID used by the documented derivation or verification.
 * @param uid_size UID size accepted by the documented operation.
 * @param signature Borrowed originality signature bytes.
 * @param signature_size Size of signature in bytes.
 * @param verified Non-NULL destination set to one for a valid signature or MAC and zero otherwise.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_offline_verify_originality_uid_signature(
    const char* curve, const uint8_t* public_key, size_t public_key_size, const uint8_t* uid,
    size_t uid_size, const uint8_t* signature, size_t signature_size, uint32_t* verified,
    df_error* error);

#ifdef __cplusplus
}
#endif
#endif
