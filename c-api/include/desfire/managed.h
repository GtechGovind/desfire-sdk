/**
 * @file managed.h
 * @brief Managed checked DESFire EV3 operations for C99 and older C++ consumers.
 */
#ifndef DESFIRE_MANAGED_H
#define DESFIRE_MANAGED_H

#include <desfire/key_provider.h>
#include <desfire/transport.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Omit the UID request option byte. */
#define DF_UID_OPTION_OMITTED 0u
/** @brief Request the documented UID response without an NUID. */
#define DF_UID_WITHOUT_NUID 1u
/** @brief Request the documented UID response including the four-byte NUID. */
#define DF_UID_WITH_NUID 2u
/** @brief ISO UPDATE RECORD instruction variant 0xDC. */
#define DF_ISO_UPDATE_RECORD_DC 0xDCu
/** @brief ISO UPDATE RECORD instruction variant 0xDD. */
#define DF_ISO_UPDATE_RECORD_DD 0xDDu
/** @brief Transaction-plan data-file write operation. */
#define DF_TRANSACTION_WRITE_DATA 1u
/** @brief Transaction-plan value-file credit operation. */
#define DF_TRANSACTION_CREDIT 2u
/** @brief Transaction-plan value-file debit operation. */
#define DF_TRANSACTION_DEBIT 3u
/** @brief Transaction-plan value-file limited-credit operation. */
#define DF_TRANSACTION_LIMITED_CREDIT 4u
/** @brief Transaction-plan record-file append operation. */
#define DF_TRANSACTION_WRITE_RECORD 5u
/** @brief Transaction-plan record-file update operation. */
#define DF_TRANSACTION_UPDATE_RECORD 6u
/** @brief Transaction-plan record-file clear operation. */
#define DF_TRANSACTION_CLEAR_RECORD_FILE 7u

/** @brief Versioned named PICC configuration flags for SetConfiguration option zero. */
typedef struct df_picc_configuration_v1 {
    uint32_t struct_size;                           /**< sizeof(df_picc_configuration_v1). */
    uint32_t abi_version;                           /**< DF_ABI_VERSION. */
    uint32_t disable_format;                        /**< Boolean option-zero disable-format flag. */
    uint32_t random_identifier;                     /**< Boolean random-identifier flag. */
    uint32_t proximity_check_mandatory;             /**< Boolean mandatory proximity-check flag. */
    uint32_t virtual_card_authentication_mandatory; /**< Boolean mandatory VCA flag. */
    uint32_t error_code_binding;                    /**< Boolean error-code binding flag. */
    uint32_t random_identifier_configuration;       /**< Boolean random-ID configuration flag. */
    uint32_t four_byte_nuid_configuration;    /**< Boolean four-byte NUID configuration flag. */
    uint64_t reserved[DF_ABI_RESERVED_WORDS]; /**< Must be zero. */
} df_picc_configuration_v1;

/** @brief Versioned output for one delegated-application slot query. */
typedef struct df_delegated_application_info_v1 {
    uint32_t struct_size;    /**< sizeof(df_delegated_application_info_v1). */
    uint32_t abi_version;    /**< DF_ABI_VERSION. */
    uint32_t slot_version;   /**< One-byte slot version widened without sign extension. */
    uint32_t quota_limit;    /**< Sixteen-bit configured delegated quota. */
    uint32_t free_blocks;    /**< Sixteen-bit remaining delegated blocks. */
    uint32_t application_id; /**< Assigned 24-bit native application identifier. */
    uint64_t reserved[DF_ABI_RESERVED_WORDS]; /**< Must be zero. */
} df_delegated_application_info_v1;

/** @brief One checked mutation in a managed atomic transaction plan. */
typedef struct df_transaction_operation_v1 {
    uint32_t struct_size;                     /**< sizeof(df_transaction_operation_v1). */
    uint32_t abi_version;                     /**< DF_ABI_VERSION. */
    uint32_t kind;                            /**< One DF_TRANSACTION_* value. */
    uint32_t file;                            /**< Target native file number. */
    uint32_t communication;                   /**< DF_PLAIN, DF_MAC, or DF_FULL. */
    uint32_t offset;                          /**< Byte offset for data/record writes. */
    uint32_t record;                          /**< Record number for update-record. */
    uint32_t amount;                          /**< Unsigned value for value mutations. */
    const uint8_t* data;                      /**< Borrowed data for write mutations. */
    size_t data_size;                         /**< Data bytes; zero for value mutations. */
    uint64_t reserved[DF_ABI_RESERVED_WORDS]; /**< Must be zero. */
} df_transaction_operation_v1;

/**
 * @brief Read the complete 28-byte native GetVersion payload.
 * @param card Open handle returned by df_open; ownership remains with the caller.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param out Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_get_version(df_card card, uint32_t timeout_ms, df_buffer** out, df_error* error);

/**
 * @brief Read the available PICC storage in bytes.
 * @param card Open handle returned by df_open; ownership remains with the caller.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param out Non-NULL destination written only on success; ownership remains with the caller.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_free_memory(df_card card, uint32_t timeout_ms, uint32_t* out, df_error* error);

/**
 * @brief Select a native application and replace the previous authentication context.
 * @param card Open handle returned by df_open; ownership remains with the caller.
 * @param aid Native application identifier, 0 through 0xFFFFFF; zero denotes the PICC.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_select_application(df_card card, uint32_t aid, uint32_t timeout_ms,
                                     df_error* error);

/**
 * @brief Read one native file number per returned byte.
 * @param card Open handle returned by df_open; ownership remains with the caller.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param out Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_file_ids(df_card card, uint32_t timeout_ms, df_buffer** out, df_error* error);

/**
 * @brief Establish Standard AES authentication with one borrowed exact key.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param key_number Native or ISO key selector in the range accepted by the selected authentication
 * profile.
 * @param key Borrowed AES-128 key bytes; caller memory is never retained.
 * @param key_size Size of key in bytes; AES entry points require exactly sixteen.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_authenticate_standard_aes(df_card card, uint32_t key_number, const uint8_t* key,
                                            size_t key_size, uint32_t timeout_ms, df_error* error);

/**
 * @brief Resolve exactly one key and establish Standard AES before card I/O.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param key_number Native or ISO key selector in the range accepted by the selected authentication
 * profile.
 * @param provider Validated synchronous AES-128 provider descriptor borrowed for this operation.
 * @param request Validated non-secret key reference, scope, purpose, and derivation context.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_authenticate_standard_aes_provider(df_card card, uint32_t key_number,
                                                     const df_key_provider_v1* provider,
                                                     const df_key_request_v1* request,
                                                     uint32_t timeout_ms, df_error* error);

/**
 * @brief Establish EV2 First with no PCD capability bytes and return verified metadata.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param key_number Native or ISO key selector in the range accepted by the selected authentication
 * profile.
 * @param key Borrowed AES-128 key bytes; caller memory is never retained.
 * @param key_size Size of key in bytes; AES entry points require exactly sixteen.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param out Initialized ABI-v1 descriptor that receives verified EV2 authentication metadata.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_authenticate_ev2_first_aes(df_card card, uint32_t key_number, const uint8_t* key,
                                             size_t key_size, uint32_t timeout_ms,
                                             df_authentication_info_v1* out, df_error* error);

/**
 * @brief Resolve exactly one key, establish EV2 First, and return verified metadata.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param key_number Native or ISO key selector in the range accepted by the selected authentication
 * profile.
 * @param provider Validated synchronous AES-128 provider descriptor borrowed for this operation.
 * @param request Validated non-secret key reference, scope, purpose, and derivation context.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param out Initialized ABI-v1 descriptor that receives verified EV2 authentication metadata.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_authenticate_ev2_first_aes_provider(df_card card, uint32_t key_number,
                                                      const df_key_provider_v1* provider,
                                                      const df_key_request_v1* request,
                                                      uint32_t timeout_ms,
                                                      df_authentication_info_v1* out,
                                                      df_error* error);

/**
 * @brief Establish EV2 First with zero through six PCD capability bytes.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param key_number Native or ISO key selector in the range accepted by the selected authentication
 * profile.
 * @param key Borrowed AES-128 key bytes; caller memory is never retained.
 * @param key_size Size of key in bytes; AES entry points require exactly sixteen.
 * @param pcd_capabilities Borrowed PCD capability bytes; NULL is accepted only when the size is
 * zero.
 * @param pcd_capabilities_size Capability byte count; EV2 First accepts zero through six.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param out Initialized ABI-v1 descriptor that receives verified EV2 authentication metadata.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_authenticate_ev2_first_aes_with_capabilities(
    df_card card, uint32_t key_number, const uint8_t* key, size_t key_size,
    const uint8_t* pcd_capabilities, size_t pcd_capabilities_size, uint32_t timeout_ms,
    df_authentication_info_v1* out, df_error* error);

/**
 * @brief Resolve exactly one key and establish EV2 First with explicit capabilities.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param key_number Native or ISO key selector in the range accepted by the selected authentication
 * profile.
 * @param provider Validated synchronous AES-128 provider descriptor borrowed for this operation.
 * @param request Validated non-secret key reference, scope, purpose, and derivation context.
 * @param pcd_capabilities Borrowed PCD capability bytes; NULL is accepted only when the size is
 * zero.
 * @param pcd_capabilities_size Capability byte count; EV2 First accepts zero through six.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param out Initialized ABI-v1 descriptor that receives verified EV2 authentication metadata.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_authenticate_ev2_first_aes_with_capabilities_provider(
    df_card card, uint32_t key_number, const df_key_provider_v1* provider,
    const df_key_request_v1* request, const uint8_t* pcd_capabilities, size_t pcd_capabilities_size,
    uint32_t timeout_ms, df_authentication_info_v1* out, df_error* error);

/**
 * @brief Replace an active EV2 session through NonFirst using one exact key.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param key_number Native or ISO key selector in the range accepted by the selected authentication
 * profile.
 * @param key Borrowed AES-128 key bytes; caller memory is never retained.
 * @param key_size Size of key in bytes; AES entry points require exactly sixteen.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param out Initialized ABI-v1 descriptor that receives verified EV2 authentication metadata.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_authenticate_ev2_non_first_aes(df_card card, uint32_t key_number,
                                                 const uint8_t* key, size_t key_size,
                                                 uint32_t timeout_ms,
                                                 df_authentication_info_v1* out, df_error* error);

/**
 * @brief Resolve exactly one key and replace an active EV2 session through NonFirst.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param key_number Native or ISO key selector in the range accepted by the selected authentication
 * profile.
 * @param provider Validated synchronous AES-128 provider descriptor borrowed for this operation.
 * @param request Validated non-secret key reference, scope, purpose, and derivation context.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param out Initialized ABI-v1 descriptor that receives verified EV2 authentication metadata.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_authenticate_ev2_non_first_aes_provider(df_card card, uint32_t key_number,
                                                          const df_key_provider_v1* provider,
                                                          const df_key_request_v1* request,
                                                          uint32_t timeout_ms,
                                                          df_authentication_info_v1* out,
                                                          df_error* error);

/**
 * @brief Read application identifiers as consecutive three-byte little-endian values.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_application_ids(df_card handle, uint32_t timeout_ms, df_buffer** output,
                                  df_error* error);

/**
 * @brief Read native GetISOFileIDs output as consecutive two-byte little-endian identifiers.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_iso_file_ids(df_card handle, uint32_t timeout_ms, df_buffer** output,
                               df_error* error);

/**
 * @brief Read the selected application key-settings payload in native wire order.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_get_key_settings(df_card handle, uint32_t timeout_ms, df_buffer** output,
                                   df_error* error);

/**
 * @brief Read the selected application key-set version payload in native wire order.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_get_key_set_versions(df_card handle, uint32_t timeout_ms, df_buffer** output,
                                       df_error* error);

/**
 * @brief Read the real card UID through the authenticated native command.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_get_card_uid(df_card handle, uint32_t timeout_ms, df_buffer** output,
                               df_error* error);

/**
 * @brief Read the raw originality signature for separate trusted-key verification.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_read_originality_signature(df_card handle, uint32_t timeout_ms,
                                             df_buffer** output, df_error* error);

/**
 * @brief Abort the card transaction currently pending in the selected application.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_abort_transaction(df_card handle, uint32_t timeout_ms, df_error* error);

/**
 * @brief Execute the authenticated PICC format operation and invalidate the session.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_format_picc(df_card handle, uint32_t timeout_ms, df_error* error);

/**
 * @brief Delete one file from the selected application.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param file Native file number, 0 through 31.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_delete_file(df_card handle, uint32_t file, uint32_t timeout_ms, df_error* error);

/**
 * @brief Read a validated native file-settings payload in wire order.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param file Native file number, 0 through 31.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_get_file_settings(df_card handle, uint32_t file, uint32_t timeout_ms,
                                    df_buffer** output, df_error* error);

/**
 * @brief Stage removal of all records in the selected record file.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param file Native file number, 0 through 31.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_clear_record_file(df_card handle, uint32_t file, uint32_t timeout_ms,
                                    df_error* error);

/**
 * @brief Read three little-endian SDM counter bytes followed by two reserved bytes.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param file Native file number, 0 through 31.
 * @param communication DF_PLAIN, DF_MAC, or DF_FULL, matching the file policy.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_get_file_counters(df_card handle, uint32_t file, uint32_t communication,
                                    uint32_t timeout_ms, df_buffer** output, df_error* error);

/**
 * @brief Delete a nonzero native application identifier.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param aid Nonzero native application identifier, 1 through 0xFFFFFF.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_delete_application(df_card handle, uint32_t aid, uint32_t timeout_ms,
                                     df_error* error);

/**
 * @brief Change the selected application key-settings byte.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param settings New application key-settings byte, 0 through 255.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_change_key_settings(df_card handle, uint32_t settings, uint32_t timeout_ms,
                                      df_error* error);

/**
 * @brief Read the version payload for one native key and optional key set.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param number Native EV3 key selector, 0 through 63; an explicit key set requires 0 through 13.
 * @param key_set Key-set selector; -1 omits the optional field, otherwise 0 through 15.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_get_key_version(df_card handle, uint32_t number, int32_t key_set,
                                  uint32_t timeout_ms, df_buffer** output, df_error* error);

/**
 * @brief Initialize the selected EV3 key set.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param key_set Required key-set selector, 0 through 15.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_initialize_key_set(df_card handle, uint32_t key_set, uint32_t timeout_ms,
                                     df_error* error);

/**
 * @brief Activate the requested EV3 key set and invalidate the old authentication context.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param key_set Required key-set selector, 0 through 15.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_roll_key_set(df_card handle, uint32_t key_set, uint32_t timeout_ms,
                               df_error* error);

/**
 * @brief Finalize an EV3 key set with its version byte.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param key_set Required key-set selector, 0 through 15.
 * @param version Version byte, 0 through 255.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_finalize_key_set(df_card handle, uint32_t key_set, uint32_t version,
                                   uint32_t timeout_ms, df_error* error);

/**
 * @brief Read native data-file bytes using the selected communication mode.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param file Native file number, 0 through 31.
 * @param offset Byte offset, 0 through 0xFFFFFF; the complete range must fit the native field.
 * @param length Byte count, 0 through 0xFFFFFF; zero requests the remaining file content.
 * @param communication DF_PLAIN, DF_MAC, or DF_FULL, matching the file policy.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_read_data(df_card handle, uint32_t file, uint32_t offset, uint32_t length,
                            uint32_t communication, uint32_t timeout_ms, df_buffer** output,
                            df_error* error);

/**
 * @brief Write native data-file bytes; backup-file writes remain pending until commit.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param file Native file number, 0 through 31.
 * @param offset Byte offset, 0 through 0xFFFFFF; the complete range must fit the native field.
 * @param data Borrowed nonempty payload, valid until the call returns.
 * @param size Payload length in bytes; must match the operation-specific width or range.
 * @param communication DF_PLAIN, DF_MAC, or DF_FULL, matching the file policy.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_write_data(df_card handle, uint32_t file, uint32_t offset, const uint8_t* data,
                             size_t size, uint32_t communication, uint32_t timeout_ms,
                             df_error* error);

/**
 * @brief Stage bytes in a native record file at a byte offset.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param file Native file number, 0 through 31.
 * @param offset Byte offset, 0 through 0xFFFFFF; the complete range must fit the native field.
 * @param data Borrowed nonempty payload, valid until the call returns.
 * @param size Payload length in bytes; must match the operation-specific width or range.
 * @param communication DF_PLAIN, DF_MAC, or DF_FULL, matching the file policy.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_write_record(df_card handle, uint32_t file, uint32_t offset, const uint8_t* data,
                               size_t size, uint32_t communication, uint32_t timeout_ms,
                               df_error* error);

/**
 * @brief Read native record-file content from the specified record index.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param file Native file number, 0 through 31.
 * @param first First native record index, 0 through 0xFFFFFF.
 * @param count Record count, 0 through 0xFFFFFF; zero requests the remaining records.
 * @param communication DF_PLAIN, DF_MAC, or DF_FULL, matching the file policy.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_read_records(df_card handle, uint32_t file, uint32_t first, uint32_t count,
                               uint32_t communication, uint32_t timeout_ms, df_buffer** output,
                               df_error* error);

/**
 * @brief Stage replacement bytes within one native record.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param file Native file number, 0 through 31.
 * @param record Native record index, 0 through 0xFFFFFF.
 * @param offset Byte offset, 0 through 0xFFFFFF; the complete range must fit the native field.
 * @param data Borrowed nonempty payload, valid until the call returns.
 * @param size Payload length in bytes; must match the operation-specific width or range.
 * @param communication DF_PLAIN, DF_MAC, or DF_FULL, matching the file policy.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_update_record(df_card handle, uint32_t file, uint32_t record, uint32_t offset,
                                const uint8_t* data, size_t size, uint32_t communication,
                                uint32_t timeout_ms, df_error* error);

/**
 * @brief Stage an increase to a native value file.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param file Native file number, 0 through 31.
 * @param amount Nonnegative change amount, 0 through INT32_MAX.
 * @param communication DF_PLAIN, DF_MAC, or DF_FULL, matching the file policy.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_credit(df_card handle, uint32_t file, uint32_t amount, uint32_t communication,
                         uint32_t timeout_ms, df_error* error);

/**
 * @brief Stage a decrease to a native value file.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param file Native file number, 0 through 31.
 * @param amount Nonnegative change amount, 0 through INT32_MAX.
 * @param communication DF_PLAIN, DF_MAC, or DF_FULL, matching the file policy.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_debit(df_card handle, uint32_t file, uint32_t amount, uint32_t communication,
                        uint32_t timeout_ms, df_error* error);

/**
 * @brief Stage a limited-credit increase permitted by the value-file policy.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param file Native file number, 0 through 31.
 * @param amount Nonnegative change amount, 0 through INT32_MAX.
 * @param communication DF_PLAIN, DF_MAC, or DF_FULL, matching the file policy.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_limited_credit(df_card handle, uint32_t file, uint32_t amount,
                                 uint32_t communication, uint32_t timeout_ms, df_error* error);

/**
 * @brief Read the signed value of a native value file.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param file Native file number, 0 through 31.
 * @param communication DF_PLAIN, DF_MAC, or DF_FULL, matching the file policy.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Non-NULL destination written only on success; ownership remains with the caller.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_get_value(df_card handle, uint32_t file, uint32_t communication,
                            uint32_t timeout_ms, int32_t* output, df_error* error);

/**
 * @brief Commit staged changes and optionally return the transaction MAC evidence.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param return_mac One requests twelve TMC/TMV bytes; zero returns an empty owned buffer.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 *
 * @note An unknown outcome requires reconciliation with card/backend evidence before any new
 * mutation; this function never retries a commit.
 */
DF_API int32_t df_commit_transaction(df_card handle, uint32_t return_mac, uint32_t timeout_ms,
                                     df_buffer** output, df_error* error);

/**
 * @brief Submit a sixteen-byte ReaderID and return the previous encrypted ReaderID.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param reader_id Borrowed sixteen-byte ReaderID, valid until the call returns.
 * @param size ReaderID length in bytes; must be sixteen.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_commit_reader_id(df_card handle, const uint8_t* reader_id, size_t size,
                                   uint32_t timeout_ms, df_buffer** output, df_error* error);

/**
 * @brief Create an AES application with optional ISO selection identifiers.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param aid Nonzero native application identifier, 1 through 0xFFFFFF.
 * @param key_settings Application key-settings byte, 0 through 255.
 * @param key_count Number of AES application keys, 1 through 14.
 * @param iso_id Optional ISO identifier, -1 to omit or 0 through 65535 to include.
 * @param df_name Borrowed optional DF name; NULL is allowed only when df_name_size is zero.
 * @param df_name_size DF name length in bytes, at most sixteen; ISO configuration rules also apply.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_create_application(df_card handle, uint32_t aid, uint32_t key_settings,
                                     uint32_t key_count, int32_t iso_id, const uint8_t* df_name,
                                     size_t df_name_size, uint32_t timeout_ms, df_error* error);

/**
 * @brief Create a standard or backup native data file.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param file Native file number, 0 through 31.
 * @param length Nonzero file size in bytes, at most 0xFFFFFF.
 * @param communication DF_PLAIN, DF_MAC, or DF_FULL, matching the file policy.
 * @param access_rights Packed 16-bit native access rights: read, write, RW, change from high to low
 * nibble. The integer is sent little-endian; 0x1234 produces wire bytes 34 12.
 * @param iso_id Optional ISO identifier, -1 to omit or 0 through 65535 to include.
 * @param backup Zero creates a standard data file; one creates a transactional backup data file.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_create_data_file(df_card handle, uint32_t file, uint32_t length,
                                   uint32_t communication, uint32_t access_rights, int32_t iso_id,
                                   uint32_t backup, uint32_t timeout_ms, df_error* error);

/**
 * @brief Create a native value file with explicit signed limits and initial value.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param file Native file number, 0 through 31.
 * @param lower_limit Inclusive signed lower bound; must not exceed upper_limit.
 * @param upper_limit Inclusive signed upper bound; must not be below lower_limit.
 * @param initial_value Initial signed value, within the inclusive configured limits.
 * @param communication DF_PLAIN, DF_MAC, or DF_FULL, matching the file policy.
 * @param access_rights Packed 16-bit native access rights: read, write, RW, change from high to low
 * nibble. The integer is sent little-endian; 0x1234 produces wire bytes 34 12.
 * @param limited_credit Zero disables limited credit; one enables the file option.
 * @param free_get_value Zero disables free value reads; one enables the file option.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_create_value_file(df_card handle, uint32_t file, int32_t lower_limit,
                                    int32_t upper_limit, int32_t initial_value,
                                    uint32_t communication, uint32_t access_rights,
                                    uint32_t limited_credit, uint32_t free_get_value,
                                    uint32_t timeout_ms, df_error* error);

/**
 * @brief Create a linear or cyclic native record file.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param file Native file number, 0 through 31.
 * @param record_size Nonzero record width in bytes, at most 0xFFFFFF.
 * @param maximum_records Nonzero record capacity, at most 0xFFFFFF.
 * @param communication DF_PLAIN, DF_MAC, or DF_FULL, matching the file policy.
 * @param access_rights Packed 16-bit native access rights: read, write, RW, change from high to low
 * nibble. The integer is sent little-endian; 0x1234 produces wire bytes 34 12.
 * @param iso_id Optional ISO identifier, -1 to omit or 0 through 65535 to include.
 * @param cyclic Zero creates a linear record file; one creates a cyclic record file.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_create_record_file(df_card handle, uint32_t file, uint32_t record_size,
                                     uint32_t maximum_records, uint32_t communication,
                                     uint32_t access_rights, int32_t iso_id, uint32_t cyclic,
                                     uint32_t timeout_ms, df_error* error);

/**
 * @brief Change file communication and access rights under the current command policy.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param file Native file number, 0 through 31.
 * @param communication DF_PLAIN, DF_MAC, or DF_FULL, matching the file policy.
 * @param access_rights Packed 16-bit native access rights: read, write, RW, change from high to low
 * nibble. The integer is sent little-endian; 0x1234 produces wire bytes 34 12.
 * @param command_communication Protection for this settings change; DF_PLAIN, DF_MAC, or DF_FULL.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_change_file_settings(df_card handle, uint32_t file, uint32_t communication,
                                       uint32_t access_rights, uint32_t command_communication,
                                       uint32_t timeout_ms, df_error* error);

/**
 * @brief Create an AES transaction-MAC file with an explicit backend key.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param file Native file number, 0 through 31.
 * @param access_rights Packed 16-bit native access rights: read, write, RW, change from high to low
 * nibble. The integer is sent little-endian; 0x1234 produces wire bytes 34 12.
 * @param key Borrowed sixteen-byte AES key; never retained as caller memory.
 * @param key_size Length of key in bytes; must be sixteen.
 * @param version Version byte, 0 through 255.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_create_transaction_mac_file(df_card handle, uint32_t file, uint32_t access_rights,
                                              const uint8_t* key, size_t key_size, uint32_t version,
                                              uint32_t timeout_ms, df_error* error);

/**
 * @brief Replace an AES key using the verified current authentication selector.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param number Native EV3 key selector, 0 through 63, subject to command-specific restrictions.
 * @param new_key Borrowed sixteen-byte replacement AES key.
 * @param new_key_size Replacement-key length in bytes; must be sixteen.
 * @param version Version byte, 0 through 255.
 * @param authenticated_key Native selector matching the current verified authentication, 0
 * through 63.
 * @param old_key Borrowed old key for another key or nonzero key set; omitted for the current key.
 * @param old_key_size Zero for the current key in set zero; otherwise sixteen.
 * @param key_set Key-set selector; -1 omits the optional field, otherwise 0 through 15.
 * @param picc_master One selects PICC AES master-key encoding; zero selects application-key
 * encoding.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_change_aes_key(df_card handle, uint32_t number, const uint8_t* new_key,
                                 size_t new_key_size, uint32_t version, uint32_t authenticated_key,
                                 const uint8_t* old_key, size_t old_key_size, int32_t key_set,
                                 uint32_t picc_master, uint32_t timeout_ms, df_error* error);

/**
 * @brief Select an ISO file with CLA 00 and optionally return its FCI bytes.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param identifier ISO file identifier, 0 through 65535.
 * @param selection ISO file selection: 0 by identifier, 1 child DF, or 2 elementary file.
 * @param response ISO SELECT response: 0 for FCI or 12 to omit FCI.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_iso_select_file(df_card handle, uint32_t identifier, uint32_t selection,
                                  uint32_t response, uint32_t timeout_ms, df_buffer** output,
                                  df_error* error);

/**
 * @brief Select an ISO DF by name and replace the prior authentication context.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param name Borrowed ISO DF name, valid until the call returns.
 * @param size DF name width, one through sixteen bytes.
 * @param response ISO SELECT response: 0 for FCI or 12 to omit FCI.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_iso_select_df_name(df_card handle, const uint8_t* name, size_t size,
                                     uint32_t response, uint32_t timeout_ms, df_buffer** output,
                                     df_error* error);

/**
 * @brief Read ISO binary content, checking response CMAC when ISO AES is active.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param short_identifier -1 uses the current file; 0 through 31 supplies a short file identifier.
 * @param offset Byte offset: 0 through 32767 for the current file, or 0 through 255 with a short
 * identifier.
 * @param length Expected response bytes, 1 through 65536.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_iso_read_binary(df_card handle, int32_t short_identifier, uint32_t offset,
                                  uint32_t length, uint32_t timeout_ms, df_buffer** output,
                                  df_error* error);

/**
 * @brief Update ISO binary content using the current ISO authentication state.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param short_identifier -1 uses the current file; 0 through 31 supplies a short file identifier.
 * @param offset Byte offset: 0 through 32767 for the current file, or 0 through 255 with a short
 * identifier.
 * @param data Borrowed nonempty payload, valid until the call returns.
 * @param size Nonzero data width, at most 65535 bytes and within transport capacity.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_iso_update_binary(df_card handle, int32_t short_identifier, uint32_t offset,
                                    const uint8_t* data, size_t size, uint32_t timeout_ms,
                                    df_buffer** output, df_error* error);

/**
 * @brief Read ISO records, checking response CMAC when ISO AES is active.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param record ISO record index, 0 through 255.
 * @param short_identifier ISO short file identifier, 0 through 31.
 * @param selection ISO record selection: 4 for one record, 5 for records from the given index.
 * @param length Expected response bytes, 1 through 65536.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_iso_read_records(df_card handle, uint32_t record, uint32_t short_identifier,
                                   uint32_t selection, uint32_t length, uint32_t timeout_ms,
                                   df_buffer** output, df_error* error);

/**
 * @brief Append a record with an ISO CLA 00 command.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param short_identifier ISO short file identifier, 0 through 31.
 * @param data Borrowed nonempty payload, valid until the call returns.
 * @param size Nonzero data width, at most 65535 bytes and within transport capacity.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 */
DF_API int32_t df_iso_append_record(df_card handle, uint32_t short_identifier, const uint8_t* data,
                                    size_t size, uint32_t timeout_ms, df_buffer** output,
                                    df_error* error);

/**
 * @brief Read an ISO challenge without establishing a verified SDK session.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param length Challenge width in bytes; must be eight or sixteen.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 *
 * @note A successful challenge command does not prove card authenticity or establish response-MAC
 * state.
 */
DF_API int32_t df_iso_get_challenge(df_card handle, uint32_t length, uint32_t timeout_ms,
                                    df_buffer** output, df_error* error);

/**
 * @brief Send a caller-prepared ISO authentication cryptogram without establishing SDK trust.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param number Zero for PICC master scope, or 0 through 13 for application scope.
 * @param application Zero selects PICC master key; one selects an application key.
 * @param algorithm ISO algorithm reference: 0 context, 2 two-key TDEA, 4 three-key TDEA, or 9 AES.
 * @param data Borrowed nonempty payload, valid until the call returns.
 * @param size Cryptogram width: sixteen bytes for two-key TDEA, 32 for three-key TDEA/AES; context
 * permits either.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 *
 * @note Use df_authenticate_iso_aes for a complete verified software AES session. This command only
 * transports the supplied protocol material.
 */
DF_API int32_t df_iso_external_authenticate(df_card handle, uint32_t number, uint32_t application,
                                            uint32_t algorithm, const uint8_t* data, size_t size,
                                            uint32_t timeout_ms, df_buffer** output,
                                            df_error* error);

/**
 * @brief Send a caller-prepared ISO challenge without verifying the returned card proof.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param number Zero for PICC master scope, or 0 through 13 for application scope.
 * @param application Zero selects PICC master key; one selects an application key.
 * @param algorithm ISO algorithm reference: 0 context, 2 two-key TDEA, 4 three-key TDEA, or 9 AES.
 * @param data Borrowed nonempty payload, valid until the call returns.
 * @param size Challenge width: eight bytes for two-key TDEA, sixteen for three-key TDEA/AES;
 * context permits either.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned response buffer; must point to NULL before I/O; free with
 * df_buffer_free.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 *
 * @note Use df_authenticate_iso_aes for proof verification and retained response-MAC state. The
 * returned cryptogram remains caller-owned protocol evidence.
 */
DF_API int32_t df_iso_internal_authenticate(df_card handle, uint32_t number, uint32_t application,
                                            uint32_t algorithm, const uint8_t* data, size_t size,
                                            uint32_t timeout_ms, df_buffer** output,
                                            df_error* error);

/**
 * @brief Verify the complete ISO mutual AES proof and establish private response-MAC state.
 * @param handle Open handle returned by df_open; ownership remains with the caller.
 * @param number Zero for PICC master scope, or 0 through 13 for application scope.
 * @param application Zero selects PICC master key; one selects an application key.
 * @param key Borrowed sixteen-byte AES key; never retained as caller memory.
 * @param key_size Length of key in bytes; must be sixteen.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional per-call error storage; includes delivery outcome and original card status.
 * @return DF_OK on success, or a stable df_error_code with exact delivery evidence in error.
 *
 * @note The key must already be resolved or diversified by the caller. ISO reads verify the
 * retained response CMAC after successful mutual authentication.
 */
DF_API int32_t df_authenticate_iso_aes(df_card handle, uint32_t number, uint32_t application,
                                       const uint8_t* key, size_t key_size, uint32_t timeout_ms,
                                       df_error* error);

/**
 * @brief Resolve exactly one key and establish ISO AES before the first APDU.
 * @param handle Open managed-card handle; ownership remains with the caller.
 * @param number Native or ISO key selector in the range accepted by the operation.
 * @param application Zero selects the PICC master key; one selects an application key.
 * @param provider Validated synchronous AES-128 provider descriptor borrowed for this operation.
 * @param request Validated non-secret key reference, scope, purpose, and derivation context.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_authenticate_iso_aes_provider(df_card handle, uint32_t number,
                                                uint32_t application,
                                                const df_key_provider_v1* provider,
                                                const df_key_request_v1* request,
                                                uint32_t timeout_ms, df_error* error);

/**
 * @brief Read validated GetDFNames records as AID-LE3, ISO-ID-BE2, length, and name tuples.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned result buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_get_df_names(df_card card, uint32_t timeout_ms, df_buffer** output,
                               df_error* error);

/**
 * @brief Erase managed authentication locally without performing card I/O.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_reset_authentication(df_card card, df_error* error);

/**
 * @brief Stage a MIFARE Classic RestoreTransfer between two checked value files.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param target_file Target file required by this operation.
 * @param source_file Source file required by this operation.
 * @param communication Communication required by this operation.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_restore_transfer(df_card card, uint32_t target_file, uint32_t source_file,
                                   uint32_t communication, uint32_t timeout_ms, df_error* error);

/**
 * @brief Create one checked delegated AES application with exact issuer authorization bytes.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param aid Nonzero 24-bit native application identifier.
 * @param key_settings Documented application key-settings byte.
 * @param number_of_keys Documented AES key-count and key-type byte.
 * @param slot Sixteen-bit delegated-application slot number.
 * @param slot_version Delegated slot version byte.
 * @param quota_limit Sixteen-bit delegated storage quota.
 * @param iso_file_identifiers One when ISO file identifiers are enabled; otherwise zero.
 * @param key_settings3 Optional third key-settings byte, or -1 when absent.
 * @param iso_id Optional ISO DF identifier, or -1 when absent.
 * @param df_name Borrowed ISO DF name; NULL is accepted only when the size is zero.
 * @param df_name_size ISO DF-name size from zero through sixteen bytes.
 * @param encrypted_default_key Borrowed issuer-generated encrypted default-key record.
 * @param encrypted_default_key_size Size of the encrypted default-key record required by the
 * command.
 * @param dam_mac Borrowed eight-byte delegated-application authorization MAC.
 * @param dam_mac_size Size of dam_mac; must be eight.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_create_delegated_application(
    df_card card, uint32_t aid, uint32_t key_settings, uint32_t number_of_keys, uint32_t slot,
    uint32_t slot_version, uint32_t quota_limit, uint32_t iso_file_identifiers,
    int32_t key_settings3, int32_t iso_id, const uint8_t* df_name, size_t df_name_size,
    const uint8_t* encrypted_default_key, size_t encrypted_default_key_size, const uint8_t* dam_mac,
    size_t dam_mac_size, uint32_t timeout_ms, df_error* error);

/**
 * @brief Read and decode one delegated-application slot.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param slot Sixteen-bit delegated-application slot number.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Initialized ABI-v1 descriptor that receives the decoded slot information.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_get_delegated_application_info(df_card card, uint32_t slot, uint32_t timeout_ms,
                                                 df_delegated_application_info_v1* output,
                                                 df_error* error);

/**
 * @brief Delete one delegated application using an exact issuer-generated DAM MAC.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param aid Nonzero 24-bit native application identifier.
 * @param dam_mac Borrowed eight-byte delegated-application authorization MAC.
 * @param dam_mac_size Size of dam_mac; must be eight.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_delete_delegated_application(df_card card, uint32_t aid, const uint8_t* dam_mac,
                                               size_t dam_mac_size, uint32_t timeout_ms,
                                               df_error* error);

/**
 * @brief Read UID and optional four-byte NUID with one explicit documented request option.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param option One documented UID request selector: omitted, UID only, or UID with NUID.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned result buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_get_card_uid_variant(df_card card, uint32_t option, uint32_t timeout_ms,
                                       df_buffer** output, df_error* error);

/**
 * @brief Set documented PICC option-zero flags using a versioned descriptor.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param configuration Validated versioned configuration descriptor borrowed for this call.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_set_picc_configuration(df_card card,
                                         const df_picc_configuration_v1* configuration,
                                         uint32_t timeout_ms, df_error* error);

/**
 * @brief Set the exact nine-byte option-five capability record.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param capabilities Borrowed exact nine-byte PICC capability record.
 * @param capabilities_size Size of capabilities; must be nine.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_set_capability_configuration(df_card card, const uint8_t* capabilities,
                                               size_t capabilities_size, uint32_t timeout_ms,
                                               df_error* error);

/**
 * @brief Set the default application AES key and its version.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param key Borrowed AES-128 key bytes; caller memory is never retained.
 * @param key_size Size of key in bytes; AES entry points require exactly sixteen.
 * @param key_version AES key version byte.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_set_default_aes_key(df_card card, const uint8_t* key, size_t key_size,
                                      uint32_t key_version, uint32_t timeout_ms, df_error* error);

/**
 * @brief Resolve exactly one replacement key and set the default application AES key.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param provider Validated synchronous AES-128 provider descriptor borrowed for this operation.
 * @param request Validated non-secret key reference, scope, purpose, and derivation context.
 * @param key_version AES key version byte.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_set_default_aes_key_provider(df_card card, const df_key_provider_v1* provider,
                                               const df_key_request_v1* request,
                                               uint32_t key_version, uint32_t timeout_ms,
                                               df_error* error);

/**
 * @brief Set a complete two-through-twenty-byte ATS including its length byte.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param ats Borrowed complete ATS including its leading length byte.
 * @param ats_size Complete ATS size from two through twenty bytes.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_set_ats(df_card card, const uint8_t* ats, size_t ats_size, uint32_t timeout_ms,
                          df_error* error);

/**
 * @brief Set the two-byte user ATQA value.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param atqa Two-byte user ATQA value.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_set_atqa(df_card card, uint32_t atqa, uint32_t timeout_ms, df_error* error);

/**
 * @brief Execute the documented ISO UPDATE RECORD 0xDC or 0xDD variant.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param instruction ISO UPDATE RECORD instruction byte, either 0xDC or 0xDD.
 * @param record ISO record number accepted by the selected instruction variant.
 * @param short_identifier ISO short file identifier accepted by the selected instruction variant.
 * @param reference_control ISO record reference-control byte.
 * @param data Borrowed input bytes; NULL is accepted only when data_size is zero.
 * @param data_size Number of borrowed input bytes.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned result buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_iso_update_record(df_card card, uint32_t instruction, uint32_t record,
                                    uint32_t short_identifier, uint32_t reference_control,
                                    const uint8_t* data, size_t data_size, uint32_t timeout_ms,
                                    df_buffer** output, df_error* error);

/**
 * @brief Execute one through 128 checked mutations and one explicit commit under one lock.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param operations Borrowed array of validated versioned transaction operations.
 * @param operation_count Number of transaction operations; must be one through 128.
 * @param return_mac One to request commit transaction-MAC data; otherwise zero.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param output Receives an owned result buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_execute_transaction(df_card card, const df_transaction_operation_v1* operations,
                                      size_t operation_count, uint32_t return_mac,
                                      uint32_t timeout_ms, df_buffer** output, df_error* error);

/**
 * @brief Resolve new and optional old AES keys before changing one native key.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param number Native or ISO key selector in the range accepted by the operation.
 * @param new_key_provider Provider used to resolve the replacement AES-128 key before card I/O.
 * @param new_key_request Request describing the replacement key and its non-secret context.
 * @param version Key or key-set version byte required by the selected operation.
 * @param authenticated_key Currently authenticated key number used to select change-key encoding.
 * @param old_key_provider Optional provider used to resolve the current AES-128 key.
 * @param old_key_request Optional request describing the current key and its non-secret context.
 * @param key_set Key-set selector, or -1 when the operation does not target a key set.
 * @param picc_master One for PICC master-key semantics; zero for application-key semantics.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_change_aes_key_provider(
    df_card card, uint32_t number, const df_key_provider_v1* new_key_provider,
    const df_key_request_v1* new_key_request, uint32_t version, uint32_t authenticated_key,
    const df_key_provider_v1* old_key_provider, const df_key_request_v1* old_key_request,
    int32_t key_set, uint32_t picc_master, uint32_t timeout_ms, df_error* error);

/**
 * @brief Resolve one AES key before creating a transaction-MAC file.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param file Native file number in the documented range.
 * @param access_rights Packed four-nibble native access-rights value.
 * @param provider Validated synchronous AES-128 provider descriptor borrowed for this operation.
 * @param request Validated non-secret key reference, scope, purpose, and derivation context.
 * @param version Key or key-set version byte required by the selected operation.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_create_transaction_mac_file_provider(
    df_card card, uint32_t file, uint32_t access_rights, const df_key_provider_v1* provider,
    const df_key_request_v1* request, uint32_t version, uint32_t timeout_ms, df_error* error);

#ifdef __cplusplus
}
#endif
#endif
