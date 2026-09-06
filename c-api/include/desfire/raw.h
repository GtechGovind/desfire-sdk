/**
 * @file raw.h
 * @brief Expert raw native, secure-native, and true ISO channel contracts.
 */
#ifndef DESFIRE_RAW_H
#define DESFIRE_RAW_H

#include <desfire/key_provider.h>
#include <desfire/transport.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Permit exactly one native additional-frame continuation. */
#define DF_RAW_SINGLE_CONTINUATION 0x00000001u
/** @brief Sentinel requesting automatic native first-frame payload sizing. */
#define DF_RAW_NO_FIRST_FRAME_BOUNDARY ((size_t)-1)
/** @brief Select ISO APDU length encoding from the command lengths. */
#define DF_ISO_LENGTH_AUTOMATIC 0u
/** @brief Require short ISO APDU length encoding. */
#define DF_ISO_LENGTH_SHORT 1u
/** @brief Require extended ISO APDU length encoding. */
#define DF_ISO_LENGTH_EXTENDED 2u
/** @brief Indicate that no raw secure-session profile is selected. */
#define DF_SECURE_PROFILE_NONE 0u
/** @brief Select the raw Standard AES secure-session profile. */
#define DF_SECURE_PROFILE_STANDARD_AES 1u
/** @brief Select the raw EV2 secure-session profile. */
#define DF_SECURE_PROFILE_EV2 2u

/** @brief Versioned unprotected native logical-command descriptor. */
typedef struct df_native_request_v1 {
    uint32_t struct_size;         /**< sizeof(df_native_request_v1). */
    uint32_t abi_version;         /**< DF_ABI_VERSION. */
    uint32_t framing;             /**< DF_NATIVE or DF_ISO_WRAPPED; must match the transport. */
    uint32_t command;             /**< Native instruction byte, 0 through 255. */
    const uint8_t* data;          /**< Borrowed status-free logical command data. */
    size_t data_size;             /**< Data bytes, bounded to 16 MiB. */
    size_t maximum_response;      /**< Positive aggregate status-free response bound. */
    size_t first_frame_data_size; /**< Exact first payload or DF_RAW_NO_FIRST_FRAME_BOUNDARY. */
    uint32_t flags;               /**< DF_RAW_SINGLE_CONTINUATION or zero. */
    uint32_t reserved32;          /**< Must be zero. */
    uint64_t reserved[DF_ABI_RESERVED_WORDS]; /**< Must be zero. */
} df_native_request_v1;

/** @brief Versioned secure-native command layout with no inferred command semantics. */
typedef struct df_native_secure_request_v1 {
    uint32_t struct_size;           /**< sizeof(df_native_secure_request_v1). */
    uint32_t abi_version;           /**< DF_ABI_VERSION. */
    uint32_t profile;               /**< DF_SECURE_PROFILE_STANDARD_AES or DF_SECURE_PROFILE_EV2. */
    uint32_t command;               /**< Native instruction byte. */
    const uint8_t* header;          /**< Borrowed clear authenticated header. */
    size_t header_size;             /**< Header bytes. */
    const uint8_t* data;            /**< Borrowed command data. */
    size_t data_size;               /**< Data bytes. */
    uint32_t request_communication; /**< DF_PLAIN, DF_MAC, or DF_FULL. */
    uint32_t response_communication; /**< DF_PLAIN, DF_MAC, or DF_FULL. */
    size_t minimum_response;         /**< Minimum verified clear response bytes. */
    size_t maximum_response;         /**< Maximum verified clear response bytes. */
    size_t first_frame_data_size;    /**< Prepared-wire boundary or no-boundary sentinel. */
    uint32_t flags;                  /**< DF_RAW_SINGLE_CONTINUATION or zero. */
    uint32_t invalidates_session;    /**< One erases the active raw session after success. */
    uint64_t reserved[DF_ABI_RESERVED_WORDS]; /**< Must be zero. */
} df_native_secure_request_v1;

/** @brief Versioned true ISO/IEC 7816 command APDU descriptor. */
typedef struct df_iso_apdu_v1 {
    uint32_t struct_size;     /**< sizeof(df_iso_apdu_v1). */
    uint32_t abi_version;     /**< DF_ABI_VERSION. */
    uint32_t cla;             /**< Class byte. */
    uint32_t ins;             /**< Instruction byte. */
    uint32_t p1;              /**< First parameter byte. */
    uint32_t p2;              /**< Second parameter byte. */
    const uint8_t* data;      /**< Borrowed APDU data. */
    size_t data_size;         /**< Zero through 65535 bytes. */
    uint32_t has_le;          /**< Zero omits Le; one uses le. */
    uint32_t le;              /**< Literal expected length, 1 through 65536. */
    uint32_t length_encoding; /**< One DF_ISO_LENGTH_* value. */
    uint32_t correct_length;  /**< Permit one 6Cxx resend only when caller proves safety. */
    size_t maximum_response;  /**< Positive aggregate data bound. */
    size_t maximum_frames;    /**< Positive continuation-frame bound. */
    uint64_t reserved[DF_ABI_RESERVED_WORDS]; /**< Must be zero. */
} df_iso_apdu_v1;

/**
 * @brief Open an independent raw channel and retain its transport context.
 * @param transport Validated transport descriptor borrowed for the duration of this call.
 * @param out Non-NULL destination initially set to zero; receives the new raw-channel handle.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_raw_open(const df_transport_v1* transport, df_raw_channel* out, df_error* error);

/**
 * @brief Close a raw channel; DF_BUSY leaves it open and retained.
 * @param channel Open raw-channel handle; ownership remains with the caller.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_raw_close(df_raw_channel channel, df_error* error);

/**
 * @brief Reset a raw transport and erase all raw secure sessions.
 * @param channel Open raw-channel handle; ownership remains with the caller.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_raw_reset(df_raw_channel channel, df_error* error);

/**
 * @brief Request raw-channel cancellation without waiting for its operation lock.
 * @param channel Open raw-channel handle; ownership remains with the caller.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_raw_cancel(df_raw_channel channel, df_error* error);

/**
 * @brief Report external card-state replacement to a raw channel.
 * @param channel Open raw-channel handle; ownership remains with the caller.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_raw_notify_state_change(df_raw_channel channel, df_error* error);

/**
 * @brief Exchange exactly one native physical frame and preserve its status byte.
 * @param channel Open raw-channel handle; ownership remains with the caller.
 * @param framing Native framing selector, DF_NATIVE or DF_ISO_WRAPPED.
 * @param command Native instruction byte from zero through 255.
 * @param data Borrowed input bytes; NULL is accepted only when data_size is zero.
 * @param data_size Number of borrowed input bytes.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param native_status Non-NULL destination for the exact final native status byte.
 * @param response Receives an owned response buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_raw_native_frame(df_raw_channel channel, uint32_t framing, uint32_t command,
                                   const uint8_t* data, size_t data_size, uint32_t timeout_ms,
                                   uint32_t* native_status, df_buffer** response, df_error* error);

/**
 * @brief Exchange a bounded native logical command including explicitly requested AF chaining.
 * @param channel Open raw-channel handle; ownership remains with the caller.
 * @param request Validated versioned native request with explicit framing, bounds, and chaining.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param native_status Non-NULL destination for the exact final native status byte.
 * @param response Receives an owned response buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_raw_native_exchange(df_raw_channel channel, const df_native_request_v1* request,
                                      uint32_t timeout_ms, uint32_t* native_status,
                                      df_buffer** response, df_error* error);

/**
 * @brief Exchange one true ISO APDU and preserve the exact final 16-bit status word.
 * @param channel Open raw-channel handle; ownership remains with the caller.
 * @param request Validated versioned APDU with explicit length and continuation policy.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param iso_status Non-NULL destination for the exact final ISO status word.
 * @param response Receives an owned response buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_raw_iso_exchange(df_raw_channel channel, const df_iso_apdu_v1* request,
                                   uint32_t timeout_ms, uint32_t* iso_status, df_buffer** response,
                                   df_error* error);

/**
 * @brief Install a Standard AES session on a native raw channel using one exact key.
 * @param channel Open raw-channel handle; ownership remains with the caller.
 * @param key_number Native or ISO key selector in the range accepted by the selected authentication
 * profile.
 * @param key Borrowed AES-128 key bytes; caller memory is never retained.
 * @param key_size Size of key in bytes; AES entry points require exactly sixteen.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_raw_authenticate_standard_aes(df_raw_channel channel, uint32_t key_number,
                                                const uint8_t* key, size_t key_size,
                                                uint32_t timeout_ms, df_error* error);

/**
 * @brief Resolve exactly one key and install a Standard AES raw session.
 * @param channel Open raw-channel handle; ownership remains with the caller.
 * @param key_number Native or ISO key selector in the range accepted by the selected authentication
 * profile.
 * @param provider Validated synchronous AES-128 provider descriptor borrowed for this operation.
 * @param request Validated non-secret key reference, scope, purpose, and derivation context.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_raw_authenticate_standard_aes_provider(df_raw_channel channel,
                                                         uint32_t key_number,
                                                         const df_key_provider_v1* provider,
                                                         const df_key_request_v1* request,
                                                         uint32_t timeout_ms, df_error* error);

/**
 * @brief Install EV2 First on a native raw channel and return verified public metadata.
 * @param channel Open raw-channel handle; ownership remains with the caller.
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
DF_API int32_t df_raw_authenticate_ev2_first_aes(df_raw_channel channel, uint32_t key_number,
                                                 const uint8_t* key, size_t key_size,
                                                 const uint8_t* pcd_capabilities,
                                                 size_t pcd_capabilities_size, uint32_t timeout_ms,
                                                 df_authentication_info_v1* out, df_error* error);

/**
 * @brief Resolve one key and install EV2 First with zero through six capability bytes.
 * @param channel Open raw-channel handle; ownership remains with the caller.
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
DF_API int32_t df_raw_authenticate_ev2_first_aes_provider(
    df_raw_channel channel, uint32_t key_number, const df_key_provider_v1* provider,
    const df_key_request_v1* request, const uint8_t* pcd_capabilities, size_t pcd_capabilities_size,
    uint32_t timeout_ms, df_authentication_info_v1* out, df_error* error);

/**
 * @brief Replace a raw EV2 session through NonFirst while preserving TI and counter.
 * @param channel Open raw-channel handle; ownership remains with the caller.
 * @param key_number Native or ISO key selector in the range accepted by the selected authentication
 * profile.
 * @param key Borrowed AES-128 key bytes; caller memory is never retained.
 * @param key_size Size of key in bytes; AES entry points require exactly sixteen.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param out Initialized ABI-v1 descriptor that receives verified EV2 authentication metadata.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_raw_authenticate_ev2_non_first_aes(df_raw_channel channel, uint32_t key_number,
                                                     const uint8_t* key, size_t key_size,
                                                     uint32_t timeout_ms,
                                                     df_authentication_info_v1* out,
                                                     df_error* error);

/**
 * @brief Resolve exactly one key and replace a raw EV2 session through NonFirst.
 * @param channel Open raw-channel handle; ownership remains with the caller.
 * @param key_number Native or ISO key selector in the range accepted by the selected authentication
 * profile.
 * @param provider Validated synchronous AES-128 provider descriptor borrowed for this operation.
 * @param request Validated non-secret key reference, scope, purpose, and derivation context.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param out Initialized ABI-v1 descriptor that receives verified EV2 authentication metadata.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_raw_authenticate_ev2_non_first_aes_provider(
    df_raw_channel channel, uint32_t key_number, const df_key_provider_v1* provider,
    const df_key_request_v1* request, uint32_t timeout_ms, df_authentication_info_v1* out,
    df_error* error);

/**
 * @brief Establish a verified ISO mutual AES session on an ISO raw channel.
 * @param channel Open raw-channel handle; ownership remains with the caller.
 * @param key_number Native or ISO key selector in the range accepted by the selected authentication
 * profile.
 * @param application Zero selects the PICC master key; one selects an application key.
 * @param key Borrowed AES-128 key bytes; caller memory is never retained.
 * @param key_size Size of key in bytes; AES entry points require exactly sixteen.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_raw_authenticate_iso_aes(df_raw_channel channel, uint32_t key_number,
                                           uint32_t application, const uint8_t* key,
                                           size_t key_size, uint32_t timeout_ms, df_error* error);

/**
 * @brief Resolve exactly one key and establish ISO mutual AES on an ISO raw channel.
 * @param channel Open raw-channel handle; ownership remains with the caller.
 * @param key_number Native or ISO key selector in the range accepted by the selected authentication
 * profile.
 * @param application Zero selects the PICC master key; one selects an application key.
 * @param provider Validated synchronous AES-128 provider descriptor borrowed for this operation.
 * @param request Validated non-secret key reference, scope, purpose, and derivation context.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_raw_authenticate_iso_aes_provider(df_raw_channel channel, uint32_t key_number,
                                                    uint32_t application,
                                                    const df_key_provider_v1* provider,
                                                    const df_key_request_v1* request,
                                                    uint32_t timeout_ms, df_error* error);

/**
 * @brief Execute a checked ISO data command or EF selection through the active raw ISO AES session.
 *
 * The APDU must exactly match a supported checked SELECT EF, READ/UPDATE BINARY,
 * READ/APPEND/UPDATE RECORD command. Arbitrary instructions and DF selection fail before I/O.
 * @param channel Open raw-channel handle; ownership remains with the caller.
 * @param request Validated versioned APDU accepted by the checked secure ISO command factory.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param iso_status Non-NULL destination for the exact final ISO status word.
 * @param response Receives an owned response buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_raw_iso_secure_exchange(df_raw_channel channel, const df_iso_apdu_v1* request,
                                          uint32_t timeout_ms, uint32_t* iso_status,
                                          df_buffer** response, df_error* error);

/**
 * @brief Execute one explicit secure-native request using its selected active raw session.
 * @param channel Open raw-channel handle; ownership remains with the caller.
 * @param request Validated secure request with explicit header, data, modes, and response bounds.
 * @param timeout_ms Positive timeout budget in milliseconds for the complete logical operation.
 * @param response Receives an owned response buffer; must point to NULL before the call.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_raw_native_secure_exchange(df_raw_channel channel,
                                             const df_native_secure_request_v1* request,
                                             uint32_t timeout_ms, df_buffer** response,
                                             df_error* error);

#ifdef __cplusplus
}
#endif
#endif
