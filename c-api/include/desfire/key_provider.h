/**
 * @file key_provider.h
 * @brief Versioned synchronous AES-128 key-provider contract.
 */
#ifndef DESFIRE_KEY_PROVIDER_H
#define DESFIRE_KEY_PROVIDER_H

#include <desfire/base.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Resolve a key for card authentication. */
#define DF_KEY_PURPOSE_AUTHENTICATION 0u
/** @brief Resolve the current key needed to authorize a key replacement. */
#define DF_KEY_PURPOSE_CURRENT_KEY 1u
/** @brief Resolve a replacement key to install on the card. */
#define DF_KEY_PURPOSE_REPLACEMENT_KEY 2u
/** @brief Resolve a delegated-application issuer or default key. */
#define DF_KEY_PURPOSE_DELEGATED_APPLICATION 3u
/** @brief Resolve an application transaction-MAC key. */
#define DF_KEY_PURPOSE_TRANSACTION_MAC 4u
/** @brief Resolve a key for a stateless offline cryptographic operation. */
#define DF_KEY_PURPOSE_OFFLINE_OPERATION 5u
/** @brief Native Standard AES authentication profile. */
#define DF_AUTH_PROFILE_STANDARD_AES 0u
/** @brief Native EV2 First AES authentication profile. */
#define DF_AUTH_PROFILE_EV2_FIRST 1u
/** @brief Native EV2 NonFirst AES authentication profile. */
#define DF_AUTH_PROFILE_EV2_NON_FIRST 2u
/** @brief ISO/IEC 7816 mutual AES authentication profile. */
#define DF_AUTH_PROFILE_ISO_AES 3u
/** @brief Native application or PICC key scope. */
#define DF_KEY_SCOPE_NATIVE 0u
/** @brief ISO PICC master-key scope. */
#define DF_KEY_SCOPE_ISO_PICC 1u
/** @brief ISO application-key scope. */
#define DF_KEY_SCOPE_ISO_APPLICATION 2u
/** @brief Sentinel used by optional unsigned descriptor fields. */
#define DF_OPTION_ABSENT UINT32_MAX

/**
 * @brief Report whether a caller-owned key-resolution cancellation request is active.
 * @param context Borrowed caller-owned cancellation context.
 * @return Nonzero when cancellation is requested; zero otherwise.
 */
typedef uint32_t (*df_key_cancelled_fn)(void* context);

/**
 * @brief ABI-v1 non-secret metadata for exactly one key resolution.
 *
 * Byte pointers are borrowed until the authentication call returns. reference must contain one
 * through 1024 bytes. Diversification and user context together are limited to 65536 bytes.
 * application_id and key_set use DF_OPTION_ABSENT when omitted. Reserved words must be zero.
 */
typedef struct df_key_request_v1 {
    uint32_t struct_size;             /**< sizeof(df_key_request_v1). */
    uint32_t abi_version;             /**< DF_ABI_VERSION. */
    uint32_t purpose;                 /**< DF_KEY_PURPOSE_AUTHENTICATION. */
    uint32_t authentication_profile;  /**< One DF_AUTH_PROFILE_* value, or DF_OPTION_ABSENT. */
    uint32_t scope;                   /**< One DF_KEY_SCOPE_* value. */
    uint32_t key_number;              /**< Native or ISO key selector. */
    uint32_t application_id;          /**< 24-bit AID or DF_OPTION_ABSENT. */
    uint32_t key_set;                 /**< 0..15 or DF_OPTION_ABSENT. */
    const uint8_t* reference;         /**< Non-secret provider identifier. */
    size_t reference_size;            /**< One through 1024 bytes. */
    const uint8_t* diversification;   /**< Construction-specific bytes. */
    size_t diversification_size;      /**< Zero through 65536 bytes. */
    const uint8_t* user_context;      /**< Provider routing metadata. */
    size_t user_context_size;         /**< Zero through 65536 bytes. */
    void* cancellation_context;       /**< Borrowed context for is_cancelled. */
    df_key_cancelled_fn is_cancelled; /**< Optional cooperative cancellation query. */
    uint64_t reserved[DF_ABI_RESERVED_WORDS]; /**< Must be zero. */
} df_key_request_v1;

/**
 * @brief Resolve one exportable AES-128 key into SDK-owned storage.
 * @param context Retained provider context.
 * @param request Validated non-secret request borrowed for this call.
 * @param key Writable SDK-owned output with capacity exactly sixteen.
 * @param capacity Output capacity in bytes.
 * @param written Receives exactly sixteen on success.
 * @param error Provider failure evidence; diagnostics must not contain key material.
 * @return DF_OK or a stable df_error_code before card I/O.
 */
typedef int32_t (*df_key_resolve_fn)(void* context, const df_key_request_v1* request, uint8_t* key,
                                     size_t capacity, size_t* written, df_error* error);

/**
 * @brief Retain one provider context for the duration of an authentication call.
 * @param context Caller-owned provider context to retain.
 */
typedef void (*df_key_provider_retain_fn)(void* context);

/**
 * @brief Release one matching provider-context retain after resolution returns.
 * @param context Previously retained caller-owned provider context.
 */
typedef void (*df_key_provider_release_fn)(void* context);

/** @brief ABI-v1 synchronous exportable AES-128 key provider. */
typedef struct df_key_provider_v1 {
    uint32_t struct_size;                     /**< sizeof(df_key_provider_v1). */
    uint32_t abi_version;                     /**< DF_ABI_VERSION. */
    void* context;                            /**< Caller-owned provider state. */
    df_key_resolve_fn resolve;                /**< Mandatory exactly-once resolver. */
    df_key_provider_retain_fn retain;         /**< Optional context retain callback. */
    df_key_provider_release_fn release;       /**< Optional paired release callback. */
    uint64_t reserved[DF_ABI_RESERVED_WORDS]; /**< Must be zero. */
} df_key_provider_v1;

/** @brief Public metadata returned only after verified EV2 authentication. */
typedef struct df_authentication_info_v1 {
    uint32_t struct_size;                     /**< sizeof(df_authentication_info_v1). */
    uint32_t abi_version;                     /**< DF_ABI_VERSION. */
    uint8_t transaction_identifier[4];        /**< EV2 transaction identifier. */
    uint8_t picc_capabilities[6];             /**< Verified PICC capability record. */
    uint8_t pcd_capabilities[6];              /**< Verified padded PCD capability echo. */
    uint64_t reserved[DF_ABI_RESERVED_WORDS]; /**< Written as zero by the SDK. */
} df_authentication_info_v1;

#ifdef __cplusplus
}
#endif
#endif
