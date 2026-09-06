/**
 * @file base.h
 * @brief Stable C99 scalar, error, and owned-buffer contracts for DESFire EV3.
 */
#ifndef DESFIRE_BASE_H
#define DESFIRE_BASE_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#if defined(DESFIRE_C_EXPORTS)
/** @brief Export one stable C ABI symbol from a Windows shared library build. */
#define DF_API __declspec(dllexport)
#else
/** @brief Import one stable C ABI symbol from a Windows shared library build. */
#define DF_API __declspec(dllimport)
#endif
#else
/** @brief Export one stable C ABI symbol with default ELF or Mach-O visibility. */
#define DF_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Current stable descriptor and exported-symbol ABI revision. */
#define DF_ABI_VERSION 1u
/** @brief Reserved 64-bit words carried by every extensible ABI-v1 descriptor. */
#define DF_ABI_RESERVED_WORDS 8u

/** @brief Direct native command framing selector. */
#define DF_NATIVE 0u
/** @brief ISO-wrapped native command framing selector. */
#define DF_ISO_WRAPPED 1u
/** @brief Plain communication mode without command encryption or a secure MAC. */
#define DF_PLAIN 0u
/** @brief Authenticated communication mode using a secure-message MAC. */
#define DF_MAC 1u
/** @brief Full communication mode using secure-message encryption and authentication. */
#define DF_FULL 3u
/** @brief Delivery outcome proving that no card frame was transmitted. */
#define DF_NOT_SENT 0u
/** @brief Delivery outcome proving that the card rejected the operation. */
#define DF_REJECTED 1u
/** @brief Delivery outcome proving that the card accepted the complete operation. */
#define DF_SUCCEEDED 2u
/** @brief Delivery outcome for a mutation whose final card state is uncertain. */
#define DF_UNKNOWN 3u

/** @brief Opaque managed-card handle; closed identifiers are never reused. */
typedef uint64_t df_card;

/** @brief Opaque raw-channel handle; closed identifiers are never reused. */
typedef uint64_t df_raw_channel;

/** @brief Opaque owned byte buffer returned by the ABI. */
typedef struct df_buffer df_buffer;

/** @brief Stable per-call failure evidence with a fixed 256-byte ABI width. */
typedef struct df_error {
    uint32_t code;          /**< Stable df_error_code value. */
    uint32_t outcome;       /**< Stable delivery outcome. */
    uint16_t device_status; /**< Native byte or ISO status word when available. */
    char message[246];      /**< NUL-terminated, secret-free diagnostic. */
} df_error;

/** @brief Stable error codes returned directly by every fallible C function. */
enum df_error_code {
    DF_OK = 0,                 /**< Operation completed successfully. */
    DF_INVALID_ARGUMENT = 1,   /**< Caller input or descriptor validation failed. */
    DF_TRANSPORT = 2,          /**< Reader transport reported a failure. */
    DF_CARD_REMOVED = 3,       /**< Card removal interrupted the operation. */
    DF_TIMEOUT = 4,            /**< Complete operation exceeded its timeout budget. */
    DF_CANCELLED = 5,          /**< Caller cancellation interrupted the operation. */
    DF_MALFORMED_RESPONSE = 6, /**< Card response violated the checked wire contract. */
    DF_CARD_REJECTED = 7,      /**< Card returned a documented rejecting status. */
    DF_AUTHENTICATION = 8,     /**< Authentication failed or was rejected. */
    DF_INTEGRITY = 9,          /**< MAC, padding, or other integrity validation failed. */
    DF_UNSUPPORTED = 10,       /**< Requested operation or combination is unsupported. */
    DF_STALE_HANDLE = 11,      /**< Opaque handle is closed or unknown. */
    DF_BUSY = 12,              /**< Same-card operation or callback reentry is active. */
    DF_SESSION_INVALID = 13,   /**< Required secure session is absent or stale. */
    DF_COUNTER_EXHAUSTED = 14, /**< Secure-message command counter cannot advance safely. */
    DF_BUFFER_TOO_SMALL = 15,  /**< Caller or transport storage cannot hold required bytes. */
    DF_CRYPTO = 16,            /**< Cryptographic provider or primitive failed. */
    DF_INTERNAL = 17           /**< Unexpected internal failure contained at the C boundary. */
};

/**
 * @brief Return the ABI revision implemented by the loaded library.
 * @return The stable ABI revision implemented by the loaded library.
 */
DF_API uint32_t df_abi_version(void);

/**
 * @brief Borrow the NUL-terminated SHA-256 of the exact API manifest used for this build.
 * @return Borrowed process-lifetime NUL-terminated lowercase SHA-256 text.
 */
DF_API const char* df_manifest_sha256(void);

/**
 * @brief Read the byte count owned by a buffer, or zero for NULL.
 * @param buffer Owned C ABI buffer, or NULL where explicitly accepted.
 * @return The number of owned bytes, or zero when buffer is NULL.
 */
DF_API size_t df_buffer_size(const df_buffer* buffer);

/**
 * @brief Borrow immutable bytes until the matching buffer is freed.
 * @param buffer Owned C ABI buffer, or NULL where explicitly accepted.
 * @return Borrowed immutable bytes valid until df_buffer_free, or NULL for a NULL buffer.
 */
DF_API const uint8_t* df_buffer_data(const df_buffer* buffer);

/**
 * @brief Wipe and release an owned buffer; NULL is accepted.
 * @param buffer Owned C ABI buffer, or NULL where explicitly accepted.
 */
DF_API void df_buffer_free(df_buffer* buffer);

#ifdef __cplusplus
}
#endif
#endif
