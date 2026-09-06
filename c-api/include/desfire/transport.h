/**
 * @file transport.h
 * @brief Versioned retained transport callbacks and handle lifecycle.
 */
#ifndef DESFIRE_TRANSPORT_H
#define DESFIRE_TRANSPORT_H

#include <desfire/base.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Retain one caller context before df_open or df_raw_open returns.
 * @param context Caller-owned callback context to retain.
 */
typedef void (*df_context_retain_fn)(void* context);

/**
 * @brief Release one prior retain after the final callback lease ends.
 * @param context Previously retained caller-owned callback context.
 */
typedef void (*df_context_release_fn)(void* context);

/**
 * @brief Send exactly one physical frame without an implicit retry.
 * @param context Retained connection context.
 * @param tx Borrowed complete frame valid only during this callback.
 * @param tx_size Request bytes.
 * @param rx Writable SDK-owned response storage.
 * @param capacity Maximum response bytes.
 * @param received Actual response bytes, never greater than capacity.
 * @param timeout_ms Remaining positive operation budget.
 * @param error Failure evidence; use DF_UNKNOWN when delivery is uncertain.
 * @return DF_OK or a stable df_error_code.
 */
typedef int32_t (*df_exchange_fn)(void* context, const uint8_t* tx, size_t tx_size, uint8_t* rx,
                                  size_t capacity, size_t* received, uint32_t timeout_ms,
                                  df_error* error);

/**
 * @brief Request cancellation independently of the active exchange lock.
 * @param context Retained connection context whose active exchange should be interrupted.
 */
typedef void (*df_cancel_fn)(void* context);

/**
 * @brief Reset physical card state and report exact failure evidence.
 * @param context Retained connection context to reset.
 * @param error Destination for redacted reset failure and delivery evidence.
 * @return DF_OK or a stable df_error_code.
 */
typedef int32_t (*df_reset_fn)(void* context, df_error* error);

/**
 * @brief ABI-v1 transport descriptor copied by open functions.
 *
 * Set struct_size, abi_version, framing, all three limits, context, and exchange. retain and
 * release must either both be NULL for externally managed context or both be non-NULL. Reserved
 * words must be zero. The SDK calls retain once and defers release until every callback returns.
 */
typedef struct df_transport_v1 {
    uint32_t struct_size;                     /**< sizeof(df_transport_v1). */
    uint32_t abi_version;                     /**< DF_ABI_VERSION. */
    uint32_t framing;                         /**< DF_NATIVE or DF_ISO_WRAPPED. */
    uint32_t max_transmit;                    /**< Maximum encoded request bytes. */
    uint32_t max_receive;                     /**< Maximum encoded response bytes. */
    uint32_t max_native_frame;                /**< Native opcode plus payload capacity. */
    void* context;                            /**< Caller context retained as declared below. */
    df_exchange_fn exchange;                  /**< Mandatory one-frame callback. */
    df_cancel_fn cancel;                      /**< Optional concurrent cancellation callback. */
    df_reset_fn reset;                        /**< Optional reset callback. */
    df_context_retain_fn retain;              /**< Optional context retain callback. */
    df_context_release_fn release;            /**< Optional paired context release callback. */
    uint64_t reserved[DF_ABI_RESERVED_WORDS]; /**< Must be zero. */
} df_transport_v1;

/** @brief Source-compatible ABI-v1 descriptor name. */
typedef df_transport_v1 df_transport;

/**
 * @brief Open a managed Card and retain its callback context without card I/O.
 * @param transport Validated transport descriptor borrowed for the duration of this call.
 * @param out Non-NULL destination initially set to zero; receives the new managed-card handle.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_open(const df_transport_v1* transport, df_card* out, df_error* error);

/**
 * @brief Close a managed Card; DF_BUSY leaves it open and retained.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_close(df_card card, df_error* error);

/**
 * @brief Reset the managed transport and erase all local session state.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_reset(df_card card, df_error* error);

/**
 * @brief Request cancellation without waiting for the managed operation lock.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_cancel(df_card card, df_error* error);

/**
 * @brief Report external card-state replacement and invalidate managed state.
 * @param card Open managed-card handle; ownership remains with the caller.
 * @param error Optional destination for redacted error, status, and delivery-outcome evidence.
 * @return DF_OK on success; otherwise a stable df_error_code with failure evidence in error.
 */
DF_API int32_t df_notify_state_change(df_card card, df_error* error);

#ifdef __cplusplus
}
#endif
#endif
