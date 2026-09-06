/**
 * @file
 * @brief Failure categories and execution evidence used across SDK boundaries.
 */
#pragma once
#include <cstdint>
#include <string>
#include <utility>

namespace desfire {

    /**
     * @brief Stable SDK failure categories. Card status bytes remain available separately.
     */
    enum class ErrorCode : std::uint32_t {
        /** A caller-supplied value violates the local API contract. */
        invalid_argument = 1,

        /** Reader or transport infrastructure failed. */
        transport,

        /** Removal or reset evidence invalidated the active card connection. */
        card_removed,

        /** An operation exceeded its requested deadline. */
        timeout,

        /** Cancellation was observed before the operation completed. */
        cancelled,

        /** Untrusted response bytes violate their protocol shape. */
        malformed_response,

        /** The card returned a documented non-success status. */
        card_rejected,

        /** Mutual authentication or its card proof failed. */
        authentication,

        /** Cryptographic integrity validation failed. */
        integrity,

        /** The requested capability is unavailable in this implementation. */
        unsupported,

        /** The handle refers to an invalidated connection generation. */
        stale_handle,

        /** Another operation already owns the serialized connection. */
        busy,

        /** Required authentication state is absent or invalidated. */
        session_invalid,

        /** A protected-message counter cannot advance safely. */
        counter_exhausted,

        /** Caller-provided output storage cannot hold the complete result. */
        buffer_too_small,

        /** A cryptographic primitive or provider failed. */
        crypto,

        /** An unexpected local implementation failure occurred. */
        internal
    };

    /**
     * @brief Evidence about command execution, not a recommendation to retry.
     *
     * `not_sent` means no command was delivered; `rejected` means the peer rejected it;
     * `succeeded` means execution is confirmed. `unknown` means a mutation may already
     * have taken effect. Recovery must reconcile state instead of blindly retrying.
     */
    enum class Outcome : std::uint8_t {
        /** Available evidence shows that no command reached the peer. */
        not_sent,

        /** The peer received and explicitly rejected the command. */
        rejected,

        /** The peer confirmed successful execution. */
        succeeded,

        /** Delivery or mutation completion cannot be established safely. */
        unknown
    };

    /**
     * @brief An owned diagnostic with no key material or authentication payloads.
     */
    struct Error {
        /** Stable failure category suitable for programmatic decisions. */
        ErrorCode code{ErrorCode::internal};

        /** Human-readable, secret-free diagnostic owned by this value. */
        std::string message;

        /** Best available evidence about whether the operation reached the peer. */
        Outcome outcome{Outcome::not_sent};

        /**
         * @brief Original native/ISO status when available; zero means no status was attached.
         */
        std::uint16_t device_status{0};
    };

    /**
     * @brief Construct a pre-transmission argument failure; the caller can correct its input.
     * @param message Human-readable explanation that must not include secret material.
     * @return An Error with invalid_argument and Outcome::not_sent.
     */
    inline Error invalid(std::string message) {
        return {.code = ErrorCode::invalid_argument, .message = std::move(message)};
    }

} // namespace desfire
