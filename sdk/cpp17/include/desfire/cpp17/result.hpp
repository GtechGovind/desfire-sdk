/**
 * @file result.hpp
 * @brief Exception-free C++17 result and owned error evidence for the DESFire C ABI.
 */
#pragma once

#include <cstdint>
#include <desfire/base.h>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>

namespace desfire::cpp17 {

    /** @brief Stable operation failure codes shared with the versioned C ABI. */
    enum class ErrorCode : std::uint32_t {
        invalid_argument = DF_INVALID_ARGUMENT, /**< Caller input failed local validation. */
        transport = DF_TRANSPORT,               /**< Reader transport failed. */
        card_removed = DF_CARD_REMOVED,         /**< Card or tag left the reader field. */
        timeout = DF_TIMEOUT,                   /**< Logical operation exceeded its timeout. */
        cancelled = DF_CANCELLED,               /**< Operation was cancelled. */
        malformed_response =
            DF_MALFORMED_RESPONSE,          /**< Card response failed structural validation. */
        card_rejected = DF_CARD_REJECTED,   /**< Card returned a rejecting status. */
        authentication = DF_AUTHENTICATION, /**< Authentication protocol failed. */
        integrity = DF_INTEGRITY,           /**< MAC, padding, or cryptographic integrity failed. */
        unsupported = DF_UNSUPPORTED,       /**< Requested feature or ABI is unsupported. */
        stale_handle = DF_STALE_HANDLE,     /**< Native handle no longer names a live object. */
        busy = DF_BUSY, /**< Card or channel is executing another logical operation. */
        session_invalid = DF_SESSION_INVALID, /**< Secure session is absent or unusable. */
        counter_exhausted =
            DF_COUNTER_EXHAUSTED, /**< Secure messaging counter cannot advance safely. */
        buffer_too_small =
            DF_BUFFER_TOO_SMALL, /**< Caller output storage cannot hold the result. */
        crypto = DF_CRYPTO,      /**< Cryptographic provider or primitive failed. */
        internal = DF_INTERNAL   /**< Unexpected SDK invariant failed. */
    };

    /** @brief Evidence describing whether a failed operation could have reached the card. */
    enum class Outcome : std::uint32_t {
        not_sent = DF_NOT_SENT,   /**< No card frame was transmitted. */
        rejected = DF_REJECTED,   /**< Card received and rejected the operation. */
        succeeded = DF_SUCCEEDED, /**< Operation is known to have completed. */
        unknown = DF_UNKNOWN      /**< Delivery or mutation outcome requires reconciliation. */
    };

    /** @brief Owned, secret-free failure evidence copied before the C call returns. */
    struct Error final {
        ErrorCode code{ErrorCode::internal}; /**< Stable operation failure category. */
        Outcome outcome{Outcome::not_sent};  /**< Best available evidence of whether the operation
                                                reached the card. */
        std::uint16_t device_status{}; /**< Native status byte or ISO status word when available. */
        std::string message;           /**< Owned redacted diagnostic text. */

        /**
         * @brief Copy a fixed-width C error into ordinary C++17 ownership.
         * @param native Per-call C error storage.
         * @return Owned error retaining the stable code, outcome, status, and message.
         */
        static Error from_native(const df_error& native) {
            return {static_cast<ErrorCode>(native.code), static_cast<Outcome>(native.outcome),
                    native.device_status, std::string(native.message)};
        }
    };

    /**
     * @brief A value-or-error result that never throws as part of its public contract.
     * @tparam T Success value type; it may be move-only.
     *
     * Callers must test the result before accessing value() or error(). The unchecked accessors
     * avoid an exception dependency so the same header works with `-fno-exceptions`.
     */
    template <class T> class [[nodiscard]] Result final {
    public:

        /**
         * @brief Construct a successful result by moving its value.
         * @param value Success value.
         * @return Result containing the value.
         */
        static Result success(T value) {
            return Result(std::move(value));
        }

        /**
         * @brief Construct a failed result with owned evidence.
         * @param error Failure evidence.
         * @return Result containing the error.
         */
        static Result failure(Error error) {
            return Result(std::move(error));
        }

        /**
         * @brief Report whether this result contains a success value.
         * @return True when value access is valid; false when error access is valid.
         */
        explicit operator bool() const noexcept {
            return std::holds_alternative<T>(storage_);
        }

        /**
         * @brief Return the success value; the result must have been checked first.
         * @return The stored success value; callers must first verify that the result succeeded.
         */
        T& value() & noexcept {
            return *std::get_if<T>(&storage_);
        }

        /**
         * @brief Return the immutable success value; the result must have been checked first.
         * @return The stored success value; callers must first verify that the result succeeded.
         */
        const T& value() const& noexcept {
            return *std::get_if<T>(&storage_);
        }

        /**
         * @brief Move the success value; the result must have been checked first.
         * @return The stored success value; callers must first verify that the result succeeded.
         */
        T&& value() && noexcept {
            return std::move(*std::get_if<T>(&storage_));
        }

        /**
         * @brief Return mutable failure evidence; the result must be failed.
         * @return Owned redacted failure evidence.
         */
        Error& error() & noexcept {
            return *std::get_if<Error>(&storage_);
        }

        /**
         * @brief Return immutable failure evidence; the result must be failed.
         * @return Owned redacted failure evidence.
         */
        const Error& error() const& noexcept {
            return *std::get_if<Error>(&storage_);
        }

        /**
         * @brief Move failure evidence; the result must be failed.
         * @return Owned redacted failure evidence.
         */
        Error&& error() && noexcept {
            return std::move(*std::get_if<Error>(&storage_));
        }

    private:

        /**
         * @brief Store a successful value without requiring a default constructor.
         * @param value Already-validated scalar or success value stored by the object.
         */
        explicit Result(T value) : storage_(std::in_place_type<T>, std::move(value)) {}

        /**
         * @brief Store an error without constructing the success type.
         * @param error Per-call C error storage paired with the returned status.
         */
        explicit Result(Error error) : storage_(std::in_place_type<Error>, std::move(error)) {}

        std::variant<T, Error> storage_; /**< Discriminated storage containing either the success
                                            value or failure evidence. */
    };

    /** @brief Void specialization for operations that only report success or failure. */
    template <> class [[nodiscard]] Result<void> final {
    public:

        /**
         * @brief Construct a successful void result.
         * @return A result representing successful completion.
         */
        static Result success() {
            return Result(true, {});
        }

        /**
         * @brief Construct a failed void result.
         * @param error Failure evidence.
         * @return Failed result containing the error.
         */
        static Result failure(Error error) {
            return Result(false, std::move(error));
        }

        /**
         * @brief Report whether the void operation succeeded.
         * @return True after successful completion; false when error evidence is stored.
         */
        explicit operator bool() const noexcept {
            return success_;
        }

        /**
         * @brief Return mutable failure evidence; the result must be failed.
         * @return Owned redacted failure evidence.
         */
        Error& error() & noexcept {
            return error_;
        }

        /**
         * @brief Return immutable failure evidence; the result must be failed.
         * @return Owned redacted failure evidence.
         */
        const Error& error() const& noexcept {
            return error_;
        }

        /**
         * @brief Move failure evidence; the result must be failed.
         * @return Owned redacted failure evidence.
         */
        Error&& error() && noexcept {
            return std::move(error_);
        }

    private:

        /**
         * @brief Construct the specialized representation.
         * @param success Whether the specialized void result represents success.
         * @param error Per-call C error storage paired with the returned status.
         */
        Result(bool success, Error error) : success_(success), error_(std::move(error)) {}

        bool success_{}; /**< Whether the specialized void result represents success. */
        Error error_{};  /**< Owned failure evidence for the unsuccessful state. */
    };

    namespace detail {

        /**
         * @brief Build a local argument failure that proves no C call was made.
         * @param message Secret-free diagnostic moved into local failure evidence.
         * @return Owned redacted failure evidence.
         */
        inline Error invalid_argument(std::string message) {
            return {ErrorCode::invalid_argument, Outcome::not_sent, 0, std::move(message)};
        }

        /**
         * @brief Convert one failed C status and its matching error storage.
         * @param status Stable status returned by the matching C ABI invocation.
         * @param native Versioned C ABI value to copy into C++ ownership.
         * @return Owned redacted failure evidence.
         */
        inline Error native_error(std::int32_t status, const df_error& native) {
            if (native.code != DF_OK) {
                return Error::from_native(native);
            }
            return {static_cast<ErrorCode>(status), Outcome::not_sent, 0,
                    "C ABI returned failure without error evidence"};
        }

    } // namespace detail
} // namespace desfire::cpp17
