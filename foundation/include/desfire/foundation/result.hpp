/**
 * @file result.hpp
 * @brief Explicit value-or-error results with support for move-only payloads.
 *
 * Expected SDK failures are stored as Error values rather than thrown as exceptions.
 * Accessors throw only when the caller requests a value from a failed result.
 */
#pragma once

#include "error.hpp"

#include <expected>
#include <utility>

namespace desfire {

    /**
     * @brief Own either a successful value or an expected SDK failure.
     *
     * Check operator bool() before accessing value() or error(). No error is silently
     * converted to a default value, and move-only payloads retain their ownership rules.
     *
     * @tparam T The successful payload type stored by `std::expected`.
     *
     * @par Example
     * Construct and inspect a successful result:
     * @code{.cpp}
     * Result<int> result = 42;
     * if (result) {
     *     const int value = result.value();
     * }
     * @endcode
     */
    template <class T> class [[nodiscard]] Result {

        std::expected<T, Error> data_; ///< Stored result or error alternative.

    public:

        /**
         * @brief Construct a successful result by taking ownership of a value.
         *
         * @param value Payload to move into the result's storage.
         * @note Intentionally permits conversion so SDK functions can return a T
         * directly. Move-only inputs must be passed as rvalues.
         */
        Result(T value) : data_(std::move(value)) {}

        /**
         * @brief Construct a failed result with its execution evidence intact.
         *
         * @param error Owned diagnostic and delivery-outcome information.
         * @note Intentionally permits conversion so an Error can be propagated with
         * a return statement without throwing an exception.
         */
        Result(Error error) : data_(std::unexpected(std::move(error))) {}

        /**
         * @brief Check whether the result currently contains a successful payload.
         *
         * @return True for the value alternative; false otherwise.
         * @note Explicit conversion supports conditions without implicit arithmetic
         * or unintended conversion to unrelated integer parameters.
         */
        explicit operator bool() const noexcept {
            return data_.has_value();
        }

        /**
         * @brief Borrow the payload from a mutable lvalue result.
         *
         * @return A mutable reference owned by this result.
         * @throws std::bad_expected_access If the result does not contain a value.
         * @warning The reference must not outlive the result or a change of its alternative.
         */
        [[nodiscard]] T& value() & {
            return data_.value();
        }

        /**
         * @brief Borrow the payload from a const lvalue result without copying it.
         *
         * @return A read-only reference owned by this result.
         * @throws std::bad_expected_access If the result does not contain a value.
         * @warning The reference must not outlive the result or a change of its alternative.
         */
        [[nodiscard]] const T& value() const& {
            return data_.value();
        }

        /**
         * @brief Expose the payload for moving from an rvalue result.
         *
         * @return An rvalue reference to the payload; accessing it alone does not move it.
         * @throws std::bad_expected_access If the result does not contain a value.
         * @note Construct the destination while this result is alive. The result
         * retains a potentially moved-from value alternative after extraction.
         */
        [[nodiscard]] T&& value() && {
            return std::move(data_).value();
        }

        /**
         * @brief Borrow failure information from a mutable lvalue result.
         *
         * @return A mutable reference to the stored error.
         * @pre The result contains an error.
         * @note Mutating the diagnostic must not invent stronger delivery evidence.
         */
        [[nodiscard]] Error& error() & {
            return data_.error();
        }

        /**
         * @brief Borrow failure information without copying the diagnostic string.
         *
         * @return A read-only reference to the stored error.
         * @pre The result contains an error.
         * @warning The reference must not outlive this result.
         */
        [[nodiscard]] const Error& error() const& {
            return data_.error();
        }
    };

    /**
     * @brief Represent success or failure for an operation with no return payload.
     *
     * Default construction stores a success marker. An Error stores failure evidence;
     * callers inspect operator bool() before accessing the diagnostic.
     */
    template <> class [[nodiscard]] Result<void> {

        std::expected<void, Error> data_; ///< Stored result or error alternative.

    public:

        /**
         * @brief Construct a successful result without a payload.
         */
        Result() = default;

        /**
         * @brief Construct a failure while retaining diagnostic ownership.
         *
         * @param error Failure category, diagnostic message, and execution evidence.
         */
        Result(Error error) : data_(std::unexpected(std::move(error))) {}

        /**
         * @brief Check whether the operation succeeded.
         *
         * @return True when the success marker is active; false otherwise.
         */
        explicit operator bool() const noexcept {
            return data_.has_value();
        }

        /**
         * @brief Borrow the diagnostic after checking that the operation failed.
         *
         * @return A read-only reference to the owned error.
         * @pre The result contains an error.
         * @warning The reference must not outlive this result.
         */
        [[nodiscard]] const Error& error() const {
            return data_.error();
        }
    };

} // namespace desfire
