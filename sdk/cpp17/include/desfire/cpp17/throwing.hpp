/**
 * @file throwing.hpp
 * @brief Optional exception adapter for applications that choose throwing control flow.
 */
#pragma once

#include <desfire/cpp17.hpp>
#include <stdexcept>

namespace desfire::cpp17::throwing {

    /** @brief Exception retaining the same structured evidence as an exception-free Result. */
    class ErrorException final : public std::runtime_error {
    public:

        /**
         * @brief Copy one facade error into exception ownership.
         * @param error Structured failure returned by the primary API.
         */
        explicit ErrorException(Error error)
            : std::runtime_error(error.message), error_(std::move(error)) {}

        /**
         * @brief Return the complete structured failure evidence.
         * @return Owned redacted failure evidence.
         */
        const Error& error() const noexcept {
            return error_;
        }

    private:

        Error error_; /**< Owned failure evidence for the unsuccessful state. */
    };

    /**
     * @brief Return a success value or throw ErrorException with preserved evidence.
     * @tparam T Success type, including move-only values.
     * @param result Primary exception-free result.
     * @return Moved success value.
     * @throws ErrorException when result contains a failure.
     */
    template <class T> T value_or_throw(Result<T> result) {
        if (!result) {
            throw ErrorException(std::move(result).error());
        }
        return std::move(result).value();
    }

    /**
     * @brief Return normally on success or throw ErrorException for a void result.
     * @param result Primary exception-free result.
     * @throws ErrorException when result contains a failure.
     */
    inline void value_or_throw(Result<void> result) {
        if (!result) {
            throw ErrorException(std::move(result).error());
        }
    }
} // namespace desfire::cpp17::throwing
