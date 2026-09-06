/**
 * @file channel.hpp
 * @brief Native secure-messaging execution over a serialized raw channel.
 */
#pragma once

#include "request.hpp"

#include <desfire/ev3/native/raw/channel.hpp>

#include <memory>

namespace desfire::ev3::security::ev2 {
    class Session;
}

namespace desfire::ev3::security::standard_aes {
    class Session;
}

namespace desfire::ev3::native::secure {

    /**
     * @brief Apply native secure messaging around exactly one checked logical command.
     *
     * The channel borrows caller-owned session objects only for synchronous calls. A caller must
     * not use one session concurrently through different secure channels. The underlying raw
     * channel serializes framing and all additional frames. Any failure after message preparation
     * invalidates the borrowed session so an IV or counter can never be reused.
     */
    class SecureNativeChannel final {
    public:

        /**
         * @brief Create a secure executor over one raw channel.
         * @param raw Shared raw channel retained for this object's lifetime.
         * @return Secure channel ownership, or invalid_argument for an absent dependency.
         */
        static Result<std::shared_ptr<SecureNativeChannel>>
        connect(std::shared_ptr<raw::RawNativeChannel> raw);

        /** @brief Release the retained raw channel without owning or erasing caller sessions. */
        ~SecureNativeChannel();

        /** @brief Secure channels cannot duplicate raw-channel ownership by copying. */
        SecureNativeChannel(const SecureNativeChannel&) = delete;

        /** @brief Secure channels cannot copy-assign raw-channel identity. */
        SecureNativeChannel& operator=(const SecureNativeChannel&) = delete;

        /** @brief Secure channels retain stable shared identity and cannot be moved. */
        SecureNativeChannel(SecureNativeChannel&&) = delete;

        /** @brief Secure channels retain stable shared identity and cannot be move-assigned. */
        SecureNativeChannel& operator=(SecureNativeChannel&&) = delete;

        /**
         * @brief Execute a checked request without native authentication.
         * @param request Borrowed checked command fields.
         * @param options One deadline and cancellation token for all additional frames.
         * @return Bounded status-free response, or framing/card/transport evidence.
         */
        Result<Bytes> exchange_unprotected(const Request& request,
                                           const ExchangeOptions& options = {});

        /**
         * @brief Execute a checked request using Standard AES chained-IV messaging.
         * @param request Borrowed checked command fields and protection modes.
         * @param session Exclusively borrowed Standard AES session; invalidated after ambiguity.
         * @param options One deadline and cancellation token for the complete command.
         * @return Verified clear response bytes, or exact failure evidence.
         */
        Result<Bytes> exchange(const Request& request, security::standard_aes::Session& session,
                               const ExchangeOptions& options = {});

        /**
         * @brief Execute a checked request using EV2 counter-based AES messaging.
         * @param request Borrowed checked command fields and protection modes.
         * @param session Exclusively borrowed EV2 session; invalidated after ambiguity.
         * @param options One deadline and cancellation token for the complete command.
         * @return Verified clear response bytes, or exact failure evidence.
         */
        Result<Bytes> exchange(const Request& request, security::ev2::Session& session,
                               const ExchangeOptions& options = {});

    private:

        /**
         * @brief Retain a validated raw channel.
         * @param raw Shared serialized raw executor.
         */
        explicit SecureNativeChannel(std::shared_ptr<raw::RawNativeChannel> raw);

        std::shared_ptr<raw::RawNativeChannel> raw_; ///< Shared raw channel used for physical I/O.
    };

} // namespace desfire::ev3::native::secure
