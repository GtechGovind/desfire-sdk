/**
 * @file channel.hpp
 * @brief Serialized unprotected DESFire native command channel.
 */
#pragma once

#include "../framing.hpp"
#include "message.hpp"

#include <desfire/foundation/transport.hpp>

#include <chrono>
#include <memory>

namespace desfire::ev3::native::raw {

    /**
     * @brief Serialize unprotected native traffic over one exclusively owned activated transport.
     *
     * The channel selects direct or ISO-wrapped presentation from the transport's declared
     * capabilities. It performs native additional-frame upload and download, but deliberately
     * applies no command-specific checking or secure messaging. Do not wrap the same transport in
     * more than one channel because independent locks cannot prevent frame interleaving.
     *
     * `cancel()` is the only thread-safe operation that may run concurrently with an exchange.
     * Other calls serialize. Recursive entry from a transport callback returns `busy` before I/O.
     */
    class RawNativeChannel final : public std::enable_shared_from_this<RawNativeChannel> {
        struct State;

    public:

        /**
         * @brief Hold exclusive channel ownership across an adaptive multi-frame operation.
         *
         * A transaction is move-only and must not outlive its channel. Its deadline, cancellation
         * token, transport generation, and delivery evidence span every call to `exchange_frame()`
         * and `exchange()` until destruction.
         */
        class Transaction final {
        public:

            /** @brief Release exclusive channel ownership without performing card I/O. */
            ~Transaction();

            /**
             * @brief Transfer the exclusive transaction and its accumulated delivery evidence.
             * @param other Live transaction whose ownership is consumed.
             */
            Transaction(Transaction&& other) noexcept;

            /** @brief Transactions cannot be copied because each owns one channel lock. */
            Transaction(const Transaction&) = delete;

            /** @brief Transactions cannot replace an already held channel lock. */
            Transaction& operator=(Transaction&&) = delete;

            /** @brief Transactions cannot share one channel lock by copy assignment. */
            Transaction& operator=(const Transaction&) = delete;

            /**
             * @brief Exchange exactly one native physical frame under this transaction.
             * @param command Native instruction byte.
             * @param data Status-free frame data borrowed until the transport call returns.
             * @return Decoded response or failure with delivery evidence accumulated across the
             * transaction.
             * @warning This function does not interpret `AF` or automatically continue.
             */
            Result<Response> exchange_frame(Byte command, ByteView data);

            /**
             * @brief Exchange one logical command including all native additional frames.
             * @param request Owned raw command, response bound, and optional upload boundary.
             * @return Terminal native status and concatenated response bytes.
             * @warning A failure after any earlier transaction frame is confirmed has
             * `Outcome::unknown`; no frame is retried.
             */
            Result<Response> exchange(const Request& request);

        private:

            friend class RawNativeChannel;

            /**
             * @brief Adopt one locked channel operation and its common control budget.
             * @param state Shared channel state retained through transaction destruction.
             * @param options Positive deadline and cancellation controls.
             */
            Transaction(std::shared_ptr<State> state, const ExchangeOptions& options);

            /**
             * @brief Return controls reduced to the remaining common deadline.
             * @return Per-frame controls, or timeout/cancellation/generation evidence before I/O.
             */
            Result<ExchangeOptions> remaining_options() const;

            std::shared_ptr<State>
                state_; ///< Shared raw-channel state retained for the operation lifetime.
            std::chrono::steady_clock::time_point
                deadline_{};         ///< Absolute deadline shared by every frame in this operation.
            std::stop_token stop_{}; ///< Cooperative cancellation token for this operation.
            std::uint64_t generation_{}; ///< Card generation captured when this state was created.
            bool sent_any_frame_{};      ///< Whether any request frame may have reached the card.
            bool owns_operation_{};      ///< Whether this transaction owns raw-channel admission.
        };

        /**
         * @brief Create a raw channel for one activated transport.
         * @param transport Exclusively owned logical card transport retained by shared ownership.
         * @return Channel ownership, or invalid_argument when the dependency is absent.
         */
        static Result<std::shared_ptr<RawNativeChannel>>
        connect(std::shared_ptr<CardTransport> transport);

        /** @brief Release the channel after any caller-owned transactions have ended. */
        ~RawNativeChannel();

        /** @brief Channels cannot copy transport identity or operation serialization state. */
        RawNativeChannel(const RawNativeChannel&) = delete;

        /** @brief Channels cannot copy-assign transport identity or lock state. */
        RawNativeChannel& operator=(const RawNativeChannel&) = delete;

        /** @brief Channels retain a stable shared identity and cannot be moved. */
        RawNativeChannel(RawNativeChannel&&) = delete;

        /** @brief Channels retain a stable shared identity and cannot be move-assigned. */
        RawNativeChannel& operator=(RawNativeChannel&&) = delete;

        /**
         * @brief Start one exclusive adaptive operation.
         * @param options Positive total deadline and cancellation token for every transaction
         * frame.
         * @return Move-only transaction, or a pre-I/O timeout/cancellation/reentry error.
         */
        Result<Transaction> begin(const ExchangeOptions& options = {});

        /**
         * @brief Execute one complete raw native command under one exclusive transaction.
         * @param request Raw native command and hard response/chaining bounds.
         * @param options Positive total deadline and cancellation controls.
         * @return Terminal native response or exact transport/framing/delivery evidence.
         */
        Result<Response> exchange(const Request& request, const ExchangeOptions& options = {});

        /**
         * @brief Reset the transport while excluding all native operations.
         * @return Transport reset evidence; success is expected to change `generation()`.
         */
        Result<void> reset();

        /**
         * @brief Interrupt pending transport I/O without waiting for the operation lock.
         */
        void cancel() noexcept;

        /**
         * @brief Return the explicit native framing selected from transport capabilities.
         * @return Direct or proprietary ISO-wrapped presentation.
         */
        [[nodiscard]] native::Framing framing() const noexcept;

        /**
         * @brief Return the provider-maintained activated-card generation.
         * @return Current transport generation; changes invalidate card/session state.
         */
        [[nodiscard]] std::uint64_t generation() const noexcept;

    private:

        /**
         * @brief Retain initialized shared state after dependency validation.
         * @param state Transport, framing, and serialization state.
         */
        explicit RawNativeChannel(std::shared_ptr<State> state);

        std::shared_ptr<State>
            state_; ///< Shared raw-channel state retained for the operation lifetime.
    };

} // namespace desfire::ev3::native::raw
