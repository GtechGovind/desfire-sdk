/**
 * @file channel.hpp
 * @brief Serialized raw ISO APDU exchange with bounded continuation and one deadline.
 */
#pragma once

#include "codec.hpp"
#include <desfire/foundation/transport.hpp>

#include <memory>
#include <mutex>

namespace desfire::ev3::iso7816::raw {

    /** @brief Hard byte, frame, and explicitly authorized length-correction limits. */
    struct Limits final {
        std::size_t max_response{65536}; ///< Maximum aggregate bytes before SW1/SW2.
        std::size_t max_frames{1024};    ///< Maximum physical exchanges including continuations.
        bool correct_length{};           ///< Permit one 6Cxx resend; caller proves retry safety.
    };

    /**
     * @brief Logical owner of one APDU transport, serializing complete logical exchanges.
     *
     * A Channel is deliberately noncopyable and nonmovable. cancel() remains callable from another
     * thread while exchange() owns the operation mutex. Every 61xx continuation and optional 6Cxx
     * correction shares the initial card generation and elapsed-time deadline. Callers must not
     * construct another independently operated channel over the same transport. A managed Card may
     * share the transport with its native channel because its outer operation lock serializes both.
     */
    class Channel final {
    public:

        /**
         * @brief Validate and retain one logically exclusive activated APDU transport.
         * @param transport Non-null shared transport retained by the channel.
         * @return Logical channel or invalid_argument without touching a card.
         * @warning Except inside one managed Card, do not construct concurrent channels over the
         * same transport because their independent locks cannot serialize complete exchanges.
         */
        static Result<std::unique_ptr<Channel>> create(std::shared_ptr<CardTransport> transport);

        /** @brief Destroy the owned transport after callers stop all operations. */
        ~Channel() = default;

        /** @brief Prevent duplicated channel identity and operation locking. */
        Channel(const Channel&) = delete;
        /** @brief Prevent duplicated transport ownership. */
        Channel& operator=(const Channel&) = delete;
        /** @brief Keep the synchronization address stable for bound security sessions. */
        Channel(Channel&&) = delete;
        /** @brief Keep the synchronization address stable for bound security sessions. */
        Channel& operator=(Channel&&) = delete;

        /**
         * @brief Execute one raw APDU with bounded 61xx continuation under one deadline.
         * @param apdu Owned raw fields borrowed for this operation.
         * @param options Total timeout and cancellation controls for all physical frames.
         * @param limits Aggregate response, frame, and optional 6Cxx correction policy.
         * @return Final response retaining data and SW1/SW2, or conservative delivery evidence.
         * @warning Set Limits::correct_length only when resending the instruction is proven safe.
         */
        Result<Response> exchange(const Apdu& apdu, const ExchangeOptions& options = {},
                                  const Limits& limits = {});

        /** @brief Return immutable capabilities of the exclusively owned transport. */
        [[nodiscard]] TransportCapabilities capabilities() const;

        /**
         * @brief Return the owned transport generation used to bind session state.
         * @return Current card-generation counter.
         */
        [[nodiscard]] std::uint64_t generation() const noexcept;

        /** @brief Forward cooperative cancellation without waiting for the operation mutex. */
        void cancel() noexcept;

        /**
         * @brief Reset the owned transport while excluding logical APDU exchange.
         * @return Transport reset result; a successful provider advances generation().
         */
        Result<void> reset();

    private:

        /** @brief Retain a transport already validated by create(). */
        explicit Channel(std::shared_ptr<CardTransport> transport);

        std::shared_ptr<CardTransport>
            transport_; ///< Transport used for serialized card exchanges.
        std::recursive_mutex
            operation_mutex_;     ///< Serializes operations while allowing reentry detection.
        bool operation_active_{}; ///< True while an exchange or reset owns callback admission.
    };

} // namespace desfire::ev3::iso7816::raw
