/**
 * @file
 * @brief Reader contracts independent of DESFire command semantics.
 */
#pragma once
#include "bytes.hpp"
#include <chrono>
#include <memory>
#include <stop_token>

namespace desfire {

    /**
     * @brief Encoding accepted by the reader, independent of ISO-DEP link fragmentation.
     */
    enum class Framing {
        /** Reader accepts native command bytes without an ISO 7816 APDU envelope. */
        native,

        /** Reader accepts complete ISO 7816 APDUs. */
        iso7816
    };

    /**
     * @brief Advertised limits are hard bounds, not estimates inferred from reader names.
     */
    struct TransportCapabilities {
        /** Encoding expected by exchange(). */
        Framing framing{Framing::iso7816};

        /** Maximum encoded request bytes, including any APDU framing. */
        std::size_t max_transmit{261};

        /** Maximum encoded response bytes, including status bytes. */
        std::size_t max_receive{65538};

        /** Native command byte plus payload capacity in one logical native frame. */
        std::size_t max_native_frame{60};

        /** Whether cancel() can interrupt a pending exchange. */
        bool can_cancel{false};

        /** Whether reset() can perform a physical or logical card reset. */
        bool can_reset{false};

        /** Whether the transport can return reader-measured RF timing evidence. */
        bool hardware_timing{false};
    };

    /**
     * @brief Per-exchange controls borrowed by the transport for the duration of I/O.
     */
    struct ExchangeOptions {
        /**
         * @brief Maximum duration of the requested exchange; non-positive values are invalid.
         */
        std::chrono::milliseconds timeout{5000};

        /** Cooperative cancellation state borrowed for the duration of the exchange. */
        std::stop_token stop{};
    };

    /**
     * @brief A connection to an already activated card.
     *
     * Implementations own reader I/O, not DESFire status interpretation. An engine
     * serializes calls to exchange(); cancel() must remain callable from another thread.
     * Implementations must never repeat a frame after uncertain delivery.
     */
    class CardTransport {
    public:

        /** @brief Destroy a transport after pending I/O is cancelled and callers release it. */
        virtual ~CardTransport() = default;

        /**
         * @brief Report actual connection limits; do not infer timing support from reader identity.
         * @return Immutable capabilities for the currently opened connection.
         */
        virtual TransportCapabilities capabilities() const = 0;

        /**
         * @brief Changes whenever removal, reset, or reconnection invalidates card state.
         * @return Provider-maintained connection generation; equal values describe the same state.
         */
        virtual std::uint64_t generation() const noexcept = 0;

        /**
         * @brief Send one frame and return the complete reader response.
         * @param frame Borrowed only for the duration of this call.
         * @param options Deadline budget and cooperative cancellation request.
         * @return Owned response bytes, or an error with delivery evidence.
         * @warning Report Outcome::unknown when delivery cannot be determined.
         */
        virtual Result<Bytes> exchange(ByteView frame, const ExchangeOptions& options) = 0;

        /**
         * @brief Interrupt pending I/O without acquiring the engine's operation lock.
         */
        virtual void cancel() noexcept = 0;

        /**
         * @brief Reset card state if supported; successful implementations advance generation().
         * @return Success after reset, or unsupported/transport failure evidence.
         */
        virtual Result<void> reset() {
            return Error{ErrorCode::unsupported, "Transport cannot reset"};
        }
    };

    /**
     * @brief SAM APDUs share the byte-exchange contract, but not DESFire application semantics.
     */
    using SamTransport = CardTransport;

    /**
     * @brief A provider-local connection identifier and a human-readable reader name.
     */
    struct ReaderInfo {
        /** Provider-local stable identifier accepted by ReaderProvider::open(). */
        std::string id;

        /** Human-readable reader name for selection and diagnostics. */
        std::string name;
    };

    /**
     * @brief Reader discovery is separate from protocol execution so the core remains portable.
     */
    class ReaderProvider {
    public:

        /** @brief Destroy a provider after any returned connections are independently retained. */
        virtual ~ReaderProvider() = default;

        /**
         * @brief Enumerate available endpoints without selecting a card application.
         * @return Provider-local reader identities, or a discovery failure without a connection.
         */
        virtual Result<std::vector<ReaderInfo>> readers() = 0;

        /**
         * @brief Open an endpoint by its provider-local ID and return shared connection ownership.
         * @param id ID previously reported by readers() for this provider instance.
         * @return A transport retaining the opened connection, or a provider/transport error.
         */
        virtual Result<std::shared_ptr<CardTransport>> open(std::string_view id) = 0;
    };

    /**
     * @brief Response paired with reader-measured RF duration; host scheduling time is excluded.
     */
    struct TimedResponse {
        /** Complete owned reader response for the corresponding request frame. */
        Bytes response;

        /** Reader-measured RF round-trip duration excluding host scheduling time. */
        std::chrono::nanoseconds rf_round_trip;
    };

    /**
     * @brief RF timing evidence must originate from the reader, not host wall-clock estimates.
     */
    class TimedExchangeTransport : public CardTransport {
    public:

        /**
         * @brief Exchange the sequence using the reader's timing facilities. The plugin must
         * document timing accuracy and sequencing; an interface alone proves neither.
         * @param frames Complete reader frames in the required timing-sensitive order.
         * @param options Deadline and cancellation controls for the complete sequence.
         * @return One reader-measured response per sent frame, or failure evidence.
         * @warning Implementations must report hardware-measured timing only; host scheduling
         *          duration is not proximity-check evidence.
         */
        virtual Result<std::vector<TimedResponse>>
        timed_exchange(std::span<const Bytes> frames, const ExchangeOptions& options) = 0;
    };

} // namespace desfire
