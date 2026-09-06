/**
 * @file channel.cpp
 * @brief Serialized bounded DESFire native exchange implementation.
 */
#include <desfire/ev3/native/raw/channel.hpp>

#include <desfire/ev3/native/raw/codec.hpp>

#include <algorithm>
#include <chrono>
#include <limits>
#include <mutex>

namespace desfire::ev3::native::raw {

    namespace {

        /** @brief Native status asking the host to continue the current logical exchange. */
        constexpr Byte additional_frame_status = 0xAF;

        /** @brief Bound a malformed peer that endlessly requests continuation frames. */
        constexpr std::size_t maximum_chain_frames = 4096;

        /**
         * @brief Map the transport's historical framing enum to explicit native terminology.
         * @param framing Framing reported by the activated transport.
         * @return Direct native or proprietary ISO-wrapped native presentation.
         */
        native::Framing map_framing(desfire::Framing framing) noexcept {
            if (framing == desfire::Framing::native) {
                return native::Framing::direct;
            }

            return native::Framing::iso_wrapped;
        }

        /**
         * @brief Upgrade a later pre-send frame failure because earlier frames changed card state.
         * @param error Failure evidence returned by one physical frame.
         * @param sent_any_frame Whether an earlier frame completed in this transaction.
         * @return Error preserving its category and status with conservative outcome evidence.
         */
        Error normalize_delivery(Error error, bool sent_any_frame) {
            if (sent_any_frame && error.outcome == Outcome::not_sent) {
                error.outcome = Outcome::unknown;
            }

            return error;
        }

    } // namespace

    /** @brief Internal RawNativeChannel state shared by the channel operation. */
    struct RawNativeChannel::State {
        std::shared_ptr<CardTransport> transport; ///< Activated card transport.
        native::Framing framing{
            native::Framing::iso_wrapped}; ///< Native framing selected for the activated transport.
        std::recursive_mutex operation_mutex; ///< Mutex serializing operations for this card.
        bool operation_active{}; ///< Whether a managed operation currently owns admission.
    };

    /** @brief Implement `Transaction` to construct or transfer exclusive native transaction state.
     */
    RawNativeChannel::Transaction::Transaction(std::shared_ptr<State> state,
                                               const ExchangeOptions& options)
        : state_(std::move(state)), deadline_(std::chrono::steady_clock::now() + options.timeout),
          stop_(options.stop), generation_(state_->transport->generation()), owns_operation_(true) {
    }

    /** @brief Implement `Transaction` to construct or transfer exclusive native transaction state.
     */
    RawNativeChannel::Transaction::Transaction(Transaction&& other) noexcept
        : state_(std::move(other.state_)), deadline_(other.deadline_), stop_(other.stop_),
          generation_(other.generation_), sent_any_frame_(other.sent_any_frame_),
          owns_operation_(other.owns_operation_) {
        other.owns_operation_ = false;
    }

    /** @brief Clear channel activity and unlock after the last adaptive frame. */
    RawNativeChannel::Transaction::~Transaction() {
        if (owns_operation_) {
            state_->operation_active = false;
            state_->operation_mutex.unlock();
        }
    }

    /** @brief Implement `remaining_options` to derive the remaining timeout while preserving one
     * logical deadline. */
    Result<ExchangeOptions> RawNativeChannel::Transaction::remaining_options() const {
        const auto now = std::chrono::steady_clock::now();
        const auto prior_outcome = sent_any_frame_ ? Outcome::unknown : Outcome::not_sent;
        if (now >= deadline_) {
            return Error{ErrorCode::timeout, "Native operation deadline expired", prior_outcome};
        }
        if (state_->transport->generation() != generation_) {
            return Error{ErrorCode::card_removed, "Card state changed during native operation",
                         prior_outcome};
        }
        if (stop_.stop_requested()) {
            return Error{ErrorCode::cancelled, "Native operation cancelled", prior_outcome};
        }

        return ExchangeOptions{
            .timeout = std::chrono::ceil<std::chrono::milliseconds>(deadline_ - now),
            .stop = stop_,
        };
    }

    /** @brief Implement `exchange_frame` to exchange one physical native frame with generation
     * checks. */
    Result<Response> RawNativeChannel::Transaction::exchange_frame(Byte command, ByteView data) {
        auto controls = remaining_options();
        if (!controls) {
            return controls.error();
        }

        const auto capabilities = state_->transport->capabilities();
        if (capabilities.max_native_frame == 0 ||
            data.size() > capabilities.max_native_frame - 1U) {
            return normalize_delivery(invalid("Native frame exceeds transport native capacity"),
                                      sent_any_frame_);
        }
        auto encoded = raw::encode(command, data, state_->framing);
        if (!encoded) {
            return normalize_delivery(encoded.error(), sent_any_frame_);
        }
        if (encoded.value().size() > capabilities.max_transmit) {
            return normalize_delivery(invalid("Native frame exceeds transport transmit capacity"),
                                      sent_any_frame_);
        }

        Result<Bytes> wire_response =
            Error{ErrorCode::internal, "Transport did not complete", Outcome::unknown};
        try {
            wire_response = state_->transport->exchange(encoded.value(), controls.value());
        } catch (...) {
            return Error{ErrorCode::internal, "Native transport threw", Outcome::unknown};
        }
        if (!wire_response) {
            return normalize_delivery(wire_response.error(), sent_any_frame_);
        }

        sent_any_frame_ = true;
        if (state_->transport->generation() != generation_) {
            return Error{ErrorCode::card_removed, "Card state changed after native frame",
                         Outcome::unknown};
        }
        if (wire_response.value().size() > capabilities.max_receive) {
            return Error{ErrorCode::malformed_response,
                         "Native response exceeds transport receive capacity", Outcome::unknown};
        }

        return raw::decode(wire_response.value(), state_->framing);
    }

    /** @brief Implement `exchange` to execute one bounded serialized card exchange. */
    Result<Response> RawNativeChannel::Transaction::exchange(const Request& request) {
        if (request.maximum_response == 0) {
            return normalize_delivery(invalid("Native response limit must be positive"),
                                      sent_any_frame_);
        }

        const auto capabilities = state_->transport->capabilities();
        const std::size_t framing_overhead = state_->framing == native::Framing::direct ? 1U : 6U;
        if (capabilities.max_transmit <= framing_overhead || capabilities.max_native_frame < 2) {
            return normalize_delivery(invalid("Transport cannot carry a native command frame"),
                                      sent_any_frame_);
        }

        std::size_t data_per_frame = std::min(capabilities.max_transmit - framing_overhead,
                                              capabilities.max_native_frame - 1U);
        if (state_->framing == native::Framing::iso_wrapped) {
            data_per_frame = std::min(data_per_frame,
                                      static_cast<std::size_t>(std::numeric_limits<Byte>::max()));
        }
        if (data_per_frame == 0) {
            return normalize_delivery(invalid("Transport has no native command data capacity"),
                                      sent_any_frame_);
        }
        if (request.first_frame_data_size &&
            (*request.first_frame_data_size == 0 ||
             *request.first_frame_data_size >= request.data.size() ||
             *request.first_frame_data_size > data_per_frame)) {
            return normalize_delivery(
                invalid("Required first-frame boundary cannot fit this transport"),
                sent_any_frame_);
        }
        if (request.single_continuation_frame &&
            (!request.first_frame_data_size ||
             request.data.size() - *request.first_frame_data_size > data_per_frame)) {
            return normalize_delivery(
                invalid("Required continuation frame cannot fit this transport"), sent_any_frame_);
        }

        std::size_t uploaded = 0;
        Byte next_command = request.command;
        Bytes assembled_response;

        for (std::size_t frame_index = 0; frame_index < maximum_chain_frames; ++frame_index) {
            const std::size_t remaining = request.data.size() - uploaded;
            std::size_t current_size = std::min(data_per_frame, remaining);
            if (frame_index == 0 && request.first_frame_data_size) {
                current_size = *request.first_frame_data_size;
            }

            auto response = exchange_frame(next_command,
                                           ByteView(request.data).subspan(uploaded, current_size));
            if (!response) {
                return response.error();
            }

            uploaded += current_size;
            if (response.value().data.size() >
                request.maximum_response - assembled_response.size()) {
                return Error{ErrorCode::malformed_response,
                             "Native chained response exceeds configured limit", Outcome::unknown};
            }
            if (uploaded < request.data.size() &&
                (!response.value().data.empty() ||
                 response.value().status != additional_frame_status)) {
                return Error{ErrorCode::malformed_response,
                             "Card did not acknowledge native request continuation",
                             Outcome::unknown};
            }

            append(assembled_response, response.value().data);
            if (response.value().status != additional_frame_status) {
                if (uploaded < request.data.size()) {
                    return Error{ErrorCode::malformed_response,
                                 "Card ended native request before accepting all data",
                                 Outcome::unknown};
                }

                return Response{response.value().status, std::move(assembled_response)};
            }
            next_command = additional_frame_status;
        }

        return Error{ErrorCode::malformed_response,
                     "Native command exceeded additional-frame limit", Outcome::unknown};
    }

    /** @brief Implement `RawNativeChannel` to construct or transfer serialized native-channel
     * state. */
    RawNativeChannel::RawNativeChannel(std::shared_ptr<State> state) : state_(std::move(state)) {}

    /** @brief Implement `~RawNativeChannel` to cancel active work before releasing raw-channel
     * state. */
    RawNativeChannel::~RawNativeChannel() = default;

    /** @brief Implement `connect` to validate dependencies and create a ready channel. */
    Result<std::shared_ptr<RawNativeChannel>>
    RawNativeChannel::connect(std::shared_ptr<CardTransport> transport) {
        if (!transport) {
            return invalid("Raw native channel requires a transport");
        }

        auto state = std::make_shared<State>();
        state->framing = map_framing(transport->capabilities().framing);
        state->transport = std::move(transport);
        return std::shared_ptr<RawNativeChannel>(new RawNativeChannel(std::move(state)));
    }

    /** @brief Implement `begin` to acquire exclusive admission for one logical native operation. */
    Result<RawNativeChannel::Transaction> RawNativeChannel::begin(const ExchangeOptions& options) {
        if (options.timeout.count() <= 0) {
            return invalid("Native operation timeout must be positive");
        }
        if (options.stop.stop_requested()) {
            return Error{ErrorCode::cancelled, "Native operation cancelled before transmission"};
        }

        try {
            state_->operation_mutex.lock();
        } catch (...) {
            return Error{ErrorCode::internal, "Native operation lock failed"};
        }
        if (state_->operation_active) {
            state_->operation_mutex.unlock();
            return Error{ErrorCode::busy, "Native transport callback cannot reenter the channel"};
        }

        state_->operation_active = true;
        try {
            return Transaction(state_, options);
        } catch (...) {
            state_->operation_active = false;
            state_->operation_mutex.unlock();
            return Error{ErrorCode::internal, "Native transaction construction failed"};
        }
    }

    /** @brief Implement `exchange` to execute one bounded serialized card exchange. */
    Result<Response> RawNativeChannel::exchange(const Request& request,
                                                const ExchangeOptions& options) {
        auto transaction = begin(options);
        if (!transaction) {
            return transaction.error();
        }

        return transaction.value().exchange(request);
    }

    /**
     * @brief Serialize transport reset against native operations.
     * @return Underlying reset evidence or busy for callback reentry.
     */
    Result<void> RawNativeChannel::reset() {
        try {
            std::unique_lock lock(state_->operation_mutex);
            if (state_->operation_active) {
                return Error{ErrorCode::busy,
                             "Native transport callback cannot reset an active channel"};
            }

            state_->operation_active = true;

            struct ActiveReset final {
                bool& active;

                /** @brief Clear reset activity when the transport reset returns. */
                ~ActiveReset() {
                    active = false;
                }
            } active_reset{state_->operation_active};

            return state_->transport->reset();
        } catch (...) {
            return Error{ErrorCode::internal, "Native transport reset threw", Outcome::unknown};
        }
    }

    /** @brief Forward cancellation without taking the channel operation lock. */
    void RawNativeChannel::cancel() noexcept {
        state_->transport->cancel();
    }

    /** @brief Return the framing fixed when this channel was connected. */
    native::Framing RawNativeChannel::framing() const noexcept {
        return state_->framing;
    }

    /** @brief Return the current provider-maintained card generation. */
    std::uint64_t RawNativeChannel::generation() const noexcept {
        return state_->transport->generation();
    }

} // namespace desfire::ev3::native::raw
