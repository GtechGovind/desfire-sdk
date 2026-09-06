/**
 * @file adapters.cpp
 * @brief Retained transport and key-provider adapters for the C ABI.
 */
#include "detail/internal.hpp"

#include <limits>

namespace desfire::c_api::detail {
    namespace {
        /**
         * @brief Report whether every ABI-reserved word remains zero.
         * @tparam Size Compile-time reserved-word count.
         * @param reserved Fixed reserved-word array to inspect.
         * @return True only when every reserved word is zero.
         */
        template <std::size_t Size>
        bool reserved_is_zero(const std::uint64_t (&reserved)[Size]) noexcept {
            return std::all_of(std::begin(reserved), std::end(reserved),
                               [](std::uint64_t value) { return value == 0; });
        }

        /**
         * @brief Translate callback evidence without trusting out-of-range enum values.
         * @param code Integer error code returned by the foreign callback.
         * @param evidence Foreign callback status and delivery evidence.
         * @return Redacted internal error with validated code and outcome values.
         */
        Error callback_error(std::int32_t code, const df_error& evidence) {
            const bool valid_code = code >= DF_INVALID_ARGUMENT && code <= DF_INTERNAL;
            const bool valid_outcome = evidence.outcome <= DF_UNKNOWN;
            return Error{valid_code ? static_cast<ErrorCode>(code) : ErrorCode::transport,
                         "Reader callback failed",
                         valid_outcome ? static_cast<Outcome>(evidence.outcome) : Outcome::unknown,
                         evidence.device_status};
        }
    } // namespace

    /** @brief Implement the documented `TransportLease::TransportLease` helper. */
    TransportLease::TransportLease(const df_transport_v1& descriptor) : descriptor_(descriptor) {
        if (descriptor_.retain) {
            descriptor_.retain(descriptor_.context);
        }
    }

    /** @brief Implement the documented `TransportLease::~TransportLease` helper. */
    TransportLease::~TransportLease() {
        try {
            if (descriptor_.release) {
                descriptor_.release(descriptor_.context);
            }
        } catch (...) {
            // A foreign release callback cannot propagate from a C++ destructor.
        }
    }

    /** @brief Implement the documented `TransportLease::descriptor` helper. */
    const df_transport_v1& TransportLease::descriptor() const noexcept {
        return descriptor_;
    }

    /** @brief Implement the documented `make_transport` helper. */
    Result<std::shared_ptr<transports::CallbackTransport>>
    make_transport(const df_transport_v1* descriptor) {
        constexpr std::size_t maximum_buffer = 16U * 1024U * 1024U;
        if (!descriptor || descriptor->struct_size != sizeof(df_transport_v1) ||
            descriptor->abi_version != DF_ABI_VERSION || descriptor->framing > DF_ISO_WRAPPED ||
            !descriptor->exchange || descriptor->max_transmit < 6 || descriptor->max_receive < 2 ||
            descriptor->max_native_frame < 2 || descriptor->max_transmit > maximum_buffer ||
            descriptor->max_receive > maximum_buffer ||
            descriptor->max_native_frame > descriptor->max_transmit ||
            ((descriptor->retain == nullptr) != (descriptor->release == nullptr)) ||
            !reserved_is_zero(descriptor->reserved)) {
            return invalid("Invalid transport ABI, callbacks, limits or reserved fields");
        }

        auto lease = std::make_shared<TransportLease>(*descriptor);
        const auto& config = lease->descriptor();
        TransportCapabilities capabilities;
        capabilities.framing = config.framing == DF_NATIVE ? Framing::native : Framing::iso7816;
        capabilities.max_transmit = config.max_transmit;
        capabilities.max_receive = config.max_receive;
        capabilities.max_native_frame = config.max_native_frame;
        capabilities.can_cancel = config.cancel != nullptr;
        capabilities.can_reset = config.reset != nullptr;

        transports::TransportCallbacks callbacks;
        callbacks.exchange = [lease](ByteView request,
                                     const ExchangeOptions& options) -> Result<Bytes> {
            const auto& current = lease->descriptor();
            Bytes response(current.max_receive);
            std::size_t received{};
            df_error evidence{};
            evidence.outcome = DF_UNKNOWN;
            const auto remaining = options.timeout.count();
            const auto timeout = static_cast<std::uint32_t>(
                std::min<std::int64_t>(remaining, std::numeric_limits<std::uint32_t>::max()));
            const auto status =
                current.exchange(current.context, request.data(), request.size(), response.data(),
                                 response.size(), &received, timeout, &evidence);
            if (status != DF_OK) {
                return callback_error(status, evidence);
            }
            if (received > response.size()) {
                return Error{ErrorCode::malformed_response,
                             "Reader callback exceeded receive capacity", Outcome::unknown};
            }
            response.resize(received);
            return response;
        };
        if (config.cancel) {
            callbacks.cancel = [lease] {
                const auto& current = lease->descriptor();
                current.cancel(current.context);
            };
        }
        if (config.reset) {
            callbacks.reset = [lease]() -> Result<void> {
                const auto& current = lease->descriptor();
                df_error evidence{};
                evidence.outcome = DF_UNKNOWN;
                const auto status = current.reset(current.context, &evidence);
                if (status != DF_OK) {
                    return callback_error(status, evidence);
                }
                return {};
            };
        }
        return std::make_shared<transports::CallbackTransport>(capabilities, std::move(callbacks));
    }

    /** @brief Implement the documented `KeyProviderAdapter::create` helper. */
    Result<std::unique_ptr<KeyProviderAdapter>>
    KeyProviderAdapter::create(const df_key_provider_v1* provider,
                               const df_key_request_v1* request) {
        if (!provider || !request || provider->struct_size != sizeof(df_key_provider_v1) ||
            provider->abi_version != DF_ABI_VERSION || !provider->resolve ||
            ((provider->retain == nullptr) != (provider->release == nullptr)) ||
            !reserved_is_zero(provider->reserved)) {
            return invalid("Invalid AES-128 key-provider descriptor");
        }
        return std::unique_ptr<KeyProviderAdapter>(new KeyProviderAdapter(*provider, *request));
    }

    /** @brief Implement the documented `KeyProviderAdapter::KeyProviderAdapter` helper. */
    KeyProviderAdapter::KeyProviderAdapter(df_key_provider_v1 provider, df_key_request_v1 request)
        : provider_(provider), request_(request) {
        if (provider_.retain) {
            provider_.retain(provider_.context);
        }
    }

    /** @brief Implement the documented `KeyProviderAdapter::~KeyProviderAdapter` helper. */
    KeyProviderAdapter::~KeyProviderAdapter() {
        try {
            if (provider_.release) {
                provider_.release(provider_.context);
            }
        } catch (...) {
            // A foreign release callback cannot propagate from a C++ destructor.
        }
    }

    /** @brief Implement the documented `KeyProviderAdapter::resolve` helper. */
    Result<key_derivation::Aes128Key>
    KeyProviderAdapter::resolve(const key_derivation::KeyRequest& request) {
        static_cast<void>(request);
        if (resolved_) {
            return Error{ErrorCode::internal, "Key provider was invoked more than once"};
        }
        resolved_ = true;
        if (request_.is_cancelled && request_.is_cancelled(request_.cancellation_context) != 0) {
            return Error{ErrorCode::cancelled, "Key resolution cancelled before provider access"};
        }

        SecureBuffer key(key_derivation::aes128_key_size);
        std::size_t written{};
        df_error evidence{};
        evidence.outcome = DF_NOT_SENT;
        const auto status =
            provider_.resolve(provider_.context, &request_, key.mutable_view().data(), key.size(),
                              &written, &evidence);
        if (status != DF_OK) {
            const bool valid_code = status >= DF_INVALID_ARGUMENT && status <= DF_INTERNAL;
            return Error{valid_code ? static_cast<ErrorCode>(status) : ErrorCode::crypto,
                         "AES-128 key provider failed", Outcome::not_sent};
        }
        if (written != key_derivation::aes128_key_size) {
            return Error{ErrorCode::crypto, "AES-128 key provider returned an invalid key size"};
        }
        return key_derivation::Aes128Key::adopt(std::move(key));
    }

} // namespace desfire::c_api::detail
