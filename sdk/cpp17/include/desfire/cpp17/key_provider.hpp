/**
 * @file key_provider.hpp
 * @brief Move-only AES-128 keys and synchronous custom key-source contracts for C++17.
 */
#pragma once

#include <algorithm>
#include <array>
#include <cstring>
#include <desfire/cpp17/types.hpp>
#include <desfire/key_provider.h>

namespace desfire::cpp17 {

    /** @brief General key use recorded in derivation and provider metadata. */
    enum class KeyPurpose : std::uint32_t {
        authentication = DF_KEY_PURPOSE_AUTHENTICATION, /**< Establish a card session. */
        current_key = DF_KEY_PURPOSE_CURRENT_KEY,       /**< Resolve the currently installed key. */
        replacement_key = DF_KEY_PURPOSE_REPLACEMENT_KEY, /**< Resolve a replacement key. */
        delegated_application = DF_KEY_PURPOSE_DELEGATED_APPLICATION, /**< Authorize a delegated
                                                                         application operation. */
        transaction_mac =
            DF_KEY_PURPOSE_TRANSACTION_MAC, /**< Calculate or verify transaction evidence. */
        offline_operation =
            DF_KEY_PURPOSE_OFFLINE_OPERATION /**< Perform a stateless offline utility. */
    };

    /** @brief Authentication family selected for one provider request. */
    enum class AuthenticationProfile : std::uint32_t {
        standard_aes = DF_AUTH_PROFILE_STANDARD_AES,   /**< Native AuthenticateAES (`0xAA`). */
        ev2_first = DF_AUTH_PROFILE_EV2_FIRST,         /**< EV2 First authentication. */
        ev2_non_first = DF_AUTH_PROFILE_EV2_NON_FIRST, /**< EV2 NonFirst authentication. */
        iso_aes = DF_AUTH_PROFILE_ISO_AES              /**< ISO AES authentication. */
    };

    /** @brief Card key namespace selected for one provider request. */
    enum class KeyScope : std::uint32_t {
        native = DF_KEY_SCOPE_NATIVE,     /**< Native PICC or selected-application key space. */
        iso_picc = DF_KEY_SCOPE_ISO_PICC, /**< ISO PICC master-key scope. */
        iso_application = DF_KEY_SCOPE_ISO_APPLICATION /**< ISO application-key scope. */
    };

    /** @brief Allocation-free cooperative cancellation query for synchronous providers. */
    class CancellationToken final {
    public:

        /** @brief Callback type returning true after cancellation is requested. */
        using Check = bool (*)(void*) noexcept;

        /** @brief Construct a token that never reports cancellation. */
        CancellationToken() noexcept = default;

        /**
         * @brief Borrow one cancellation callback and its context.
         * @param context Caller context that must outlive the authentication call.
         * @param check Nonthrowing cancellation query; null means never cancelled.
         */
        CancellationToken(void* context, Check check) noexcept : context_(context), check_(check) {}

        /**
         * @brief Query the borrowed callback without taking the card operation lock.
         * @return True after cancellation is requested; otherwise false.
         */
        bool stop_requested() const noexcept {
            return check_ != nullptr && check_(context_);
        }

    private:

        void* context_{}; /**< Borrowed context passed to the cancellation callback. */
        Check check_{};   /**< Borrowed nonthrowing cancellation callback. */
    };

    /** @brief Exactly sixteen secret bytes with move-only ownership and best-effort wiping. */
    class Aes128Key final {
    public:

        /** @brief Wipe owned secret bytes before releasing storage. */
        ~Aes128Key() {
            wipe();
        }

        /** @brief Prevent copying secret ownership. */
        Aes128Key(const Aes128Key&) = delete;

        /** @brief Prevent copying secret ownership. */
        Aes128Key& operator=(const Aes128Key&) = delete;

        /**
         * @brief Transfer secret ownership and wipe the moved-from object.
         * @param other Source object whose sole ownership is transferred.
         */
        Aes128Key(Aes128Key&& other) noexcept : bytes_(other.bytes_), valid_(other.valid_) {
            other.wipe();
        }

        /**
         * @brief Replace this key by moving another key and wiping both prior states.
         * @param other Source object whose sole ownership is transferred.
         * @return A reference to this key after ownership transfer.
         */
        Aes128Key& operator=(Aes128Key&& other) noexcept {
            if (this != &other) {
                wipe();
                bytes_ = other.bytes_;
                valid_ = other.valid_;
                other.wipe();
            }
            return *this;
        }

        /**
         * @brief Import exactly sixteen borrowed bytes.
         * @param bytes AES-128 key material copied immediately.
         * @return Move-only key or a local not-sent length error.
         */
        static Result<Aes128Key> import(const Bytes& bytes) {
            if (bytes.size() != 16) {
                return Result<Aes128Key>::failure(
                    detail::invalid_argument("AES-128 keys must contain exactly sixteen bytes"));
            }
            Aes128Key key;
            std::copy(bytes.begin(), bytes.end(), key.bytes_.begin());
            key.valid_ = true;
            return Result<Aes128Key>::success(std::move(key));
        }

        /**
         * @brief Report whether this object still owns a complete key.
         * @return True while this object owns a usable sixteen-byte AES key; otherwise false.
         */
        bool valid() const noexcept {
            return valid_;
        }

        /**
         * @brief Borrow secret bytes only for the duration of a synchronous operation.
         * @return Pointer to the sixteen secret bytes while valid(), otherwise nullptr.
         */
        const std::uint8_t* data() const noexcept {
            return valid_ ? bytes_.data() : nullptr;
        }

        /**
         * @brief Return sixteen for a live key and zero for a moved-from key.
         * @return Sixteen for a live key; zero after its ownership was moved.
         */
        std::size_t size() const noexcept {
            return valid_ ? bytes_.size() : 0;
        }

    private:

        /** @brief Construct empty ownership for import and provider adapters. */
        Aes128Key() noexcept = default;

        /** @brief Overwrite the in-object secret and mark it invalid. */
        void wipe() noexcept {
            volatile std::uint8_t* destination = bytes_.data();
            for (std::size_t index = 0; index < bytes_.size(); ++index) {
                destination[index] = 0;
            }
            valid_ = false;
        }

        std::array<std::uint8_t, 16>
            bytes_{};  /**< In-object secret key bytes overwritten when ownership ends. */
        bool valid_{}; /**< Whether this object currently owns a usable key. */
    };

    /** @brief Non-secret metadata supplied to one custom AES derivation. */
    struct Aes128DerivationContext final {
        KeyPurpose purpose{
            KeyPurpose::authentication}; /**< Operation class for which the key will be used. */
        KeyNumber key_number{
            KeyNumber::make(0)
                .value()}; /**< Native key selector included in derivation and provider metadata. */
        std::optional<ApplicationId> application_id; /**< Optional native application scope. */
        std::optional<KeySetNumber> key_set;         /**< Optional EV3 key-set scope. */
        Bytes
            diversification_input; /**< Explicit non-secret bytes supplied to custom derivation. */
        Bytes user_context;        /**< Opaque non-secret caller routing context. */
    };

    /** @brief Custom synchronous derivation strategy that returns one fresh AES key. */
    class Aes128KeyDeriver {
    public:

        /** @brief Allow destruction through the provider interface. */
        virtual ~Aes128KeyDeriver() = default;

        /**
         * @brief Derive one fresh key without retaining or mutating the borrowed master key.
         * @param master_key Live AES-128 master key borrowed until return.
         * @param context Non-secret construction and routing metadata.
         * @return Fresh move-only AES-128 key or not-sent failure evidence.
         */
        virtual Result<Aes128Key> derive(const Aes128Key& master_key,
                                         const Aes128DerivationContext& context) noexcept = 0;
    };

    /** @brief Non-secret identifier and context for one synchronous provider resolution. */
    struct KeyRequest final {
        Bytes reference; /**< Non-secret provider lookup identifier. */
        Aes128DerivationContext
            context; /**< Derivation context and card scope accompanying the key reference. */
        std::optional<AuthenticationProfile>
            authentication_profile; /**< Optional authentication family for authentication requests.
                                     */
        KeyScope scope{
            KeyScope::native}; /**< Card key namespace containing the requested selector. */
        CancellationToken cancellation; /**< Cooperative cancellation query for provider work. */
    };

    /** @brief Custom synchronous key provider invoked exactly once before the first card frame. */
    class Aes128KeyProvider {
    public:

        /** @brief Allow destruction through the provider interface. */
        virtual ~Aes128KeyProvider() = default;

        /**
         * @brief Resolve one fresh exportable AES key from non-secret request metadata.
         * @param request Metadata borrowed until return; observe its cancellation token if able.
         * @return Fresh move-only AES-128 key or not-sent failure evidence.
         */
        virtual Result<Aes128Key> resolve(const KeyRequest& request) noexcept = 0;
    };

    namespace detail {

        /**
         * @brief Validate C++ request bounds before constructing borrowed C pointers.
         * @param request Non-secret key lookup request borrowed for the synchronous provider call.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        inline Result<void> validate_key_request(const KeyRequest& request) {
            if (request.reference.empty() || request.reference.size() > 1024) {
                return Result<void>::failure(
                    invalid_argument("key reference must contain one through 1024 bytes"));
            }
            const auto diversification_size = request.context.diversification_input.size();
            const auto user_size = request.context.user_context.size();
            if (diversification_size > 65536 || user_size > 65536 ||
                diversification_size > 65536 - user_size) {
                return Result<void>::failure(invalid_argument(
                    "diversification input and user context exceed the 64-KiB bound"));
            }
            const auto purpose = static_cast<std::uint32_t>(request.context.purpose);
            if (purpose > DF_KEY_PURPOSE_OFFLINE_OPERATION) {
                return Result<void>::failure(
                    invalid_argument("key request purpose is outside the documented range"));
            }
            if (request.context.purpose == KeyPurpose::authentication &&
                !request.authentication_profile) {
                return Result<void>::failure(
                    invalid_argument("authentication key requests require an auth profile"));
            }
            if (request.context.purpose != KeyPurpose::authentication &&
                request.authentication_profile) {
                return Result<void>::failure(invalid_argument(
                    "non-authentication key requests must omit the authentication profile"));
            }
            return Result<void>::success();
        }

        /**
         * @brief Query one C++ cancellation token through the C callback shape.
         * @param context Borrowed callback or derivation context that remains valid through the
         * call.
         * @return One when cancellation was requested; otherwise zero.
         */
        inline std::uint32_t key_cancelled(void* context) noexcept {
            const auto* token = static_cast<const CancellationToken*>(context);
            return token != nullptr && token->stop_requested() ? 1U : 0U;
        }

        /**
         * @brief Copy one provider error into fixed C storage without secret-dependent data.
         * @param source Secret-free C++ failure evidence copied into fixed C storage.
         * @param destination Optional C error storage to populate with redacted failure evidence.
         */
        inline void write_native_error(const Error& source, df_error* destination) noexcept {
            if (destination == nullptr) {
                return;
            }
            *destination = {};
            destination->code = static_cast<std::uint32_t>(source.code);
            destination->outcome = static_cast<std::uint32_t>(source.outcome);
            destination->device_status = source.device_status;
            const auto count = std::min(source.message.size(), sizeof(destination->message) - 1);
            std::memcpy(destination->message, source.message.data(), count);
            destination->message[count] = '\0';
        }

        /**
         * @brief Adapt one nonthrowing C++ provider call to the versioned C callback contract.
         * @param context Borrowed callback or derivation context that remains valid through the
         * call.
         * @param native_request Borrowed C request already represented by the retained C++ request.
         * @param key Live AES-128 key borrowed only until the operation returns.
         * @param capacity Writable output capacity in bytes.
         * @param written Output count set to sixteen after successful key resolution.
         * @param error Per-call C error storage paired with the returned status.
         * @return DF_OK after writing exactly sixteen key bytes, or a stable C error code.
         */
        inline std::int32_t resolve_key(void* context, const df_key_request_v1* native_request,
                                        std::uint8_t* key, std::size_t capacity,
                                        std::size_t* written, df_error* error) noexcept {
            (void)native_request;
            if (context == nullptr || key == nullptr || written == nullptr || capacity != 16) {
                const auto failure = invalid_argument("invalid AES provider callback storage");
                write_native_error(failure, error);
                return static_cast<std::int32_t>(failure.code);
            }
            auto* state = static_cast<std::pair<Aes128KeyProvider*, const KeyRequest*>*>(context);
            auto resolved = state->first->resolve(*state->second);
            if (!resolved) {
                write_native_error(resolved.error(), error);
                return static_cast<std::int32_t>(resolved.error().code);
            }
            if (!resolved.value().valid()) {
                const Error failure{ErrorCode::crypto, Outcome::not_sent, 0,
                                    "AES provider returned an invalid key"};
                write_native_error(failure, error);
                return static_cast<std::int32_t>(failure.code);
            }
            std::memcpy(key, resolved.value().data(), 16);
            *written = 16;
            return DF_OK;
        }

        /** @brief Own borrowed C request fields for the duration of one synchronous C call. */
        class ProviderCall final {
        public:

            /**
             * @brief Construct C provider and request descriptors over live C++ objects.
             * @param provider Provider borrowed through the complete authentication call.
             * @param request Request borrowed through the complete authentication call.
             */
            ProviderCall(Aes128KeyProvider& provider, const KeyRequest& request)
                : state_(&provider, &request) {
                provider_.struct_size = sizeof(provider_);
                provider_.abi_version = DF_ABI_VERSION;
                provider_.context = &state_;
                provider_.resolve = &resolve_key;

                request_.struct_size = sizeof(request_);
                request_.abi_version = DF_ABI_VERSION;
                request_.purpose = static_cast<std::uint32_t>(request.context.purpose);
                request_.authentication_profile =
                    request.authentication_profile
                        ? static_cast<std::uint32_t>(*request.authentication_profile)
                        : DF_OPTION_ABSENT;
                request_.scope = static_cast<std::uint32_t>(request.scope);
                request_.key_number = request.context.key_number.value();
                request_.application_id = request.context.application_id
                                              ? request.context.application_id->value()
                                              : DF_OPTION_ABSENT;
                request_.key_set =
                    request.context.key_set ? request.context.key_set->value() : DF_OPTION_ABSENT;
                request_.reference = detail::byte_data(request.reference);
                request_.reference_size = request.reference.size();
                request_.diversification = detail::byte_data(request.context.diversification_input);
                request_.diversification_size = request.context.diversification_input.size();
                request_.user_context = detail::byte_data(request.context.user_context);
                request_.user_context_size = request.context.user_context.size();
                request_.cancellation_context =
                    const_cast<CancellationToken*>(&request.cancellation);
                request_.is_cancelled = &key_cancelled;
            }

            /**
             * @brief Return the temporary C provider descriptor.
             * @return The versioned C provider descriptor valid for the lifetime of this adapter.
             */
            const df_key_provider_v1* provider() const noexcept {
                return &provider_;
            }

            /**
             * @brief Return the temporary C request descriptor.
             * @return The versioned C key request valid for the lifetime of this adapter.
             */
            const df_key_request_v1* request() const noexcept {
                return &request_;
            }

        private:

            std::pair<Aes128KeyProvider*, const KeyRequest*>
                state_; /**< Borrowed provider and request pair retained through the C call. */
            df_key_provider_v1 provider_{}; /**< Versioned C provider descriptor backed by the C++
                                               callback adapter. */
            df_key_request_v1 request_{}; /**< Versioned C request descriptor whose pointers borrow
                                             C++ storage. */
        };

    } // namespace detail
} // namespace desfire::cpp17
