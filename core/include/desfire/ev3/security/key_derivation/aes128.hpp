/**
 * @file aes128.hpp
 * @brief Exact move-only AES-128 keys and host key-resolution interfaces.
 */
#pragma once

#include <desfire/ev3/model/authentication.hpp>
#include <desfire/foundation/secure_buffer.hpp>

#include <utility>

namespace desfire::ev3::security::key_derivation {

    /** @brief Exact byte width of every managed AES-128 authentication key. */
    inline constexpr std::size_t aes128_key_size = 16;

    /**
     * @brief Own exactly 16 key bytes and wipe them on destruction or replacement.
     *
     * The type is move-only so authentication, derivation, and provider paths transfer one scoped
     * owner. It does not lock memory and cannot erase copies retained by callers, providers, the
     * operating system, or a cryptographic primitive implementation.
     */
    class Aes128Key final {
    public:

        /**
         * @brief Copy exactly 16 caller-owned bytes into wiped storage.
         * @param bytes Borrowed AES-128 key material copied during this call.
         * @return Move-only key, or invalid_argument for every other length.
         */
        static Result<Aes128Key> import(ByteView bytes);

        /**
         * @brief Adopt a move-only buffer only when it contains exactly 16 bytes.
         * @param bytes Secret allocation whose ownership is consumed on success or failure.
         * @return Move-only key, or invalid_argument after the rejected buffer is wiped.
         */
        static Result<Aes128Key> adopt(SecureBuffer bytes);

        /** @brief Wipe the owned key allocation. */
        ~Aes128Key() = default;

        /**
         * @brief Transfer exact key ownership.
         * @param other Key whose views become invalid after the move.
         */
        Aes128Key(Aes128Key&& other) noexcept = default;

        /**
         * @brief Wipe the current key and adopt a replacement.
         * @param other Key whose views become invalid after the move.
         * @return This exact-key owner.
         */
        Aes128Key& operator=(Aes128Key&& other) noexcept = default;

        /** @brief Prevent copying AES key material. */
        Aes128Key(const Aes128Key&) = delete;

        /** @brief Prevent copy assignment of AES key material. */
        Aes128Key& operator=(const Aes128Key&) = delete;

        /**
         * @brief Borrow key bytes for one synchronous cryptographic operation.
         * @return Exactly 16 bytes until this key is moved, replaced, or destroyed; an empty view
         * from a moved-from key.
         */
        [[nodiscard]] ByteView view() const noexcept;

        /**
         * @brief Report whether this object still owns an exact key after moves.
         * @return True only when 16 bytes remain owned.
         */
        [[nodiscard]] bool valid() const noexcept;

    private:

        /**
         * @brief Retain a buffer already proven to contain exactly 16 bytes.
         * @param bytes Move-only exact key material.
         */
        explicit Aes128Key(SecureBuffer bytes) : bytes_(std::move(bytes)) {}

        SecureBuffer bytes_; ///< Owned sensitive byte storage.
    };

    /**
     * @brief Derive one exportable AES-128 key from a scoped master key and caller context.
     */
    class Aes128KeyDeriver {
    public:

        /** @brief Destroy the deriver after every synchronous `derive()` call returns. */
        virtual ~Aes128KeyDeriver();

        /**
         * @brief Derive exactly one key without retaining inputs.
         * @param master_key Exact caller-owned master key borrowed for this call.
         * @param context Bounded purpose, selector, diversification, and user context.
         * @return Independent move-only AES-128 key or redacted local failure evidence.
         */
        virtual Result<Aes128Key> derive(const Aes128Key& master_key,
                                         const Aes128DerivationContext& context) = 0;
    };

    /**
     * @brief Resolve one exportable AES-128 key from a host key service or software store.
     *
     * Non-exportable SAM/HSM keys require a separate cryptographic-operation provider because this
     * interface returns key bytes. Implementations receive only non-secret reference/context data
     * and must observe `KeyRequest::cancellation()` when their backend supports cancellation.
     */
    class Aes128KeyProvider {
    public:

        /** @brief Destroy the provider after every synchronous `resolve()` call returns. */
        virtual ~Aes128KeyProvider();

        /**
         * @brief Resolve exactly one independently owned AES-128 key.
         * @param request Non-secret key reference, policy context, scope, and cancellation token.
         * @return Move-only exact key or redacted provider failure evidence.
         * @warning Implementations must not put secret bytes in diagnostics or persistent logs.
         */
        virtual Result<Aes128Key> resolve(const KeyRequest& request) = 0;
    };

} // namespace desfire::ev3::security::key_derivation
