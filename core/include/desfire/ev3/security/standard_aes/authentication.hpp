/**
 * @file authentication.hpp
 * @brief Standard DESFire AES authentication using native command 0xAA.
 */
#pragma once

#include <desfire/ev3/native/raw/message.hpp>
#include <desfire/foundation/crypto_provider.hpp>

#include <functional>

namespace desfire::ev3::security::standard_aes {

    /** @brief Move-only session key produced by verified standard AES authentication. */
    struct AuthenticationMaterial {
        SecureBuffer session_key; ///< Sixteen-byte key derived from the verified nonce exchange.
    };

    /**
     * @brief Exchange one authentication frame through a caller-owned serialized connection.
     *
     * The callback must send exactly one native frame, must not retry uncertain delivery, and must
     * remain valid until authenticate() returns.
     */
    using AuthenticationExchange =
        std::function<Result<native::raw::Response>(Byte command, ByteView payload)>;

    /**
     * @brief Execute standard AES Authenticate using native command 0xAA.
     * @param crypto AES-CBC and cryptographically secure random provider.
     * @param key_number Native key selector, zero through 63.
     * @param key Exactly sixteen direct or host-derived AES-128 key bytes.
     * @param exchange Serialized one-frame exchange callback owned by Card.
     * @return Verified move-only session material, or exact local/card/transport evidence.
     *
     * Successful authentication establishes chained-IV standard AES secure messaging. It is
     * distinct from AuthenticateEV2First and AuthenticateEV2NonFirst.
     */
    Result<AuthenticationMaterial> authenticate(CryptoProvider& crypto, Byte key_number,
                                                ByteView key,
                                                const AuthenticationExchange& exchange);

} // namespace desfire::ev3::security::standard_aes
