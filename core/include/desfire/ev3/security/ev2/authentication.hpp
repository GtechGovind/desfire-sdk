/**
 * @file authentication.hpp
 * @brief DESFire EV2 First and NonFirst AES authentication available on EV3.
 */
#pragma once

#include <desfire/ev3/model/authentication.hpp>
#include <desfire/ev3/native/raw/message.hpp>
#include <desfire/foundation/crypto_provider.hpp>

#include <functional>

namespace desfire::ev3::security::ev2 {

    /** @brief Move-only session secrets and public metadata from verified EV2 authentication. */
    struct AuthenticationMaterial {
        SecureBuffer encryption_key; ///< Sixteen-byte session encryption key.
        SecureBuffer mac_key;        ///< Sixteen-byte session message-authentication key.
        model::AuthenticationInfo
            information{}; ///< Verified public transaction and capability data.
    };

    /**
     * @brief Exchange one authentication frame through a caller-owned serialized connection.
     *
     * The callback must send exactly one native frame, must not retry uncertain delivery, and must
     * remain valid until the authentication function returns.
     */
    using AuthenticationExchange =
        std::function<Result<native::raw::Response>(Byte command, ByteView payload)>;

    /**
     * @brief Execute AuthenticateEV2First without a PCD capability record.
     * @param crypto AES-CBC, AES-CMAC, and cryptographically secure random provider.
     * @param key_number EV3 key selector, zero through 63.
     * @param key Exactly sixteen direct or host-derived AES-128 key bytes.
     * @param exchange Serialized one-frame exchange callback owned by Card.
     * @return Private session keys and verified public transaction metadata.
     */
    Result<AuthenticationMaterial> authenticate_first(CryptoProvider& crypto, Byte key_number,
                                                      ByteView key,
                                                      const AuthenticationExchange& exchange);

    /**
     * @brief Execute AuthenticateEV2First with an explicit PCD capability record.
     * @param crypto AES-CBC, AES-CMAC, and cryptographically secure random provider.
     * @param key_number EV3 key selector, zero through 63.
     * @param key Exactly sixteen direct or host-derived AES-128 key bytes.
     * @param pcd_capabilities Zero through six PCD capability bytes sent to the card.
     * @param exchange Serialized one-frame exchange callback owned by Card.
     * @return Private session keys and verified public transaction metadata.
     *
     * The card must echo the supplied bytes and zero-pad the returned record to six bytes. An echo
     * mismatch fails authentication before session keys are exposed.
     */
    Result<AuthenticationMaterial> authenticate_first(CryptoProvider& crypto, Byte key_number,
                                                      ByteView key, ByteView pcd_capabilities,
                                                      const AuthenticationExchange& exchange);

    /**
     * @brief Execute AuthenticateEV2NonFirst while retaining verified transaction metadata.
     * @param crypto AES-CBC, AES-CMAC, and cryptographically secure random provider.
     * @param key_number EV3 key selector, zero through 63.
     * @param key Exactly sixteen direct or host-derived AES-128 key bytes.
     * @param previous Metadata verified by the active First authentication.
     * @param exchange Serialized one-frame exchange callback owned by Card.
     * @return Replacement session keys and retained public transaction metadata.
     */
    Result<AuthenticationMaterial> authenticate_nonfirst(CryptoProvider& crypto, Byte key_number,
                                                         ByteView key,
                                                         model::AuthenticationInfo previous,
                                                         const AuthenticationExchange& exchange);

} // namespace desfire::ev3::security::ev2
