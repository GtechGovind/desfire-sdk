/**
 * @file nxp_aes128.hpp
 * @brief NXP AN10922 AES-128 diversification for scoped managed keys.
 */
#pragma once

#include "aes128.hpp"

#include <desfire/foundation/crypto_provider.hpp>

#include <memory>

namespace desfire::ev3::security::key_derivation::nxp_aes128 {

    /**
     * @brief Derive an AES-128 key using NXP AN10922 revision 2.2 section 2.2.
     * @param crypto AES-128 no-padding CBC primitive provider.
     * @param master_key Exact caller-owned AES-128 master key.
     * @param context Context whose diversification input must contain one through 31 bytes.
     * @return Independently owned move-only AES-128 key.
     *
     * The caller defines the diversification input and its byte order. Purpose, card key number,
     * application, key set, and user context remain policy metadata and are not silently inserted
     * into the AN10922 byte string. The construction always processes two AES blocks.
     */
    Result<Aes128Key> derive(CryptoProvider& crypto, const Aes128Key& master_key,
                             const Aes128DerivationContext& context);

    /** @brief Apply NXP AN10922 through an injected AES primitive provider. */
    class Deriver final : public Aes128KeyDeriver {
    public:

        /**
         * @brief Retain a primitive provider without retaining any master-key material.
         * @param crypto Shared AES provider; null causes derivation to fail locally.
         */
        explicit Deriver(std::shared_ptr<CryptoProvider> crypto);

        /**
         * @brief Diversify one scoped AES-128 software key.
         * @param master_key Exact caller-owned master key.
         * @param context Bounded context containing a one through 31-byte diversification input.
         * @return Independent exact key or argument/crypto failure before card I/O.
         */
        Result<Aes128Key> derive(const Aes128Key& master_key,
                                 const Aes128DerivationContext& context) override;

    private:

        std::shared_ptr<CryptoProvider> crypto_; ///< Primitive provider without retained key data.
    };

} // namespace desfire::ev3::security::key_derivation::nxp_aes128
