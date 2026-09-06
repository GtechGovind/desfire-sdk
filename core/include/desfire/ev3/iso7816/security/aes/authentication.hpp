/**
 * @file authentication.hpp
 * @brief Named ISO mutual AES authentication factory.
 */
#pragma once

#include <desfire/ev3/iso7816/checked/channel.hpp>
#include <desfire/foundation/crypto_provider.hpp>

#include <memory>

namespace desfire::ev3::iso7816::security::aes {

    class Session;

    /**
     * @brief Complete mutual ISO AES authentication under one deadline.
     * @param channel Checked channel bound to one exclusively owned APDU transport.
     * @param crypto AES randomness and no-padding CBC provider.
     * @param key Checked PICC or application key reference.
     * @param derived_key Borrowed exact sixteen-byte AES card key.
     * @param options Shared timeout and cancellation controls for the complete proof.
     * @param encoding APDU length representation for all authentication steps.
     * @return Verified session with a private derived key after card proof verification.
     * @warning The channel must outlive the returned session.
     */
    Result<std::unique_ptr<Session>>
    authenticate(checked::Channel& channel, CryptoProvider& crypto, checked::KeyReference key,
                 ByteView derived_key, const ExchangeOptions& options = {},
                 raw::LengthEncoding encoding = raw::LengthEncoding::automatic);

} // namespace desfire::ev3::iso7816::security::aes
