/**
 * @file originality_signature.hpp
 * @brief Offline originality-signature verification with caller-owned trust anchors.
 */
#pragma once

#include <desfire/foundation/crypto_provider.hpp>

namespace desfire::ev3::offline {

    /**
     * @brief Verify the raw-UID secp224r1 originality-signature construction with an explicit key.
     * @param crypto ECDSA verification provider; UID is passed as the raw digest without hashing.
     * @param trusted_public_key Exactly 57 SEC1 bytes: 0x04 followed by 28-byte X and Y values.
     * @param uid Exactly seven real UID bytes in transmitted order.
     * @param signature Exactly 56 signature bytes, 28-byte r followed by 28-byte s.
     * @return True for a valid signature, false for mismatch, or an argument/provider error.
     *
     * The host must select the authoritative key for its specific product. No default key
     * from a different DESFire product is selected, and this static signature does not
     * establish a live authenticated card session.
     */
    Result<bool> verify_originality_uid_signature(CryptoProvider& crypto,
                                                  ByteView trusted_public_key, ByteView uid,
                                                  ByteView signature);

} // namespace desfire::ev3::offline
