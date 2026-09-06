/**
 * @file originality_signature.cpp
 * @brief Offline originality-signature implementation.
 */
#include <desfire/ev3/offline/originality_signature.hpp>

#include "detail/aes_support.hpp"

#include <algorithm>

namespace desfire::ev3::offline {

    using namespace detail;

    /** @brief Implement caller-key originality-signature verification. */
    Result<bool> verify_originality_uid_signature(CryptoProvider& crypto,
                                                  ByteView trusted_public_key, ByteView uid,
                                                  ByteView signature) {
        if (trusted_public_key.size() != 57 || trusted_public_key.front() != 0x04 ||
            uid.size() != 7 || signature.size() != 56) {
            return invalid("Originality verification requires a 57-byte SEC1 key, 7-byte UID and "
                           "56-byte signature");
        }
        try {
            return crypto.verify_ecdsa("secp224r1", trusted_public_key, uid, signature);
        } catch (...) {
            return Error{ErrorCode::internal, "Offline originality verification failed"};
        }
    }

} // namespace desfire::ev3::offline
