/**
 * @file
 * @brief Explicit construction of the optional OpenSSL primitive provider.
 */
#pragma once
#include <desfire/foundation/crypto_provider.hpp>
#include <memory>

namespace desfire {
    /**
     * @brief Create a provider with its own OpenSSL library context.
     * @param allow_legacy Explicitly permit DES/TDEA and load OpenSSL's legacy provider.
     * @return A shared primitive provider, or a failure if required modules cannot load.
     *
     * This factory does not change the process-wide OpenSSL configuration. It does not
     * authenticate cards, derive DESFire session keys, or assert a compliance certification.
     */
    Result<std::shared_ptr<CryptoProvider>> openssl_provider(bool allow_legacy = false);
} // namespace desfire
