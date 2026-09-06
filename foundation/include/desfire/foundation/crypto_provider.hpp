/**
 * @file
 * @brief Injectable primitives without vendor or OpenSSL types in public interfaces.
 */
#pragma once
#include "secure_buffer.hpp"

namespace desfire {

    /**
     * @brief Primitive algorithms, not DESFire authentication modes or security policies.
     */
    enum class Cipher {
        /** AES with a 128-bit key and a 128-bit block. */
        aes128,

        /** AES with a 192-bit key and a 128-bit block. */
        aes192,

        /** AES with a 256-bit key and a 128-bit block. */
        aes256,

        /** Single DES with a 64-bit key representation and a 64-bit block. */
        des,

        /** Two-key Triple DES with a 128-bit key representation and a 64-bit block. */
        tdes2,

        /** Three-key Triple DES with a 192-bit key representation and a 64-bit block. */
        tdes3
    };

    /**
     * @brief Return the required key width for one primitive cipher.
     * @param cipher Primitive algorithm whose key width is requested.
     * @return Eight bytes for DES, 16 for AES-128/two-key TDEA, 24 for AES-192/three-key TDEA,
     *         or 32 for AES-256.
     * @note The result describes a primitive key, not a DESFire authentication-mode capability.
     */
    inline std::size_t key_size(Cipher cipher) {
        switch (cipher) {
        case Cipher::des:
            return 8;
        case Cipher::aes128:
        case Cipher::tdes2:
            return 16;
        case Cipher::aes192:
        case Cipher::tdes3:
            return 24;
        case Cipher::aes256:
            return 32;
        }
        return 0;
    }

    /**
     * @brief Return the no-padding CBC block width for one primitive cipher.
     * @param cipher Primitive algorithm whose block width is requested.
     * @return Eight bytes for DES/TDEA and 16 bytes for AES.
     */
    inline std::size_t block_size(Cipher cipher) {
        return cipher == Cipher::des || cipher == Cipher::tdes2 || cipher == Cipher::tdes3 ? 8 : 16;
    }

    /**
     * @brief Cryptographic primitives supplied independently of the protocol engine.
     *
     * Inputs are borrowed for the duration of a call. Providers must use a secure random
     * source and must not retain or log caller keys. DESFire session derivation, padding,
     * MAC truncation, and counters belong to the protocol implementation.
     */
    class CryptoProvider {
    public:

        /** @brief Destroy a provider after callers have released all borrowed input views. */
        virtual ~CryptoProvider() = default;

        /**
         * @brief Produce cryptographically random bytes without a deterministic fallback.
         * @param size Exact number of random bytes requested.
         * @return Exactly @p size owned bytes, or a crypto failure before protocol I/O begins.
         */
        virtual Result<Bytes> random(std::size_t size) = 0;

        /**
         * @brief Apply one no-padding CBC operation.
         * @param cipher Selected primitive algorithm.
         * @param key Borrowed key with the exact width returned by key_size(@p cipher).
         * @param iv Borrowed initial vector with the exact width returned by block_size(@p cipher).
         * @param input Borrowed whole-number-of-blocks input; ownership remains with the caller.
         * @param encrypt True for primitive CBC encryption and false for primitive CBC decryption.
         * @return Owned output with the same size as @p input, or a crypto/argument failure.
         * @pre The provider must not apply padding, retain the key, or log any input.
         */
        virtual Result<Bytes> cbc(Cipher cipher, ByteView key, ByteView iv, ByteView input,
                                  bool encrypt) = 0;

        /**
         * @brief Calculate the complete primitive CMAC for a borrowed message.
         * @param cipher CMAC-capable primitive algorithm.
         * @param key Borrowed key with the required primitive width.
         * @param input Borrowed message bytes, including an allowed empty message.
         * @return The full provider CMAC; protocol code owns truncation and wire ordering.
         */
        virtual Result<Bytes> cmac(Cipher cipher, ByteView key, ByteView input) = 0;

        /**
         * @brief Verify a digest against a fixed-width raw ECDSA `r || s` signature.
         * @param curve Provider-supported curve name.
         * @param public_key Borrowed encoded public key accepted by the selected provider.
         * @param digest Borrowed precomputed digest; this method does not hash input data.
         * @param raw_signature Borrowed fixed-width concatenation of `r` and `s`.
         * @return True for a valid signature, false for a validly parsed mismatch, or an error for
         *         unsupported/malformed cryptographic inputs.
         */
        virtual Result<bool> verify_ecdsa(std::string_view curve, ByteView public_key,
                                          ByteView digest, ByteView raw_signature) = 0;
    };

    /**
     * @brief Resolve a host-accessible software key into move-only storage.
     *
     * Opaque SAM keys require a separate provider that performs cryptographic operations
     * without exporting key bytes into host memory.
     */
    class KeyProvider {
    public:

        /** @brief Destroy the provider after consumers release all resolved key handles. */
        virtual ~KeyProvider() = default;

        /**
         * @brief Resolve one named software key into owned sensitive storage.
         * @param reference Provider-defined stable key reference; it is not interpreted by core.
         * @param algorithm Required primitive algorithm and output width.
         * @return Move-only key material with the exact @p algorithm width, or an error.
         * @warning Implementations must not return aliases to mutable key-store buffers or log
         *          either the reference's secret content or resolved key bytes.
         */
        virtual Result<SecureBuffer> resolve(std::string_view reference, Cipher algorithm) = 0;
    };

} // namespace desfire
