/**
 * @file
 * @brief Private-context EVP implementation and local cryptographic resource ownership.
 */
#include <desfire/crypto/openssl.hpp>
#include <limits>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

namespace desfire {
    namespace {
        // OpenSSL allocates opaque objects with different destruction functions. Pair each
        // allocation with its matching deleter so every early-return path releases it.
        template <class T, auto Free> using Owner = std::unique_ptr<T, decltype(Free)>;

        // Keep the public failure generic: provider internals and input material must not
        // accidentally become diagnostics. Detailed secret-free observability can be added
        // separately.
        /**
         * @brief Create a generic crypto failure for provider errors.
         *
         * @return Error that does not expose provider internals or input material.
         */
        Error failure() {
            return {ErrorCode::crypto, "Cryptographic provider operation failed"};
        }

        /**
         * @brief Map DESFire cipher to OpenSSL cipher-name constants.
         *
         * @param c Engine cipher descriptor.
         * @return OpenSSL cipher name string.
         */
        const char* cipher_name(Cipher c) {
            // Fetch by algorithm name inside our private context, never through deprecated
            // low-level cipher APIs or process-global provider configuration.
            switch (c) {
            case Cipher::aes128:
                return "AES-128-CBC";
            case Cipher::aes192:
                return "AES-192-CBC";
            case Cipher::aes256:
                return "AES-256-CBC";
            case Cipher::des:
                return "DES-CBC";
            case Cipher::tdes2:
                return "DES-EDE-CBC";
            case Cipher::tdes3:
                return "DES-EDE3-CBC";
            }
            return "";
        }

        class OpenSsl final : public CryptoProvider {
            // A private context makes legacy opt-in local to this SDK instance. Session
            // state is not stored here; each primitive call creates its own working context.
            OSSL_LIB_CTX* context_{OSSL_LIB_CTX_new()};
            OSSL_PROVIDER* normal_{nullptr};
            OSSL_PROVIDER* legacy_{nullptr};
            bool allow_legacy_;

        public:

            /**
             * @brief Create an OpenSSL-backed provider and optional legacy context.
             *
             * @param legacy Whether to load the legacy provider for DES/TDEA.
             */
            explicit OpenSsl(bool legacy) : allow_legacy_(legacy) {
                // Load only the requested provider set. good() makes initialization failure
                // observable through the factory instead of exposing a half-ready object.
                if (context_) {
                    normal_ = OSSL_PROVIDER_load(context_, "default");
                    if (legacy) {
                        legacy_ = OSSL_PROVIDER_load(context_, "legacy");
                    }
                }
            }

            /**
             * @brief Release loaded providers before freeing the private OpenSSL context.
             */
            ~OpenSsl() override {
                // Provider handles belong to the library context and must be released first.
                OSSL_PROVIDER_unload(legacy_);
                OSSL_PROVIDER_unload(normal_);
                OSSL_LIB_CTX_free(context_);
            }

            /**
             * @brief Check provider initialization and requested legacy policy load.
             *
             * @return True when the default provider is available and legacy policy
             * is present when requested.
             */
            bool good() const {
                // Legacy mode is explicit: failing to load it must not silently downgrade policy.
                return context_ && normal_ && (!allow_legacy_ || legacy_);
            }

            /**
             * @brief Return cryptographically random bytes.
             *
             * @param n Byte count requested.
             * @return Random bytes or an invalid/crypto error.
             */
            Result<Bytes> random(std::size_t n) override {
                // Bound an accidental oversized allocation. A failed CSPRNG never falls
                // back to deterministic or lower-quality entropy.
                if (n > 16 * 1024 * 1024) {
                    return invalid("Random request too large");
                }
                Bytes out(n);
                if (n && RAND_bytes_ex(context_, out.data(), n, 0) != 1) {
                    return failure();
                }
                return out;
            }

            /**
             * @brief Run AES/TDEA CBC encryption or decryption without padding.
             *
             * IV length and input multiple-of-block restrictions are enforced before
             * dispatching to the OpenSSL context.
             *
             * @param algorithm Requested cipher mode.
             * @param key Key bytes.
             * @param iv Initialization vector.
             * @param input Input bytes.
             * @param encrypt True for encrypt, false for decrypt.
             * @return Cipher output bytes.
             */
            Result<Bytes> cbc(Cipher algorithm, ByteView key, ByteView iv, ByteView input,
                              bool encrypt) override {
                // Validate before modulo and integer narrowing. Short-circuit evaluation
                // rejects an invalid IV length before it can become a zero divisor.
                if (key.size() != key_size(algorithm) || iv.size() != block_size(algorithm) ||
                    input.size() % iv.size() ||
                    input.size() > std::size_t(std::numeric_limits<int>::max() - 32)) {
                    return invalid("Invalid cipher key, IV, or block length");
                }
                if (block_size(algorithm) == 8 && !allow_legacy_) {
                    return Error{ErrorCode::unsupported,
                                 "Legacy cryptography requires explicit opt-in"};
                }
                Owner<EVP_CIPHER, EVP_CIPHER_free> cipher(
                    EVP_CIPHER_fetch(context_, cipher_name(algorithm), nullptr), EVP_CIPHER_free);
                Owner<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> ctx(EVP_CIPHER_CTX_new(),
                                                               EVP_CIPHER_CTX_free);
                if (!cipher || !ctx) {
                    return failure();
                }
                if (EVP_CipherInit_ex2(ctx.get(), cipher.get(), key.data(), iv.data(),
                                       encrypt ? 1 : 0, nullptr) != 1 ||
                    EVP_CIPHER_CTX_set_padding(ctx.get(), 0) != 1) {
                    return failure();
                }
                // Disable OpenSSL padding because the DESFire security mode owns padding
                // and CRC placement. Reserve a block for EVP's documented output headroom.
                Bytes out(input.size() + block_size(algorithm));
                int used = 0;
                if (EVP_CipherUpdate(ctx.get(), out.data(), &used, input.data(),
                                     static_cast<int>(input.size())) != 1 ||
                    used < 0 || static_cast<std::size_t>(used) > out.size()) {
                    wipe(out);
                    // Failed decryption may have produced partial plaintext: erase it
                    // instead of returning or retaining an unauthenticated fragment.
                    return failure();
                }
                const auto used_size = static_cast<std::size_t>(used);
                int tail = 0;
                if (EVP_CipherFinal_ex(ctx.get(), out.data() + used_size, &tail) != 1 || tail < 0 ||
                    static_cast<std::size_t>(tail) > out.size() - used_size) {
                    wipe(out);
                    return failure();
                }
                out.resize(used_size + static_cast<std::size_t>(tail));
                return out;
            }

            /**
             * @brief Compute CMAC over an input message.
             *
             * @param algorithm Supported key algorithm.
             * @param key CMAC key.
             * @param input Message bytes.
             * @return CMAC output of the cipher block size.
             */
            Result<Bytes> cmac(Cipher algorithm, ByteView key, ByteView input) override {
                // Return a full primitive CMAC. EV1/EV2/LRP truncation and message layout
                // must be applied by their respective protocol constructions, not here.
                if (key.size() != key_size(algorithm)) {
                    return invalid("Invalid CMAC key size");
                }
                if (block_size(algorithm) == 8 && !allow_legacy_) {
                    return Error{ErrorCode::unsupported,
                                 "Legacy cryptography requires explicit opt-in"};
                }
                Owner<EVP_MAC, EVP_MAC_free> mac(EVP_MAC_fetch(context_, "CMAC", nullptr),
                                                 EVP_MAC_free);
                if (!mac) {
                    return failure();
                }
                Owner<EVP_MAC_CTX, EVP_MAC_CTX_free> ctx(EVP_MAC_CTX_new(mac.get()),
                                                         EVP_MAC_CTX_free);
                char* name = const_cast<char*>(cipher_name(algorithm));
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, name, 0),
                    OSSL_PARAM_construct_end()};
                Bytes out(block_size(algorithm));
                std::size_t count = 0;
                if (!ctx || EVP_MAC_init(ctx.get(), key.data(), key.size(), params) != 1 ||
                    EVP_MAC_update(ctx.get(), input.data(), input.size()) != 1 ||
                    EVP_MAC_final(ctx.get(), out.data(), &count, out.size()) != 1) {
                    return failure();
                }
                out.resize(count);
                return out;
            }

            /**
             * @brief Verify raw ECDSA signature data using OpenSSL.
             *
             * @param curve Named curve identifier.
             * @param public_key Caller-encoded public key.
             * @param digest Message digest bytes.
             * @param signature Raw R||S signature material.
             * @return True when verification succeeds, false for mismatch.
             */
            Result<bool> verify_ecdsa(std::string_view curve, ByteView public_key, ByteView digest,
                                      ByteView signature) override {
                // The API accepts raw r || s and a caller-supplied digest. OpenSSL expects
                // DER for verification, so only the signature encoding is converted here.
                if (curve.empty() || public_key.empty() || signature.empty() ||
                    signature.size() % 2 || signature.size() > 132) {
                    return invalid("Invalid ECDSA input");
                }
                std::string curve_name(curve);
                Owner<EVP_PKEY_CTX, EVP_PKEY_CTX_free> import(
                    EVP_PKEY_CTX_new_from_name(context_, "EC", nullptr), EVP_PKEY_CTX_free);
                OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                                        curve_name.data(), 0),
                                       OSSL_PARAM_construct_octet_string(
                                           OSSL_PKEY_PARAM_PUB_KEY,
                                           const_cast<Byte*>(public_key.data()), public_key.size()),
                                       OSSL_PARAM_construct_end()};
                EVP_PKEY* raw = nullptr;
                if (!import || EVP_PKEY_fromdata_init(import.get()) != 1 ||
                    EVP_PKEY_fromdata(import.get(), &raw, EVP_PKEY_PUBLIC_KEY, params) != 1) {
                    return failure();
                }
                Owner<EVP_PKEY, EVP_PKEY_free> key(raw, EVP_PKEY_free);
                Owner<ECDSA_SIG, ECDSA_SIG_free> sig(ECDSA_SIG_new(), ECDSA_SIG_free);
                auto n = static_cast<int>(signature.size() / 2);
                BIGNUM* r = BN_bin2bn(signature.data(), n, nullptr);
                BIGNUM* s = BN_bin2bn(signature.data() + n, n, nullptr);
                // set0 transfers ownership only on success. On failure, the BIGNUMs still
                // belong to us; on success ECDSA_SIG's deleter releases both values.
                if (!sig || !r || !s || ECDSA_SIG_set0(sig.get(), r, s) != 1) {
                    BN_free(r);
                    BN_free(s);
                    return failure();
                }
                int size = i2d_ECDSA_SIG(sig.get(), nullptr);
                if (size <= 0) {
                    return failure();
                }
                Bytes der(static_cast<std::size_t>(size));
                auto* ptr = der.data();
                if (i2d_ECDSA_SIG(sig.get(), &ptr) != size) {
                    return failure();
                }
                Owner<EVP_PKEY_CTX, EVP_PKEY_CTX_free> verify(
                    EVP_PKEY_CTX_new_from_pkey(context_, key.get(), nullptr), EVP_PKEY_CTX_free);
                if (!verify || EVP_PKEY_verify_init(verify.get()) != 1) {
                    return failure();
                }
                int result = EVP_PKEY_verify(verify.get(), der.data(), der.size(), digest.data(),
                                             digest.size());
                if (result < 0) {
                    return failure();
                }
                // A validly processed mismatch is false, distinct from provider failure.
                return result == 1;
            }
        };
    } // namespace

    /** @brief Implement `openssl_provider` to create an isolated OpenSSL crypto provider. */
    Result<std::shared_ptr<CryptoProvider>> openssl_provider(bool allow_legacy) {
        // Return only the public interface; no OpenSSL type appears in installed headers.
        auto p = std::make_shared<OpenSsl>(allow_legacy);
        if (!p->good()) {
            return failure();
        }
        return std::shared_ptr<CryptoProvider>(std::move(p));
    }
} // namespace desfire
