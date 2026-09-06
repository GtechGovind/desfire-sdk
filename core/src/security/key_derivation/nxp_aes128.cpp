/**
 * @file nxp_aes128.cpp
 * @brief Independently implemented NXP AN10922 AES-128 two-block key diversification.
 */
#include <desfire/ev3/security/key_derivation/nxp_aes128.hpp>

#include <algorithm>
#include <array>

namespace desfire::ev3::security::key_derivation::nxp_aes128 {

    namespace {

        /** @brief Implement `double_subkey` to derive the next AES-CMAC subkey in place. */
        void double_subkey(std::span<Byte> subkey) noexcept {
            const auto reduction = static_cast<Byte>(0x87U & (0U - (subkey.front() >> 7U)));
            for (std::size_t index = 0; index + 1 < subkey.size(); ++index) {
                subkey[index] =
                    static_cast<Byte>((subkey[index] << 1U) | (subkey[index + 1] >> 7U));
            }
            subkey.back() = static_cast<Byte>((subkey.back() << 1U) ^ reduction);
        }

    } // namespace

    /** @brief Implement `derive` to derive an AES-128 key with the documented AN10922 construction.
     */
    Result<Aes128Key> derive(CryptoProvider& crypto, const Aes128Key& master_key,
                             const Aes128DerivationContext& context) {
        const ByteView diversification_input = context.diversification_input();
        if (!master_key.valid() || diversification_input.empty() ||
            diversification_input.size() > 31) {
            return invalid(
                "NXP AES-128 requires an exact key and 1 through 31 diversification bytes");
        }
        try {
            const std::array<Byte, aes128_key_size> zero{};
            auto encrypted_zero = crypto.cbc(Cipher::aes128, master_key.view(), zero, zero, true);
            if (!encrypted_zero) {
                return encrypted_zero.error();
            }
            SecureBuffer subkey(std::move(encrypted_zero.value()));
            if (subkey.size() != aes128_key_size) {
                return Error{ErrorCode::crypto, "NXP AES-128 primitive returned an invalid length"};
            }
            double_subkey(subkey.mutable_view());

            SecureBuffer input(32);
            input.mutable_view()[0] = 0x01;
            std::ranges::copy(diversification_input, input.mutable_view().begin() + 1);
            if (diversification_input.size() < 31) {
                input.mutable_view()[diversification_input.size() + 1] = 0x80;
                double_subkey(subkey.mutable_view());
            }
            for (std::size_t index = 0; index < aes128_key_size; ++index) {
                input.mutable_view()[aes128_key_size + index] ^= subkey.view()[index];
            }
            auto encrypted =
                crypto.cbc(Cipher::aes128, master_key.view(), zero, input.view(), true);
            if (!encrypted) {
                return encrypted.error();
            }
            SecureBuffer output(std::move(encrypted.value()));
            if (output.size() != input.size()) {
                return Error{ErrorCode::crypto, "NXP AES-128 primitive returned an invalid length"};
            }
            return Aes128Key::import(output.view().last(aes128_key_size));
        } catch (...) {
            return Error{ErrorCode::internal, "NXP AES-128 dependency failed"};
        }
    }

    /** @brief Retain the AES primitive provider without retaining key material. */
    Deriver::Deriver(std::shared_ptr<CryptoProvider> crypto) : crypto_(std::move(crypto)) {}

    /** @brief Apply AN10922 to one exact master key and scoped derivation context. */
    Result<Aes128Key> Deriver::derive(const Aes128Key& master_key,
                                      const Aes128DerivationContext& context) {
        if (!crypto_) {
            return invalid("NXP AES-128 derivation requires an AES provider");
        }
        return nxp_aes128::derive(*crypto_, master_key, context);
    }

} // namespace desfire::ev3::security::key_derivation::nxp_aes128
