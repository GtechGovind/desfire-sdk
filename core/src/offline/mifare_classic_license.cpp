/**
 * @file mifare_classic_license.cpp
 * @brief Offline AES MIFARE Classic license-MAC implementation.
 */
#include <desfire/ev3/offline/mifare_classic_license.hpp>

#include "detail/aes_support.hpp"

#include <algorithm>

namespace desfire::ev3::offline {

    using namespace detail;

    /** @brief Implement the documented MIFARE Classic license authorization MAC. */
    Result<std::array<Byte, 8>> calculate_mfc_license_mac_aes(CryptoProvider& crypto,
                                                              ByteView license_mac_key,
                                                              ByteView mfc_license,
                                                              ByteView mfc_sector_secrets) {
        const bool valid_license =
            !mfc_license.empty() && mfc_license.size() <= 0xFFU &&
            mfc_license.size() == 1U + (static_cast<std::size_t>(mfc_license.front()) * 2U);
        if (license_mac_key.size() != aes_size || !valid_license ||
            mfc_sector_secrets.size() > maximum_mfc_license_input - mfc_license.size() - 1U) {
            return invalid("MFC license MAC requires a 16-byte AES key, a complete license and at "
                           "most 65,535 authenticated input bytes");
        }
        try {
            SecureBuffer input(1U + mfc_license.size() + mfc_sector_secrets.size());
            input.mutable_view().front() = 0x01;
            std::ranges::copy(mfc_license, input.mutable_view().subspan(1).begin());
            std::ranges::copy(mfc_sector_secrets,
                              input.mutable_view().subspan(1 + mfc_license.size()).begin());
            auto full =
                secret_result(crypto.cmac(Cipher::aes128, license_mac_key, input.view()), aes_size);
            if (!full) {
                return full.error();
            }
            std::array<Byte, 8> output{};
            for (std::size_t index = 0; index < output.size(); ++index) {
                output[index] = full.value().view()[(2U * index) + 1U];
            }
            return output;
        } catch (...) {
            return Error{ErrorCode::internal, "MFC license MAC calculation failed"};
        }
    }

} // namespace desfire::ev3::offline
