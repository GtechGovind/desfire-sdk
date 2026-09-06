/**
 * @file aes_support.hpp
 * @brief Private bounds and checked AES primitive-output ownership for offline helpers.
 */
#pragma once

#include <desfire/foundation/crypto_provider.hpp>

#include <cstddef>
#include <utility>

namespace desfire::ev3::offline::detail {

    /** @brief Exact AES block and key width used by supported offline constructions. */
    inline constexpr std::size_t aes_size = 16;

    /** @brief Maximum caller-supplied complete transaction input accepted by offline helpers. */
    inline constexpr std::size_t maximum_input_size = 16U * 1024U * 1024U;

    /** @brief Maximum authenticated input represented by NXP's uint16_t MFC length. */
    inline constexpr std::size_t maximum_mfc_license_input = 0xFFFFU;

    /**
     * @brief Transfer primitive output into erased-on-release storage after checking its size.
     * @param result Owned primitive output, consumed without copying secret bytes.
     * @param expected Exact required output length.
     * @return Protected bytes, the provider error, or a crypto error for a wrong provider length.
     */
    inline Result<SecureBuffer> secret_result(Result<Bytes> result, std::size_t expected) {
        if (!result) {
            return result.error();
        }
        SecureBuffer output(std::move(result.value()));
        if (output.size() != expected) {
            return Error{ErrorCode::crypto, "Offline AES primitive returned an invalid length"};
        }
        return output;
    }

} // namespace desfire::ev3::offline::detail
