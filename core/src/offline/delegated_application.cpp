/**
 * @file delegated_application.cpp
 * @brief Offline AES delegated-application primitive implementations.
 */
#include <desfire/ev3/offline/delegated_application.hpp>

#include "detail/aes_support.hpp"

#include <algorithm>

namespace desfire::ev3::offline {

    using namespace detail;

    /** @brief Implement delegated default-key encryption as declared by the public helper. */
    Result<SecureBuffer> encrypt_delegated_default_key_aes(CryptoProvider& crypto,
                                                           ByteView dam_encryption_key,
                                                           ByteView application_default_key,
                                                           Byte application_default_key_version) {
        if (dam_encryption_key.size() != aes_size || application_default_key.size() != aes_size) {
            return invalid("Delegated EncK requires two 16-byte AES keys");
        }
        try {
            auto random = crypto.random(7);
            if (!random) {
                return random.error();
            }
            if (random.value().size() != 7) {
                return Error{ErrorCode::crypto,
                             "Delegated EncK random source returned an invalid length"};
            }
            SecureBuffer clear(32);
            std::ranges::copy(random.value(), clear.mutable_view().begin());
            std::ranges::copy(application_default_key, clear.mutable_view().begin() + 7);
            clear.mutable_view()[23] = application_default_key_version;
            const std::array<Byte, aes_size> zero_iv{};
            return secret_result(
                crypto.cbc(Cipher::aes128, dam_encryption_key, zero_iv, clear.view(), true), 32);
        } catch (...) {
            return Error{ErrorCode::internal, "Delegated EncK construction failed"};
        }
    }

    /** @brief Implement delegated-application creation authorization MAC calculation. */
    Result<std::array<Byte, 8>> calculate_delegated_application_mac_aes(
        CryptoProvider& crypto, ByteView dam_mac_key,
        const model::DelegatedApplicationConfiguration& configuration,
        ByteView encrypted_default_key) {
        if (dam_mac_key.size() != aes_size || encrypted_default_key.size() != 32) {
            return invalid("Delegated DAM MAC requires a 16-byte AES key and 32-byte EncK");
        }
        try {
            const std::array<Byte, 8> zero_mac{};
            auto command = native::checked::create_delegated_application(
                configuration, encrypted_default_key, zero_mac);
            if (!command) {
                return command.error();
            }
            Bytes input;
            input.reserve(1 + command.value().header().size() + encrypted_default_key.size());
            input.push_back(command.value().opcode());
            append(input, command.value().header());
            append(input, command.value().data().first(encrypted_default_key.size()));
            auto full = secret_result(crypto.cmac(Cipher::aes128, dam_mac_key, input), aes_size);
            if (!full) {
                return full.error();
            }
            std::array<Byte, 8> output{};
            for (std::size_t index = 0; index < output.size(); ++index) {
                output[index] = full.value().view()[(2 * index) + 1];
            }
            return output;
        } catch (...) {
            return Error{ErrorCode::internal, "Delegated DAM MAC construction failed"};
        }
    }

    /** @brief Implement delegated-application deletion authorization MAC calculation. */
    Result<std::array<Byte, 8>>
    calculate_delegated_application_delete_mac_aes(CryptoProvider& crypto, ByteView dam_mac_key,
                                                   model::ApplicationId application) {
        if (dam_mac_key.size() != aes_size || application.value() == 0) {
            return invalid("Delegated deletion DAM MAC requires a 16-byte AES key and nonzero AID");
        }
        try {
            std::array<Byte, 4> input{0xDA, static_cast<Byte>(application.value()),
                                      static_cast<Byte>(application.value() >> 8U),
                                      static_cast<Byte>(application.value() >> 16U)};
            auto full = secret_result(crypto.cmac(Cipher::aes128, dam_mac_key, input), aes_size);
            if (!full) {
                return full.error();
            }
            std::array<Byte, 8> output{};
            for (std::size_t index = 0; index < output.size(); ++index) {
                output[index] = full.value().view()[(2 * index) + 1];
            }
            return output;
        } catch (...) {
            return Error{ErrorCode::internal, "Delegated deletion DAM MAC construction failed"};
        }
    }

    /** @brief Implement delegated configuration authorization MAC calculation. */
    Result<std::array<Byte, 8>> calculate_delegated_configuration_mac_aes(CryptoProvider& crypto,
                                                                          ByteView dam_mac_key,
                                                                          ByteView old_df_name,
                                                                          ByteView new_df_name) {
        if (dam_mac_key.size() != aes_size || old_df_name.size() > 16 || new_df_name.size() > 16) {
            return invalid("Delegated configuration DAM MAC requires a 16-byte AES key and DF "
                           "names of at most 16 bytes");
        }
        try {
            std::array<Byte, 34> input{};
            input[0] = static_cast<Byte>(old_df_name.size());
            std::ranges::copy(old_df_name, input.begin() + 1);
            input[17] = static_cast<Byte>(new_df_name.size());
            std::ranges::copy(new_df_name, input.begin() + 18);
            auto full = secret_result(crypto.cmac(Cipher::aes128, dam_mac_key, input), aes_size);
            if (!full) {
                return full.error();
            }
            std::array<Byte, 8> output{};
            for (std::size_t index = 0; index < output.size(); ++index) {
                output[index] = full.value().view()[(2 * index) + 1];
            }
            return output;
        } catch (...) {
            return Error{ErrorCode::internal,
                         "Delegated configuration DAM MAC construction failed"};
        }
    }

} // namespace desfire::ev3::offline
