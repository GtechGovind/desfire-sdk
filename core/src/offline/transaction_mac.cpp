/**
 * @file transaction_mac.cpp
 * @brief Offline AES transaction primitive implementations.
 */
#include <desfire/ev3/offline/transaction_mac.hpp>

#include "detail/aes_support.hpp"

#include <algorithm>

namespace desfire::ev3::offline {

    using namespace detail;

    /** @brief Implement AES transaction-key derivation from explicit backend evidence. */
    Result<TransactionMacKeys> derive_transaction_mac_keys_aes(CryptoProvider& crypto,
                                                               ByteView transaction_key,
                                                               ByteView uid,
                                                               std::uint32_t committed_counter) {
        if (transaction_key.size() != aes_size || uid.size() != 7 || committed_counter == 0) {
            return invalid(
                "AES transaction derivation requires a 16-byte key, 7-byte UID and nonzero TMC");
        }
        try {
            std::array<Byte, aes_size> vector{0x5A, 0x00, 0x01, 0x00, 0x80};
            for (std::size_t index = 0; index < 4; ++index) {
                vector[5 + index] = static_cast<Byte>(committed_counter >> (index * 8U));
            }
            std::ranges::copy(uid, vector.begin() + 9);
            auto mac =
                secret_result(crypto.cmac(Cipher::aes128, transaction_key, vector), aes_size);
            if (!mac) {
                return mac.error();
            }
            vector[0] = 0xA5;
            auto encryption =
                secret_result(crypto.cmac(Cipher::aes128, transaction_key, vector), aes_size);
            if (!encryption) {
                return encryption.error();
            }
            return TransactionMacKeys{std::move(mac.value()), std::move(encryption.value())};
        } catch (...) {
            return Error{ErrorCode::internal, "Offline transaction-key derivation failed"};
        }
    }

    /** @brief Implement truncated transaction MAC calculation over caller-supplied TMI. */
    Result<std::array<Byte, 8>> calculate_transaction_mac_aes(CryptoProvider& crypto,
                                                              ByteView session_mac_key,
                                                              ByteView transaction_input) {
        if (session_mac_key.size() != aes_size || transaction_input.empty() ||
            transaction_input.size() > maximum_input_size) {
            return invalid(
                "AES transaction MAC requires a 16-byte key and nonempty TMI of at most 16 MiB");
        }
        try {
            auto full = secret_result(
                crypto.cmac(Cipher::aes128, session_mac_key, transaction_input), aes_size);
            if (!full) {
                return full.error();
            }
            std::array<Byte, 8> output{};
            for (std::size_t index = 0; index < output.size(); ++index) {
                output[index] = full.value().view()[(2 * index) + 1];
            }
            return output;
        } catch (...) {
            return Error{ErrorCode::internal, "Offline transaction MAC calculation failed"};
        }
    }

    /** @brief Implement transaction MAC verification with constant-time comparison. */
    Result<bool> verify_transaction_mac_aes(CryptoProvider& crypto, ByteView transaction_key,
                                            ByteView uid, std::uint32_t committed_counter,
                                            ByteView transaction_input, ByteView transaction_mac) {
        if (transaction_mac.size() != 8) {
            return invalid("Transaction MAC verification requires exactly eight TMV bytes");
        }
        auto keys =
            derive_transaction_mac_keys_aes(crypto, transaction_key, uid, committed_counter);
        if (!keys) {
            return keys.error();
        }
        auto computed =
            calculate_transaction_mac_aes(crypto, keys.value().mac_key.view(), transaction_input);
        if (!computed) {
            return computed.error();
        }
        return constant_time_equal(computed.value(), transaction_mac);
    }

    /** @brief Implement ReaderID decryption with the derived transaction encryption key. */
    Result<SecureBuffer> decrypt_transaction_reader_id_aes(CryptoProvider& crypto,
                                                           ByteView session_encryption_key,
                                                           ByteView encrypted_reader_id) {
        if (session_encryption_key.size() != aes_size || encrypted_reader_id.size() != aes_size) {
            return invalid("ReaderID decryption requires a 16-byte transaction key and ciphertext");
        }
        try {
            const std::array<Byte, aes_size> zero_iv{};
            return secret_result(crypto.cbc(Cipher::aes128, session_encryption_key, zero_iv,
                                            encrypted_reader_id, false),
                                 aes_size);
        } catch (...) {
            return Error{ErrorCode::internal, "Offline ReaderID decryption failed"};
        }
    }

} // namespace desfire::ev3::offline
