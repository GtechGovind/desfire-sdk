/**
 * @file transaction_mac.hpp
 * @brief Offline AES transaction-key derivation, MAC verification, and ReaderID recovery.
 */
#pragma once

#include <desfire/foundation/crypto_provider.hpp>

#include <array>
#include <cstdint>

namespace desfire::ev3::offline {

    /** @brief Move-only transaction keys; independent from authentication/session messaging keys.
     */
    struct TransactionMacKeys {
        /** @brief Sixteen-byte session key used for transaction MAC calculation. */
        SecureBuffer mac_key;
        /** @brief Sixteen-byte session key used for ReaderID decryption. */
        SecureBuffer encryption_key;
    };

    /**
     * @brief Derive the shared AES transaction keys for an explicit seven-byte real UID.
     * @param crypto AES-128 CMAC provider; no reader or card operation is performed.
     * @param transaction_key Exactly sixteen bytes of backend-owned AppTransactionMACKey.
     * @param uid Exactly seven real UID bytes in transmitted order, never a four-byte Random ID.
     * @param committed_counter Nonzero TMC associated with the TMV being verified, in host order.
     * @return Protected MAC and encryption keys, or a local size/provider failure.
     *
     * Uses the shared AES construction documented in MF2DLHX0 section 10.3.2.3:
     * labels 0x5A/0xA5, fixed 00 01 00 80, TMC least significant byte first, and UID.
     * The caller passes the resulting transaction counter, not the preceding TMC;
     * this function does not add one or wrap the counter. LRP/other UID profiles are excluded.
     */
    Result<TransactionMacKeys> derive_transaction_mac_keys_aes(CryptoProvider& crypto,
                                                               ByteView transaction_key,
                                                               ByteView uid,
                                                               std::uint32_t committed_counter);

    /**
     * @brief Calculate the truncated AES-CMAC of caller-supplied complete transaction input.
     * @param crypto AES-128 CMAC provider.
     * @param session_mac_key Exactly sixteen bytes from transaction-key derivation.
     * @param transaction_input Nonempty validated TMI, at most 16 MiB, already in protocol order.
     * @return Eight-byte TMV using alternating CMAC bytes 1, 3, ..., 15.
     *
     * This function neither constructs nor infers the EV3 command accumulation, file
     * exclusions, record padding, application policy, or replay state. Those require the
     * installation's exact EV3 specification and transaction evidence.
     */
    Result<std::array<Byte, 8>> calculate_transaction_mac_aes(CryptoProvider& crypto,
                                                              ByteView session_mac_key,
                                                              ByteView transaction_input);

    /**
     * @brief Verify a TMV from explicit backend key, UID, counter, and complete TMI.
     * @param crypto AES-128 primitive provider.
     * @param transaction_key Exactly sixteen backend-owned AppTransactionMACKey bytes.
     * @param uid Exactly seven real UID bytes in transmitted order.
     * @param committed_counter Nonzero TMC returned with the transaction MAC being verified.
     * @param transaction_input Complete, validated nonempty TMI, at most 16 MiB.
     * @param transaction_mac Exactly eight received TMV bytes.
     * @return True for an equal MAC, false for mismatch, or a local argument/provider failure.
     * @warning Matching a MAC does not detect replay; the backend must enforce counter history.
     */
    Result<bool> verify_transaction_mac_aes(CryptoProvider& crypto, ByteView transaction_key,
                                            ByteView uid, std::uint32_t committed_counter,
                                            ByteView transaction_input, ByteView transaction_mac);

    /**
     * @brief Decrypt the previous ReaderID using the independently derived transaction key.
     * @param crypto AES-128 no-padding CBC provider.
     * @param session_encryption_key Exactly sixteen SesTMENCKey bytes.
     * @param encrypted_reader_id Exactly sixteen EncTMRI response bytes.
     * @return Sixteen private ReaderID bytes, using zero IV and no padding removal.
     * @pre The caller must authenticate the containing response or validate its transaction MAC.
     */
    Result<SecureBuffer> decrypt_transaction_reader_id_aes(CryptoProvider& crypto,
                                                           ByteView session_encryption_key,
                                                           ByteView encrypted_reader_id);

} // namespace desfire::ev3::offline
