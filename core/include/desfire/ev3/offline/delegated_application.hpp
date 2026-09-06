/**
 * @file delegated_application.hpp
 * @brief Offline AES delegated-application key protection and authorization MACs.
 */
#pragma once

#include <desfire/ev3/native/checked/applications.hpp>
#include <desfire/foundation/crypto_provider.hpp>

#include <array>

namespace desfire::ev3::offline {

    /**
     * @brief Encrypt one AES delegated-application default key with fresh random padding.
     * @param crypto AES-128 CBC provider and cryptographically secure random source.
     * @param dam_encryption_key Exactly sixteen bytes of issuer-owned DAMEncKey.
     * @param application_default_key Exactly sixteen bytes of application default key material.
     * @param application_default_key_version Version byte bound into the encrypted key record.
     * @return Protected 32-byte EncK value ready for CreateDelegatedApplication.
     *
     * The clear record is seven random bytes, the 16-byte application key, its version, and eight
     * zero bytes. Encryption uses AES-128 CBC with a zero IV and no provider padding, as documented
     * by the supplied NXP SAM AV3 delegated-application example.
     */
    Result<SecureBuffer> encrypt_delegated_default_key_aes(CryptoProvider& crypto,
                                                           ByteView dam_encryption_key,
                                                           ByteView application_default_key,
                                                           Byte application_default_key_version);

    /**
     * @brief Calculate the issuer authorization MAC for one AES delegated application.
     * @param crypto AES-128 CMAC provider.
     * @param dam_mac_key Exactly sixteen issuer-owned DAMMACKey bytes.
     * @param configuration Validated application, slot, version, and quota fields.
     * @param encrypted_default_key Exact 32-byte EncK produced for this application.
     * @return Eight-byte DAM MAC using alternating full-CMAC bytes 1, 3, ..., 15.
     *
     * The authenticated input is the exact first CreateDelegatedApplication frame followed by
     * EncK. The caller remains responsible for securely transferring DAM authorization material.
     */
    Result<std::array<Byte, 8>> calculate_delegated_application_mac_aes(
        CryptoProvider& crypto, ByteView dam_mac_key,
        const model::DelegatedApplicationConfiguration& configuration,
        ByteView encrypted_default_key);

    /**
     * @brief Calculate the issuer authorization MAC for delegated-application deletion.
     * @param crypto AES-128 CMAC provider.
     * @param dam_mac_key Exactly sixteen issuer-owned DAMMACKey bytes.
     * @param application Nonzero delegated application identifier to delete.
     * @return Eight-byte DAM MAC using alternating full-CMAC bytes 1, 3, ..., 15.
     *
     * The authenticated input is the DeleteApplication opcode followed by the native
     * least-significant-byte-first AID, matching the documented delete variant of GenerateDAMMAC.
     */
    Result<std::array<Byte, 8>>
    calculate_delegated_application_delete_mac_aes(CryptoProvider& crypto, ByteView dam_mac_key,
                                                   model::ApplicationId application);

    /**
     * @brief Calculate the DAM MAC authorizing delegated application DF-name configuration.
     * @param crypto AES-128 CMAC provider.
     * @param dam_mac_key Exactly sixteen issuer-owned DAMMACKey bytes.
     * @param old_df_name Existing ISO DF name, from zero through sixteen bytes.
     * @param new_df_name Replacement ISO DF name, from zero through sixteen bytes.
     * @return Eight-byte alternating-byte truncation of CMAC over two padded name records.
     *
     * Each record is its one-byte length followed by a zero-padded sixteen-byte name. This helper
     * implements the documented GenerateDAMMACSetConfig calculation only; it does not guess the
     * card's option-6 SetConfiguration payload.
     */
    Result<std::array<Byte, 8>> calculate_delegated_configuration_mac_aes(CryptoProvider& crypto,
                                                                          ByteView dam_mac_key,
                                                                          ByteView old_df_name,
                                                                          ByteView new_df_name);

} // namespace desfire::ev3::offline
