/**
 * @file mifare_classic_license.hpp
 * @brief Offline AES MIFARE Classic compatibility license authorization MAC.
 */
#pragma once

#include <desfire/foundation/crypto_provider.hpp>

#include <array>

namespace desfire::ev3::offline {

    /**
     * @brief Calculate the AES authorization MAC for MIFARE Classic compatibility operations.
     * @param crypto AES-128 CMAC provider; no card or reader operation is performed.
     * @param license_mac_key Exactly sixteen issuer-owned MFCLicenseMACKey bytes.
     * @param mfc_license BlockCount followed by exactly that many BlockNr/BlockOption byte pairs.
     * @param mfc_sector_secrets Caller-supplied MFCSectorSecrets in authoritative protocol order.
     * @return Eight-byte alternating-byte truncation of AES-CMAC.
     *
     * The authenticated input is exactly 0x01 || MFCLicense || MFCSectorSecrets. This helper does
     * not infer the undocumented sector-secret subfields or unsupported card-command options.
     */
    Result<std::array<Byte, 8>> calculate_mfc_license_mac_aes(CryptoProvider& crypto,
                                                              ByteView license_mac_key,
                                                              ByteView mfc_license,
                                                              ByteView mfc_sector_secrets);

} // namespace desfire::ev3::offline
