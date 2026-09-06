"""Published and independently computed native offline utility vectors."""

from __future__ import annotations

import os
import unittest

from desfire_ev3 import (
    Aes128Key,
    ApplicationId,
    DelegatedApplicationConfiguration,
    Offline,
)


@unittest.skipUnless(os.environ.get("DESFIRE_LIBRARY"), "Set DESFIRE_LIBRARY to the built C ABI")
class OfflineTests(unittest.TestCase):
    """Prove Python ownership and ctypes layouts against native known-answer tests."""

    def setUp(self) -> None:
        """Load the same explicitly selected manifest-checked native library per test."""
        self.offline = Offline(os.environ["DESFIRE_LIBRARY"])

    def test_an10922_published_aes128_vector(self) -> None:
        """AN10922 derivation matches the published AES-128 result byte for byte."""
        master = Aes128Key(bytes.fromhex("00112233445566778899aabbccddeeff"))
        derived = self.offline.derive_nxp_aes128(
            master,
            bytes.fromhex("04782e21801d803042f54e585020416275"),
        )
        try:
            self.assertEqual(derived.snapshot().hex(), "a8dd63a3b89d54b37ca802473fda9175")
        finally:
            derived.close()
            master.close()

    def test_transaction_mac_complete_workflow(self) -> None:
        """Transaction session keys, TMV verification, and ReaderID recovery match fixtures."""
        key = Aes128Key(bytes.fromhex("00112233445566778899aabbccddeeff"))
        uid = bytes.fromhex("04782e21801d80")
        tmi = bytes.fromhex("3d0200000003000000000000000000000010203000000000000000000000000000")
        expected_keys = bytes.fromhex(
            "2db206d20f493ac4524eade977e976b4a0dd3ea52546ec462fe0f466feb3a62f"
        )
        expected_mac = bytes.fromhex("1e285e485ba62de1")
        self.assertEqual(self.offline.derive_transaction_mac_keys_aes(key, 1, uid), expected_keys)
        session_mac = Aes128Key(expected_keys[:16])
        session_enc = Aes128Key(expected_keys[16:])
        try:
            self.assertEqual(
                self.offline.calculate_transaction_mac_session_aes(session_mac, tmi),
                expected_mac,
            )
            self.assertTrue(
                self.offline.verify_transaction_mac_aes(key, 1, uid, tmi, expected_mac),
            )
            self.assertFalse(
                self.offline.verify_transaction_mac_aes(key, 2, uid, tmi, expected_mac),
            )
            self.assertEqual(
                self.offline.decrypt_transaction_reader_id_aes(
                    session_enc,
                    bytes.fromhex("4cba5402f5723fa30dfcdf9477e623f5"),
                ).hex(),
                "00112233445566778899aabbccddeeff",
            )
        finally:
            session_mac.close()
            session_enc.close()
            key.close()

    def test_delegated_and_mfc_mac_vectors(self) -> None:
        """Delegated creation/deletion/configuration and MFC license MAC layouts are exact."""
        dam = Aes128Key(bytes.fromhex("11" * 16))
        configuration = DelegatedApplicationConfiguration(
            ApplicationId(0x563412),
            0xEF,
            1,
            0,
            0,
            0x40,
        )
        encrypted = bytes.fromhex(
            "9232c82a913fa1cfcdc7ed5ec63ab45ce991c06a1f485156db8c3cdcb689bd27"
        )
        try:
            self.assertEqual(
                self.offline.calculate_delegated_application_mac_aes(
                    dam,
                    configuration,
                    encrypted,
                ).hex(),
                "5d941683b901612b",
            )
            self.assertEqual(
                self.offline.calculate_delegated_application_delete_mac_aes(
                    dam,
                    ApplicationId(0x563412),
                ).hex(),
                "dcd2f30e702c9370",
            )
            self.assertEqual(
                self.offline.calculate_delegated_configuration_mac_aes(
                    dam,
                    bytes.fromhex("a0000003965643"),
                    bytes.fromhex("a0000003965644"),
                ).hex(),
                "d28ca69a54454b38",
            )
        finally:
            dam.close()
        license_key = Aes128Key(bytes.fromhex("00112233445566778899aabbccddeeff"))
        try:
            self.assertEqual(
                self.offline.calculate_mfc_license_mac_aes(
                    license_key,
                    bytes.fromhex("0204a108b2"),
                    bytes(range(32)),
                ).hex(),
                "766edc8921f03e2e",
            )
        finally:
            license_key.close()


if __name__ == "__main__":
    unittest.main()
