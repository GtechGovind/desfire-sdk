#!/usr/bin/env python3
"""Focused fail-closed tests for Android package evidence validation."""

from copy import deepcopy
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parent))

from verify_aar import validate_evidence as validate_aar_evidence  # noqa: E402
from verify_apk import validate_evidence as validate_apk_evidence  # noqa: E402


OPENSSL_SHA256 = "a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2"


def valid_evidence() -> dict[str, object]:
    """Return the smallest production-profile evidence accepted by both verifiers."""
    return {
        "api": 23,
        "cxx_standard": "26",
        "openssl_version": "3.5.8",
        "openssl_sha256": OPENSSL_SHA256,
        "ndk_source_properties": "Pkg.Desc = Android NDK\nPkg.Revision = 29.0.14206865\n",
        "abis": {"arm64-v8a": {}, "armeabi-v7a": {}, "x86_64": {}},
    }


class PackageEvidenceTest(unittest.TestCase):
    """Require every package verifier to reject a self-consistent nonproduction profile."""

    def test_accepts_production_profile(self) -> None:
        """Accept the exact API, C++, dependency, NDK, and ABI contract."""
        for validator in (validate_aar_evidence, validate_apk_evidence):
            validator(valid_evidence())

    def test_rejects_changed_profile_fields(self) -> None:
        """Reject each security-relevant field independently of native binary hashes."""
        changes = {
            "api": 24,
            "cxx_standard": "23",
            "openssl_version": "3.5.7",
            "openssl_sha256": "0" * 64,
            "ndk_source_properties": "Pkg.Revision = 28.2.13676358\n",
            "abis": {"arm64-v8a": {}, "x86_64": {}},
        }
        for validator in (validate_aar_evidence, validate_apk_evidence):
            for field, value in changes.items():
                with self.subTest(validator=validator.__module__, field=field):
                    evidence = deepcopy(valid_evidence())
                    evidence[field] = value
                    with self.assertRaises(RuntimeError):
                        validator(evidence)


if __name__ == "__main__":
    unittest.main()
