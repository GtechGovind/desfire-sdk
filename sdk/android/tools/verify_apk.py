#!/usr/bin/env python3
"""Verify showcase APK native contents, hashes, storage, and 16 KiB ZIP alignment."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile


ABIS = {"arm64-v8a", "armeabi-v7a", "x86_64"}
PAGE_SIZE_ABIS = {"arm64-v8a", "x86_64"}
EXPECTED_OPENSSL_SHA256 = "a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2"


def sha256(data: bytes) -> str:
    """Return the SHA-256 digest of one in-memory archive member."""
    return hashlib.sha256(data).hexdigest()


def validate_evidence(evidence: dict[str, object]) -> None:
    """Reject evidence from a different Android API, compiler mode, NDK, or OpenSSL source."""
    if evidence.get("api") != 23 or evidence.get("cxx_standard") != "26":
        raise RuntimeError("Native build evidence must record Android API 23 and C++26")
    if (
        evidence.get("openssl_version") != "3.5.8"
        or evidence.get("openssl_sha256") != EXPECTED_OPENSSL_SHA256
    ):
        raise RuntimeError("Native build evidence does not match pinned OpenSSL 3.5.8")
    ndk_properties = evidence.get("ndk_source_properties")
    if not isinstance(ndk_properties, str) or (
        "Pkg.Revision = 29.0.14206865" not in ndk_properties.splitlines()
    ):
        raise RuntimeError("Native build evidence does not match Android NDK 29.0.14206865")
    evidence_abis = evidence.get("abis")
    if not isinstance(evidence_abis, dict) or set(evidence_abis) != ABIS:
        raise RuntimeError("Build evidence must contain every distributed Android ABI")


def verify_archive(path: Path, evidence: dict[str, object]) -> None:
    """Require each evidence-bound SDK library exactly once in one APK."""
    if not path.is_file():
        raise RuntimeError(f"Missing APK: {path}")
    evidence_abis = evidence["abis"]
    if not isinstance(evidence_abis, dict):
        raise RuntimeError("Build evidence ABI map is malformed")

    expected_entries = {
        f"lib/{abi}/{library}"
        for abi, libraries in evidence_abis.items()
        for library in libraries
    }
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise RuntimeError(f"APK contains duplicate archive names: {path}")
        actual_entries = {name for name in names if name in expected_entries}
        if actual_entries != expected_entries:
            raise RuntimeError(
                "APK SDK-native members differ from evidence: "
                f"missing={sorted(expected_entries - actual_entries)}, "
                f"extra={sorted(actual_entries - expected_entries)}"
            )
        for abi, libraries in evidence_abis.items():
            if not isinstance(libraries, dict):
                raise RuntimeError(f"Invalid evidence library map for {abi}")
            for library, expected in libraries.items():
                if not isinstance(expected, dict):
                    raise RuntimeError(f"Invalid evidence for {abi}/{library}")
                member = f"lib/{abi}/{library}"
                information = archive.getinfo(member)
                if abi in PAGE_SIZE_ABIS and information.compress_type != zipfile.ZIP_STORED:
                    raise RuntimeError(f"64-bit native member must be uncompressed: {member}")
                contents = archive.read(member)
                if len(contents) != expected.get("size"):
                    raise RuntimeError(f"APK native size differs from evidence: {member}")
                if sha256(contents) != expected.get("sha256"):
                    raise RuntimeError(f"APK native digest differs from evidence: {member}")


def main() -> None:
    """Verify both showcase variants and delegate ZIP offsets to Android zipalign."""
    module = Path(__file__).resolve().parents[1]
    repository = module.parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence",
        type=Path,
        default=module / "build/native/build-evidence.json",
    )
    parser.add_argument(
        "--apk",
        action="append",
        type=Path,
        default=[],
        help="APK to verify; may be supplied more than once",
    )
    parser.add_argument("--zipalign", required=True, type=Path)
    arguments = parser.parse_args()
    apks = arguments.apk or [
        repository / "examples/android-app/build/outputs/apk/debug/example-app-debug.apk",
        repository
        / "examples/android-app/build/outputs/apk/release/example-app-release-unsigned.apk",
    ]
    if not arguments.zipalign.is_file():
        raise RuntimeError(f"Missing Android zipalign executable: {arguments.zipalign}")
    evidence = json.loads(arguments.evidence.read_text(encoding="utf-8"))
    validate_evidence(evidence)
    for apk in apks:
        verify_archive(apk, evidence)
        subprocess.run(
            [str(arguments.zipalign), "-c", "-P", "16", "4", str(apk)],
            check=True,
        )
        digest = hashlib.sha256(apk.read_bytes()).hexdigest()
        print(f"Complete APK verified: {apk}")
        print(f"SHA256: {digest}; bytes: {apk.stat().st_size}")


if __name__ == "__main__":
    main()
