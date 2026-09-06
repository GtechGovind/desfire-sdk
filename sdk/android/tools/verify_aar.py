#!/usr/bin/env python3
"""Verify a complete Android AAR against the native build's hashed ELF evidence."""
import argparse
import hashlib
from io import BytesIO
import json
from pathlib import Path
import zipfile


EXPECTED_OPENSSL_SHA256 = "a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2"


def validate_evidence(evidence):
    """Reject evidence from a different Android API, compiler mode, NDK, or OpenSSL source."""
    if evidence.get('api') != 23 or evidence.get('cxx_standard') != '26':
        raise RuntimeError('Native build evidence must record Android API 23 and C++26')
    if (evidence.get('openssl_version') != '3.5.8' or
            evidence.get('openssl_sha256') != EXPECTED_OPENSSL_SHA256):
        raise RuntimeError('Native build evidence does not match pinned OpenSSL 3.5.8')
    ndk_properties = evidence.get('ndk_source_properties')
    if (not isinstance(ndk_properties, str) or
            'Pkg.Revision = 29.0.14206865' not in ndk_properties.splitlines()):
        raise RuntimeError('Native build evidence does not match Android NDK 29.0.14206865')
    if set(evidence.get('abis', {})) != {'arm64-v8a', 'armeabi-v7a', 'x86_64'}:
        raise RuntimeError('Build evidence must contain every distributed Android ABI')


def main():
    """Reject missing API classes, notices, shrinker rules, ABIs or changed native binaries."""
    module = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--aar', type=Path,
                        default=module / 'build/outputs/aar/desfire-ev3-android-release.aar')
    parser.add_argument('--evidence', type=Path,
                        default=module / 'build/native/build-evidence.json')
    arguments = parser.parse_args()
    evidence = json.loads(arguments.evidence.read_text())
    validate_evidence(evidence)
    with zipfile.ZipFile(arguments.aar) as archive:
        names = archive.namelist()
        native_entries = [name for name in names if name.endswith('.so')]
        if len(native_entries) != 9 or 'proguard.txt' not in names:
            raise RuntimeError('AAR must contain nine native libraries and consumer shrinker rules')
        for abi, libraries in evidence['abis'].items():
            for name, expected in libraries.items():
                actual = hashlib.sha256(archive.read(f'jni/{abi}/{name}')).hexdigest()
                if actual != expected['sha256']:
                    raise RuntimeError(f'AAR native binary differs from verified ELF: {abi}/{name}')
        with zipfile.ZipFile(BytesIO(archive.read('classes.jar'))) as classes:
            required = ['com/desfire/ev3/android/AndroidCardSession.class',
                        'com/desfire/ev3/android/AndroidRawSession.class',
                        'com/desfire/ev3/android/IsoDepTransport.class',
                        'META-INF/LICENSE.openssl', 'META-INF/NOTICE.openssl',
                        'META-INF/NOTICE.android-toolchain', 'META-INF/NOTICE.android-ndk',
                        'META-INF/LICENSE.desfire', 'META-INF/NOTICE.desfire']
            for name in required:
                if name not in classes.namelist():
                    raise RuntimeError(f'AAR lacks required API or notice: {name}')
            forbidden = ['com/desfire/ev3/Card.class', 'com/desfire/ev3/BlockingCard.class']
            for name in forbidden:
                if name in classes.namelist():
                    raise RuntimeError(f'AAR must depend on the portable Kotlin module: {name}')
    digest = hashlib.sha256(arguments.aar.read_bytes()).hexdigest()
    print(f'Complete AAR verified: {arguments.aar}')
    print(f'SHA256: {digest}; bytes: {arguments.aar.stat().st_size}')


if __name__ == '__main__':
    main()
