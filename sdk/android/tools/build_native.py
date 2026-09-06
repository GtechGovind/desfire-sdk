#!/usr/bin/env python3
"""Build verified OpenSSL and EV3 Android JNI for ARM64, ARMv7, and x86_64."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[3]
OPENSSL_VERSION = '3.5.8'
OPENSSL_SHA256 = 'a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2'
OPENSSL_URL = f'https://github.com/openssl/openssl/releases/download/openssl-{OPENSSL_VERSION}/openssl-{OPENSSL_VERSION}.tar.gz'
ABIS = {
    'arm64-v8a': ('android-arm64', 'aarch64-linux-android', 'AArch64'),
    'armeabi-v7a': ('android-arm', 'arm-linux-androideabi', 'ARM'),
    'x86_64': ('android-x86_64', 'x86_64-linux-android', 'Advanced Micro Devices X86-64'),
}


def run(arguments, *, cwd=None, env=None, log=None):
    """Run checked argument arrays and keep noisy compiler output in an explicit build log."""
    print('Running:', ' '.join(map(str, arguments)), flush=True)
    if log:
        with Path(log).open('a') as output:
            subprocess.run(list(map(str, arguments)), cwd=cwd, env=env, check=True,
                           stdout=output, stderr=subprocess.STDOUT)
    else:
        subprocess.run(list(map(str, arguments)), cwd=cwd, env=env, check=True)


def checksum(path):
    """Hash an artifact incrementally without allocating its full contents."""
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def main():
    """Build selected ABIs and reject wrong architectures or missing dependencies."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ndk', type=Path, default=os.environ.get('ANDROID_NDK_ROOT'))
    parser.add_argument('--api', type=int, default=23)
    parser.add_argument('--abis', nargs='+', choices=ABIS, default=list(ABIS))
    parser.add_argument('--jobs', type=int, default=min(os.cpu_count() or 2, 12))
    parser.add_argument('--cxx-standard', choices=['23', '26'], default='26')
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--build-root', type=Path, default=ROOT / 'sdk/android/build/native')
    parser.add_argument('--output', type=Path, default=ROOT / 'sdk/android/build/native-jniLibs')
    arguments = parser.parse_args()
    if not arguments.ndk or not (arguments.ndk / 'build/cmake/android.toolchain.cmake').is_file():
        parser.error('--ndk must name an installed Android NDK (or set ANDROID_NDK_ROOT)')
    if arguments.api < 23 or arguments.jobs < 1:
        parser.error('API must be at least 23 and jobs must be positive')
    ndk = arguments.ndk.resolve()
    build_root = arguments.build_root.resolve()
    output_root = arguments.output.resolve()
    build_root.mkdir(parents=True, exist_ok=True)
    output_root.mkdir(parents=True, exist_ok=True)
    host_tag = 'darwin-x86_64' if platform.system() == 'Darwin' else 'linux-x86_64'
    toolchain = ndk / 'toolchains/llvm/prebuilt' / host_tag
    if not (toolchain / 'bin/clang').is_file():
        parser.error('Installed NDK does not contain the required host LLVM toolchain')
    archive = arguments.archive
    if archive is None:
        archive = build_root / f'openssl-{OPENSSL_VERSION}.tar.gz'
        if not archive.exists():
            temporary = archive.with_suffix('.download')
            urllib.request.urlretrieve(OPENSSL_URL, temporary)
            temporary.replace(archive)
    archive = archive.resolve()
    if checksum(archive) != OPENSSL_SHA256:
        raise RuntimeError('OpenSSL archive checksum differs from the pinned official release')
    environment = os.environ.copy()
    environment['ANDROID_NDK_ROOT'] = str(ndk)
    environment['PATH'] = str(toolchain / 'bin') + os.pathsep + environment.get('PATH', '')
    environment.pop('CC', None)
    environment.pop('CXX', None)
    evidence = {'openssl_version': OPENSSL_VERSION, 'openssl_sha256': OPENSSL_SHA256,
                'ndk_source_properties': (ndk / 'source.properties').read_text(),
                'api': arguments.api, 'cxx_standard': arguments.cxx_standard, 'abis': {}}
    for abi in arguments.abis:
        openssl_target, triple, machine = ABIS[abi]
        abi_build = build_root / abi
        abi_build.mkdir(exist_ok=True)
        source = abi_build / f'openssl-{OPENSSL_VERSION}'
        prefix = abi_build / 'openssl-install'
        log = abi_build / 'build.log'
        configuration_path = abi_build / 'openssl-configuration.json'
        configuration = {'source_sha256': OPENSSL_SHA256, 'target': openssl_target,
                         'api': arguments.api, 'ndk': evidence['ndk_source_properties']}
        if (prefix / 'lib/libcrypto.a').exists() and not configuration_path.exists():
            raise RuntimeError('Cached OpenSSL lacks build provenance; use a fresh --build-root')
        if configuration_path.exists():
            if json.loads(configuration_path.read_text()) != configuration:
                raise RuntimeError('OpenSSL toolchain configuration changed; use a fresh --build-root')
        if not source.exists():
            # The release checksum is pinned before extraction; reject traversal as an additional boundary.
            with tarfile.open(archive) as package:
                for member in package.getmembers():
                    destination = (abi_build / member.name).resolve()
                    if not destination.is_relative_to(abi_build):
                        raise RuntimeError('Source archive contains path traversal')
                    if member.isdev():
                        raise RuntimeError('Source archive contains a special device')
                    if member.issym() or member.islnk():
                        base = destination.parent if member.issym() else abi_build
                        if not (base / member.linkname).resolve().is_relative_to(abi_build):
                            raise RuntimeError('Source archive link escapes extraction directory')
                package.extractall(abi_build)
        if not (prefix / 'lib/libcrypto.a').is_file():
            run(['perl', 'Configure', openssl_target, 'no-shared', 'no-tests', 'no-apps',
                 'no-docs', 'no-legacy', 'no-fips', 'no-module', 'no-dso', '-fPIC',
                 f'-D__ANDROID_API__={arguments.api}', f'--prefix={prefix}', '--libdir=lib'],
                cwd=source, env=environment, log=log)
            run(['make', f'-j{arguments.jobs}', 'build_libs'], cwd=source, env=environment, log=log)
            run(['make', 'install_dev'], cwd=source, env=environment, log=log)
        configuration_path.write_text(json.dumps(configuration, indent=2) + '\n')
        sdk_build = abi_build / 'sdk'
        run(['cmake', '-S', ROOT, '-B', sdk_build, '-G', 'Ninja',
             f'-DCMAKE_TOOLCHAIN_FILE={ndk / "build/cmake/android.toolchain.cmake"}',
             f'-DANDROID_ABI={abi}', f'-DANDROID_PLATFORM=android-{arguments.api}',
             '-DANDROID_STL=c++_shared', '-DCMAKE_BUILD_TYPE=Release',
             f'-DDESFIRE_CXX_STANDARD={arguments.cxx_standard}', '-DDESFIRE_BUILD_JNI=ON',
             '-DDESFIRE_BUILD_TESTS=OFF', '-DDESFIRE_BUILD_PCSC=OFF',
             '-DOPENSSL_USE_STATIC_LIBS=TRUE', f'-DOPENSSL_ROOT_DIR={prefix}',
             f'-DOPENSSL_CRYPTO_LIBRARY={prefix / "lib/libcrypto.a"}',
             f'-DOPENSSL_INCLUDE_DIR={prefix / "include"}',
             '-DCMAKE_SHARED_LINKER_FLAGS=-Wl,-z,max-page-size=16384'], env=environment, log=log)
        run(['cmake', '--build', sdk_build, '--target', 'desfire_jni', '-j', arguments.jobs],
            env=environment, log=log)
        destination = output_root / abi
        destination.mkdir(exist_ok=True)
        artifacts = {
            'libdesfire_c.so': sdk_build / 'c-api/libdesfire_c.so',
            'libdesfire_jni.so': sdk_build / 'sdk/kotlin/libdesfire_jni.so',
            'libc++_shared.so': toolchain / 'sysroot/usr/lib' / triple / 'libc++_shared.so',
        }
        abi_evidence = {}
        for name, origin in artifacts.items():
            target = destination / name
            shutil.copy2(origin, target)
            run([toolchain / 'bin/llvm-strip', '--strip-unneeded', target], log=log)
            headers = subprocess.check_output([toolchain / 'bin/llvm-readelf', '-h', '-d', '-l', target], text=True)
            if not re.search(r'Machine:\s+' + machine + r'\b', headers):
                raise RuntimeError(f'Unexpected ELF architecture for {target}')
            if '.so.1' in headers or 'libcrypto.so' in headers:
                raise RuntimeError(f'Unexpected versioned or dynamic crypto dependency for {target}')
            needed = re.findall(r'NEEDED[^\n]*\[([^\]]+)\]', headers)
            allowed = set(artifacts) | {'libc.so', 'libm.so', 'libdl.so', 'liblog.so'}
            if set(needed) - allowed:
                raise RuntimeError(f'Unpackaged dependency in {target}: {needed}')
            if abi == 'arm64-v8a':
                loads = [line for line in headers.splitlines() if line.strip().startswith('LOAD')]
                if not loads or any(int(line.split()[-1], 16) < 16384 for line in loads):
                    raise RuntimeError(f'ARM64 binary is not aligned for 16 KB Android pages: {target}')
            abi_evidence[name] = {'sha256': checksum(target), 'size': target.stat().st_size,
                                  'elf': headers}
        exported = subprocess.check_output([toolchain / 'bin/llvm-nm', '-D', '--defined-only',
                                           destination / 'libdesfire_jni.so'], text=True)
        required_jni = (
            'Java_com_desfire_ev3_NativeRuntime_abiVersion',
            'Java_com_desfire_ev3_NativeRuntime_manifestSha256',
            'Java_com_desfire_ev3_Native_open', 'Java_com_desfire_ev3_Native_close',
            'Java_com_desfire_ev3_Native_cancel', 'Java_com_desfire_ev3_Native_invoke',
            'Java_com_desfire_ev3_Native_authenticateDirect',
            'Java_com_desfire_ev3_Native_authenticateDerived',
            'Java_com_desfire_ev3_Native_authenticateProvider',
            'Java_com_desfire_ev3_Native_setDefaultAesKeyDirect',
            'Java_com_desfire_ev3_Native_setDefaultAesKeyDerived',
            'Java_com_desfire_ev3_Native_setDefaultAesKeyProvider',
            'Java_com_desfire_ev3_Native_changeAesKeyProvider',
            'Java_com_desfire_ev3_Native_createTransactionMacFileProvider',
            'Java_com_desfire_ev3_raw_RawNative_open',
            'Java_com_desfire_ev3_raw_RawNative_close',
            'Java_com_desfire_ev3_raw_RawNative_cancel',
            'Java_com_desfire_ev3_raw_RawNative_invoke',
            'Java_com_desfire_ev3_raw_RawNative_authenticateDirect',
            'Java_com_desfire_ev3_raw_RawNative_authenticateDerived',
            'Java_com_desfire_ev3_raw_RawNative_authenticateProvider',
            'Java_com_desfire_ev3_offline_OfflineNative_deriveDirect',
            'Java_com_desfire_ev3_offline_OfflineNative_deriveProvider',
            'Java_com_desfire_ev3_offline_OfflineNative_transactionMacDirect',
            'Java_com_desfire_ev3_offline_OfflineNative_transactionMacProvider',
            'Java_com_desfire_ev3_offline_OfflineNative_verifyOriginality',
            'Java_com_desfire_ev3_offline_OfflineNative_invoke',
            'Java_com_desfire_ev3_offline_OfflineNative_invokeProvider',
        )
        for symbol in required_jni:
            if symbol not in exported:
                raise RuntimeError(f'JNI binary is missing required entry point: {symbol}')
        c_exports = subprocess.check_output([toolchain / 'bin/llvm-nm', '-D', '--defined-only',
                                            destination / 'libdesfire_c.so'], text=True)
        expected_c_exports = {
            line for line in (ROOT / 'c-api/abi/abi-v1.symbols').read_text().splitlines()
            if line.startswith('df_')
        }
        actual_c_exports = {
            match.group(1)
            for match in re.finditer(r'\b(df_[a-z0-9_]+)(?:@@[A-Za-z0-9_.]+)?$', c_exports, re.M)
        }
        if actual_c_exports != expected_c_exports:
            raise RuntimeError(
                'Android C ABI differs from frozen baseline: '
                f'missing={sorted(expected_c_exports - actual_c_exports)}, '
                f'extra={sorted(actual_c_exports - expected_c_exports)}')
        if re.search(r'\b(?:EVP_|OPENSSL_|AES_)', c_exports):
            raise RuntimeError('C ABI exposes private static crypto symbols')
        shutil.copy2(source / 'LICENSE.txt', build_root / 'OPENSSL-LICENSE.txt')
        notices = ROOT / 'sdk/android/build/generated/licenseResources/META-INF'
        notices.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / 'LICENSE.txt', notices / 'LICENSE.openssl')
        copyright_section = (source / 'README.md').read_text().partition('\nCopyright\n')[2]
        if not copyright_section:
            raise RuntimeError('Pinned OpenSSL README lacks its expected copyright notice')
        (notices / 'NOTICE.openssl').write_text(
            f'OpenSSL {OPENSSL_VERSION}\nCopyright\n' + copyright_section)
        shutil.copy2(ndk / 'NOTICE.toolchain', notices / 'NOTICE.android-toolchain')
        shutil.copy2(ndk / 'NOTICE', notices / 'NOTICE.android-ndk')
        shutil.copy2(ROOT / 'LICENSE', notices / 'LICENSE.desfire')
        shutil.copy2(ROOT / 'NOTICE', notices / 'NOTICE.desfire')
        evidence['abis'][abi] = abi_evidence
        print(f'Verified {abi} runtime binaries', flush=True)
    (build_root / 'build-evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print(f'Native libraries ready at {output_root}', flush=True)


if __name__ == '__main__':
    main()
