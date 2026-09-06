# Verification and qualification record

Run validation from the repository root. Every build must use a fresh or correctly reconfigured
CMake directory; a passing stale binary is not evidence for changed source.

```sh
cmake --preset debug
cmake --build --preset debug --parallel
ctest --preset debug

cmake --preset release
cmake --build --preset release --parallel
ctest --preset release

cmake --preset compat23
cmake --build --preset compat23 --parallel
ctest --preset compat23

cmake --preset sanitized
cmake --build --preset sanitized --parallel
ctest --preset sanitized

cmake --preset thread-sanitized
cmake --build --preset thread-sanitized --parallel
ctest --preset thread-sanitized
```

The host suite checks exact direct-native, wrapped-native and true-ISO frames; parser rejection;
published cryptographic vectors; secure counter and session transitions; lost-response outcomes;
additional-frame boundaries; callback reentry; concurrent cancellation; C ownership and ABI
layout; strict C++17 compatibility; and 100,000 deterministic structured/random parser inputs.
The build also compiles every public modern C++, C99 and C++17 header independently. The optional
coverage-guided fuzzer could not link on this host because Xcode's Apple Clang 21 installation lacks
`libclang_rt.fuzzer_osx.a`; the deterministic parser stress target remains active under both
sanitizer configurations.

Install and test consumers independently in both modern language modes:

```sh
cmake --install build/release --prefix "$PWD/build/install"
cmake -S tests/install-consumer -B build/install-consumer -G Ninja \
  -DCMAKE_PREFIX_PATH="$PWD/build/install" \
  -DDESFIRE_INSTALL_CONSUMER_CXX_STANDARD=26
cmake --build build/install-consumer --parallel
ctest --test-dir build/install-consumer --output-on-failure
```

Binding commands and prerequisites live in each SDK README. All binding generators consume the
canonical manifest. They verify ABI version 1, the canonical digest, 125 exports and 120 fallible
operations before opening a handle. Generated code contains no protocol encoding.

## Evidence recorded on 2026-09-06

- macOS ARM64 C++26 debug/release and C++23 release: 15/15 tests passed in each configuration.
- macOS ARM64 ASan/UBSan and TSan: 15/15 tests passed in each instrumented configuration.
- PC/SC-enabled C++26 source build: 15/15 host/replay tests passed; no physical reader was attached.
- Core-only C++26 and C++23 builds without OpenSSL, PC/SC, C ABI or JNI: 3/3 applicable tests passed.
- Installed packages: C99, C++17, C++17 `-fno-exceptions`, throwing C++17, and modern C++23/C++26
  consumers passed 5/5 in each modern mode.
- ABI/API gates: all 125 exports matched the Mach-O/ELF/PE allowlists; all 120 operation IDs matched
  the manifest and six generated binding inventories; every public native and facade header
  compiled alone.
- Python: 28/28 tests passed on Python 3.10 and 3.12; strict mypy, Ruff, generated parity, wheel,
  source distribution, clean Python 3.10 installation and known-answer smoke test passed.
- Node/TypeScript: 20/20 native tests passed on Node 26; strict TypeScript, generated parity and npm
  package verification passed. Node 20/22/24 runtime execution remains a release-matrix task.
- Kotlin/JVM/JNI: clean host conformance passed against C++26 and C++23 native builds; the public
  example compiled. The suite covers managed/raw/offline paths, providers, cancellation, reentry
  and independent JCE cryptographic fixtures.
- Android: OpenSSL 3.5.8 and the complete C/JNI runtime built for `arm64-v8a`, `armeabi-v7a` and
  `x86_64` at API 23 with C++26. Export/dependency checks, ARM64 16 KiB alignment, release assembly,
  lint, Android-test/example compilation and nine-library AAR verification passed. No Android
  emulator or physical NFC device was attached for the current revision.
- Swift 6: 14/14 macOS tests passed with complete strict concurrency and warnings as errors against
  a macOS 14 native library using static OpenSSL 3.5.8. iOS 16 ARM64 device and x86_64 simulator
  source builds, including `DesfireEV3CoreNFC`, passed. No signed XCFramework was assembled.
- The 60,000-iteration release benchmark measured 4,735.15 MiB/s codec throughput and 548,647
  EV2 session operations/s on this host. These values are initial host evidence, not thresholds for
  other hardware; future releases require a controlled same-host baseline before applying the 5%
  regression gate.

Package hashes from this uncommitted development tree are recorded only as build evidence:

- Android AAR: `fbe6e275eb739c6458a04aa5ac6201b9dd546306eb231c7d552eb185fd2c2fb2`.
- Python wheel: `ff7d03ec2fa135d64ec2b811705c38406d4a8af5839aeda59e7de9fa665a5ef6`.
- Python source distribution: `0d5f6d9fd07175527c8be8a641d5b2f38a60174af024588ed05eda8c71f90085`.
- Node source package: `4a85c2229ecac5c5f38c9f45fae1d5a567f46da979cb12a825fa4a34337dd386`.

This is source, host, cross-compilation and package evidence. It is not evidence for a physical EV3
card, RF timing, a deployed PC/SC reader, ARMv7 device execution, Android API 23 runtime, CoreNFC
device behavior, Windows, Linux, SAM/HSM, production keys, field transaction policy or
certification.

## Required target acceptance

Before production, record the exact SDK revision, compiler, OS/ABI, reader and firmware, EV3 part
and card configuration, application/file/key policy, and test-key provenance. On each target, run:

1. activation and removal during every authentication and additional-frame boundary;
2. native and ISO-wrapped long reads/writes at actual reader limits;
3. AES First/NonFirst, MAC/full reads and writes, wrong-key and tamper failures;
4. power loss and cancellation before, during and after each value/backup/record mutation and commit;
5. durable reconciliation of a lost commit response without blind retry;
6. concurrent reader-event/cancel/application calls and reconnect generation changes;
7. malformed or truncated reader responses and maximum-size inputs;
8. originality/TMV verification using authoritative EV3 keys and transaction definitions;
9. memory/thread/latency soak tests under the application's real workload; and
10. signed release artifact, dependency-license, symbol/export, SBOM and upgrade/rollback checks.

Record observed frames and outcomes without storing keys or personal card data. A passed build,
source compile, replay fixture, emulator run and physical target acceptance are separate levels.
