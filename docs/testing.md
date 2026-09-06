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

This C++26 example installs and tests consumers independently of the build tree:

```sh
cmake --install build/release --prefix "$PWD/build/install"
cmake -S tests/install-consumer -B build/install-consumer -G Ninja \
  -DCMAKE_PREFIX_PATH="$PWD/build/install" \
  -DDESFIRE_INSTALL_CONSUMER_CXX_STANDARD=26
cmake --build build/install-consumer --parallel
ctest --test-dir build/install-consumer --output-on-failure
```

Repeat the same two install-consumer steps with `build/compat23`, a separate install prefix and
`DESFIRE_INSTALL_CONSUMER_CXX_STANDARD=23` to verify the C++23 core package. The C99 and C++17
consumers remain insulated from the core language mode in both installations.

Binding commands and prerequisites live in each SDK README. All binding generators consume the
canonical manifest. They verify ABI version 1, the canonical digest, 125 exports and 120 fallible
operations before opening a handle. Generated code contains no protocol encoding.

## Current commit-bound evidence

The final local evidence is bound to revision
[`6378f6f`](https://github.com/GtechGovind/desfire-sdk/commit/6378f6fe84d239a722f1bbca584280e801bc672d)
and canonical API digest
`15bff2b3d371174e8b26350f95b2f6589149b50fab11652ec181961015416596`.

- C++26 debug/release, C++23 release, ASan/UBSan, and TSan each passed 15/15 tests. Four
  concurrency-sensitive scenarios passed another 80 TSan executions with no diagnostic.
- Installed C99, C++17, C++17 `-fno-exceptions`, throwing C++17, and modern C++ consumers passed
  5/5. API/ABI generation matched all 120 operations and 125 exports; all 44 mutation operations
  carry an explicit reconciliation contract.
- Python passed 28 tests, mypy, Ruff, wheel/source-distribution build, and Python 3.10 clean-install
  verification. Node passed 20 tests, strict TypeScript, generated parity, native-addon build, and
  package verification. Kotlin/JNI passed its host conformance and compiled example.
- Swift passed 14 macOS tests and compiled both products for iOS 16 ARM64 device and x86_64
  simulator with complete strict concurrency and warnings as errors.
- Android Gradle 9.6.0 / AGP 9.4.0 completed 200 tasks for release/debug assembly, lint, unit tests,
  Android-test compilation, and the Compose showcase. The C++26 native runtime and OpenSSL 3.5.8
  were verified for ARM64, ARMv7, and x86_64, including required 16 KiB alignment. The AAR, debug
  APK, and unsigned release APK digests are recorded in `spec/qualification-record.yaml`. The
  [hosted API 37.0 run](https://github.com/GtechGovind/desfire-sdk/actions/runs/34031311221)
  passed both the SDK/JNI and Compose showcase instrumentation suites on a 16 KiB emulator.
- The exact 407-file Git archive passed complete-history and source Gitleaks scans. Semgrep reported
  zero findings over 374 targets, and Grype reported zero matches across the 50-component source
  SBOM. The build-tool graph retains two high and five medium advisories documented in
  `docs/qualification/supply-chain-security.md`; the shipped managed runtime graph has none.

Physical EV3, PC/SC reader, Android NFC, CoreNFC, production-key, and certification evidence
remain unrun.

## Retained evidence recorded on 2026-09-06

The implementation evidence below is bound to revision
[`0f3b733`](https://github.com/GtechGovind/desfire-sdk/commit/0f3b733f27b73481f7b26cf9402b64ccfc256e75).
The corresponding hosted runs are [native](https://github.com/GtechGovind/desfire-sdk/actions/runs/34018109654),
[sanitizers](https://github.com/GtechGovind/desfire-sdk/actions/runs/34018109616),
[bindings](https://github.com/GtechGovind/desfire-sdk/actions/runs/34018109623),
[CodeQL](https://github.com/GtechGovind/desfire-sdk/actions/runs/34018109680),
[quality](https://github.com/GtechGovind/desfire-sdk/actions/runs/34018109788),
[Android](https://github.com/GtechGovind/desfire-sdk/actions/runs/34018114369), and
[security](https://github.com/GtechGovind/desfire-sdk/actions/runs/34018115410).

- Hosted Linux, macOS, and Windows C++23/C++26 builds: 15/15 tests passed in each matrix
  configuration, including installed C, C++17, and modern C++ consumers.
- Local macOS ARM64 C++26 debug/release and C++23 release: 15/15 tests passed in each
  configuration.
- macOS ARM64 ASan/UBSan and TSan: 15/15 tests passed in each instrumented configuration.
- PC/SC-enabled C++26 source build: 15/15 host/replay tests passed; no physical reader was attached.
- Core-only C++26 and C++23 builds without OpenSSL, PC/SC, C ABI or JNI: 3/3 applicable tests passed.
- Installed packages: C99, C++17, C++17 `-fno-exceptions`, throwing C++17, and modern C++23/C++26
  consumers passed 5/5 in each modern mode.
- ABI/API gates: all 125 exports matched the Mach-O/ELF/PE allowlists; all 120 operation IDs matched
  the manifest and six generated binding inventories; every public native and facade header
  compiled alone.
- Python: 28/28 tests passed on Python 3.10 and 3.14; strict mypy, Ruff, generated parity, wheel,
  source distribution, clean Python 3.10 installation and known-answer smoke test passed.
- Node/TypeScript: 20/20 native tests passed on Node 20, 22, 24, and 26 on Linux; strict
  TypeScript, generated parity and npm package verification passed.
- Kotlin/JVM/JNI: clean host conformance passed against C++26 and C++23 native builds; the public
  example compiled. The suite covers managed/raw/offline paths, providers, cancellation, reentry
  and independent JCE cryptographic fixtures.
- Android: OpenSSL 3.5.8 and the complete C/JNI runtime built for `arm64-v8a`, `armeabi-v7a` and
  `x86_64` at API 23 with C++26. Export/dependency checks, ARM64 16 KiB alignment, release assembly,
  lint, Android-test/example compilation and nine-library AAR verification passed. No Android
  emulator or physical NFC device was attached for the recorded revision.
- Swift 6: 14/14 macOS tests passed with complete strict concurrency and warnings as errors against
  a macOS 14 native library using static OpenSSL 3.5.8. iOS 16 ARM64 device and x86_64 simulator
  source builds, including `DesfireEV3CoreNFC`, passed. No signed XCFramework was assembled.
- The 60,000-iteration release benchmark measured 4,735.15 MiB/s codec throughput and 548,647
  EV2 session operations/s on this host. These values are initial host evidence, not thresholds for
  other hardware; future releases require a controlled same-host baseline before applying the 5%
  regression gate.
- The opt-in CodSpeed executable and public-repository workflow provide hosted simulation profiles
  for native codecs and EV2 MAC sessions. After the public repository is imported into CodSpeed,
  set the repository variable `CODSPEED_ENABLED=true`, configure its performance-check threshold
  to 5%, and establish the first approved baseline. Until then, CI executes both benchmarks as a
  smoke test without uploading. Hosted comparisons do not establish embedded-reader performance
  acceptance; a controlled same-host release baseline is still required before the local 5% gate
  can be enforced.

Per-run Android, Python, Node, source-archive, SBOM, and checksum artifacts are retained by their
workflows. A release record must bind final artifact hashes to its source revision and attestation;
development-run package hashes are not evergreen release identifiers.

This is source, host, cross-compilation and package evidence. It is not evidence for a physical EV3
card, RF timing, a deployed PC/SC reader, ARMv7 device execution, Android API 23 runtime, CoreNFC
device behavior, SAM/HSM, production keys, field transaction policy or
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
