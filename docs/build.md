# Build and integrate

The default core mode is C++26, with an explicit C++23 compatibility configuration.
The current host qualification uses Apple Clang 21 on macOS ARM64. CMake 4.1 does not
advertise Apple Clang's C++26 mode, so configuration probes `-std=c++26` before supplying
that missing CMake flag metadata. A compiler rejecting that flag fails configuration;
there is no silent language downgrade.

## Native dependencies

| Dependency | Required for | Notes |
| --- | --- | --- |
| CMake 3.25+ and C/C++ compiler | Every native build | Ninja is used by repository presets |
| OpenSSL Crypto 3.5+ | Supplied crypto provider and C ABI | Public core headers contain no OpenSSL implementation types |
| PC/SC SDK | Optional desktop PC/SC transport | macOS framework, Linux `libpcsclite` through pkg-config, Windows WinSCard |
| JDK | Optional Kotlin/JNI bridge | Enable `DESFIRE_BUILD_JNI` and follow the Kotlin guide |
| Doxygen | Generated native API reference | Warnings fail `docs`; authored-contract checks run in `docs-check` |

PC/SC is enabled by default. Disable it with `-DDESFIRE_BUILD_PCSC=OFF` for callback-only or
card-free integration. Compiling PC/SC support is separate from reader interoperability testing.
Host builds normally link the system OpenSSL runtime; package it according to the deployment
platform's rules.

## Choose a native configuration

| Goal | Command |
| --- | --- |
| Default C++26 release | `cmake --preset release` |
| Maintained C++23 compatibility | `cmake --preset compat23` |
| Debug tests | `cmake --preset debug` |
| ASan and UBSan | `cmake --preset sanitized` |
| ThreadSanitizer | `cmake --preset thread-sanitized` |
| Custom card-free build | Use the command below |

```sh
cmake -S . -B build/local -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DDESFIRE_CXX_STANDARD=23 -DDESFIRE_BUILD_PCSC=OFF
cmake --build build/local --parallel
ctest --test-dir build/local --output-on-failure
cmake --install build/local --prefix "$PWD/build/install"
```

C99 and C++17 consumers use the installed C ABI. A matching architecture, OS ABI, and
runtime deployment are still required; C ABI compatibility does not make a macOS binary
usable on Windows or an ARM library usable on x86.

```cmake
find_package(desfire-sdk CONFIG REQUIRED)
target_link_libraries(c_reader PRIVATE desfire::c)
target_link_libraries(cpp17_reader PRIVATE desfire::cpp17)
```

Use `#include <desfire.h>` from C and `#include <desfire/cpp17.hpp>` from the C++17 facade.
Do not include `<desfire/ev3/ev3.hpp>` in a C++17 translation unit. The installed consumer
fixture under `tests/install-consumer` verifies that modern language requirements do
not propagate through the C target.

For the modern API, link `desfire::ev3_core`, the selected transport, and crypto provider.
`Card::connect()` takes shared ownership of an already activated `CardTransport` and a
`CryptoProvider`. No reader is implicitly selected.

| Installed target | Purpose |
| --- | --- |
| `desfire::foundation` | Byte, result, error, secret, transport, and crypto contracts |
| `desfire::ev3_core` | Modern typed EV3 protocol and managed Card |
| `desfire::crypto_openssl` | Optional OpenSSL primitive provider |
| `desfire::transport_callback` | Adapter for an application-owned reader SDK |
| `desfire::transport_replay` | Deterministic request/response transport for tests |
| `desfire::transport_pcsc` | Optional desktop PC/SC discovery and exchange |
| `desfire::c` | Versioned C99 ABI v1 |
| `desfire::cpp17` | Header-only C++17 facade over the C ABI |

See [reader integration](reader-integration.md) for a complete read-only PC/SC flow and callback
adapter contract.

## Android and Apple

Android has a reproducible NDK build script that verifies the pinned OpenSSL source
checksum and builds ARM64, ARMv7 and x86_64 JNI/C runtimes. The AAR contains the Android IsoDep
adapter and native runtime; the portable Kotlin JAR remains a separate Gradle API dependency.
Follow `sdk/android/README.md`; native build outputs remain in ignored build directories. The
Android packages compile and target Android 17 / API 37 with a minimum runtime API of 23. API 23
itself has not been runtime-qualified in this session.

Swift is a Swift Package facade over the same C ABI. The portable `DesfireEV3` and separate
`DesfireEV3CoreNFC` products compile for iOS 16 device and simulator targets. Build OpenSSL and
the C ABI for the same deployment target and architecture as the app; the macOS 14 verification
uses a pinned static OpenSSL 3.5.8 build. `sdk/apple/tools/build_xcframework.py` validates explicit
device and universal-simulator archives before assembly. Signing, physical CoreNFC exchange and
EV3 qualification remain release acceptance work.

## Build without the bundled primitive provider

`core-only` disables OpenSSL, the C ABI, JNI, and PC/SC. Inject a `CryptoProvider` for
managed secure operations and a `CardTransport` for frame I/O. The C ABI uses OpenSSL for
software primitives and exposes `df_key_provider_v1` for caller-defined exportable AES-128
key resolution. Non-exportable SAM/HSM keys require a separate cryptographic-operation
provider contract and remain outside this release.
