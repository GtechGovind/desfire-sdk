# Build and integrate

The default core mode is C++26, with an explicit C++23 compatibility configuration.
The current host qualification uses Apple Clang 21 on macOS ARM64. CMake 4.1 does not
advertise Apple Clang's C++26 mode, so configuration probes `-std=c++26` before supplying
that missing CMake flag metadata. A compiler rejecting that flag fails configuration;
there is no silent language downgrade.

## Native dependencies

- CMake 3.25 or newer and a working C/C++ compiler; Ninja is used by the presets.
- OpenSSL 3.5+ Crypto for the supplied provider and C ABI. OpenSSL implementation types
  do not appear in public protocol headers. Host builds normally link the system
  OpenSSL runtime; package it according to the target platform's deployment rules.
- PC/SC is optional. macOS uses its framework, Linux uses `libpcsclite` through pkg-config,
  and Windows uses WinSCard. Disable it with `-DDESFIRE_BUILD_PCSC=OFF` for callback-only
  integration. PC/SC compilation is separate from reader interoperability testing.
- JNI is optional: enable `-DDESFIRE_BUILD_JNI=ON` and provide a JDK. See the Kotlin README.
- Doxygen is required for the `docs` target. Documentation warnings fail the build; `docs-check`
  separately verifies authored declarations and out-of-line definitions.

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

## Android and Apple

Android has a reproducible NDK build script that verifies the pinned OpenSSL source
checksum and builds ARM64, ARMv7 and x86_64 JNI/C runtimes. The AAR also contains portable Kotlin
classes and the IsoDep adapter. Follow `sdk/android/README.md`; native build outputs remain
in ignored build directories. The Android minimum target is API 23, but API 23 itself
has not been runtime-qualified in this session.

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
