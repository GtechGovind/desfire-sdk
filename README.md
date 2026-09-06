# DESFire EV3 SDK

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Native compatibility](https://github.com/GtechGovind/desfire-sdk/actions/workflows/native.yml/badge.svg)](https://github.com/GtechGovind/desfire-sdk/actions/workflows/native.yml)
[![Language bindings](https://github.com/GtechGovind/desfire-sdk/actions/workflows/bindings.yml/badge.svg)](https://github.com/GtechGovind/desfire-sdk/actions/workflows/bindings.yml)
[![CodeQL](https://github.com/GtechGovind/desfire-sdk/actions/workflows/codeql.yml/badge.svg)](https://github.com/GtechGovind/desfire-sdk/actions/workflows/codeql.yml)
![Core: C++26 and C++23](https://img.shields.io/badge/core-C%2B%2B26%20%7C%20C%2B%2B23-00599C.svg)
![ABI: C99 v1](https://img.shields.io/badge/ABI-C99%20v1-555555.svg)
![Status: development release](https://img.shields.io/badge/status-development%20release-orange.svg)

An independently authored EV3 SDK with a C++26 core, a versioned C99 ABI, and C++17,
Python, Node/TypeScript, Kotlin/JVM, Android, and Swift interfaces. This repository contains the
EV3-only implementation.

The implemented paths cover native commands, ISO-wrapped native commands, and true
ISO 7816 commands. Standard AES (`0xAA`) and EV2 AES First/NonFirst authentication use
their documented chained-IV and counter-based plain/MAC/full messaging profiles. ISO
AES authentication has its own state and response-integrity handling. AES delegated
application creation includes checked two-frame commands plus offline EncK and
create/delete/configuration DAM-MAC generation. Reader activation and card provisioning belong to
the integrating application.

This is a development release with substantial host, sanitizer, binding, and Android
cross-build/package evidence. It has **not been qualified on physical EV3 cards or production
readers**. SDM configuration/interpretation and automatic EV3 transaction-MAC input construction
are explicitly unimplemented. Other capability and platform limits are listed in the
[coverage matrix](spec/coverage.md). No blanket EV3-completeness or battle-tested claim is made.

## Why use this SDK

- **One protocol implementation:** framing, parsing, authentication, secure messaging, and
  transaction outcomes live in the native core instead of being reimplemented by each binding.
- **Friendly and expert surfaces:** typed managed workflows cover documented operations, while
  bounded raw native and ISO channels preserve exact statuses for advanced integrations.
- **Explicit recovery:** errors retain delivery outcome and card status, and mutations are never
  retried automatically after an uncertain transmission.
- **Flexible key integration:** callers can supply an exact AES-128 key, a custom derivation policy,
  or a provider that resolves a scoped non-secret key reference before card I/O.
- **Older toolchain access:** C++17 applications use the facade over ABI v1; C and older C++
  applications use the C99 API directly.
- **Auditable parity:** a canonical operation manifest drives all bindings, and coverage records
  distinguish implemented software from physical-card and reader qualification.

## Choose an interface

| Need | Interface |
| --- | --- |
| Direct modern native integration | `desfire::ev3_core` with C++26 or C++23 |
| Stable native ABI or older C++ compiler | `<desfire.h>` and `desfire::c` |
| Typed C++17 integration | `<desfire/cpp17.hpp>` and `desfire::cpp17` |
| Application-language workflow | Kotlin/JVM, Android, Python, Node/TypeScript, or Swift SDK |
| Exact command/status control | The interface's explicit `raw` or expert namespace |

Managed and raw owners cannot use the same activated transport concurrently. Reader activation,
timeouts, and cancellation are supplied by the integrating application.

## Build

Use CMake 3.25+, Ninja, a compiler accepting C++26, and OpenSSL 3.5+ development files.
The C++23 build is available for toolchains that do not yet accept C++26.

```sh
cmake --preset debug
cmake --build --preset debug --parallel
ctest --preset debug
cmake --install build/debug --prefix "$PWD/build/install"
```

For C++23, use the `compat23` presets or `-DDESFIRE_CXX_STANDARD=23`. The `sanitized`
preset enables ASan and UBSan. The `core-only` preset builds without OpenSSL, PC/SC,
or the C ABI for hosts supplying their own providers.

C++26 is the default language mode; this does not assert implementation of every
C++26 library feature. Consumer compatibility is explicit:

| Consumer | Installed CMake target | Requirement |
| --- | --- | --- |
| Modern native C++ API | `desfire::ev3_core` | SDK-selected C++23 or C++26 mode |
| C++17 facade | `desfire::cpp17` | C++17 compiler; links the C ABI |
| C or older C++ integration | `desfire::c` | C99-compatible header; platform C calling convention |

The C++17 facade uses the C ABI internally. It does not require an older compiler to
compile the C++26 implementation, and no STL objects or C++ exceptions cross the ABI.
See [build and integration](docs/build.md) for platform dependencies and installation.

## Quick card-free usage

Offline operations use the same C ABI and bindings without opening a reader. This C++17 example
imports a test key and performs NXP AES-128 diversification:

```cpp
#include <desfire/cpp17.hpp>

int main() {
    using namespace desfire::cpp17;

    auto key = Aes128Key::import(Bytes(16));
    if (!key) {
        return 1;
    }

    auto derived = offline::derive_nxp_aes128(
        key.value(), Bytes{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06});
    return derived ? 0 : 1;
}
```

Build and run the complete checked examples:

```sh
cmake --build build/debug --target desfire_c_offline_example desfire_cpp17_offline_example
./build/debug/examples/desfire_cpp17_offline_example
```

Online use starts by adapting the reader's exchange, reset, and cancellation operations to the
selected binding. The binding guides below provide complete ownership and recovery examples.

## Use and verification

- [C ABI ownership and recovery](docs/api-contract.md)
- [C++17 facade](sdk/cpp17/README.md)
- [Python](sdk/python/README.md)
- [Node.js and TypeScript](sdk/node/README.md)
- [Kotlin/JVM](sdk/kotlin/README.md) and [Android](sdk/android/README.md)
- [Swift](sdk/apple/README.md)
- [Command coverage and exclusions](spec/coverage.md)
- [Reproducible tests and qualification record](docs/testing.md)
- [Release procedure and evidence](RELEASING.md)
- [Architecture](docs/architecture.md) and [coding standards](docs/coding-standards.md)
- [Compiled and executable examples](examples/README.md)

The SDK does not automatically retry a mutation or reconnect after uncertain delivery.
Applications must reconcile an `unknown` transaction outcome before attempting another
mutation. Keys are caller supplied; the SDK includes no production credentials.

Distributed under [Apache-2.0](LICENSE). See [NOTICE](NOTICE) and
[dependency notices](docs/dependencies.md). Restricted reference documents and vendor
implementations are excluded from distribution.

Contributions and issue reports are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md),
[SUPPORT.md](SUPPORT.md), the [code of conduct](CODE_OF_CONDUCT.md), and
[GOVERNANCE.md](GOVERNANCE.md) before participating. Report security vulnerabilities through the
private process in [SECURITY.md](SECURITY.md), not a public issue.
