# Examples

The examples are intentionally small and contain public test material only. Card-free examples
run the real native offline implementation; reader examples show lifecycle and API integration but
need an application-owned reader or mobile NFC session.

| Language | Example | Verification level |
| --- | --- | --- |
| C | [Offline NXP AES-128 diversification](c/offline_key_derivation.c) | Compiled by native CI; executable command below |
| C++17 | [Offline NXP AES-128 diversification](cpp17/offline_key_derivation.cpp) | Compiled by native CI; executable command below |
| Python | [Offline NXP AES-128 diversification](python/offline_key_derivation.py) | Manual C shared-library command below |
| Node.js | [Offline NXP AES-128 diversification](node/offline-key-derivation.mjs) | Manual N-API addon command below |
| Kotlin/JVM | [Offline NXP AES-128 diversification](kotlin/OfflineKeyDerivation.kt) | Compiled by `examplesCheck` |
| Android | [Compose Showcase application](android-app/README.md) | Three-ABI APK assembly and strict lint in Android CI; physical NFC required |
| Swift | [Offline NXP AES-128 diversification](swift/OfflineKeyDerivation.swift) | Parsed by Swift 6 source checks |

## Native C and C++17

Configure from the repository root. PC/SC is disabled because these examples do not need a reader.

```sh
cmake -S . -B build/examples -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DDESFIRE_CXX_STANDARD=23 \
  -DDESFIRE_BUILD_PCSC=OFF
cmake --build build/examples --parallel \
  --target desfire_c_offline_example desfire_cpp17_offline_example

./build/examples/examples/desfire_c_offline_example
./build/examples/examples/desfire_cpp17_offline_example
```

## Python

```sh
DESFIRE_LIBRARY="$PWD/build/examples/c-api/libdesfire_c.dylib" \
  PYTHONPATH=sdk/python/src \
  python3 examples/python/offline_key_derivation.py
```

Use `libdesfire_c.so` on Linux or an absolute path to `desfire_c.dll` on Windows. Set the
platform runtime library search path if dependent shared libraries are not already discoverable.

## Node.js and TypeScript

Build the C ABI and Node addon first by following the [Node SDK guide](../sdk/node/README.md), then
run:

```sh
DESFIRE_NODE_ADDON="$PWD/build/node-ev3/desfire_node.node" \
  DYLD_LIBRARY_PATH="$PWD/build/ev3/c-api" \
  node examples/node/offline-key-derivation.mjs
```

Use `LD_LIBRARY_PATH` on Linux. On Windows, place the matching `desfire_c.dll` beside the addon
or on the process DLL search path.

## Kotlin/JVM and Android

The repository-owned Gradle wrapper and strict verification metadata make dependency resolution
repeatable:

```sh
python3 sdk/android/tools/build_native.py

./gradlew -p sdk/kotlin --dependency-verification strict \
  --no-daemon --no-build-cache examplesCheck

./gradlew -p sdk/android --dependency-verification strict \
  --no-daemon --no-build-cache \
  compileDebugAndroidTestSources \
  :example-app:assembleDebug :example-app:lintDebug \
  -PdesfireNativeDirectory="$PWD/sdk/android/build/native-jniLibs"
```

The [Compose Showcase](android-app/README.md) produces an installable APK and demonstrates NFC
discovery, managed and raw session ownership, typed discovery/authentication/file/transaction
workflows, all 120 searchable operations, review-before-send mutation handling, and Direct,
Derived, Provider, and optional GKey Provider key paths. It contains no default key or seed. The
smaller [owned IsoDep snippet](android/IsoDepSession.kt) remains a focused lifecycle example.

## Swift

```sh
swiftc -parse examples/swift/OfflineKeyDerivation.swift
```

Run the complete Swift package checks with `python3 sdk/apple/tools/test.py` after building the
native C library as described in the [Swift SDK guide](../sdk/apple/README.md).

## Integrating a physical reader

Read the [reader integration guide](../docs/reader-integration.md) for PC/SC and callback transport
examples, framing selection, limits, lifecycle, and result handling. Applications must load keys
from their own provider, retain transaction outcome evidence, and reconcile unknown mutations.
