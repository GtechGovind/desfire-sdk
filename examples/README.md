# Examples

The C and C++17 examples are normal CMake targets and build with the root project. The Python and
Node examples execute the published NXP AES-128 diversification vector against an explicitly
selected native library. Kotlin's `examplesCheck` task compiles its public example, Android's
`compileDebugAndroidTestKotlin` compiles the NFC example, and Swift parses its standalone example
as part of the documented verification commands.

```sh
cmake --build build/release --target desfire_c_offline_example desfire_cpp17_offline_example

DESFIRE_LIBRARY="$PWD/build/release/c-api/libdesfire_c.dylib" \
  PYTHONPATH=sdk/python/src python3 examples/python/offline_key_derivation.py

DESFIRE_NODE_ADDON="$PWD/build/node/desfire_node.node" \
  DYLD_LIBRARY_PATH="$PWD/build/release/c-api" \
  node examples/node/offline-key-derivation.mjs

../TR/gradlew -p sdk/kotlin examplesCheck
../TR/gradlew -p sdk/android compileDebugAndroidTestKotlin
swiftc -parse examples/swift/OfflineKeyDerivation.swift
```

Replace macOS library names and loader variables with their Linux or Windows equivalents. The
examples contain only public test material. Applications must load keys from their own provider,
retain transaction outcome evidence, and reconcile unknown mutations.
