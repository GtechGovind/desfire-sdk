# DESFire EV3 Android SDK

The Android module depends on `:desfire-kotlin` and contains only Android-specific integration:
`IsoDepTransport` and `AndroidCardSession`. It does not compile or duplicate the portable Kotlin
source tree.

Use an already connected `IsoDep` from NFC discovery. `AndroidCardSession` opens the portable
suspend-first `Card`, owns the adapter, and closes the card before the Android connection:

```kotlin
val isoDep = IsoDep.get(tag) ?: return
isoDep.connect()
val session = AndroidCardSession.open(isoDep)
try {
    session.card.selectApplication(ApplicationId(1))
    val bytes = session.card.readData(FileNumber(0), ByteOffset(0), 16, Communication.PLAIN)
} finally {
    session.close()
}
```

Portable `Card` calls dispatch through `Dispatchers.IO`. `IsoDepTransport` rejects a direct exchange
on the Android main thread. Android assembles ISO-DEP fragments; the core handles documented
DESFire additional frames. Cancellation closes `IsoDep` to interrupt `transceive`. A lost or
cancelled tag must be rediscovered, and reset reports `UNSUPPORTED` because Android cannot promise
a physical reset without rediscovery. An I/O failure after entering `transceive` preserves
`Outcome.UNKNOWN`; no layer reconnects or retries the command.

The AAR packages the Android adapter, consumer shrinker rules, `libdesfire_jni.so`,
`libdesfire_c.so`, and `libc++_shared.so` for `arm64-v8a`, `armeabi-v7a`, and `x86_64`. The portable
Kotlin JAR is a Gradle API dependency and remains a separate artifact. Published Maven metadata
carries that transitive dependency. A local flat-file AAR integration must add the portable Kotlin
JAR and coroutines explicitly.

Build with Android SDK 36, NDK 29.0.14206865, CMake, Ninja, Perl, Make, Python 3.9+, and a compatible
Gradle release:

```sh
export ANDROID_HOME="$HOME/Library/Android/sdk"
export ANDROID_NDK_ROOT="$ANDROID_HOME/ndk/29.0.14206865"
python3 sdk/android/tools/build_native.py
../TR/gradlew -p sdk/android assembleRelease
python3 sdk/android/tools/verify_aar.py
```

Packaging fails when an expected native library is missing. The native build records per-ABI ELF
hashes in `build/native/build-evidence.json`; AAR verification compares those exact hashes, required
Android classes, notices, and shrinker rules. It also requires the complete frozen C export set and
every managed, raw, provider, offline, and manifest-check JNI entry point. Run
`connectedDebugAndroidTest` on ARM hardware or an
ARM emulator to cross Android Kotlin, packaged JNI, C, C++, and the deterministic replay transport.
Host/Android replay tests do not establish NFC RF behavior, minimum-API device operation, ARMv7
runtime behavior, or EV3 card/profile certification; validate those on the deployment hardware.
