# DESFire EV3 Android SDK

The Android module depends on `:desfire-kotlin` and contains only Android-specific integration:
`IsoDepTransport`, `AndroidCardSession`, and `AndroidRawSession`. It does not compile or duplicate
the portable Kotlin source tree. The [Compose Showcase](../../examples/android-app/README.md)
demonstrates these adapters in a lifecycle-aware application.

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

Use `AndroidRawSession.open(isoDep)` for exact native or ISO exchanges. A raw session exclusively
owns its connected `IsoDep`; never share that activation with an `AndroidCardSession`. Close the
managed session before rediscovery and raw admission, and close the raw session before returning to
managed workflows.

Both `open` functions transfer `IsoDep` ownership only when they return a session. If opening throws,
the caller retains the handle and must retry `close()` when a suppressed cleanup failure is present.
The Showcase keeps this pre-session owner in its serialized controller and will not admit another tag
until release succeeds.

Portable `Card` calls dispatch through `Dispatchers.IO`. `IsoDepTransport` rejects a direct exchange
on the Android main thread. Android assembles ISO-DEP fragments; the core handles documented
DESFire additional frames. Cancellation closes `IsoDep` to interrupt `transceive`. A lost or
cancelled tag must be rediscovered, and reset reports `UNSUPPORTED` because Android cannot promise
a physical reset without rediscovery. An I/O failure after entering `transceive` preserves
`Outcome.UNKNOWN`; no layer reconnects or retries the command.

The AAR packages the Android adapter, consumer shrinker rules, `libdesfire_jni.so`,
`libdesfire_c.so`, and `libc++_shared.so` for `arm64-v8a`, `armeabi-v7a`, and `x86_64`. The portable
Kotlin JAR is a Gradle API dependency and remains a separate artifact. A future Maven publication
must carry that transitive dependency. A local flat-file AAR integration must add the portable
Kotlin JAR and coroutines explicitly.

Build with Android SDK 37, NDK 29.0.14206865, CMake, Ninja, Perl, Make, Python 3.9+, and a compatible
pinned repository Gradle wrapper:

```sh
export ANDROID_HOME="$HOME/Library/Android/sdk"
export ANDROID_NDK_ROOT="$ANDROID_HOME/ndk/29.0.14206865"
python3 sdk/android/tools/build_native.py
./gradlew -p sdk/android --dependency-verification strict \
  --no-daemon --no-build-cache assembleRelease
python3 sdk/android/tools/verify_aar.py
```

Packaging fails when an expected native library is missing. The native build records per-ABI ELF
hashes in `build/native/build-evidence.json`; AAR verification compares those exact hashes, required
Android classes, notices, and shrinker rules. It also requires the current 125-symbol ABI v1
allowlist and every managed, raw, provider, offline, and manifest-check JNI entry point. Run
`connectedDebugAndroidTest` on ARM hardware or an ARM emulator to cross Android Kotlin, packaged
JNI, C, C++, and the deterministic replay transport.
The Android package workflow also installs and launches the Showcase on its API 37, 16 KiB x86_64
emulator and exercises the card-free raw review/confirmation flow. That smoke test does not emulate
NFC RF or a physical card.
Host/Android replay tests do not establish NFC RF behavior, minimum-API device operation, ARMv7
runtime behavior, or EV3 card/profile certification; validate those on the deployment hardware.

Kotlin and Android heap objects can retain key copies outside JNI control. Keep direct keys scoped,
exclude them from logging and crash reports, disable secret-bearing heap dumps, and use a provider
for short-lived exportable keys where possible. Offline transaction-MAC helpers require the
caller's complete authoritative TMI; automatic EV3 TMI construction is unavailable.
