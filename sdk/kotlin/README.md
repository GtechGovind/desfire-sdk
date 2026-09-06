# DESFire EV3 Kotlin SDK

This portable Kotlin/JVM module is the primary Kotlin API. `Card` is suspend-first;
`BlockingCard` is the explicit blocking facade for applications that already own a worker thread.
Both delegate protocol, framing, authentication, secure messaging and delivery evidence to the
native core through the stable C ABI.

The application supplies one already activated `CardTransport`. Its `exchange` method sends one
physical frame exactly once with the remaining operation timeout. It must not reconnect, retry, or
hide card replacement. The SDK retains the callback until close completes; the application closes
its physical reader afterwards.

```kotlin
val card = Card.open(transport)
try {
    card.selectApplication(ApplicationId(1))
    val bytes = card.readData(FileNumber(0), ByteOffset(0), 32, Communication.PLAIN)
} finally {
    card.close()
}
```

Concurrent calls on one `Card` or `BlockingCard` execute FIFO as complete logical operations.
Coroutine cancellation while waiting for the queue performs no native call. Once native execution
starts, coroutine cancellation does not establish whether a mutating command was delivered. Call
`requestCancellation()` to interrupt the transport and use the resulting `Outcome`; reconcile
`UNKNOWN` before deciding whether another mutation is safe. Close rejects new work, drains already
admitted calls, closes the native handle once, and then releases callback ownership.

Authentication has profile-specific names and accepts `KeySource.Direct`, `KeySource.Derived`, or
`KeySource.Provider`:

```kotlin
val source = KeySource.Provider(
    provider = keyProvider,
    reference = "fare-app-key-0".encodeToByteArray(),
    applicationId = ApplicationId(0x112233),
)
val info = card.authenticateEv2FirstAes(KeyNumber(0), source)
```

Direct and master-key inputs are copied at construction. JNI copies and wipes native key buffers.
`Derived` performs documented NXP AES-128 diversification before card I/O. A provider receives one
non-secret `KeyRequest`, must return exactly sixteen exportable AES bytes, and is called once before
the first card frame. Provider diagnostics are redacted at the JNI boundary. Provider-owned key
storage remains the provider's responsibility.

`com.desfire.ev3.offline` exposes the documented stateless AES helpers: NXP AN10922
diversification, delegated EncK and DAM MAC calculation, MIFARE Classic license MAC, transaction
session-key derivation, TMV calculation and verification, transaction-reader-ID decryption, and
secp224r1 UID originality verification. Provider overloads preserve the C key-purpose metadata and
resolve exactly once. The Kotlin module checks the linked C ABI version and canonical manifest hash
when native code is first loaded, so a stale JNI/C package fails before a card operation.

`com.desfire.ev3.raw` exposes a separately opened `RawChannel` and `BlockingRawChannel` for expert
native frames, bounded native logical exchanges, true ISO APDUs, explicit secure-native requests,
and raw authentication sessions. Raw descriptors require every chaining, length, communication,
and invalidation choice; the SDK does not infer command semantics or share an active managed-card
connection.

Build from the repository root with a JDK and OpenSSL available:

```sh
cmake -S . -B build/ev3 -DDESFIRE_BUILD_JNI=ON
cmake --build build/ev3 --target desfire_jni
../TR/gradlew -p sdk/kotlin hostTest \
  -PdesfireNativeDirectory="$PWD/build/ev3/sdk/kotlin"
../TR/gradlew -p sdk/kotlin jar
```

Use your installed Gradle or project wrapper in place of the example wrapper path. Install
`desfire_jni` and `desfire_c` together with their runtime dependencies, or point
`java.library.path` at the build directory for host tests.

The deterministic host suite crosses Kotlin, JNI, the C ABI, the C++ core, and replay transports.
It covers exact native/ISO wire exchanges, structured callback errors, FIFO serialization,
concurrent cancellation, queued coroutine cancellation, close/stale handles, provider pre-I/O
failure, raw status preservation, and ISO AES session CMAC behavior. These checks do not certify RF
hardware, secure key custody, production card profiles, or device timing. Offline JNI coverage uses
published and independently generated known-answer vectors for diversification, delegated and MFC
MACs, transaction session keys and TMVs, ReaderID decryption, and originality signatures.
