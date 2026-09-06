# GKey compatibility derivation

`GKeyDerivation` is an optional Kotlin compatibility strategy for deployments whose existing card
keys follow the GKey layout. It is independent of DESFire authentication and secure messaging.
Applications choose it explicitly; the SDK never substitutes it for NXP AES-128 diversification.

No seed or default key is built into the SDK. Every base key and seed comes from the application,
and all examples and tests use synthetic public data.

## Public API

The portable Kotlin module exposes:

```kotlin
GKeyDerivation.derive(baseKey, cardUid)
GKeyDerivation.expandSingleSeed(seedUtf8)
GKeyDerivation.expandApplicationMaster(firstSeedUtf8, tenthSeedUtf8)
GKeyDerivation.expandCardMaster(orderedSeedsUtf8)
GKeyProvider(baseKey)
```

Use `derive` when a key service already supplies the 16-byte base key. The expansion functions are
provided for compatibility tooling that receives caller-owned seed bytes. Prefer `ByteArray` input;
JVM `String` instances cannot be deterministically cleared.

## Base-key expansion

Each seed is exactly 32 UTF-8 bytes. Text that happens to contain hexadecimal characters remains
text and is not decoded.

| Profile | SHA-256 input |
| --- | --- |
| Single seed | one 32-byte seed |
| Application master | first seed immediately followed by tenth seed |
| Card master | ten ordered seeds joined by literal ASCII `, ` separators |

After SHA-256, every digest byte whose unsigned value is less than `0x10` becomes `0xA0 | value`.
Other bytes remain unchanged. The first 16 transformed bytes form the AES-128 base key. Temporary
digest storage is cleared before the function returns.

## UID binding

`derive` requires a 16-byte base key and at least six UID bytes. It uses the first six UID bytes in
their supplied order; trailing UID bytes are ignored for compatibility.

For UID nibble index `j` from 0 through 11:

```text
nibble(j) = high(uid[j / 2]) when j is even, otherwise low(uid[j / 2])
output[0] = base[0]
output[j + 1] = (nibble(j) << 4) | (base[j + 1] & 0x0F)
output[13..15] = base[13..15]
```

This public synthetic vector also proves that a seventh UID byte does not affect the result:

```text
base    = 00112233445566778899AABBCCDDEEFF
uid     = 04112233445566
derived = 000142131425263738494A5B5CDDEEFF
```

## Provider integration

`GKeyProvider` stores one copied base key for a session, derives from the request's diversification
bytes, and returns a fresh disposable key to the SDK. Provider resolution runs inside normal card
operation admission and before the first card frame.

```kotlin
val baseKey = loadBaseKeyFromApplicationVault()
val provider = GKeyProvider(baseKey)
baseKey.fill(0)

try {
    val source = KeySource.Provider(
        provider = provider,
        reference = "fare-application-key-0".encodeToByteArray(),
        diversification = discoveredCardUid,
        applicationId = ApplicationId(0x112233),
    )
    card.authenticateEv2FirstAes(KeyNumber(0), source)
} finally {
    provider.close()
}
```

`close` is idempotent, clears the retained base-key copy, and rejects later resolution. The SDK
copies then clears every array returned by a Kotlin key provider. Providers must therefore return a
fresh array and must keep exception messages free of key material.

## Security boundary

GKey UID binding replaces 48 base-key bits with public UID bits and is not a cryptographic
diversification function. Keep it only where existing card compatibility requires the exact layout;
use a reviewed cryptographic diversification scheme for new deployments.

The JVM, input method, debugger, crash reporter, and operating system can retain copies outside the
SDK's control. Applications must exclude secrets from logs, analytics, saved UI state, clipboard
workflows, and crash payloads. `GKeyProvider` accepts exportable AES key bytes; opaque hardware-key
operations need a separate cryptographic primitive provider.
