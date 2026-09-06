# Kotlin and Android binding architecture

`sdk/kotlin` is the portable Kotlin/JVM product. It owns typed models, `CardTransport`, the
suspend-first `Card`, the explicit `BlockingCard`, key-source policy, the expert `raw` package, and
the JNI bridge. `sdk/android` depends on that module and owns only Android NFC integration. Android
must never compile a second copy of the portable source tree because duplicate JNI owners can split
handle state and break close or cancellation.

One managed or raw owner admits complete logical operations FIFO. Suspend callers may cancel while
queued without native work. Once JNI dispatch starts, native state remains owned until the reader
returns or explicit cancellation completes. Cancellation bypasses the FIFO gate, calls the
transport concurrently, and marks an active key-provider invocation cancelled. Close rejects new
admissions, drains existing work, closes the C handle once, and releases Java global references only
after the C ABI reports success.

`KeySource.Direct` contains one copied AES-128 key. `KeySource.Derived` contains a copied AES-128
master key and one through 31 NXP diversification bytes; JNI invokes the C offline derivation and
keeps the derived key in wiping native storage. `KeySource.Provider` contains non-secret routing
metadata and a synchronous resolver. JNI constructs the versioned C key-provider request, exposes
only purpose, optional authentication profile, scope, selector, optional application/key-set,
reference, diversification, user context, and cancellation state, and redacts callback failures.
Resolution occurs before card I/O and never retries.

The `offline` package covers every stateless AES operation in ABI v1, including NXP key
diversification, delegated EncK and DAM MAC variants, MIFARE Classic license MAC, transaction
session keys, TMV calculation and verification, ReaderID decryption, and UID originality
verification. Direct key arrays are copied and wiped in JNI. Provider variants retain exact
purpose metadata and fail before any card I/O. JNI verifies the linked ABI version and canonical
manifest SHA-256 against the generated Kotlin inventory during first load.

The JNI implementation is split by ownership:

- `context.{hpp,cpp}` owns VM attachment, structured errors, wiping input buffers, and separate
  managed/raw registries.
- `transport.{hpp,cpp}` owns exact-once physical exchange, cancel, and reset callbacks.
- `key_provider.{hpp,cpp}` owns provider global references, C descriptors, cooperative cancellation,
  and key-copy wiping.
- `entrypoints.cpp` owns exported JNI lifecycle, authentication, checked managed dispatch, raw
  descriptors, manifest verification, and stateless offline dispatch.
- `operations.inc` remains private checked managed dispatch data; profile-specific authentication
  does not use the removed ambiguous slot.

The raw package opens a separately owned C raw channel. It exposes status-preserving physical native
frames, bounded native logical requests, true ISO APDUs, explicit secure-native requests, and
profile-specific raw authentication. Every response/chaining/communication/session-invalidation
choice is caller-visible. A raw channel cannot be derived from or silently share a managed card.

`IsoDepTransport` accepts only a connected tag, rejects main-thread exchange, assigns the remaining
per-frame timeout, and performs one `transceive`. Tag loss and I/O failure after dispatch retain
unknown delivery. Cancellation closes the Android connection, and reset stays unsupported until
NFC rediscovery creates a new transport and card generation.
