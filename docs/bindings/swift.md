# Swift and Apple platforms

`DesfireEV3` is the portable Swift concurrency facade. `DesfireEV3CoreNFC` adds the Apple NFC
transport without exposing CoreNFC types through the portable product. `RawCard` provides the
complete expert surface over an independently owned C handle.

An actor or explicit admission controller owns lifecycle and FIFO ordering. Blocking C calls
run on a private serial executor rather than Swift's cooperative executor. Task cancellation
before admission is `not_sent`; active interruption preserves the native delivery outcome.

Swift key providers resolve a scoped exportable AES-128 key asynchronously before native I/O.
Binding copies are released and wiped on every exit, while Swift and operating-system copies
remain outside that guarantee.

The frozen library has 125 exports. The generated inventory fixes all 120 fallible C operations
and the native manifest digest.
`Card`, `RawCard`, and `Offline` provide typed coverage for managed/runtime, expert raw, and all
21 offline direct/provider entries. Swift providers resolve asynchronously inside FIFO admission;
the binding then uses the equivalent direct-key C entry so no Swift concurrency crosses a
synchronous C callback.

The mobile release contains an XCFramework for iOS device and simulator architectures plus a
SwiftPM package. CoreNFC session invalidation, tag loss, expiry, and rediscovery require
physical-device acceptance before a production-qualified claim.
