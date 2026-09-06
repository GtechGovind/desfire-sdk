# Hardware acceptance

Record the SDK revision, compiler, target OS and ABI, device, reader and firmware, EV3 part
and card configuration, application/file/key policy, and non-secret key provenance for each
qualification run.

The target suite must exercise card activation and removal at every authentication and
continuation boundary; direct/wrapped native and ISO operations; Standard AES, EV2 First,
EV2 NonFirst, and ISO AES; wrong-key and tamper failures; maximum reader transfers; staged
mutations and lost commit responses; cancellation and reconnect races; malformed reader
responses; and long-running latency, memory, and thread stability.

For Android, execute on API 23 and the current supported API using every packaged ABI that
can run on available hardware or an emulator. Real NFC tests must cover tag removal,
cancel-by-close, rediscovery, and foreground lifecycle changes.

For Apple, execute the XCFramework on iOS device and simulator targets. Real CoreNFC tests
must cover session expiry, invalidation, tag removal, cancellation, and rediscovery.

Host builds, replay fixtures, cross-compilation, emulator execution, and physical-card
acceptance are separate evidence classes. A release may claim only the classes recorded in
the dated qualification record.
