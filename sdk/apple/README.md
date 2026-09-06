# Swift facade for DESFire EV3

This Swift 6 package calls the stable C ABI. Protocol encoding, AES security,
state validation and native/ISO transport handling live in the C++ core. Each
card has a serial background queue; its async methods do not perform blocking
reader I/O on the caller's main thread.

Build the native library first, then run the host tests:

```sh
cmake -S . -B build/ev3 -DCMAKE_BUILD_TYPE=Release
cmake --build build/ev3 --parallel
python3 sdk/apple/tools/test.py
```

For another native build directory:

```sh
python3 sdk/apple/tools/test.py --native-build /absolute/path/to/build
```

The system module includes `c-api/include/desfire.h` and links `desfire_c` from
the chosen build's `c-api` directory. The test script supplies those paths and
its runtime loader path explicitly. For a separate app, add this package as a
local dependency, expose the installed C include directory to Clang, and link
and embed the matching native library and its dependencies. Build the native
library for the same architecture and deployment target as the consuming app.
All native dependencies must use that same deployment target. The recorded macOS 14 check uses a
static OpenSSL 3.5.8 build produced with `MACOSX_DEPLOYMENT_TARGET=14.0`; merely declaring an older
Swift package target does not lower a prebuilt native dependency's target.

```swift
import DesfireEV3
import Foundation

func inspect(reader: any Reader) async throws -> Data {
    let card = try Card(reader: reader, options: .init(framing: .isoWrapped))
    do {
        let files = try await card.file_ids()
        try await card.close()
        return files
    } catch {
        try? await card.close()
        throw error
    }
}
```

Implement `Reader.exchange` around the application's physical reader. It receives
an owned `Data` frame and a timeout in milliseconds and returns an owned response.
It must honor the timeout and must not retry frames. Set `supportsCancel` or
`supportsReset` only when the corresponding method is implemented. Cancellation
can run concurrently with exchange, so that reader implementation must support
concurrent cancellation safely. `reset` is explicit physical reader work;
`notify_state_change` only invalidates SDK state after external card activity.

Choose `.native` for raw native framing or `.isoWrapped` for an APDU-capable
reader. True ISO methods such as `iso_get_challenge` require `.isoWrapped` and
send actual ISO commands through their separate core path. The native maximum
frame defaults to 60 bytes and should be changed only for a verified reader/card
configuration. Input identifiers and protocol ranges are checked by the C ABI
before I/O. Communication settings use the `CommunicationMode` enum.

Method and parameter names preserve the C ABI spelling for cross-language
traceability. The frozen library has 125 exports, and the package inventory contains all **120
fallible operations** in its C ABI manifest:
managed/runtime, offline, and expert raw surfaces. `Card` exposes every managed operation through
62 generated C-shaped methods plus typed authentication, key-source, structured-management, and
lifecycle methods. `RawCard` covers native, ISO, secure, lifecycle, and AES-session operations on
an independently owned handle. `Offline` covers the full 21-entry C surface through 12 typed
methods; provider variants use the same asynchronous `KeySource` workflow and call the direct C
entry only after resolution. The generated inventory and tests compare all symbols and stable IDs
against the canonical headers and manifest. Regenerate after C ABI changes with:

```sh
python3 sdk/apple/tools/generate.py
```

`Card` retains its reader until `close` completes. Closing waits for previously
queued work, rejects new work, and releases native ownership exactly once. The
application still owns physical-reader shutdown. Pending operations retain the
card; `deinit` is a final cleanup fallback. Binary inputs use Swift `Data` value
semantics and are borrowed only for the synchronous ABI call; results are copied
before freeing the native buffer. The facade cannot guarantee erasure of Swift
or operating-system copies of keys, so callers should minimize their lifetime.

Cancelling a queued task rejects only that task before I/O. Cancelling an active
task requests reader cancellation; the operation's native error reports whether
delivery is unknown. Cancellation is cooperative and depends on the reader.
`cancel()` can also be called directly. Reader-created child tasks inherit a
same-card reentry guard and receive `busy`; readers must never synchronously
wait for their own card using detached tasks that discard that context.

Errors preserve `code`, `outcome` and `deviceStatus`. Foreign reader diagnostics
are redacted. `unknown` means the card may have executed the command: reconcile
state before retrying. Neither the facade nor the core retries mutations.

The 14-test host suite covers exact native/wrapped/true-ISO frames, scalar and owned
buffer results, preflight rejection, card status, cancellation isolation,
active cancellation, closing during I/O, callback ownership/reentry, redacted
reader exceptions, offline transaction known answers, and 120-operation generated ABI parity.
Swift 6 device and simulator compile checks use complete strict concurrency with warnings as
errors. This is host/source validation. A signed iOS binary, physical CoreNFC exchange, EV3 card
tests, reader certification, and production qualification are not supplied by this package. Unsupported SDM
provisioning and other unverified fields remain explicit core errors.
