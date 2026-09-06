# DESFire EV3 for Node.js and TypeScript

`@desfire/ev3` exposes the checked managed Card, a separate expert raw channel, and all documented
offline AES helpers from the stable C ABI. The package supports active Node.js LTS releases starting
with Node 20 through N-API 8. Its declarations compile with TypeScript strict mode.

Each Card or RawChannel owns one worker. Blocking C calls stay on that worker while asynchronous
reader and key-provider callbacks run on the main event loop. One FIFO admits complete logical
operations per session; separate sessions execute concurrently. The same reader object cannot be
owned by a Card and RawChannel at the same time.

## Build and generation

Build the main SDK with `DESFIRE_BUILD_C_API=ON` and the OpenSSL provider, then build the addon
against either that build tree or an installed C package:

```sh
python3 sdk/node/tools/generate.py
cmake -S sdk/node -B build/node-ev3 \
  -DDESFIRE_BUILD_DIR="$PWD/build/ev3" \
  -DNODE_INCLUDE_DIR=/absolute/path/to/node/include
cmake --build build/node-ev3
DYLD_LIBRARY_PATH="$PWD/build/ev3/c-api" \
  DESFIRE_NODE_ADDON="$PWD/build/node-ev3/desfire_node.node" \
  npm --prefix sdk/node test
npm --prefix sdk/node run typecheck
```

For an installed SDK, set `DESFIRE_C_INCLUDE_DIR` and `DESFIRE_C_LIBRARY`. Windows also needs
`NODE_LIBRARY_DIR` for its Node import library. The generated dispatch, declarations, and operation
inventory come from `api/ev3-api.json`; they construct no APDUs. Loading fails before a handle is
opened when the addon ABI version or manifest SHA-256 differs from the package.

## Managed workflow

```ts
import {
    Aes128Key, Card, CommunicationMode, Framing, KeySource, keyNumber,
} from '@desfire/ev3';

const card = await Card.connect({
    async exchange(frame, { timeoutMs, signal }) {
        return reader.transceive(frame, { timeoutMs, signal });
    },
    async reset() { await reader.reset(); },
    async cancel() { await reader.cancel(); },
}, {
    addonPath: '/absolute/path/desfire_node.node',
    framing: Framing.IsoWrapped,
    maxTransmit: 261,
    maxReceive: 4096,
    maxNativeFrame: 256,
});

const authenticationKey = new Aes128Key(derivedKeyBytes);
try {
    await card.select_application(0x123456);
    await card.authenticateEv2FirstAes(keyNumber(0), KeySource.direct(authenticationKey));
    const data = await card.read_data(1, 0, 32, CommunicationMode.Full);
    await consume(data);
} finally {
    authenticationKey.close();
    await card.close();
}
```

Friendly authentication accepts `KeySource.direct`, `KeySource.derived`, or `KeySource.provider`.
Derivers and providers run after FIFO admission and before the first card frame. They return a scoped
`Aes128Key`; the binding copies and wipes its temporary native input. Provider failures are redacted,
return `Outcome.NotSent`, and perform zero reader I/O. JavaScript and the operating system can make
uncontrolled copies, so callers must also close keys they own.

Every generated snake-case method maps one manifest operation. Binary arguments are `Uint8Array` or
`Buffer`; pointer lengths are hidden. The last timeout argument accepts milliseconds or
`{ timeoutMs, signal }` and defaults to five seconds. Returned bytes are caller-owned. Typed outputs
preserve EV2 authentication metadata, delegated-application information, and native or ISO status.

## Expert raw workflow

```ts
import { Card as RawCard, Framing } from '@desfire/ev3/raw';

const raw = await RawCard.connect(reader, {
    addonPath: '/absolute/path/desfire_node.node',
    framing: Framing.Native,
});
try {
    const response = await raw.raw_native_exchange({
        framing: Framing.Native,
        command: 0x60,
        maximumResponse: 4096,
    });
    console.log(response.status, response.data);
} finally {
    await raw.close();
}
```

`@desfire/ev3/raw` supports a single native frame, bounded native continuation exchange, direct and
ISO-wrapped native framing, full true-ISO APDUs, explicit secure-native layout, checked secure ISO
exchange, and Standard AES, EV2 First/NonFirst, and ISO AES session establishment. It never infers
the header, data, communication mode, response bounds, mutation, or session effect of an arbitrary
opcode.

## Offline workflow

```ts
import { Offline } from '@desfire/ev3';

const offline = await Offline.connect('/absolute/path/desfire_node.node');
try {
    const sessionKeys = await offline.offline_derive_transaction_mac_keys_aes(
        transactionKey, committedCounter, realUid);
    const verified = await offline.offline_verify_transaction_mac_aes(
        transactionKey, committedCounter, realUid, transactionInput, transactionMac);
} finally {
    await offline.close();
}
```

Offline methods cover NXP AES-128 diversification, delegated EncK and DAM MAC variants, MIFARE
Classic license MAC, transaction session-key derivation, calculation and verification, ReaderID
decryption, and UID originality verification. Provider variants resolve exportable AES-128 keys on
the main event loop before worker dispatch.

## Cancellation, errors, and recovery

Cancelling queued work returns `Outcome.NotSent` without reader I/O. Active cancellation aborts the
reader signal and calls its optional `cancel()` hook. Once transmission might have started,
`DesfireError.outcome` remains `Outcome.Unknown` and `requiresReconciliation` is true. Mutations are
never retried automatically.

If a timed-out reader Promise has not settled, the session rejects later work until the reader
quiesces. The core can still require an explicit `reset()` or reconnect before another exchange.
Reader and provider callbacks cannot reenter their active session; they receive `ErrorCode.Busy`.
`close()` rejects new work, drains admitted work and late reader completion, then releases native,
worker, and reader ownership exactly once. A native close failure leaves the session recoverable so
the caller can retry.

The tests compile and execute against the actual N-API addon and C shared library. They cover the
120-operation manifest, direct/wrapped/ISO frames, raw status, known-answer offline AES, FIFO order,
multi-card execution, queued and active cancellation, late completion, reentry, reader exclusivity,
redaction, and no retries. These host/replay checks do not qualify physical EV3 cards, reader
firmware, RF timing, production keys, or certification.
