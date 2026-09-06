/** Integration tests use exact physical frames against the compiled C ABI addon. */
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';
import { Worker } from 'node:worker_threads';
import {
    Aes128Key, AuthenticationProfile, Card, CommunicationMode, DesfireError, ErrorCode,
    Framing, KeyPurpose, KeyScope, KeySource, Offline, Outcome, RawChannel,
    derivationContext, keyRequest,
} from '../src/index.mjs';
import {
    managedOperations, offlineOperations, operations, rawOperations,
} from '../src/operations.mjs';

const addonPath = process.env.DESFIRE_NODE_ADDON;
assert(addonPath, 'Set DESFIRE_NODE_ADDON to the absolute compiled desfire_node.node path');

/** Decode a non-secret exact wire fixture. */
function hex(value) {
    return Uint8Array.from(Buffer.from(value, 'hex'));
}

/** Return a reader that consumes each independent expected physical frame exactly once. */
function replay(frames, delay = 0) {
    let consumed = 0;
    return {
        get consumed() { return consumed; },
        async exchange(frame) {
            const [request, response] = frames[consumed++] ?? [];
            assert.equal(Buffer.from(frame).toString('hex'), request, 'exact reader request');
            if (delay) await sleep(delay);
            return hex(response);
        },
    };
}

/** Open one explicit callback reader with deterministic framing capabilities. */
function connect(reader, framing = Framing.Native) {
    return Card.connect(reader, { addonPath, framing });
}

test('all manifest operations have generated declarations and executable dispatch', () => {
    const manifest = JSON.parse(readFileSync(
        new URL('../../../api/ev3-api.json', import.meta.url), 'utf8'));
    const native = readFileSync(new URL('../native/dispatch.inc', import.meta.url), 'utf8');
    const declarations = readFileSync(new URL('../src/operations.d.ts', import.meta.url), 'utf8');
    const ignored = new Set([
        'open', 'close', 'reset', 'cancel', 'notify_state_change',
        'raw_open', 'raw_close', 'raw_reset', 'raw_cancel', 'raw_notify_state_change',
    ]);
    const names = manifest.operations.map(operation => operation.name)
        .filter(name => !ignored.has(name));
    assert.deepEqual(Object.keys(operations).sort(), names.sort());
    for (const name of names) {
        const operation = operations[name];
        const prototype = operation.surface === 'managed' ? Card.prototype
            : operation.surface === 'raw' ? RawChannel.prototype : Offline.prototype;
        assert.equal(typeof prototype[name], 'function', `${name} JavaScript method`);
        const dispatched = operation.providerDirect
            ? operations[operation.providerDirect].native : operation.native;
        assert(native.includes(`operation == "${dispatched}"`), `${name} native dispatch`);
        assert(declarations.includes(`${name}(`));
    }
    assert.equal(Object.keys(managedOperations).length, 76);
    assert.equal(Object.keys(rawOperations).length, 13);
    assert.equal(Object.keys(offlineOperations).length, 21);
});

test('worker rejects a package/native manifest mismatch before opening any handle', async () => {
    const worker = new Worker(new URL('../src/worker.mjs', import.meta.url), {
        workerData: { addonPath, manifestHash: '0'.repeat(64), mode: 'offline' },
    });
    try {
        const result = new Promise((resolve, reject) => {
            worker.once('message', resolve);
            worker.once('error', reject);
        });
        worker.postMessage({ id: 1, operation: 'openOffline', arguments: [] });
        const message = await result;
        assert.equal(message.error.code, ErrorCode.Unsupported);
        assert.equal(message.error.outcome, Outcome.NotSent);
    } finally {
        await worker.terminate();
    }
});

test('raw native and true ISO exchanges preserve data and exact status', async () => {
    const nativeReader = replay([['60aabb', 'af0102']]);
    const native = await RawChannel.connect(nativeReader, {
        addonPath, framing: Framing.Native,
    });
    try {
        const response = await native.raw_native_frame(
            Framing.Native, 0x60, hex('aabb'), 5000);
        assert.deepEqual(response, { data: hex('0102'), status: 0xAF });
    } finally {
        await native.close();
    }

    const isoReader = replay([['00b0000003', 'aabbcc6283']]);
    const iso = await RawChannel.connect(isoReader, {
        addonPath, framing: Framing.IsoWrapped,
    });
    try {
        const response = await iso.raw_iso_exchange({
            cla: 0, ins: 0xB0, p1: 0, p2: 0, le: 3,
            maximumResponse: 32, maximumFrames: 4,
        });
        assert.deepEqual(response, { data: hex('aabbcc'), status: 0x6283 });
    } finally {
        await iso.close();
    }
});

test('managed and raw sessions cannot share the same activated reader concurrently', async () => {
    const reader = replay([]);
    const card = await connect(reader);
    try {
        await assert.rejects(RawChannel.connect(reader, { addonPath, framing: Framing.Native }),
            error => error.code === ErrorCode.Busy && error.outcome === Outcome.NotSent);
    } finally {
        await card.close();
    }
    const raw = await RawChannel.connect(reader, { addonPath, framing: Framing.Native });
    await raw.close();
});

test('worker-isolated offline AES matches independent known answers', async () => {
    const offline = await Offline.connect(addonPath);
    try {
        const key = hex('00112233445566778899aabbccddeeff');
        const uid = hex('04782e21801d80');
        const derived = await offline.offline_derive_nxp_aes128(
            key, hex('04782e21801d803042f54e585020416275'));
        assert.deepEqual(derived, hex('a8dd63a3b89d54b37ca802473fda9175'));
        const providerContext = derivationContext({
            purpose: KeyPurpose.OfflineOperation, keyNumber: 0,
            diversificationInput: hex('04782e21801d803042f54e585020416275'),
        });
        const providerRequest = keyRequest({
            reference: hex('01'), context: providerContext,
            profile: AuthenticationProfile.StandardAes, scope: KeyScope.Native,
        });
        let providerCalls = 0;
        const providerDerived = await offline.offline_derive_nxp_aes128_provider(
            KeySource.provider(providerRequest, { resolve() {
                providerCalls += 1;
                return new Aes128Key(key);
            } }));
        assert.equal(providerCalls, 1);
        assert.deepEqual(providerDerived, derived);
        const sessionKeys = await offline.offline_derive_transaction_mac_keys_aes(key, 1, uid);
        assert.deepEqual(sessionKeys, hex(
            '2db206d20f493ac4524eade977e976b4a0dd3ea52546ec462fe0f466feb3a62f'));
        const input = hex(
            '3d0200000003000000000000000000000010203000000000000000000000000000');
        const mac = await offline.offline_calculate_transaction_mac_session_aes(
            sessionKeys.slice(0, 16), input);
        assert.deepEqual(mac, hex('1e285e485ba62de1'));
        assert.equal(await offline.offline_verify_transaction_mac_aes(
            key, 1, uid, input, mac), true);
        assert.deepEqual(await offline.offline_decrypt_transaction_reader_id_aes(
            sessionKeys.slice(16), hex('4cba5402f5723fa30dfcdf9477e623f5')),
        hex('00112233445566778899aabbccddeeff'));
        const damKey = new Uint8Array(16).fill(0x11);
        assert.deepEqual(await offline.offline_calculate_delegated_application_delete_mac_aes(
            damKey, 0x563412), hex('dcd2f30e702c9370'));
        assert.deepEqual(await offline.offline_calculate_delegated_configuration_mac_aes(
            damKey, hex('a0000003965643'), hex('a0000003965644')),
        hex('d28ca69a54454b38'));
    } finally {
        await offline.close();
    }
});

test('native and ISO-wrapped requests share the typed C ABI and own returned bytes', async () => {
    for (const framing of [Framing.Native, Framing.IsoWrapped]) {
        const frames = framing === Framing.Native
            ? [['6e', '00000100'], ['6f', '00010b1f'], ['6c01', '0000000080']]
            : [['906e000000', '0001009100'], ['906f000000', '010b1f9100'],
               ['906c0000010100', '000000809100']];
        const reader = replay(frames);
        const card = await connect(reader, framing);
        try {
            assert.equal(await card.free_memory(), 256);
            assert.deepEqual(await card.file_ids(), hex('010b1f'));
            assert.equal(await card.get_value(1, CommunicationMode.Plain), -2147483648);
            assert.equal(reader.consumed, 3);
        } finally {
            await card.close();
        }
    }
});

test('true ISO commands use CLA00 and preserve exact APDU responses', async () => {
    const reader = replay([['00b0000003', 'aabbcc9000']]);
    const card = await connect(reader, Framing.IsoWrapped);
    try {
        assert.deepEqual(await card.iso_read_binary(-1, 0, 3), hex('aabbcc'));
        assert.equal(reader.consumed, 1);
    } finally {
        await card.close();
    }
});

test('worker isolation permits main-event-loop timers during delayed reader I/O', async () => {
    const reader = replay([['6e', '00000100']], 80);
    const card = await connect(reader);
    let ticks = 0;
    const timer = setInterval(() => { ticks += 1; }, 5);
    try {
        assert.equal(await card.free_memory(), 256);
        assert(ticks >= 5, 'the native wait did not block application timers');
    } finally {
        clearInterval(timer);
        await card.close();
    }
});

test('queued writes snapshot input before caller mutation and serialize complete operations', async () => {
    const reader = replay([['6e', '00000100'], ['3d01000000010000aa', '00']], 25);
    const card = await connect(reader);
    const bytes = hex('aa');
    try {
        const first = card.free_memory();
        const write = card.write_data(1, 0, bytes, CommunicationMode.Plain);
        bytes[0] = 0xBB;
        await Promise.all([first, write]);
        assert.equal(reader.consumed, 2);
        assert.equal(bytes[0], 0xBB, 'caller owns its input; only worker snapshots are wiped');
    } finally {
        await card.close();
    }
});

test('invalid integers and missing authentication are rejected before reader I/O', async () => {
    let exchanges = 0;
    const card = await connect({ exchange() { exchanges += 1; return hex('00'); } });
    try {
        await assert.rejects(card.select_application(1.5), error =>
            error instanceof DesfireError && error.code === ErrorCode.InvalidArgument &&
            error.outcome === Outcome.NotSent);
        await assert.rejects(card.get_value(1, CommunicationMode.Full), error =>
            error instanceof DesfireError && error.code === ErrorCode.Authentication &&
            error.outcome === Outcome.NotSent);
        await assert.rejects(card.write_data(1, 0, 'aa', 0), error =>
            error.code === ErrorCode.InvalidArgument);
        assert.equal(exchanges, 0);
    } finally {
        await card.close();
    }
    await assert.rejects(card.free_memory(), error => error.code === ErrorCode.StaleHandle);
    await card.close();
});

test('provider failure and queued cancellation both perform zero additional card I/O', async () => {
    let exchanges = 0;
    let releaseFirst;
    const firstGate = new Promise(resolve => { releaseFirst = resolve; });
    const card = await connect({ async exchange(frame) {
        exchanges += 1;
        assert.equal(Buffer.from(frame).toString('hex'), '6e');
        await firstGate;
        return hex('00000100');
    } });
    try {
        const context = derivationContext({
            purpose: KeyPurpose.Authentication, keyNumber: 1,
        });
        const request = keyRequest({
            reference: hex('01'), context,
            profile: AuthenticationProfile.StandardAes, scope: KeyScope.Native,
        });
        await assert.rejects(card.authenticateStandardAes(1, KeySource.provider(request, {
            async resolve() { throw new Error('private-provider-detail'); },
        })), error => error.code === ErrorCode.Crypto && error.outcome === Outcome.NotSent &&
            !error.message.includes('private-provider'));
        assert.equal(exchanges, 0, 'provider failed before native transmission');

        const first = card.free_memory();
        const controller = new AbortController();
        const queued = card.file_ids({ timeoutMs: 5000, signal: controller.signal });
        controller.abort();
        releaseFirst();
        assert.equal(await first, 256);
        await assert.rejects(queued, error =>
            error.code === ErrorCode.Cancelled && error.outcome === Outcome.NotSent);
        assert.equal(exchanges, 1, 'cancelled queued call performed no I/O');
    } finally {
        releaseFirst();
        await card.close();
    }
});

test('explicit cancellation interrupts active asynchronous provider resolution before I/O', async () => {
    let exchanges = 0;
    let providerEntered;
    const entered = new Promise(resolve => { providerEntered = resolve; });
    const card = await connect({ exchange() { exchanges += 1; return hex('00'); } });
    const context = derivationContext({
        purpose: KeyPurpose.Authentication, keyNumber: 1,
    });
    const request = keyRequest({
        reference: hex('01'), context,
        profile: AuthenticationProfile.StandardAes, scope: KeyScope.Native,
    });
    try {
        const pending = card.authenticateStandardAes(1, KeySource.provider(request, {
            resolve() {
                providerEntered();
                return new Promise(() => {});
            },
        }));
        await entered;
        await card.cancel();
        await assert.rejects(pending, error =>
            error.code === ErrorCode.Cancelled && error.outcome === Outcome.NotSent);
        assert.equal(exchanges, 0);
    } finally {
        await card.close();
    }
});

test('late reader completion gates new work until the transport quiesces', async () => {
    let exchanges = 0;
    const card = await connect({ async exchange(frame) {
        exchanges += 1;
        if (exchanges === 1) {
            assert.equal(Buffer.from(frame).toString('hex'), '6e');
            await sleep(100); // Intentionally ignores AbortSignal to exercise late completion.
            return hex('00000100');
        }
        assert.equal(Buffer.from(frame).toString('hex'), '6f');
        return hex('0001');
    }, async reset() {} });
    try {
        await assert.rejects(card.free_memory(20), error =>
            error.code === ErrorCode.Timeout && error.outcome === Outcome.Unknown);
        await assert.rejects(card.file_ids(), error =>
            error.code === ErrorCode.SessionInvalid && error.outcome === Outcome.NotSent);
        await sleep(110);
        await card.reset();
        assert.deepEqual(await card.file_ids(), hex('01'));
        assert.equal(exchanges, 2);
    } finally {
        await card.close();
    }
});

test('reader exceptions are redacted and unknown delivery is never automatically retried', async () => {
    let exchanges = 0;
    const card = await connect({ exchange() {
        exchanges += 1;
        throw new Error('PRIVATE_READER_DIAGNOSTIC_DO_NOT_FORWARD');
    } });
    try {
        await assert.rejects(card.free_memory(), error =>
            error instanceof DesfireError && error.code === ErrorCode.Transport &&
            error.outcome === Outcome.Unknown && !error.message.includes('PRIVATE'));
        assert.equal(exchanges, 1);
    } finally {
        await card.close();
    }
});

test('timeout returns while the event loop remains available and does not retry', async () => {
    let exchanges = 0;
    const reader = { async exchange(_frame, { signal }) {
        exchanges += 1;
        await sleep(1000, undefined, { signal });
        return hex('00');
    } };
    const card = await connect(reader);
    try {
        await assert.rejects(card.free_memory(30), error =>
            error.code === ErrorCode.Timeout && error.outcome === Outcome.Unknown);
        assert.equal(exchanges, 1);
    } finally {
        await card.close();
    }
});

test('cancellation aborts the active reader wait without waiting for native operation locks', async () => {
    let entered;
    const started = new Promise(resolve => { entered = resolve; });
    const card = await connect({ async exchange(_frame, { signal }) {
        entered();
        await sleep(1000, undefined, { signal });
        return hex('00');
    } });
    try {
        const pending = card.free_memory();
        const rejection = assert.rejects(pending, error =>
            error.code === ErrorCode.Cancelled && error.outcome === Outcome.Unknown);
        await started;
        await card.cancel();
        await rejection;
    } finally {
        await card.close();
    }
});

test('native rejection preserves card status independently for simultaneous card connections', async () => {
    const first = await connect(replay([['6e', '9d']]));
    const second = await connect(replay([['6e', '00000100']]));
    try {
        await Promise.all([
            assert.rejects(first.free_memory(), error =>
                error.code === ErrorCode.CardRejected && error.deviceStatus === 0x9D),
            second.free_memory().then(value => assert.equal(value, 256)),
        ]);
    } finally {
        await Promise.all([first.close(), second.close()]);
    }
});

test('asynchronous reader reentry returns Busy immediately without deadlock or extra I/O', async () => {
    let card;
    let exchanges = 0;
    const reader = { async exchange() {
        exchanges += 1;
        await sleep(2);
        await assert.rejects(card.file_ids(), error =>
            error.code === ErrorCode.Busy && error.outcome === Outcome.NotSent);
        await assert.rejects(card.close(), error => error.code === ErrorCode.Busy);
        return hex('00000100');
    } };
    card = await connect(reader);
    try {
        assert.equal(await card.free_memory(), 256);
        assert.equal(exchanges, 1);
    } finally {
        await card.close();
    }
});
