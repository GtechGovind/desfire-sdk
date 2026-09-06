/** Synchronous C ABI execution stays on this worker; reader I/O runs on the parent event loop. */
import { parentPort, workerData } from 'node:worker_threads';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const native = require(workerData.addonPath);
let context;
let currentId = 0;

/** Wait on a fresh shared rendezvous; blocking never occurs on the application event loop. */
function readerCall(kind, transmit, timeoutMs, capacity) {
    const shared = new SharedArrayBuffer(24 + capacity);
    const control = new Int32Array(shared, 0, 6);
    parentPort.postMessage({
        type: 'reader', id: currentId, kind, transmit, timeoutMs, capacity, shared,
        deadline: Date.now() + timeoutMs,
    });
    const wait = Atomics.wait(control, 0, 0, timeoutMs + 1000);
    if (wait === 'timed-out' || Atomics.load(control, 0) !== 1) {
        Atomics.compareExchange(control, 0, 0, 2);
        return { code: 4, outcome: 3, deviceStatus: 0 };
    }
    const code = Atomics.load(control, 2);
    if (code !== 0) {
        return { code, outcome: Atomics.load(control, 3), deviceStatus: Atomics.load(control, 4) };
    }
    const length = Atomics.load(control, 1);
    if (length < 0 || length > capacity) {
        return { code: 6, outcome: 3, deviceStatus: 0 };
    }
    return { code: 0, data: new Uint8Array(shared, 24, length).slice() };
}

/** Forward one already encoded physical frame, retaining no application-owned request bytes. */
function exchange(transmit, timeoutMs, capacity) {
    try {
        return readerCall('exchange', transmit, timeoutMs, capacity);
    } finally {
        transmit.fill(0);
    }
}

/** Forward the optional physical reset while the worker exclusively owns the card. */
function reset() {
    return readerCall('reset', new Uint8Array(), 5000, 0);
}

/** Preserve native error evidence without including reader exception details or payloads. */
function failure(error) {
    return {
        code: Number.isInteger(error?.code) ? error.code : 17,
        outcome: Number.isInteger(error?.outcome) ? error.outcome : 3,
        deviceStatus: Number.isInteger(error?.deviceStatus) ? error.deviceStatus : 0,
        message: Number.isInteger(error?.code) ? error.message : 'Native worker operation failed',
    };
}

/** Copy native result bytes into transferable storage and wipe the addon's temporary buffers. */
function ownResult(value, transfers) {
    if (value instanceof Uint8Array) {
        const owned = Uint8Array.from(value);
        value.fill(0);
        transfers.push(owned.buffer);
        return owned;
    }
    if (Array.isArray(value)) return value.map(item => ownResult(item, transfers));
    if (value && typeof value === 'object') {
        return Object.fromEntries(Object.entries(value).map(
            ([name, item]) => [name, ownResult(item, transfers)]));
    }
    return value;
}

/** Execute exactly one typed native call and wipe worker-owned binary inputs afterwards. */
function processMessage(message) {
    currentId = message.id;
    const arguments_ = message.arguments ?? [];
    try {
        let value;
        if (message.operation === 'open') {
            if (typeof native.manifestHash !== 'function' ||
                native.manifestHash() !== workerData.manifestHash) {
                throw {
                    code: 10, outcome: 0, deviceStatus: 0,
                    message: 'Native API manifest is incompatible with this package',
                };
            }
            context = workerData.mode === 'raw'
                ? native.rawOpen(exchange, workerData.hasReset ? reset : undefined,
                                 workerData.transport)
                : native.open(exchange, workerData.hasReset ? reset : undefined,
                              workerData.transport);
        } else if (message.operation === 'openOffline') {
            if (typeof native.manifestHash !== 'function' ||
                native.manifestHash() !== workerData.manifestHash) {
                throw {
                    code: 10, outcome: 0, deviceStatus: 0,
                    message: 'Native API manifest is incompatible with this package',
                };
            }
        } else if (message.operation === 'close') {
            native.close(context);
            context = undefined;
        } else if (workerData.mode === 'offline') {
            value = native.invokeOffline(message.operation, arguments_);
        } else {
            value = native.invoke(context, message.operation, arguments_);
        }
        const transfers = [];
        const owned = ownResult(value, transfers);
        parentPort.postMessage({ type: 'result', id: message.id, value: owned }, transfers);
    } catch (error) {
        parentPort.postMessage({ type: 'result', id: message.id, error: failure(error) });
    } finally {
        const wipe = value => {
            if (value instanceof Uint8Array) value.fill(0);
            else if (Array.isArray(value)) value.forEach(wipe);
            else if (value && typeof value === 'object') Object.values(value).forEach(wipe);
        };
        arguments_.forEach(wipe);
    }
}

parentPort.on('message', processMessage);
