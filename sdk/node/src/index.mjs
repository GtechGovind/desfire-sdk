/** Worker-isolated DESFire EV3 managed, raw, and offline Node.js bindings. */
import { AsyncLocalStorage } from 'node:async_hooks';
import { isAbsolute } from 'node:path';
import { Worker } from 'node:worker_threads';
import { DesfireError, ErrorCode, Outcome } from './errors.mjs';
import {
    AuthenticationProfile, KeyPurpose, KeyScope, keySourceContext, resolveKeySource,
} from './keys.mjs';
import {
    MANIFEST_SHA256, managedOperations, offlineOperations, operations, rawOperations,
} from './operations.mjs';

export {
    Aes128Key, AuthenticationProfile, KeyPurpose, KeyScope, KeySource,
    derivationContext, keyRequest,
} from './keys.mjs';
export { DesfireError, ErrorCode, Outcome } from './errors.mjs';
export { applicationId, fileNumber, keyNumber, keySet } from './identifiers.mjs';

export const Framing = Object.freeze({ Native: 0, IsoWrapped: 1 });
export const CommunicationMode = Object.freeze({ Plain: 0, Mac: 1, Full: 3 });
export const SecureProfile = Object.freeze({ None: 0, StandardAes: 1, Ev2: 2 });
export const IsoLengthEncoding = Object.freeze({ Automatic: 0, Short: 1, Extended: 2 });
export const UidOption = Object.freeze({ Omitted: 0, WithoutNuid: 1, WithNuid: 2 });
export const IsoUpdateRecordInstruction = Object.freeze({ Current: 0xDC, Selected: 0xDD });
export const TransactionOperationKind = Object.freeze({
    WriteData: 1, Credit: 2, Debit: 3, LimitedCredit: 4,
    WriteRecord: 5, UpdateRecord: 6, ClearRecordFile: 7,
});
export const RawFlags = Object.freeze({ SingleContinuation: 1 });

const MAX_BYTES = 16 * 1024 * 1024;
const readerOwners = new WeakMap();

/** Validate exact integer ranges before work is admitted to a connection queue. */
function integer(value, minimum, maximum, name) {
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
        throw new DesfireError(
            ErrorCode.InvalidArgument, `${name} must be an integer from ${minimum} through ${maximum}`);
    }
    return value;
}

/** Copy one byte range into binding-owned storage. */
function bytes(value, name) {
    if (!(value instanceof Uint8Array) || value.byteLength > MAX_BYTES) {
        throw new DesfireError(ErrorCode.InvalidArgument, `${name} must be a bounded Uint8Array`);
    }
    return Uint8Array.from(value);
}

/** Copy descriptor graphs and every contained byte range before queue admission. */
function descriptorCopy(value, kind, name) {
    if (!value || typeof value !== 'object') {
        throw new DesfireError(ErrorCode.InvalidArgument, `${name} must be an object`);
    }
    if (kind === 'transaction_operations') {
        if (!Array.isArray(value) || value.length === 0 || value.length > 65_536) {
            throw new DesfireError(
                ErrorCode.InvalidArgument, 'operations must be a bounded non-empty array');
        }
        return value.map(operation => {
            if (!operation || typeof operation !== 'object') {
                throw new DesfireError(ErrorCode.InvalidArgument, 'Invalid transaction operation');
            }
            return { ...operation, ...(operation.data === undefined
                ? {} : { data: bytes(operation.data, 'operation.data') }) };
        });
    }
    const result = { ...value };
    for (const field of ['data', 'header', 'dfName']) {
        if (result[field] !== undefined) result[field] = bytes(result[field], `${name}.${field}`);
    }
    return result;
}

/** Copy one generated argument according to its stable manifest kind. */
function copyArgument(value, argument) {
    switch (argument.kind) {
    case 'bytes': return bytes(value, argument.name);
    case 'u32':
    case 'timeout':
        return integer(value, argument.minimum ?? (argument.kind === 'timeout' ? 1 : 0),
                       argument.maximum ?? 4_294_967_295, argument.name);
    case 'boolean':
        if (typeof value !== 'boolean') {
            throw new DesfireError(ErrorCode.InvalidArgument, `${argument.name} must be boolean`);
        }
        return value ? 1 : 0;
    case 'i32':
        return integer(value, argument.minimum ?? -2_147_483_648,
                       argument.maximum ?? 2_147_483_647, argument.name);
    case 'string':
        if (typeof value !== 'string' || value.length === 0 || value.length > 128) {
            throw new DesfireError(ErrorCode.InvalidArgument, `${argument.name} is invalid`);
        }
        return value;
    case 'picc_configuration':
    case 'transaction_operations':
    case 'native_request':
    case 'native_secure_request':
    case 'iso_apdu':
        return descriptorCopy(value, argument.kind, argument.name);
    case 'key_source': return value;
    default: throw new DesfireError(ErrorCode.Internal, 'Unknown generated argument kind');
    }
}

/** Overwrite binding-owned byte copies without traversing caller-owned key-source objects. */
function wipeArguments(values, descriptors) {
    const wipe = value => {
        if (value instanceof Uint8Array) {
            if (value.byteLength !== 0) value.fill(0);
        }
        else if (Array.isArray(value)) value.forEach(wipe);
        else if (value && typeof value === 'object') Object.values(value).forEach(wipe);
    };
    values.forEach((value, index) => {
        if (descriptors[index]?.kind !== 'key_source') wipe(value);
    });
}

/** Separate a generated operation's timeout and AbortSignal from its copied ABI inputs. */
function prepareArguments(operation, input) {
    const supplied = [...input];
    const expected = operation.arguments;
    const hasTimeout = expected.at(-1)?.kind === 'timeout';
    if (hasTimeout && supplied.length === expected.length - 1) supplied.push(5000);
    let signal;
    if (!hasTimeout && supplied.length === expected.length + 1) {
        const options = supplied.pop();
        if (!options || typeof options !== 'object' ||
            (options.signal !== undefined && !(options.signal instanceof AbortSignal))) {
            throw new DesfireError(ErrorCode.InvalidArgument, 'Invalid operation options');
        }
        signal = options.signal;
    }
    if (supplied.length !== expected.length) {
        throw new DesfireError(ErrorCode.InvalidArgument, 'Incorrect typed argument count');
    }
    if (hasTimeout && supplied.at(-1) && typeof supplied.at(-1) === 'object' &&
        !(supplied.at(-1) instanceof Uint8Array)) {
        const options = supplied.at(-1);
        if (options.signal !== undefined && !(options.signal instanceof AbortSignal)) {
            throw new DesfireError(ErrorCode.InvalidArgument, 'signal must be an AbortSignal');
        }
        signal = options.signal;
        supplied[supplied.length - 1] = options.timeoutMs ?? 5000;
    }
    return { values: supplied.map((value, index) => copyArgument(value, expected[index])), signal };
}

/** Convert untrusted reader exceptions to bounded, redacted failure evidence. */
function readerFailure(error) {
    if (error instanceof DesfireError && Number.isInteger(error.code) &&
        error.code >= 1 && error.code <= 17 && Number.isInteger(error.outcome) &&
        error.outcome >= 0 && error.outcome <= 3 && Number.isInteger(error.deviceStatus) &&
        error.deviceStatus >= 0 && error.deviceStatus <= 65_535) return error;
    return new DesfireError(ErrorCode.Transport, 'Reader callback failed', Outcome.Unknown);
}

/** Publish one reader completion to the worker's shared rendezvous. */
function reply(message, data, error) {
    const control = new Int32Array(message.shared, 0, 6);
    if (Atomics.load(control, 0) !== 0) return;
    if (error) {
        Atomics.store(control, 2, error.code);
        Atomics.store(control, 3, error.outcome);
        Atomics.store(control, 4, error.deviceStatus);
    } else {
        new Uint8Array(message.shared, 24, data.byteLength).set(data);
        Atomics.store(control, 1, data.byteLength);
    }
    Atomics.store(control, 0, 1);
    Atomics.notify(control, 0);
}

/** Derive validation expectations from one provider-flavored operation. */
function keyExpectation(name, values, sourceIndex) {
    const argument = operations[name].arguments;
    const numberIndex = argument.findIndex(item =>
        item.name === 'key_number' || item.name === 'number');
    const expected = { keyNumber: numberIndex < 0 ? undefined : values[numberIndex] };
    if (name.includes('authenticate')) {
        expected.purpose = KeyPurpose.Authentication;
        expected.scope = name.includes('iso_aes') ?
            (values[argument.findIndex(item => item.name === 'application')]
                ? KeyScope.IsoApplication : KeyScope.IsoPicc) : KeyScope.Native;
        expected.profile = name.includes('ev2_first') ? AuthenticationProfile.Ev2First
            : name.includes('ev2_non_first') ? AuthenticationProfile.Ev2NonFirst
                : name.includes('iso_aes') ? AuthenticationProfile.IsoAes
                    : AuthenticationProfile.StandardAes;
    } else if (name.includes('transaction_mac')) {
        expected.purpose = KeyPurpose.TransactionMac;
    } else if (name.includes('delegated')) {
        expected.purpose = KeyPurpose.DelegatedApplication;
    } else if (name === 'change_aes_key_provider') {
        expected.purpose = sourceIndex === 0 ? KeyPurpose.ReplacementKey : KeyPurpose.CurrentKey;
    } else if (name === 'set_default_aes_key_provider') {
        expected.purpose = KeyPurpose.ReplacementKey;
    } else {
        expected.purpose = KeyPurpose.OfflineOperation;
    }
    return expected;
}

/** Map resolved provider keys onto the corresponding direct-key ABI descriptor. */
function providerDirectArguments(name, values, resolved) {
    const provider = operations[name];
    const direct = operations[provider.providerDirect];
    const byName = new Map();
    provider.arguments.forEach((argument, index) => {
        if (argument.kind !== 'key_source') byName.set(argument.name, values[index]);
    });
    let keyIndex = 0;
    return direct.arguments.map(argument => {
        if (byName.has(argument.name)) {
            const value = byName.get(argument.name);
            return argument.kind === 'boolean' ? value !== 0 : value;
        }
        if (argument.name === 'diversification') {
            return keySourceContext(values[provider.arguments.findIndex(item =>
                item.kind === 'key_source')]).diversificationInput;
        }
        if (argument.kind === 'bytes' && keyIndex < resolved.length) {
            return resolved[keyIndex++];
        }
        throw new DesfireError(ErrorCode.Internal, 'Provider/direct manifest mapping is incomplete');
    });
}

/** Shared FIFO and transport-lifecycle implementation for managed and raw sessions. */
class Session {
    #reader;
    #worker;
    #mode;
    #sequence = 0;
    #pending = new Map();
    #tail = Promise.resolve();
    #active;
    #activeResolution;
    #closed = false;
    #closing = false;
    #closePromise;
    #workerFailure;
    #readerBusy = false;
    #readerSettled = Promise.resolve();
    #quiescing = false;
    #readerScope = new AsyncLocalStorage();

    /** Create a worker only after all connection inputs have been validated. */
    constructor(reader, options, mode) {
        this.#reader = reader;
        this.#mode = mode;
        this.#worker = new Worker(new URL('./worker.mjs', import.meta.url), {
            workerData: {
                addonPath: options.addonPath, manifestHash: MANIFEST_SHA256, mode,
                transport: {
                    framing: options.framing, maxTransmit: options.maxTransmit,
                    maxReceive: options.maxReceive, maxNativeFrame: options.maxNativeFrame,
                },
                hasReset: typeof reader.reset === 'function',
            },
        });
        this.#worker.on('message', message => this.#onMessage(message));
        this.#worker.on('error', () => this.#failWorker());
        this.#worker.on('exit', () => { if (!this.#closed) this.#failWorker(); });
    }

    /** Validate, exclusively claim, and open one activated reader. */
    static async _connect(reader, options, mode) {
        if (!reader || typeof reader !== 'object' || typeof reader.exchange !== 'function') {
            throw new DesfireError(ErrorCode.InvalidArgument, 'Reader.exchange must be callable');
        }
        if (!options || typeof options.addonPath !== 'string' || !isAbsolute(options.addonPath)) {
            throw new DesfireError(ErrorCode.InvalidArgument, 'An absolute addonPath is required');
        }
        for (const name of ['reset', 'cancel']) {
            if (reader[name] !== undefined && typeof reader[name] !== 'function') {
                throw new DesfireError(ErrorCode.InvalidArgument, `Reader.${name} must be callable`);
            }
        }
        if (readerOwners.has(reader)) {
            throw new DesfireError(ErrorCode.Busy, 'Reader already belongs to an open card or raw channel');
        }
        const normalized = {
            ...options,
            framing: integer(options.framing, 0, 1, 'framing'),
            maxTransmit: integer(options.maxTransmit ?? 261, 1, MAX_BYTES, 'maxTransmit'),
            maxReceive: integer(options.maxReceive ?? 4096, 1, MAX_BYTES, 'maxReceive'),
            maxNativeFrame: integer(options.maxNativeFrame ?? 256, 2, MAX_BYTES,
                                    'maxNativeFrame'),
        };
        const session = new this(reader, normalized, mode);
        readerOwners.set(reader, session);
        try {
            await session.#dispatch('open', []);
            return session;
        } catch (error) {
            session.#closed = true;
            readerOwners.delete(reader);
            await session.#worker.terminate();
            throw error;
        }
    }

    /** Receive worker completion or begin one asynchronous reader callback. */
    #onMessage(message) {
        if (message.type === 'reader') {
            void this.#serviceReader(message);
            return;
        }
        const pending = this.#pending.get(message.id);
        if (!pending) return;
        this.#pending.delete(message.id);
        this.#active = undefined;
        if (message.error) {
            const error = message.error;
            pending.reject(new DesfireError(error.code, error.message, error.outcome,
                                            error.deviceStatus));
        } else pending.resolve(message.value);
    }

    /** Race physical I/O with timeout/cancellation while tracking late completion. */
    async #serviceReader(message) {
        const active = this.#active;
        if (!active || active.id !== message.id || active.cancelled ||
            Date.now() >= message.deadline) {
            reply(message, undefined, new DesfireError(
                ErrorCode.Cancelled, 'Reader operation cancelled before transmission',
                Outcome.NotSent));
            return;
        }
        if (this.#readerBusy) {
            reply(message, undefined, new DesfireError(
                ErrorCode.Busy, 'An earlier reader exchange has not settled', Outcome.NotSent));
            return;
        }
        const controller = new AbortController();
        active.controllers.add(controller);
        let timer;
        let cancelListener;
        try {
            const interruption = new Promise((_, reject) => {
                cancelListener = () => reject(new DesfireError(
                    ErrorCode.Cancelled, 'Reader operation cancelled', Outcome.Unknown));
                controller.signal.addEventListener('abort', cancelListener, { once: true });
                timer = setTimeout(() => {
                    reject(new DesfireError(
                        ErrorCode.Timeout, 'Reader operation timed out', Outcome.Unknown));
                    controller.abort();
                }, Math.max(1, message.deadline - Date.now()));
            });
            this.#readerBusy = true;
            const operation = Promise.resolve().then(() => this.#readerScope.run(this, () =>
                message.kind === 'reset' ? this.#reader.reset() : this.#reader.exchange(
                    message.transmit, { timeoutMs: message.timeoutMs, signal: controller.signal })));
            this.#readerSettled = operation.then(() => {}, () => {}).finally(() => {
                this.#readerBusy = false;
                this.#quiescing = false;
                message.transmit.fill(0);
            });
            const value = await Promise.race([operation, interruption]);
            const data = message.kind === 'reset' ? new Uint8Array() : value;
            if (!(data instanceof Uint8Array) || data.byteLength > message.capacity) {
                throw new DesfireError(
                    ErrorCode.MalformedResponse, 'Reader returned invalid or oversized bytes',
                    Outcome.Unknown);
            }
            reply(message, data);
        } catch (error) {
            const failure = readerFailure(error);
            if (this.#readerBusy &&
                (failure.code === ErrorCode.Timeout || failure.code === ErrorCode.Cancelled)) {
                this.#quiescing = true;
            }
            reply(message, undefined, failure);
        } finally {
            clearTimeout(timer);
            controller.signal.removeEventListener('abort', cancelListener);
            active.controllers.delete(controller);
        }
    }

    /** Reject admitted work if the native worker becomes unavailable. */
    #failWorker() {
        if (this.#workerFailure) return;
        this.#workerFailure = new DesfireError(
            ErrorCode.Internal, 'Native session worker exited', Outcome.Unknown);
        for (const pending of this.#pending.values()) pending.reject(this.#workerFailure);
        this.#pending.clear();
        for (const controller of this.#active?.controllers ?? []) controller.abort();
        this.#active = undefined;
        void this.#readerSettled.finally(() => readerOwners.delete(this.#reader));
    }

    /** Transfer binding-owned byte snapshots to one worker request. */
    #dispatch(operation, arguments_) {
        if (this.#workerFailure) return Promise.reject(this.#workerFailure);
        const id = ++this.#sequence;
        return new Promise((resolve, reject) => {
            this.#pending.set(id, { resolve, reject });
            this.#active = { id, cancelled: false, controllers: new Set() };
            const transfers = [];
            const collect = value => {
                if (value instanceof Uint8Array) transfers.push(value.buffer);
                else if (Array.isArray(value)) value.forEach(collect);
                else if (value && typeof value === 'object') Object.values(value).forEach(collect);
            };
            arguments_.forEach(collect);
            try {
                this.#worker.postMessage({ id, operation, arguments: arguments_ }, transfers);
            } catch {
                this.#pending.delete(id);
                this.#active = undefined;
                reject(new DesfireError(ErrorCode.Internal, 'Could not dispatch native operation'));
            }
        });
    }

    /** Queue one prepared operation and connect AbortSignal only after it becomes active. */
    #enqueue(operation, values, signal) {
        const task = this.#tail.then(async () => {
            try {
                if (signal?.aborted) {
                    throw new DesfireError(ErrorCode.Cancelled, 'Queued operation cancelled',
                                           Outcome.NotSent);
                }
                if (this.#quiescing) {
                    throw new DesfireError(
                        ErrorCode.SessionInvalid, 'Reader is quiescing after interrupted I/O',
                        Outcome.NotSent);
                }
                let abortListener;
                if (signal) {
                    abortListener = () => { void this.cancel(); };
                    signal.addEventListener('abort', abortListener, { once: true });
                }
                try {
                    return await this.#dispatch(operation, values);
                } finally {
                    if (signal && abortListener) {
                        signal.removeEventListener('abort', abortListener);
                    }
                }
            } finally {
                const descriptor = Object.values(operations).find(item => item.native === operation);
                wipeArguments(values, descriptor?.arguments ?? []);
            }
        });
        this.#tail = task.catch(() => {});
        return task;
    }

    /** Invoke one generated direct operation through this session's FIFO queue. */
    _invoke(name, input) {
        try {
            if (this.#closed || this.#closing) {
                throw new DesfireError(ErrorCode.StaleHandle, 'Session is closing or closed');
            }
            if (this.#isReentry()) {
                throw new DesfireError(ErrorCode.Busy, 'Reader callbacks cannot reenter a session');
            }
            const table = this.#mode === 'raw' ? rawOperations : managedOperations;
            const operation = table[name];
            if (!operation || operation.providerDirect) {
                throw new DesfireError(ErrorCode.InvalidArgument, 'Unknown direct operation');
            }
            const { values, signal } = prepareArguments(operation, input);
            return this.#enqueue(operation.native, values, signal);
        } catch (error) {
            return Promise.reject(error);
        }
    }

    /** Resolve provider key sources in FIFO order and call only the direct-key C ABI. */
    _invokeProvider(name, input) {
        try {
            if (this.#closed || this.#closing) {
                throw new DesfireError(ErrorCode.StaleHandle, 'Session is closing or closed');
            }
            if (this.#isReentry()) {
                throw new DesfireError(ErrorCode.Busy, 'Callbacks cannot reenter a session');
            }
            const table = this.#mode === 'raw' ? rawOperations : managedOperations;
            const operation = table[name];
            if (!operation?.providerDirect) {
                throw new DesfireError(ErrorCode.InvalidArgument, 'Unknown provider operation');
            }
            const { values, signal } = prepareArguments(operation, input);
            const task = this.#tail.then(async () => {
                if (signal?.aborted) {
                    throw new DesfireError(ErrorCode.Cancelled, 'Queued key operation cancelled',
                                           Outcome.NotSent);
                }
                const sources = operation.arguments
                    .map((argument, index) => ({ argument, index }))
                    .filter(item => item.argument.kind === 'key_source');
                const resolved = [];
                const resolutionController = new AbortController();
                this.#activeResolution = resolutionController;
                const resolutionSignal = signal
                    ? AbortSignal.any([signal, resolutionController.signal])
                    : resolutionController.signal;
                try {
                    for (let index = 0; index < sources.length; index += 1) {
                        const source = sources[index];
                        resolved.push(await this.#readerScope.run(this, () => resolveKeySource(
                            values[source.index], keyExpectation(name, values, index),
                            resolutionSignal)));
                    }
                    if (signal?.aborted) {
                        throw new DesfireError(
                            ErrorCode.Cancelled, 'Key operation cancelled before I/O',
                            Outcome.NotSent);
                    }
                    const direct = operations[operation.providerDirect];
                    const directValues = providerDirectArguments(name, values, resolved)
                        .map((value, index) => copyArgument(value, direct.arguments[index]));
                    let abortListener;
                    try {
                        if (signal) {
                            abortListener = () => { void this.cancel(); };
                            signal.addEventListener('abort', abortListener, { once: true });
                        }
                        return await this.#dispatch(direct.native, directValues);
                    } finally {
                        if (signal && abortListener) {
                            signal.removeEventListener('abort', abortListener);
                        }
                        wipeArguments(directValues, direct.arguments);
                    }
                } finally {
                    if (this.#activeResolution === resolutionController) {
                        this.#activeResolution = undefined;
                    }
                    for (const key of resolved) key.fill(0);
                    wipeArguments(values, operation.arguments);
                }
            });
            this.#tail = task.catch(() => {});
            return task;
        } catch (error) {
            return Promise.reject(error);
        }
    }

    /** Request reader interruption without waiting for the FIFO operation lock. */
    async cancel() {
        if (this.#closed || this.#closing) {
            throw new DesfireError(ErrorCode.StaleHandle, 'Session is closing or closed');
        }
        if (this.#active) {
            this.#active.cancelled = true;
            for (const controller of this.#active.controllers) controller.abort();
            if (this.#reader.cancel) {
                try { await this.#reader.cancel(); } catch (error) { throw readerFailure(error); }
            }
        }
        this.#activeResolution?.abort();
    }

    /** Reset the physical reader and clear native session state after prior I/O quiesces. */
    reset() { return this.#lifecycle(this.#mode === 'raw' ? 'df_raw_reset' : 'df_reset'); }

    /** Report external card replacement and invalidate native session state. */
    notify_state_change() {
        return this.#lifecycle(this.#mode === 'raw'
            ? 'df_raw_notify_state_change' : 'df_notify_state_change');
    }

    /** Serialize one nonblocking native lifecycle update. */
    #lifecycle(name) {
        if (this.#closed || this.#closing) {
            return Promise.reject(new DesfireError(
                ErrorCode.StaleHandle, 'Session is closing or closed'));
        }
        if (this.#isReentry()) {
            return Promise.reject(new DesfireError(
                ErrorCode.Busy, 'Reader callbacks cannot reenter a session'));
        }
        const task = this.#tail.then(() => this.#dispatch(name, []));
        this.#tail = task.catch(() => {});
        return task;
    }

    /** Drain admitted work and late reader completion before releasing native ownership. */
    close() {
        if (this.#isReentry()) {
            return Promise.reject(new DesfireError(
                ErrorCode.Busy, 'Reader callbacks cannot close their active session'));
        }
        if (this.#closePromise) return this.#closePromise;
        this.#closing = true;
        this.#closePromise = this.#tail.then(() => this.#readerSettled).then(async () => {
            if (!this.#workerFailure) await this.#dispatch('close', []);
            this.#closed = true;
            readerOwners.delete(this.#reader);
            await this.#worker.terminate();
        }).catch(error => {
            this.#closing = false;
            this.#closePromise = undefined;
            throw error;
        });
        return this.#closePromise;
    }

    /** Detect same-session calls from a still-active reader or key-provider callback. */
    #isReentry() { return this.#readerScope.getStore() === this; }
}

/** Managed checked Card with friendly AES authentication workflows. */
export class Card extends Session {
    /** Open a managed session on one exclusively owned reader. */
    static connect(reader, options) { return super._connect(reader, options, 'managed'); }

    /** Authenticate with Standard AES using Direct, Derived, or Provider key material. */
    authenticateStandardAes(keyNumber, keySource, options = {}) {
        return this.authenticate_standard_aes_provider(keyNumber, keySource, options);
    }

    /** Authenticate EV2 First with zero through six caller capability bytes. */
    authenticateEv2FirstAes(keyNumber, keySource, capabilities = new Uint8Array(), options = {}) {
        if (!(capabilities instanceof Uint8Array) || capabilities.byteLength > 6) {
            return Promise.reject(new DesfireError(
                ErrorCode.InvalidArgument, 'capabilities must contain zero through six bytes'));
        }
        return capabilities.byteLength === 0
            ? this.authenticate_ev2_first_aes_provider(keyNumber, keySource, options)
            : this.authenticate_ev2_first_aes_with_capabilities_provider(
                keyNumber, keySource, capabilities, options);
    }

    /** Replace an EV2 session through NonFirst while preserving transaction identity. */
    authenticateEv2NonFirstAes(keyNumber, keySource, options = {}) {
        return this.authenticate_ev2_non_first_aes_provider(keyNumber, keySource, options);
    }

    /** Establish true ISO mutual AES in PICC or selected-application scope. */
    authenticateIsoAes(keyNumber, applicationKey, keySource, options = {}) {
        if (typeof applicationKey !== 'boolean') {
            return Promise.reject(new DesfireError(
                ErrorCode.InvalidArgument, 'applicationKey must be boolean'));
        }
        return this.authenticate_iso_aes_provider(
            keyNumber, applicationKey, keySource, options);
    }
}

/** Independent expert channel for direct, ISO-wrapped, true ISO, and secure exchanges. */
export class RawChannel extends Session {
    /** Open a raw session on one exclusively owned reader. */
    static connect(reader, options) { return super._connect(reader, options, 'raw'); }

    /** Establish Standard AES on the raw native secure channel. */
    authenticateStandardAes(keyNumber, keySource, options = {}) {
        return this.raw_authenticate_standard_aes_provider(keyNumber, keySource, options);
    }

    /** Establish raw EV2 First with explicit zero-through-six-byte PCD capabilities. */
    authenticateEv2FirstAes(keyNumber, keySource, capabilities = new Uint8Array(), options = {}) {
        return this.raw_authenticate_ev2_first_aes_provider(
            keyNumber, keySource, capabilities, options);
    }

    /** Replace a raw EV2 session through NonFirst. */
    authenticateEv2NonFirstAes(keyNumber, keySource, options = {}) {
        return this.raw_authenticate_ev2_non_first_aes_provider(keyNumber, keySource, options);
    }

    /** Establish ISO mutual AES on the raw true-ISO channel. */
    authenticateIsoAes(keyNumber, applicationKey, keySource, options = {}) {
        return this.raw_authenticate_iso_aes_provider(
            keyNumber, applicationKey, keySource, options);
    }
}

/** Install generated managed methods without replacing the friendly camel-case surface. */
for (const [name, operation] of Object.entries(managedOperations)) {
    Object.defineProperty(Card.prototype, name, {
        value: function (...input) {
            return operation.providerDirect
                ? this._invokeProvider(name, input) : this._invoke(name, input);
        },
        writable: false, configurable: false,
    });
}

/** Install generated expert methods on the separately owned raw channel. */
for (const [name, operation] of Object.entries(rawOperations)) {
    Object.defineProperty(RawChannel.prototype, name, {
        value: function (...input) {
            return operation.providerDirect
                ? this._invokeProvider(name, input) : this._invoke(name, input);
        },
        writable: false, configurable: false,
    });
}

/** One worker-isolated collection of stateless offline AES operations. */
export class Offline {
    #worker;
    #sequence = 0;
    #pending = new Map();
    #tail = Promise.resolve();
    #closed = false;

    /** Start one offline worker and verify ABI/manifest identity before use. */
    static async connect(addonPath) {
        if (typeof addonPath !== 'string' || !isAbsolute(addonPath)) {
            throw new DesfireError(ErrorCode.InvalidArgument, 'An absolute addonPath is required');
        }
        const offline = new Offline(addonPath);
        await offline.#dispatch('openOffline', []);
        return offline;
    }

    /** Construct the private worker after static validation. */
    constructor(addonPath) {
        this.#worker = new Worker(new URL('./worker.mjs', import.meta.url), {
            workerData: { addonPath, manifestHash: MANIFEST_SHA256, mode: 'offline' },
        });
        this.#worker.on('message', message => {
            const pending = this.#pending.get(message.id);
            if (!pending) return;
            this.#pending.delete(message.id);
            if (message.error) pending.reject(new DesfireError(
                message.error.code, message.error.message, message.error.outcome,
                message.error.deviceStatus));
            else pending.resolve(message.value);
        });
        const fail = () => {
            const error = new DesfireError(
                ErrorCode.Internal, 'Native offline worker exited', Outcome.NotSent);
            for (const pending of this.#pending.values()) pending.reject(error);
            this.#pending.clear();
        };
        this.#worker.on('error', fail);
        this.#worker.on('exit', () => { if (!this.#closed) fail(); });
    }

    /** Dispatch one offline call to its native worker. */
    #dispatch(operation, arguments_) {
        const id = ++this.#sequence;
        return new Promise((resolve, reject) => {
            this.#pending.set(id, { resolve, reject });
            const transfers = arguments_.filter(value => value instanceof Uint8Array)
                .map(value => value.buffer);
            this.#worker.postMessage({ id, operation, arguments: arguments_ }, transfers);
        });
    }

    /** Queue one direct or provider-resolved offline operation. */
    _invoke(name, input) {
        try {
            if (this.#closed) throw new DesfireError(ErrorCode.StaleHandle, 'Offline worker closed');
            const operation = offlineOperations[name];
            const { values, signal } = prepareArguments(operation, input);
            const task = this.#tail.then(async () => {
                try {
                    if (signal?.aborted) throw new DesfireError(
                        ErrorCode.Cancelled, 'Queued offline operation cancelled', Outcome.NotSent);
                    if (!operation.providerDirect) {
                        return await this.#dispatch(operation.native, values);
                    }
                    const sources = operation.arguments
                        .map((argument, index) => ({ argument, index }))
                        .filter(item => item.argument.kind === 'key_source');
                    const resolved = [];
                    try {
                        for (let index = 0; index < sources.length; index += 1) {
                            const source = sources[index];
                            resolved.push(await resolveKeySource(
                                values[source.index], keyExpectation(name, values, index), signal));
                        }
                        const direct = operations[operation.providerDirect];
                        const directValues = providerDirectArguments(name, values, resolved)
                            .map((value, index) => copyArgument(value, direct.arguments[index]));
                        try {
                            return await this.#dispatch(direct.native, directValues);
                        } finally {
                            wipeArguments(directValues, direct.arguments);
                        }
                    } finally {
                        for (const key of resolved) key.fill(0);
                    }
                } finally {
                    wipeArguments(values, operation.arguments);
                }
            });
            this.#tail = task.catch(() => {});
            return task;
        } catch (error) {
            return Promise.reject(error);
        }
    }

    /** Drain admitted calls and terminate the offline worker. */
    close() {
        if (this.#closed) return Promise.resolve();
        this.#closed = true;
        return this.#tail.then(() => this.#worker.terminate()).then(() => undefined);
    }
}

/** Install every generated offline direct and provider-friendly method. */
for (const name of Object.keys(offlineOperations)) {
    Object.defineProperty(Offline.prototype, name, {
        value: function (...input) { return this._invoke(name, input); },
        writable: false, configurable: false,
    });
}
