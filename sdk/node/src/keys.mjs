import { DesfireError, ErrorCode, Outcome } from './errors.mjs';

export const KeyPurpose = Object.freeze({
    Authentication: 0, CurrentKey: 1, ReplacementKey: 2,
    DelegatedApplication: 3, TransactionMac: 4, OfflineOperation: 5,
});
export const AuthenticationProfile = Object.freeze({
    StandardAes: 0, Ev2First: 1, Ev2NonFirst: 2, IsoAes: 3,
});
export const KeyScope = Object.freeze({ Native: 0, IsoPicc: 1, IsoApplication: 2 });

/** Mutable owner of one AES-128 key snapshot; close overwrites this object's bytes. */
export class Aes128Key {
    #bytes;

    /** Copy exactly sixteen bytes into independently wipeable storage. */
    constructor(bytes) {
        if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 16) {
            throw new DesfireError(
                ErrorCode.InvalidArgument, 'AES-128 key must contain exactly sixteen bytes');
        }
        this.#bytes = Uint8Array.from(bytes);
    }

    /** Return one temporary copy for a native or derivation call. */
    snapshot() {
        if (this.#bytes.byteLength !== 16) {
            throw new DesfireError(ErrorCode.InvalidArgument, 'AES-128 key is closed');
        }
        return Uint8Array.from(this.#bytes);
    }

    /** Overwrite and release this owner's bytes; repeated calls are safe. */
    close() {
        this.#bytes.fill(0);
        this.#bytes = new Uint8Array();
    }
}

/** Snapshot one bounded non-secret byte input. */
function contextBytes(value, maximum, name) {
    if (!(value instanceof Uint8Array) || value.byteLength > maximum) {
        throw new DesfireError(
            ErrorCode.InvalidArgument, `${name} must be a bounded Uint8Array`);
    }
    return Uint8Array.from(value);
}

/** Validate and copy non-secret derivation context. */
export function derivationContext(value) {
    if (!value || !Number.isInteger(value.purpose) || !Number.isInteger(value.keyNumber) ||
        value.keyNumber < 0 || value.keyNumber > 31) {
        throw new DesfireError(ErrorCode.InvalidArgument, 'Invalid derivation context');
    }
    const diversificationInput = contextBytes(
        value.diversificationInput ?? new Uint8Array(), 65_536, 'diversificationInput');
    const userContext = contextBytes(
        value.userContext ?? new Uint8Array(), 65_536, 'userContext');
    if (diversificationInput.byteLength + userContext.byteLength > 65_536 ||
        (value.application !== undefined &&
         (!Number.isInteger(value.application) || value.application < 0 ||
          value.application > 0xFF_FFFF)) ||
        (value.keySet !== undefined &&
         (!Number.isInteger(value.keySet) || value.keySet < 0 || value.keySet > 15))) {
        throw new DesfireError(ErrorCode.InvalidArgument, 'Invalid derivation context range');
    }
    return Object.freeze({
        purpose: value.purpose,
        keyNumber: value.keyNumber,
        application: value.application,
        keySet: value.keySet,
        diversificationInput,
        userContext,
    });
}

/** Validate and copy one non-secret key-provider request. */
export function keyRequest(value) {
    if (!value) throw new DesfireError(ErrorCode.InvalidArgument, 'Key request is required');
    const reference = contextBytes(value.reference, 1024, 'reference');
    if (reference.byteLength === 0 || !Number.isInteger(value.profile) ||
        !Number.isInteger(value.scope)) {
        throw new DesfireError(ErrorCode.InvalidArgument, 'Invalid key-provider request');
    }
    return Object.freeze({
        reference,
        context: derivationContext(value.context),
        profile: value.profile,
        scope: value.scope,
    });
}

/** Constructors for direct, custom-derived, and provider-resolved key workflows. */
export const KeySource = Object.freeze({
    direct(key) { return Object.freeze({ kind: 'direct', key }); },
    derived(masterKey, context, deriver) {
        return Object.freeze({ kind: 'derived', masterKey, context: derivationContext(context), deriver });
    },
    provider(request, provider) {
        return Object.freeze({ kind: 'provider', request: keyRequest(request), provider });
    },
});

/** Resolve a scoped key once; provider diagnostics never cross the binding boundary. */
export async function resolveKeySource(source, expected = {}, signal) {
    try {
        if (signal?.aborted) {
            throw new DesfireError(
                ErrorCode.Cancelled, 'AES-128 key resolution cancelled', Outcome.NotSent);
        }
        if (!source || typeof source !== 'object') throw new TypeError('missing source');
        if (source.kind === 'direct') return source.key.snapshot();
        let resolved;
        if (source.kind === 'derived') {
            if ((expected.purpose !== undefined &&
                 source.context.purpose !== expected.purpose) ||
                (expected.keyNumber !== undefined &&
                 source.context.keyNumber !== expected.keyNumber) ||
                !source.deriver || typeof source.deriver.derive !== 'function') {
                throw new TypeError('derivation mismatch');
            }
            resolved = await cancellableResolution(
                Promise.resolve(source.deriver.derive(
                    source.masterKey, source.context, { signal })), signal);
        } else if (source.kind === 'provider') {
            const request = source.request;
            if ((expected.purpose !== undefined &&
                 request.context.purpose !== expected.purpose) ||
                (expected.keyNumber !== undefined &&
                 request.context.keyNumber !== expected.keyNumber) ||
                (expected.profile !== undefined && request.profile !== expected.profile) ||
                (expected.scope !== undefined && request.scope !== expected.scope) ||
                !source.provider || typeof source.provider.resolve !== 'function') {
                throw new TypeError('provider mismatch');
            }
            resolved = await cancellableResolution(
                Promise.resolve(source.provider.resolve(request, { signal })), signal);
        } else {
            throw new TypeError('unknown source');
        }
        if (!(resolved instanceof Aes128Key)) throw new TypeError('invalid resolved key');
        try { return resolved.snapshot(); } finally { resolved.close(); }
    } catch (error) {
        if (error instanceof DesfireError &&
            (error.code === ErrorCode.InvalidArgument || error.code === ErrorCode.Cancelled)) {
            throw error;
        }
        throw new DesfireError(
            ErrorCode.Crypto, 'AES-128 key resolution failed', Outcome.NotSent);
    }
}

/** Return a copied, non-secret context when a provider-style operation requires it. */
export function keySourceContext(source) {
    const context = source?.kind === 'provider' ? source.request?.context : source?.context;
    if (!context) {
        throw new DesfireError(
            ErrorCode.InvalidArgument, 'This key-source operation requires derivation context');
    }
    return derivationContext(context);
}

/** Race one provider Promise with cancellation and close a late secret result. */
async function cancellableResolution(operation, signal) {
    if (!signal) return operation;
    let cancelled = false;
    let rejectCancellation;
    const cancellation = new Promise((_, reject) => { rejectCancellation = reject; });
    const onAbort = () => {
        cancelled = true;
        rejectCancellation(new DesfireError(
            ErrorCode.Cancelled, 'AES-128 key resolution cancelled', Outcome.NotSent));
    };
    signal.addEventListener('abort', onAbort, { once: true });
    operation.then(value => {
        if (cancelled && value instanceof Aes128Key) value.close();
    }, () => {});
    try {
        return await Promise.race([operation, cancellation]);
    } finally {
        signal.removeEventListener('abort', onAbort);
    }
}
