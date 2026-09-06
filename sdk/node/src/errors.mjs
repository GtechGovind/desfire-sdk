/** Per-call execution evidence; unknown mutations require application reconciliation. */
export const Outcome = Object.freeze({ NotSent: 0, Rejected: 1, Succeeded: 2, Unknown: 3 });

/** Stable native error categories shared by every binding. */
export const ErrorCode = Object.freeze({
    InvalidArgument: 1, Transport: 2, CardRemoved: 3, Timeout: 4, Cancelled: 5,
    MalformedResponse: 6, CardRejected: 7, Authentication: 8, Integrity: 9, Unsupported: 10,
    StaleHandle: 11, Busy: 12, SessionInvalid: 13, CounterExhausted: 14,
    BufferTooSmall: 15, Crypto: 16, Internal: 17,
});

/** Native error with immutable redacted execution evidence. */
export class DesfireError extends Error {
    /** Preserve only caller-selected safe text and exact numeric native evidence. */
    constructor(code, message, outcome = Outcome.NotSent, deviceStatus = 0) {
        super(message);
        this.name = 'DesfireError';
        Object.defineProperties(this, {
            code: { value: code, enumerable: true },
            outcome: { value: outcome, enumerable: true },
            deviceStatus: { value: deviceStatus, enumerable: true },
            requiresReconciliation: {
                value: outcome === Outcome.Unknown, enumerable: true,
            },
        });
    }
}
