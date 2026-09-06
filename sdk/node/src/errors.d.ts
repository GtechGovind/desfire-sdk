export const Outcome: Readonly<{ NotSent: 0; Rejected: 1; Succeeded: 2; Unknown: 3 }>;
export const ErrorCode: Readonly<{
    InvalidArgument: 1; Transport: 2; CardRemoved: 3; Timeout: 4; Cancelled: 5;
    MalformedResponse: 6; CardRejected: 7; Authentication: 8; Integrity: 9; Unsupported: 10;
    StaleHandle: 11; Busy: 12; SessionInvalid: 13; CounterExhausted: 14;
    BufferTooSmall: 15; Crypto: 16; Internal: 17;
}>;

export class DesfireError extends Error {
    readonly code: number;
    readonly outcome: number;
    readonly deviceStatus: number;
    readonly requiresReconciliation: boolean;
    constructor(code: number, message: string, outcome?: number, deviceStatus?: number);
}
