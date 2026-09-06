/** One stable C ABI operation available to the expert binding surface. */
export interface RawOperation {
    readonly name: string;
    readonly symbol: `df_${string}`;
    readonly surface: 'runtime' | 'managed' | 'raw' | 'offline';
}

export declare const ABI_VERSION: number;
export declare const MANIFEST_SHA256: string;
export declare const OPERATIONS: Readonly<Record<number, RawOperation>>;
export {
    RawChannel, RawChannel as Card, Framing, CommunicationMode, SecureProfile,
    IsoLengthEncoding, RawFlags,
} from '../index.js';
export type {
    ConnectOptions, Reader, OperationOptions, NativeRequest, NativeSecureRequest,
    IsoApdu, NativeResponse, IsoResponse,
} from '../index.js';
