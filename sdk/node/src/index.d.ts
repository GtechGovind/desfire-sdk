import type {
    AuthenticationInfo, ManagedOperations, OfflineOperations, RawOperations,
} from './operations.js';
import type { KeySourceValue } from './keys.js';
import type { KeyNumber } from './identifiers.js';

export * from './operations.js';
export * from './keys.js';
export * from './errors.js';
export * from './identifiers.js';

export const Framing: Readonly<{ Native: 0; IsoWrapped: 1 }>;
export const CommunicationMode: Readonly<{ Plain: 0; Mac: 1; Full: 3 }>;
export const SecureProfile: Readonly<{ None: 0; StandardAes: 1; Ev2: 2 }>;
export const IsoLengthEncoding: Readonly<{ Automatic: 0; Short: 1; Extended: 2 }>;
export const UidOption: Readonly<{ Omitted: 0; WithoutNuid: 1; WithNuid: 2 }>;
export const IsoUpdateRecordInstruction: Readonly<{ Current: 220; Selected: 221 }>;
export const TransactionOperationKind: Readonly<{
    WriteData: 1; Credit: 2; Debit: 3; LimitedCredit: 4;
    WriteRecord: 5; UpdateRecord: 6; ClearRecordFile: 7;
}>;
export const RawFlags: Readonly<{ SingleContinuation: 1 }>;

/** Options for one physical exchange; cancellation can follow transmission. */
export interface ExchangeOptions {
    readonly timeoutMs: number;
    readonly signal: AbortSignal;
}

/** Activated reader owned by the host and exclusively leased by one SDK session. */
export interface Reader {
    exchange(frame: Uint8Array, options: ExchangeOptions): Uint8Array | Promise<Uint8Array>;
    reset?(): void | Promise<void>;
    cancel?(): void | Promise<void>;
}

/** Explicit N-API module, framing, and bounded transport capacities. */
export interface ConnectOptions {
    readonly addonPath: string;
    readonly framing: 0 | 1;
    readonly maxTransmit?: number;
    readonly maxReceive?: number;
    readonly maxNativeFrame?: number;
}

/** Deadline and cancellation policy for one admitted logical operation. */
export interface OperationOptions {
    readonly timeoutMs?: number;
    readonly signal?: AbortSignal;
}

export interface Card extends ManagedOperations {}

/** Friendly managed Card with one FIFO operation queue and no mutation retries. */
export class Card {
    private constructor();
    static connect(reader: Reader, options: ConnectOptions): Promise<Card>;
    authenticateStandardAes(
        keyNumber: KeyNumber, keySource: KeySourceValue,
        options?: OperationOptions): Promise<void>;
    authenticateEv2FirstAes(
        keyNumber: KeyNumber, keySource: KeySourceValue, capabilities?: Uint8Array,
        options?: OperationOptions): Promise<AuthenticationInfo>;
    authenticateEv2NonFirstAes(
        keyNumber: KeyNumber, keySource: KeySourceValue,
        options?: OperationOptions): Promise<AuthenticationInfo>;
    authenticateIsoAes(
        keyNumber: KeyNumber, applicationKey: boolean, keySource: KeySourceValue,
        options?: OperationOptions): Promise<void>;
    cancel(): Promise<void>;
    reset(): Promise<void>;
    notify_state_change(): Promise<void>;
    close(): Promise<void>;
}

export interface RawChannel extends RawOperations {}

/** Separately owned expert channel for native, wrapped-native, ISO, and secure requests. */
export class RawChannel {
    private constructor();
    static connect(reader: Reader, options: ConnectOptions): Promise<RawChannel>;
    authenticateStandardAes(
        keyNumber: KeyNumber, keySource: KeySourceValue,
        options?: OperationOptions): Promise<void>;
    authenticateEv2FirstAes(
        keyNumber: KeyNumber, keySource: KeySourceValue, capabilities?: Uint8Array,
        options?: OperationOptions): Promise<AuthenticationInfo>;
    authenticateEv2NonFirstAes(
        keyNumber: KeyNumber, keySource: KeySourceValue,
        options?: OperationOptions): Promise<AuthenticationInfo>;
    authenticateIsoAes(
        keyNumber: KeyNumber, applicationKey: boolean, keySource: KeySourceValue,
        options?: OperationOptions): Promise<void>;
    cancel(): Promise<void>;
    reset(): Promise<void>;
    notify_state_change(): Promise<void>;
    close(): Promise<void>;
}

export interface Offline extends OfflineOperations {}

/** Worker-isolated stateless offline AES, delegated, originality, and TMAC utilities. */
export class Offline {
    private constructor();
    static connect(addonPath: string): Promise<Offline>;
    close(): Promise<void>;
}
