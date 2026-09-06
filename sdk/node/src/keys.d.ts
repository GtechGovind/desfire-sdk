export const KeyPurpose: Readonly<{
    Authentication: 0; CurrentKey: 1; ReplacementKey: 2;
    DelegatedApplication: 3; TransactionMac: 4; OfflineOperation: 5;
}>;
export const AuthenticationProfile: Readonly<{
    StandardAes: 0; Ev2First: 1; Ev2NonFirst: 2; IsoAes: 3;
}>;
export const KeyScope: Readonly<{ Native: 0; IsoPicc: 1; IsoApplication: 2 }>;

export class Aes128Key {
    constructor(bytes: Uint8Array);
    snapshot(): Uint8Array;
    close(): void;
}

export interface DerivationContext {
    purpose: number;
    keyNumber: number;
    application?: number;
    keySet?: number;
    diversificationInput?: Uint8Array;
    userContext?: Uint8Array;
}

export interface KeyRequest {
    reference: Uint8Array;
    context: DerivationContext;
    profile: number;
    scope: number;
}

export interface Aes128KeyDeriver {
    derive(masterKey: Aes128Key, context: Readonly<DerivationContext>,
           options: Readonly<{ signal?: AbortSignal }>):
        Aes128Key | Promise<Aes128Key>;
}

export interface Aes128KeyProvider {
    resolve(request: Readonly<KeyRequest>, options: Readonly<{ signal?: AbortSignal }>):
        Aes128Key | Promise<Aes128Key>;
}

export type DirectKeySource = Readonly<{ kind: 'direct'; key: Aes128Key }>;
export type DerivedKeySource = Readonly<{
    kind: 'derived'; masterKey: Aes128Key; context: Readonly<DerivationContext>;
    deriver: Aes128KeyDeriver;
}>;
export type ProviderKeySource = Readonly<{
    kind: 'provider'; request: Readonly<KeyRequest>; provider: Aes128KeyProvider;
}>;
export type KeySourceValue = DirectKeySource | DerivedKeySource | ProviderKeySource;

export const KeySource: Readonly<{
    direct(key: Aes128Key): DirectKeySource;
    derived(masterKey: Aes128Key, context: DerivationContext,
            deriver: Aes128KeyDeriver): DerivedKeySource;
    provider(request: KeyRequest, provider: Aes128KeyProvider): ProviderKeySource;
}>;

export function derivationContext(value: DerivationContext): Readonly<DerivationContext>;
export function keyRequest(value: KeyRequest): Readonly<KeyRequest>;
export function resolveKeySource(
    source: KeySourceValue,
    expected?: Readonly<{ purpose?: number; keyNumber?: number; profile?: number; scope?: number }>,
    signal?: AbortSignal): Promise<Uint8Array>;
export function keySourceContext(source: KeySourceValue): Readonly<DerivationContext>;
