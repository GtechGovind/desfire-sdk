/** This compile-only example verifies public Promise methods and binary ownership types. */
import {
    Aes128Key, AuthenticationProfile, Card, CommunicationMode, Framing, Offline, RawChannel,
    KeyPurpose, KeyScope, KeySource, derivationContext, keyNumber as makeKeyNumber,
    keyRequest, type Reader,
} from '@desfire/ev3';
import { Card as RawCard } from '@desfire/ev3/raw';

const reader: Reader = {
    async exchange(frame, { signal, timeoutMs }) {
        if (signal.aborted || timeoutMs <= 0) throw new Error('cancelled');
        return frame.slice();
    },
};

/** Typecheck complete native and true-ISO calls without opening a physical reader. */
async function sample(addonPath: string): Promise<void> {
    const card = await Card.connect(reader, { addonPath, framing: Framing.IsoWrapped });
    try {
        const keyNumber = makeKeyNumber(1);
        const context = derivationContext({ purpose: KeyPurpose.Authentication, keyNumber });
        const request = keyRequest({
            reference: new Uint8Array([1]), context,
            profile: AuthenticationProfile.StandardAes, scope: KeyScope.Native,
        });
        const source = KeySource.provider(request, {
            async resolve() { return new Aes128Key(new Uint8Array(16)); },
        });
        await card.authenticateStandardAes(keyNumber, source);
        const memory: number = await card.free_memory();
        const files: Uint8Array = await card.file_ids();
        const value: number = await card.get_value(1, CommunicationMode.Full);
        await card.write_data(1, 0, new Uint8Array([1, 2]), CommunicationMode.Full);
        const bytes: Uint8Array = await card.iso_read_binary(-1, 0, 32);
        void [memory, files, value, bytes];
    } finally {
        await card.close();
    }

    const raw: RawChannel = await RawCard.connect(
        reader, { addonPath, framing: Framing.Native });
    try {
        const response = await raw.raw_native_frame(
            Framing.Native, 0x60, new Uint8Array(), { timeoutMs: 2000 });
        const status: number = response.status;
        const data: Uint8Array = response.data;
        void [status, data];
    } finally {
        await raw.close();
    }

    const offline = await Offline.connect(addonPath);
    try {
        const derived: Uint8Array = await offline.offline_derive_nxp_aes128(
            new Uint8Array(16), new Uint8Array([1]));
        void derived;
    } finally {
        await offline.close();
    }
}

void sample;
