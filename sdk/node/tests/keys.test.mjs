import assert from 'node:assert/strict';
import test from 'node:test';

import {
    Aes128Key, AuthenticationProfile, DesfireError, ErrorCode,
    KeyPurpose, KeyScope, KeySource, Outcome, derivationContext, keyRequest,
} from '../src/index.mjs';
import { resolveKeySource } from '../src/keys.mjs';

test('direct and provider keys are copied, resolved once, and wiped by their owner', async () => {
    const original = new Uint8Array(16).fill(0xA5);
    const directKey = new Aes128Key(original);
    original.fill(0);
    const direct = await resolveKeySource(KeySource.direct(directKey), {
        keyNumber: 2, profile: AuthenticationProfile.StandardAes, scope: KeyScope.Native,
    });
    assert.deepEqual(direct, new Uint8Array(16).fill(0xA5));
    direct.fill(0);

    const context = derivationContext({
        purpose: KeyPurpose.Authentication, keyNumber: 2,
        diversificationInput: new Uint8Array([1, 2, 3]),
    });
    const request = keyRequest({
        reference: new Uint8Array([7]), context,
        profile: AuthenticationProfile.StandardAes, scope: KeyScope.Native,
    });
    let calls = 0;
    const provider = { async resolve() {
        calls += 1;
        return new Aes128Key(new Uint8Array(16).fill(0x5A));
    } };
    const resolved = await resolveKeySource(KeySource.provider(request, provider), {
        keyNumber: 2, profile: AuthenticationProfile.StandardAes, scope: KeyScope.Native,
    });
    assert.equal(calls, 1);
    assert.deepEqual(resolved, new Uint8Array(16).fill(0x5A));
    directKey.close();
    assert.throws(() => directKey.snapshot(), DesfireError);
});

test('provider failure is redacted and reports not-sent evidence', async () => {
    const context = derivationContext({ purpose: KeyPurpose.Authentication, keyNumber: 1 });
    const request = keyRequest({
        reference: new Uint8Array([1]), context,
        profile: AuthenticationProfile.Ev2First, scope: KeyScope.Native,
    });
    let calls = 0;
    await assert.rejects(
        resolveKeySource(KeySource.provider(request, { resolve() {
            calls += 1;
            throw new Error('private-provider-routing-secret');
        } }), {
            keyNumber: 1, profile: AuthenticationProfile.Ev2First, scope: KeyScope.Native,
        }),
        error => error instanceof DesfireError && error.code === ErrorCode.Crypto &&
            error.outcome === Outcome.NotSent && !error.message.includes('private-provider'));
    assert.equal(calls, 1);
});
