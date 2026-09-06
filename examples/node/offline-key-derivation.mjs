/** Run the published NXP AES-128 diversification vector through the Node binding. */
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { Offline } from '../../sdk/node/src/index.mjs';

const hex = value => Uint8Array.from(Buffer.from(value, 'hex'));
const addon = resolve(process.env.DESFIRE_NODE_ADDON ?? '');
const offline = await Offline.connect(addon);
try {
    const derived = await offline.offline_derive_nxp_aes128(
        hex('00112233445566778899aabbccddeeff'),
        hex('04782e21801d803042f54e585020416275'));
    assert.deepEqual(derived, hex('a8dd63a3b89d54b37ca802473fda9175'));
} finally {
    await offline.close();
}
