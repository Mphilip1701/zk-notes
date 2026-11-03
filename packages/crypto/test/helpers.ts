import { MIN_KDF_PARAMS, type KdfParams } from '../src/index.js';

/** Cheapest parameters the library accepts: keeps the suite fast. */
export const FAST_PARAMS: KdfParams = { alg: 'argon2id', v: 1, ...MIN_KDF_PARAMS };

export function flipBit(b: Uint8Array<ArrayBuffer>, index = 0, bit = 0): Uint8Array<ArrayBuffer> {
  const copy = b.slice();
  copy[index] = copy[index]! ^ (1 << bit);
  return copy;
}

export async function rawKeyBytes(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}
