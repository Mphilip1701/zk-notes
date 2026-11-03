import { CryptoInputError, DecryptionError, randomBytes } from './encoding.js';

/** AES-256-GCM with 96-bit random IVs and a 128-bit tag. */

export const IV_LENGTH = 12;
export const TAG_LENGTH = 16;

export interface Sealed {
  iv: Uint8Array<ArrayBuffer>;
  /** ciphertext || 16-byte tag (Web Crypto layout). */
  ciphertext: Uint8Array<ArrayBuffer>;
}

function assertAesGcmKey(key: CryptoKey, usage: KeyUsage): void {
  if (!(key instanceof CryptoKey)) throw new CryptoInputError('Expected a CryptoKey');
  const alg = key.algorithm as AesKeyAlgorithm;
  if (alg.name !== 'AES-GCM' || alg.length !== 256) throw new CryptoInputError('Expected an AES-256-GCM key');
  if (!key.usages.includes(usage)) throw new CryptoInputError(`Key not usable for ${usage}`);
}

/**
 * Encrypt with an explicit IV. Only for known-answer tests: reusing an IV
 * under the same key is catastrophic for GCM. Use seal() everywhere else.
 */
export async function encryptWithIv(
  key: CryptoKey,
  iv: Uint8Array<ArrayBuffer>,
  plaintext: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  assertAesGcmKey(key, 'encrypt');
  if (iv.length !== IV_LENGTH) throw new CryptoInputError(`IV must be ${IV_LENGTH} bytes`);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad, tagLength: TAG_LENGTH * 8 },
    key,
    plaintext,
  );
  return new Uint8Array(ct);
}

export async function seal(
  key: CryptoKey,
  plaintext: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
): Promise<Sealed> {
  const iv = randomBytes(IV_LENGTH);
  const ciphertext = await encryptWithIv(key, iv, plaintext, aad);
  return { iv, ciphertext };
}

export async function open(
  key: CryptoKey,
  sealed: Sealed,
  aad: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  assertAesGcmKey(key, 'decrypt');
  if (sealed.iv.length !== IV_LENGTH) throw new CryptoInputError(`IV must be ${IV_LENGTH} bytes`);
  if (sealed.ciphertext.length < TAG_LENGTH) throw new DecryptionError('Ciphertext too short');
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: sealed.iv, additionalData: aad, tagLength: TAG_LENGTH * 8 },
      key,
      sealed.ciphertext,
    );
    return new Uint8Array(pt);
  } catch {
    // Web Crypto throws a generic OperationError; never leak more detail.
    throw new DecryptionError();
  }
}

/** Import raw 32 bytes as an AES-256-GCM key (used for tests / KATs). */
export async function importAesKey(
  raw: Uint8Array<ArrayBuffer>,
  usages: KeyUsage[] = ['encrypt', 'decrypt'],
  extractable = false,
): Promise<CryptoKey> {
  if (raw.length !== 32) throw new CryptoInputError('AES-256 key must be 32 bytes');
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, extractable, usages);
}
