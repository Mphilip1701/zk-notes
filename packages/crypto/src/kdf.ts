import { argon2id } from 'hash-wasm';
import { CryptoInputError, utf8Encode, wipe } from './encoding.js';

/**
 * Password-based key derivation (client side only).
 *
 * The parameters are stored per user on the server and returned at prelogin,
 * so they can be raised over time. Because the server supplies them, the
 * client MUST enforce floors (assertKdfParamsAcceptable) so a malicious server
 * cannot downgrade a user to cheap parameters and then brute-force the AK.
 */

export interface KdfParams {
  alg: 'argon2id';
  /** Format version of the key hierarchy. */
  v: 1;
  /** Memory cost in KiB. */
  m: number;
  /** Iterations (time cost). */
  t: number;
  /** Parallelism. */
  p: number;
}

export const DEFAULT_KDF_PARAMS: Readonly<KdfParams> = Object.freeze({
  alg: 'argon2id',
  v: 1,
  m: 64 * 1024, // 64 MiB
  t: 3,
  p: 1,
});

/** OWASP minimum for Argon2id (19 MiB, t=2, p=1). Anything weaker is refused. */
export const MIN_KDF_PARAMS = Object.freeze({ m: 19 * 1024, t: 2, p: 1 });
/** Upper bounds stop a malicious server from making the client hang or OOM. */
export const MAX_KDF_PARAMS = Object.freeze({ m: 1024 * 1024, t: 20, p: 8 });

export const SALT_LENGTH = 16;
export const KEY_LENGTH = 32;

export function assertKdfParamsAcceptable(params: unknown): asserts params is KdfParams {
  if (typeof params !== 'object' || params === null) throw new CryptoInputError('KDF params missing');
  const p = params as Record<string, unknown>;
  if (p.alg !== 'argon2id') throw new CryptoInputError('Unsupported KDF algorithm');
  if (p.v !== 1) throw new CryptoInputError('Unsupported key hierarchy version');
  for (const k of ['m', 't', 'p'] as const) {
    const val = p[k];
    if (typeof val !== 'number' || !Number.isInteger(val)) {
      throw new CryptoInputError(`KDF param ${k} must be an integer`);
    }
    if (val < MIN_KDF_PARAMS[k]) throw new CryptoInputError(`KDF param ${k} below minimum`);
    if (val > MAX_KDF_PARAMS[k]) throw new CryptoInputError(`KDF param ${k} above maximum`);
  }
  const extra = Object.keys(p).filter((k) => !['alg', 'v', 'm', 't', 'p'].includes(k));
  if (extra.length) throw new CryptoInputError('Unknown KDF params');
}

/** Unicode-normalise so the same password typed on different platforms derives the same key. */
export function normalizePassword(password: string): string {
  return password.normalize('NFC');
}

/**
 * Low-level Argon2id → raw bytes. Exposed for test vectors; application code
 * should use deriveMasterKey.
 */
export async function argon2idRaw(
  password: Uint8Array,
  salt: Uint8Array,
  params: { m: number; t: number; p: number },
  hashLength = KEY_LENGTH,
): Promise<Uint8Array<ArrayBuffer>> {
  const out = await argon2id({
    password,
    salt,
    iterations: params.t,
    memorySize: params.m,
    parallelism: params.p,
    hashLength,
    outputType: 'binary',
  });
  return out as Uint8Array<ArrayBuffer>;
}

/**
 * Master password → 32-byte Master Key. The returned buffer is the caller's to
 * wipe; prefer deriveKeys() in keys.ts, which never exposes the MK.
 */
export async function deriveMasterKey(
  password: string,
  salt: Uint8Array,
  params: KdfParams,
): Promise<Uint8Array<ArrayBuffer>> {
  assertKdfParamsAcceptable(params);
  if (typeof password !== 'string' || password.length === 0) {
    throw new CryptoInputError('Password required');
  }
  if (!(salt instanceof Uint8Array) || salt.length !== SALT_LENGTH) {
    throw new CryptoInputError(`Salt must be ${SALT_LENGTH} bytes`);
  }
  const pw = utf8Encode(normalizePassword(password));
  try {
    return await argon2idRaw(pw, salt, params);
  } finally {
    wipe(pw);
  }
}

/** HKDF-SHA256 via Web Crypto. Exposed (with salt) for RFC 5869 test vectors. */
export async function hkdfSha256(
  ikm: Uint8Array<ArrayBuffer>,
  info: Uint8Array<ArrayBuffer>,
  length: number,
  salt: Uint8Array<ArrayBuffer> = new Uint8Array(0),
): Promise<Uint8Array<ArrayBuffer>> {
  const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, base, length * 8);
  return new Uint8Array(bits);
}
