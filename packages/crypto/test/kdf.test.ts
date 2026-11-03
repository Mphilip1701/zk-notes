import { describe, expect, it } from 'vitest';
import {
  CryptoInputError,
  DEFAULT_KDF_PARAMS,
  argon2idRaw,
  assertKdfParamsAcceptable,
  deriveMasterKey,
  fromHex,
  hkdfSha256,
  toHex,
  utf8Encode,
} from '../src/index.js';
import { FAST_PARAMS } from './helpers.js';

describe('Argon2id', () => {
  // Reference vector from the Argon2 reference implementation test suite
  // (phc-winner-argon2/src/test.c, Argon2id v=0x13, t=2, m=2^16, p=1).
  it('matches the reference implementation test vector', async () => {
    const out = await argon2idRaw(utf8Encode('password'), utf8Encode('somesalt'), { t: 2, m: 65536, p: 1 });
    expect(toHex(out)).toBe('09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7');
  });

  it('deriveMasterKey is deterministic for same password+salt+params', async () => {
    const salt = new Uint8Array(16).fill(7);
    const a = await deriveMasterKey('correct horse battery staple', salt, FAST_PARAMS);
    const b = await deriveMasterKey('correct horse battery staple', salt, FAST_PARAMS);
    expect(a).toHaveLength(32);
    expect(toHex(a)).toBe(toHex(b));
  });

  it('differs when password, salt or params differ', async () => {
    const salt = new Uint8Array(16).fill(7);
    const base = toHex(await deriveMasterKey('pw-one-123456', salt, FAST_PARAMS));
    expect(toHex(await deriveMasterKey('pw-one-123457', salt, FAST_PARAMS))).not.toBe(base);
    expect(toHex(await deriveMasterKey('pw-one-123456', new Uint8Array(16).fill(8), FAST_PARAMS))).not.toBe(base);
    expect(toHex(await deriveMasterKey('pw-one-123456', salt, { ...FAST_PARAMS, t: 3 }))).not.toBe(base);
  });

  it('normalises Unicode so composed/decomposed forms derive the same key', async () => {
    const salt = new Uint8Array(16).fill(1);
    const composed = 'café-password';
    const decomposed = 'café-password';
    expect(composed).not.toBe(decomposed);
    expect(toHex(await deriveMasterKey(composed, salt, FAST_PARAMS))).toBe(
      toHex(await deriveMasterKey(decomposed, salt, FAST_PARAMS)),
    );
  });

  it('rejects bad salts and empty passwords', async () => {
    await expect(deriveMasterKey('pw', new Uint8Array(15), FAST_PARAMS)).rejects.toThrow(CryptoInputError);
    await expect(deriveMasterKey('', new Uint8Array(16), FAST_PARAMS)).rejects.toThrow(CryptoInputError);
  });
});

describe('KDF parameter policy (downgrade protection)', () => {
  it('accepts defaults and the minimum', () => {
    expect(() => assertKdfParamsAcceptable({ ...DEFAULT_KDF_PARAMS })).not.toThrow();
    expect(() => assertKdfParamsAcceptable(FAST_PARAMS)).not.toThrow();
  });

  it.each([
    ['too little memory', { ...FAST_PARAMS, m: 1024 }],
    ['too few iterations', { ...FAST_PARAMS, t: 1 }],
    ['zero parallelism', { ...FAST_PARAMS, p: 0 }],
    ['absurd memory (DoS)', { ...FAST_PARAMS, m: 1 << 30 }],
    ['non-integer', { ...FAST_PARAMS, t: 2.5 }],
    ['wrong alg', { ...FAST_PARAMS, alg: 'pbkdf2' }],
    ['wrong version', { ...FAST_PARAMS, v: 2 }],
    ['unknown field', { ...FAST_PARAMS, extra: 1 }],
    ['null', null],
    ['string', 'argon2id'],
  ])('rejects %s', (_name, params) => {
    expect(() => assertKdfParamsAcceptable(params)).toThrow(CryptoInputError);
  });

  it('deriveMasterKey enforces the policy too', async () => {
    await expect(deriveMasterKey('pw', new Uint8Array(16), { ...FAST_PARAMS, m: 8 })).rejects.toThrow(
      CryptoInputError,
    );
  });
});

describe('HKDF-SHA256', () => {
  it('RFC 5869 test case 1', async () => {
    const okm = await hkdfSha256(
      fromHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
      fromHex('f0f1f2f3f4f5f6f7f8f9'),
      42,
      fromHex('000102030405060708090a0b0c'),
    );
    expect(toHex(okm)).toBe(
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    );
  });

  it('RFC 5869 test case 3 (empty salt and info)', async () => {
    const okm = await hkdfSha256(fromHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'), new Uint8Array(0), 42);
    expect(toHex(okm)).toBe(
      '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
    );
  });
});
