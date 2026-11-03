import { describe, expect, it } from 'vitest';
import {
  CryptoInputError,
  constantTimeEqual,
  encodeAad,
  fromBase64,
  fromHex,
  randomBytes,
  toBase64,
  toHex,
  utf8Decode,
  utf8Encode,
} from '../src/index.js';

describe('encoding', () => {
  it('base64 round-trips arbitrary bytes, including large inputs', () => {
    for (const n of [0, 1, 2, 3, 31, 32, 33, 100_000]) {
      const b = randomBytes(n);
      expect(fromBase64(toBase64(b))).toEqual(b);
    }
  });

  it('base64 rejects malformed input', () => {
    for (const bad of ['abc', 'ab$=', '====', 'a=bc', 'YWJj\n', 'YW-_']) {
      expect(() => fromBase64(bad)).toThrow(CryptoInputError);
    }
  });

  it('hex round-trips and rejects junk', () => {
    const b = randomBytes(17);
    expect(fromHex(toHex(b))).toEqual(b);
    expect(() => fromHex('abc')).toThrow(CryptoInputError);
    expect(() => fromHex('zz')).toThrow(CryptoInputError);
  });

  it('utf8 round-trips non-ASCII and rejects invalid sequences', () => {
    const s = 'héllo 🔐 Ωμέγα 日本';
    expect(utf8Decode(utf8Encode(s))).toBe(s);
    expect(() => utf8Decode(new Uint8Array([0xff, 0xfe]))).toThrow();
  });

  it('constantTimeEqual', () => {
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
    expect(constantTimeEqual(new Uint8Array([1]), new Uint8Array([1, 0]))).toBe(false);
  });

  it('encodeAad is unambiguous (length-prefixed)', () => {
    expect(encodeAad('L', 'ab', 'c')).not.toEqual(encodeAad('L', 'a', 'bc'));
    expect(encodeAad('L', 'a')).not.toEqual(encodeAad('La'));
    expect(encodeAad('L', 1)).toEqual(encodeAad('L', '1'));
  });

  it('randomBytes produces distinct outputs', () => {
    expect(toHex(randomBytes(32))).not.toBe(toHex(randomBytes(32)));
  });
});
