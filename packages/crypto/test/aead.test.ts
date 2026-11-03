import { describe, expect, it } from 'vitest';
import {
  CryptoInputError,
  DecryptionError,
  IV_LENGTH,
  encryptWithIv,
  fromHex,
  importAesKey,
  open,
  randomBytes,
  seal,
  toHex,
  utf8Decode,
  utf8Encode,
} from '../src/index.js';
import { flipBit } from './helpers.js';

const AAD = utf8Encode('context');

describe('AES-256-GCM', () => {
  // McGrew & Viega GCM spec, Test Cases 13 and 14 (256-bit zero key, zero IV).
  it('known-answer test: GCM spec test case 13 (empty plaintext)', async () => {
    const key = await importAesKey(new Uint8Array(32));
    const out = await encryptWithIv(key, new Uint8Array(12), new Uint8Array(0), new Uint8Array(0));
    expect(toHex(out)).toBe('530f8afbc74536b9a963b4f1c4cb738b');
  });

  it('known-answer test: GCM spec test case 14', async () => {
    const key = await importAesKey(new Uint8Array(32));
    const out = await encryptWithIv(key, new Uint8Array(12), new Uint8Array(16), new Uint8Array(0));
    expect(toHex(out)).toBe('cea7403d4d606b6e074ec5d3baf39d18' + 'd0d1c8a799996bf0265b98b5d48ab919');
    expect(await open(key, { iv: new Uint8Array(12), ciphertext: out }, new Uint8Array(0))).toEqual(
      new Uint8Array(16),
    );
  });

  it('round-trips', async () => {
    const key = await importAesKey(randomBytes(32));
    for (const msg of ['', 'a', 'hello world', '🔐'.repeat(1000)]) {
      const sealed = await seal(key, utf8Encode(msg), AAD);
      expect(sealed.iv).toHaveLength(IV_LENGTH);
      expect(utf8Decode(await open(key, sealed, AAD))).toBe(msg);
    }
  });

  it('uses a fresh IV every time (no reuse across 2000 encryptions)', async () => {
    const key = await importAesKey(randomBytes(32));
    const ivs = new Set<string>();
    const cts = new Set<string>();
    for (let i = 0; i < 2000; i++) {
      const s = await seal(key, utf8Encode('same plaintext'), AAD);
      ivs.add(toHex(s.iv));
      cts.add(toHex(s.ciphertext));
    }
    expect(ivs.size).toBe(2000);
    expect(cts.size).toBe(2000);
  });

  it('detects tampering with ciphertext body, tag and IV', async () => {
    const key = await importAesKey(randomBytes(32));
    const sealed = await seal(key, utf8Encode('attack at dawn'), AAD);
    const last = sealed.ciphertext.length - 1;
    await expect(open(key, { ...sealed, ciphertext: flipBit(sealed.ciphertext, 0) }, AAD)).rejects.toThrow(
      DecryptionError,
    );
    await expect(open(key, { ...sealed, ciphertext: flipBit(sealed.ciphertext, last, 7) }, AAD)).rejects.toThrow(
      DecryptionError,
    );
    await expect(open(key, { ...sealed, iv: flipBit(sealed.iv, 11) }, AAD)).rejects.toThrow(DecryptionError);
    await expect(open(key, { ...sealed, ciphertext: sealed.ciphertext.slice(0, -1) }, AAD)).rejects.toThrow(
      DecryptionError,
    );
    await expect(open(key, { ...sealed, ciphertext: sealed.ciphertext.slice(0, 15) }, AAD)).rejects.toThrow(
      DecryptionError,
    );
  });

  it('detects AAD mismatch', async () => {
    const key = await importAesKey(randomBytes(32));
    const sealed = await seal(key, utf8Encode('x'), AAD);
    await expect(open(key, sealed, utf8Encode('contexT'))).rejects.toThrow(DecryptionError);
    await expect(open(key, sealed, new Uint8Array(0))).rejects.toThrow(DecryptionError);
  });

  it('fails with the wrong key', async () => {
    const k1 = await importAesKey(randomBytes(32));
    const k2 = await importAesKey(randomBytes(32));
    const sealed = await seal(k1, utf8Encode('x'), AAD);
    await expect(open(k2, sealed, AAD)).rejects.toThrow(DecryptionError);
  });

  it('rejects wrong IV lengths and non-AES-256 keys', async () => {
    const key = await importAesKey(randomBytes(32));
    await expect(encryptWithIv(key, new Uint8Array(16), new Uint8Array(1), AAD)).rejects.toThrow(CryptoInputError);
    const aes128 = await crypto.subtle.importKey('raw', randomBytes(16), 'AES-GCM', false, ['encrypt', 'decrypt']);
    await expect(seal(aes128, new Uint8Array(1), AAD)).rejects.toThrow(CryptoInputError);
    await expect(importAesKey(randomBytes(16))).rejects.toThrow(CryptoInputError);
  });

  it('decryption error message does not leak detail', async () => {
    const key = await importAesKey(fromHex('00'.repeat(32)));
    const sealed = await seal(key, utf8Encode('x'), AAD);
    const err = await open(key, { ...sealed, iv: flipBit(sealed.iv) }, AAD).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DecryptionError);
    expect((err as Error).message).not.toMatch(/OperationError|tag/i);
  });
});
