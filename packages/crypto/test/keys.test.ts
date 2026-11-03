import { describe, expect, it } from 'vitest';
import {
  DecryptionError,
  LABEL_AUTH,
  LABEL_KEK,
  createVaultKey,
  deriveKeys,
  generateSalt,
  hkdfSha256,
  open,
  randomBytes,
  rewrapVaultKey,
  seal,
  splitMasterKey,
  toHex,
  unwrapVaultKey,
  utf8Decode,
  utf8Encode,
} from '../src/index.js';
import { FAST_PARAMS, flipBit, rawKeyBytes } from './helpers.js';

const USER = '6f1c2a5e-8f3b-4d6a-9c2e-1b7d3e5f9a01';

describe('key derivation & domain separation', () => {
  it('auth key and KEK are independent HKDF outputs of the MK', async () => {
    const mk = randomBytes(32);
    const { authKey, kek } = await splitMasterKey(mk.slice());
    expect(authKey).toHaveLength(32);
    // Recompute both with the generic HKDF helper to pin the construction.
    expect(toHex(authKey)).toBe(toHex(await hkdfSha256(mk, utf8Encode(LABEL_AUTH), 32)));
    const kekBytes = await hkdfSha256(mk, utf8Encode(LABEL_KEK), 32);
    expect(toHex(kekBytes)).not.toBe(toHex(authKey));
    expect(toHex(authKey)).not.toBe(toHex(mk));
    expect(kek.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
  });

  it('the KEK is non-extractable and only usable for wrapping', async () => {
    const { kek } = await splitMasterKey(randomBytes(32));
    expect(kek.extractable).toBe(false);
    expect([...kek.usages].sort()).toEqual(['unwrapKey', 'wrapKey']);
    await expect(crypto.subtle.exportKey('raw', kek)).rejects.toThrow();
    await expect(seal(kek, new Uint8Array(1), new Uint8Array(0))).rejects.toThrow();
  });

  it('knowing the auth key does not let you unwrap the vault key', async () => {
    // Simulates the server: it holds AK and the wrapped VK. Try every obvious misuse.
    const salt = generateSalt();
    const { authKey, kek } = await deriveKeys('server-must-not-learn-this', salt, FAST_PARAMS);
    const { wrapped } = await createVaultKey(kek, USER);
    const akAsKek = await crypto.subtle.importKey('raw', authKey, 'AES-GCM', false, ['wrapKey', 'unwrapKey']);
    await expect(unwrapVaultKey(akAsKek, wrapped, USER)).rejects.toThrow(DecryptionError);
  });

  it('same password + salt reproduces the same keys (login works)', async () => {
    const salt = generateSalt();
    const a = await deriveKeys('pw-123456789', salt, FAST_PARAMS);
    const b = await deriveKeys('pw-123456789', salt, FAST_PARAMS);
    expect(toHex(a.authKey)).toBe(toHex(b.authKey));
    const { wrapped } = await createVaultKey(a.kek, USER);
    await expect(unwrapVaultKey(b.kek, wrapped, USER)).resolves.toBeDefined();
  });
});

describe('vault key wrapping', () => {
  async function setup() {
    const { kek } = await deriveKeys('vault-password-1', generateSalt(), FAST_PARAMS);
    const { vaultKey, wrapped } = await createVaultKey(kek, USER);
    return { kek, vaultKey, wrapped };
  }

  it('wrapped VK is 32 bytes + 16-byte tag with a 12-byte IV', async () => {
    const { wrapped } = await setup();
    expect(wrapped.ciphertext).toHaveLength(48);
    expect(wrapped.iv).toHaveLength(12);
  });

  it('the working VK is non-extractable', async () => {
    const { kek, vaultKey, wrapped } = await setup();
    expect(vaultKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('raw', vaultKey)).rejects.toThrow();
    const unwrapped = await unwrapVaultKey(kek, wrapped, USER);
    expect(unwrapped.extractable).toBe(false);
  });

  it('unwrapped VK decrypts data encrypted by the original', async () => {
    const { kek, vaultKey, wrapped } = await setup();
    const aad = utf8Encode('a');
    const sealed = await seal(vaultKey, utf8Encode('secret'), aad);
    const again = await unwrapVaultKey(kek, wrapped, USER);
    expect(utf8Decode(await open(again, sealed, aad))).toBe('secret');
  });

  it('wrong password cannot unwrap', async () => {
    const salt = generateSalt();
    const right = await deriveKeys('right-password', salt, FAST_PARAMS);
    const wrong = await deriveKeys('wrong-password', salt, FAST_PARAMS);
    const { wrapped } = await createVaultKey(right.kek, USER);
    await expect(unwrapVaultKey(wrong.kek, wrapped, USER)).rejects.toThrow(DecryptionError);
  });

  it('wrapped VK is bound to the user id (cannot be transplanted)', async () => {
    const { kek, wrapped } = await setup();
    await expect(unwrapVaultKey(kek, wrapped, 'another-user')).rejects.toThrow(DecryptionError);
  });

  it('tampered wrapped VK is rejected', async () => {
    const { kek, wrapped } = await setup();
    await expect(unwrapVaultKey(kek, { ...wrapped, ciphertext: flipBit(wrapped.ciphertext, 5) }, USER)).rejects.toThrow(
      DecryptionError,
    );
    await expect(unwrapVaultKey(kek, { ...wrapped, iv: flipBit(wrapped.iv, 0) }, USER)).rejects.toThrow(
      DecryptionError,
    );
  });

  it('each new vault key is random', async () => {
    const { kek } = await deriveKeys('pw-xxxxxxxxxx', generateSalt(), FAST_PARAMS);
    const a = await unwrapVaultKey(kek, (await createVaultKey(kek, USER)).wrapped, USER, true);
    const b = await unwrapVaultKey(kek, (await createVaultKey(kek, USER)).wrapped, USER, true);
    expect(toHex(await rawKeyBytes(a))).not.toBe(toHex(await rawKeyBytes(b)));
  });

  it('rewrap (password change) keeps the same VK under a new KEK; old KEK no longer works', async () => {
    const { kek: oldKek, vaultKey, wrapped } = await setup();
    const { kek: newKek } = await deriveKeys('brand-new-password', generateSalt(), FAST_PARAMS);
    const aad = utf8Encode('note');
    const sealed = await seal(vaultKey, utf8Encode('survives password change'), aad);

    const rewrapped = await rewrapVaultKey(oldKek, newKek, wrapped, USER);
    expect(toHex(rewrapped.iv)).not.toBe(toHex(wrapped.iv));

    const vk2 = await unwrapVaultKey(newKek, rewrapped, USER);
    expect(utf8Decode(await open(vk2, sealed, aad))).toBe('survives password change');
    await expect(unwrapVaultKey(oldKek, rewrapped, USER)).rejects.toThrow(DecryptionError);
  });
});
