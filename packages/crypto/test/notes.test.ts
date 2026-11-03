import { describe, expect, it } from 'vitest';
import {
  CryptoInputError,
  DecryptionError,
  MAX_NOTE_PLAINTEXT,
  PAD_BLOCK,
  createVaultKey,
  decryptNote,
  deriveKeys,
  encryptNote,
  fromBase64,
  generateSalt,
  importAesKey,
  padPlaintext,
  randomBytes,
  seal,
  toBase64,
  unpadPlaintext,
  utf8Encode,
  type NoteContext,
} from '../src/index.js';
import { FAST_PARAMS, flipBit } from './helpers.js';

const ctx: NoteContext = { userId: 'user-a', noteId: 'note-1', version: 1 };

async function vk() {
  return importAesKey(randomBytes(32));
}

describe('note encryption', () => {
  it('round-trips title and body, including Unicode and empty strings', async () => {
    const key = await vk();
    for (const payload of [
      { title: '', body: '' },
      { title: 'Shopping', body: 'milk\neggs' },
      { title: '日記 🔐', body: 'Ωμέγα'.repeat(500) },
    ]) {
      const enc = await encryptNote(key, ctx, payload);
      expect(await decryptNote(key, ctx, enc)).toEqual(payload);
    }
  });

  it('works with a real vault key from the hierarchy', async () => {
    const { kek } = await deriveKeys('pw-notes-test', generateSalt(), FAST_PARAMS);
    const { vaultKey } = await createVaultKey(kek, ctx.userId);
    const enc = await encryptNote(vaultKey, ctx, { title: 't', body: 'b' });
    expect(await decryptNote(vaultKey, ctx, enc)).toEqual({ title: 't', body: 'b' });
  });

  it('ciphertext reveals nothing obvious and is padded to blocks', async () => {
    const key = await vk();
    const enc = await encryptNote(key, ctx, { title: 'SECRET-TITLE', body: 'SECRET-BODY' });
    const ct = fromBase64(enc.ciphertext);
    expect(new TextDecoder().decode(ct)).not.toContain('SECRET');
    expect((ct.length - 16) % PAD_BLOCK).toBe(0);
    // Two notes of slightly different length are indistinguishable by size.
    const a = await encryptNote(key, ctx, { title: 'a', body: 'x' });
    const b = await encryptNote(key, ctx, { title: 'a', body: 'x'.repeat(100) });
    expect(a.ciphertext.length).toBe(b.ciphertext.length);
  });

  it('same note encrypted twice yields different ciphertexts', async () => {
    const key = await vk();
    const p = { title: 'same', body: 'same' };
    const a = await encryptNote(key, ctx, p);
    const b = await encryptNote(key, ctx, p);
    expect(a.iv).not.toBe(b.iv);
    expect(a.ciphertext).not.toBe(b.ciphertext);
  });

  describe('context binding (malicious server)', () => {
    it.each([
      ['swapped to another note id', { ...ctx, noteId: 'note-2' }],
      ['swapped to another user', { ...ctx, userId: 'user-b' }],
      ['relabelled as a newer version (rollback)', { ...ctx, version: 2 }],
    ])('rejects ciphertext %s', async (_name, other) => {
      const key = await vk();
      const enc = await encryptNote(key, ctx, { title: 't', body: 'b' });
      await expect(decryptNote(key, other, enc)).rejects.toThrow(DecryptionError);
    });
  });

  it('detects tampering', async () => {
    const key = await vk();
    const enc = await encryptNote(key, ctx, { title: 't', body: 'b' });
    const ct = fromBase64(enc.ciphertext);
    await expect(decryptNote(key, ctx, { ...enc, ciphertext: toBase64(flipBit(ct, 3)) })).rejects.toThrow(
      DecryptionError,
    );
    await expect(decryptNote(key, ctx, { ...enc, iv: toBase64(flipBit(fromBase64(enc.iv))) })).rejects.toThrow(
      DecryptionError,
    );
  });

  it('wrong key fails', async () => {
    const enc = await encryptNote(await vk(), ctx, { title: 't', body: 'b' });
    await expect(decryptNote(await vk(), ctx, enc)).rejects.toThrow(DecryptionError);
  });

  it('malformed wire data is a DecryptionError, not a crash', async () => {
    const key = await vk();
    await expect(decryptNote(key, ctx, { iv: 'not base64!', ciphertext: 'AAAA' })).rejects.toThrow(DecryptionError);
    await expect(decryptNote(key, ctx, { iv: toBase64(randomBytes(12)), ciphertext: '' })).rejects.toThrow(
      DecryptionError,
    );
  });

  it('authentic but semantically invalid plaintext is rejected', async () => {
    // e.g. a buggy/old client wrote something that is not a valid payload.
    const key = await vk();
    const { noteAad } = await import('../src/notes.js');
    for (const junk of [utf8Encode('not json'), utf8Encode('{"title":1,"body":"x"}'), utf8Encode('null')]) {
      const sealed = await seal(key, padPlaintext(junk), noteAad(ctx));
      await expect(
        decryptNote(key, ctx, { iv: toBase64(sealed.iv), ciphertext: toBase64(sealed.ciphertext) }),
      ).rejects.toThrow(DecryptionError);
    }
  });

  it('rejects oversized notes and invalid context', async () => {
    const key = await vk();
    await expect(encryptNote(key, ctx, { title: '', body: 'x'.repeat(MAX_NOTE_PLAINTEXT) })).rejects.toThrow(
      CryptoInputError,
    );
    await expect(encryptNote(key, { ...ctx, version: 0 }, { title: '', body: '' })).rejects.toThrow(CryptoInputError);
    await expect(encryptNote(key, { ...ctx, noteId: '' }, { title: '', body: '' })).rejects.toThrow(CryptoInputError);
  });
});

describe('padding', () => {
  it('round-trips at block boundaries', () => {
    for (const n of [0, 1, PAD_BLOCK - 5, PAD_BLOCK - 4, PAD_BLOCK - 3, PAD_BLOCK * 3]) {
      const data = randomBytes(n);
      const padded = padPlaintext(data);
      expect(padded.length % PAD_BLOCK).toBe(0);
      expect(unpadPlaintext(padded)).toEqual(data);
    }
  });

  it('rejects bad lengths and non-zero padding', () => {
    const padded = padPlaintext(utf8Encode('hi'));
    const badPad = padded.slice();
    badPad[padded.length - 1] = 1;
    expect(() => unpadPlaintext(badPad)).toThrow(DecryptionError);
    const badLen = padded.slice();
    badLen[0] = 0xff;
    expect(() => unpadPlaintext(badLen)).toThrow(DecryptionError);
    expect(() => unpadPlaintext(padded.slice(0, 100))).toThrow(DecryptionError);
  });
});
