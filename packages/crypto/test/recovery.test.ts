import { describe, expect, it } from 'vitest';
import {
  CryptoInputError,
  DecryptionError,
  LABEL_RECOVERY_AUTH,
  LABEL_RECOVERY_KEK,
  LABEL_VAULT_KEY_RECOVERY_WRAP,
  base32Decode,
  base32Encode,
  decryptNote,
  deriveLoginKeys,
  deriveRecoveryKeys,
  deriveRecoveryLogin,
  encryptNote,
  formatRecoveryKey,
  fromBase64,
  hkdfSha256,
  parseRecoveryKey,
  prepareRecoveryReset,
  prepareRecoverySetup,
  prepareRegistration,
  preparePasswordChange,
  randomBytes,
  splitMasterKey,
  toHex,
  unlockVault,
  unwrapVaultKey,
  utf8Encode,
} from '../src/index.js';
import { FAST_PARAMS } from './helpers.js';

const PASSWORD = 'original master password';
const KEY_FORMAT = /^([0-9A-HJKMNP-TV-Z]{5}-){10}[0-9A-HJKMNP-TV-Z]{5}$/;

describe('recovery key format', () => {
  it('base32 round-trips arbitrary lengths', () => {
    for (const n of [0, 1, 5, 16, 32, 34]) {
      const b = randomBytes(n);
      expect(base32Decode(base32Encode(b), n)).toEqual(b);
    }
  });

  it('base32 rejects non-canonical padding bits and invalid characters', () => {
    const enc = base32Encode(new Uint8Array([0xff]));
    expect(enc).toBe('ZW');
    expect(() => base32Decode('ZZ', 1)).toThrow(CryptoInputError); // trailing bits set
    expect(() => base32Decode('ZU', 1)).toThrow(CryptoInputError); // U not in alphabet
  });

  it('formats as 11 groups of 5 unambiguous characters and parses back', async () => {
    const raw = randomBytes(32);
    const s = await formatRecoveryKey(raw);
    expect(s).toMatch(KEY_FORMAT);
    expect(await parseRecoveryKey(s)).toEqual(raw);
  });

  it('parsing tolerates case, spacing, missing dashes and O/0, I/L/1 confusion', async () => {
    // Use a key containing a 0 and a 1 so the substitutions are exercised.
    let raw: Uint8Array<ArrayBuffer>;
    let s: string;
    do {
      raw = randomBytes(32);
      s = await formatRecoveryKey(raw);
    } while (!s.includes('0') || !s.includes('1'));
    const messy = `  ${s.toLowerCase().replace(/-/g, ' ').replace(/0/g, 'o').replace(/1/g, 'l')}\n`;
    expect(await parseRecoveryKey(messy)).toEqual(raw);
    expect(await parseRecoveryKey(s.replace(/-/g, ''))).toEqual(raw);
  });

  it('checksum catches a single-character typo', async () => {
    const s = await formatRecoveryKey(randomBytes(32));
    const i = 7;
    const typo = s.slice(0, i) + (s[i] === 'A' ? 'B' : 'A') + s.slice(i + 1);
    await expect(parseRecoveryKey(typo)).rejects.toThrow(/checksum/);
  });

  it('rejects wrong length and junk', async () => {
    const s = await formatRecoveryKey(randomBytes(32));
    await expect(parseRecoveryKey(s.slice(0, -1))).rejects.toThrow(CryptoInputError);
    await expect(parseRecoveryKey(s + 'A')).rejects.toThrow(CryptoInputError);
    await expect(parseRecoveryKey('')).rejects.toThrow(CryptoInputError);
    await expect(parseRecoveryKey('not a key at all!!')).rejects.toThrow(CryptoInputError);
  });
});

describe('recovery key derivation', () => {
  it('auth key and KEK are HKDF outputs with recovery-specific labels', async () => {
    const raw = randomBytes(32);
    const { authKey, kek } = await deriveRecoveryKeys(raw);
    expect(toHex(authKey)).toBe(toHex(await hkdfSha256(raw, utf8Encode(LABEL_RECOVERY_AUTH), 32)));
    expect(toHex(authKey)).not.toBe(toHex(await hkdfSha256(raw, utf8Encode(LABEL_RECOVERY_KEK), 32)));
    expect(kek.extractable).toBe(false);
    expect([...kek.usages].sort()).toEqual(['unwrapKey', 'wrapKey']);
  });

  it('is domain-separated from password-derived keys (same input bytes → different keys)', async () => {
    const ikm = randomBytes(32);
    const rec = await deriveRecoveryKeys(ikm.slice());
    const pw = await splitMasterKey(ikm.slice());
    expect(toHex(rec.authKey)).not.toBe(toHex(pw.authKey));
  });
});

describe('recovery flows', () => {
  async function account() {
    const { request: reg, vaultKey } = await prepareRegistration('r@example.com', PASSWORD, FAST_PARAMS);
    const ctx = { userId: reg.userId, noteId: 'n1', version: 1 };
    const note = await encryptNote(vaultKey, ctx, { title: 'diary', body: 'do not lose me' });
    const { request: setup, recoveryKey } = await prepareRecoverySetup({
      userId: reg.userId,
      password: PASSWORD,
      kdfSalt: reg.kdfSalt,
      kdfParams: reg.kdfParams,
      current: reg,
    });
    return { reg, ctx, note, setup, recoveryKey };
  }

  it('setup output is well-formed, proves the password, and contains no secrets in clear', async () => {
    const { reg, setup, recoveryKey } = await account();
    expect(recoveryKey).toMatch(KEY_FORMAT);
    expect(setup.currentAuthKey).toBe(reg.authKey);
    expect(fromBase64(setup.recoveryAuthKey)).toHaveLength(32);
    expect(fromBase64(setup.recoveryWrappedVaultKey)).toHaveLength(48);
    expect(fromBase64(setup.recoveryVaultKeyIv)).toHaveLength(12);
    const json = JSON.stringify(setup);
    expect(json).not.toContain(recoveryKey.replace(/-/g, ''));
    expect(json).not.toContain(PASSWORD);
  });

  it('setup fails with the wrong current password', async () => {
    const { request: reg } = await prepareRegistration('r@example.com', PASSWORD, FAST_PARAMS);
    await expect(
      prepareRecoverySetup({ userId: reg.userId, password: 'wrong', kdfSalt: reg.kdfSalt, kdfParams: reg.kdfParams, current: reg }),
    ).rejects.toThrow(DecryptionError);
  });

  it('forgot password: recovery key → new password → same notes decrypt', async () => {
    const { reg, ctx, note, setup, recoveryKey } = await account();

    const rec = await deriveRecoveryLogin(recoveryKey);
    expect(rec.authKey).toBe(setup.recoveryAuthKey); // what the server verifies
    const { request: reset, vaultKey } = await prepareRecoveryReset({
      userId: reg.userId,
      recoveryAuthKey: rec.authKey,
      recoveryKek: rec.kek,
      recoveryWrap: setup,
      newPassword: 'brand new password',
      newKdfParams: FAST_PARAMS,
    });
    expect(vaultKey.extractable).toBe(false);
    expect(await decryptNote(vaultKey, ctx, note)).toEqual({ title: 'diary', body: 'do not lose me' });

    // A later normal login with the new password works...
    const login = await deriveLoginKeys('brand new password', reset.newKdfSalt, reset.newKdfParams);
    expect(login.authKey).toBe(reset.newAuthKey);
    const vk2 = await unlockVault(login.kek, reg.userId, {
      wrappedVaultKey: reset.newWrappedVaultKey,
      vaultKeyIv: reset.newVaultKeyIv,
    });
    expect(await decryptNote(vk2, ctx, note)).toEqual({ title: 'diary', body: 'do not lose me' });
    // ...and the old password cannot unwrap the new wrap.
    const old = await deriveLoginKeys(PASSWORD, reg.kdfSalt, reg.kdfParams);
    await expect(
      unlockVault(old.kek, reg.userId, { wrappedVaultKey: reset.newWrappedVaultKey, vaultKeyIv: reset.newVaultKeyIv }),
    ).rejects.toThrow(DecryptionError);
  });

  it('a different (valid) recovery key cannot unwrap', async () => {
    const { reg, setup } = await account();
    const other = await deriveRecoveryLogin(await formatRecoveryKey(randomBytes(32)));
    await expect(
      prepareRecoveryReset({
        userId: reg.userId,
        recoveryAuthKey: other.authKey,
        recoveryKek: other.kek,
        recoveryWrap: setup,
        newPassword: 'whatever whatever',
        newKdfParams: FAST_PARAMS,
      }),
    ).rejects.toThrow(DecryptionError);
  });

  it('recovery wrap and password wrap are not interchangeable (distinct AAD labels)', async () => {
    const { reg, setup, recoveryKey } = await account();
    const rec = await deriveRecoveryLogin(recoveryKey);
    const wrap = { iv: fromBase64(setup.recoveryVaultKeyIv), ciphertext: fromBase64(setup.recoveryWrappedVaultKey) };
    // Right key, but treated as a password wrap → AAD mismatch.
    await expect(unwrapVaultKey(rec.kek, wrap, reg.userId)).rejects.toThrow(DecryptionError);
    await expect(unwrapVaultKey(rec.kek, wrap, reg.userId, false, LABEL_VAULT_KEY_RECOVERY_WRAP)).resolves.toBeDefined();
    // Bound to the user id as well.
    await expect(unwrapVaultKey(rec.kek, wrap, 'someone-else', false, LABEL_VAULT_KEY_RECOVERY_WRAP)).rejects.toThrow(
      DecryptionError,
    );
  });

  it('the recovery key keeps working after a normal password change (VK is unchanged)', async () => {
    const { reg, ctx, note, setup, recoveryKey } = await account();
    await preparePasswordChange({
      userId: reg.userId,
      currentPassword: PASSWORD,
      currentKdfSalt: reg.kdfSalt,
      currentKdfParams: reg.kdfParams,
      current: reg,
      newPassword: 'changed password!',
      newKdfParams: FAST_PARAMS,
    });
    const rec = await deriveRecoveryLogin(recoveryKey);
    const { vaultKey } = await prepareRecoveryReset({
      userId: reg.userId,
      recoveryAuthKey: rec.authKey,
      recoveryKek: rec.kek,
      recoveryWrap: setup,
      newPassword: 'third password!!',
      newKdfParams: FAST_PARAMS,
    });
    expect((await decryptNote(vaultKey, ctx, note)).title).toBe('diary');
  });

  it('each setup produces a fresh, unrelated recovery key', async () => {
    const { reg } = await account();
    const args = { userId: reg.userId, password: PASSWORD, kdfSalt: reg.kdfSalt, kdfParams: reg.kdfParams, current: reg };
    const a = await prepareRecoverySetup(args);
    const b = await prepareRecoverySetup(args);
    expect(a.recoveryKey).not.toBe(b.recoveryKey);
    expect(a.request.recoveryAuthKey).not.toBe(b.request.recoveryAuthKey);
  });

  it('reset refuses weak new KDF params', async () => {
    const { reg, setup, recoveryKey } = await account();
    const rec = await deriveRecoveryLogin(recoveryKey);
    await expect(
      prepareRecoveryReset({
        userId: reg.userId,
        recoveryAuthKey: rec.authKey,
        recoveryKek: rec.kek,
        recoveryWrap: setup,
        newPassword: 'x'.repeat(20),
        newKdfParams: { ...FAST_PARAMS, m: 1024 },
      }),
    ).rejects.toThrow(CryptoInputError);
  });
});
