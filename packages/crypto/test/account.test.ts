import { describe, expect, it } from 'vitest';
import {
  CryptoInputError,
  DecryptionError,
  decryptNote,
  deriveLoginKeys,
  encryptNote,
  fromBase64,
  prepareRegistration,
  preparePasswordChange,
  unlockVault,
} from '../src/index.js';
import { FAST_PARAMS } from './helpers.js';

const PASSWORD = 'Tr0ub4dor&3-but-longer';

describe('end-to-end account flows', () => {
  it('registration output contains no password or key material in the clear', async () => {
    const { request } = await prepareRegistration('  Alice@Example.COM ', PASSWORD, FAST_PARAMS);
    expect(request.email).toBe('alice@example.com');
    expect(request.userId).toMatch(/^[0-9a-f-]{36}$/);
    expect(fromBase64(request.kdfSalt)).toHaveLength(16);
    expect(fromBase64(request.authKey)).toHaveLength(32);
    expect(fromBase64(request.wrappedVaultKey)).toHaveLength(48);
    expect(fromBase64(request.vaultKeyIv)).toHaveLength(12);
    expect(JSON.stringify(request)).not.toContain(PASSWORD);
  });

  it('register → login → unlock → decrypt', async () => {
    const { request, vaultKey } = await prepareRegistration('a@b.c', PASSWORD, FAST_PARAMS);
    const note = await encryptNote(vaultKey, { userId: request.userId, noteId: 'n1', version: 1 }, {
      title: 'hello',
      body: 'world',
    });

    // Later, on another device: server returns salt+params at prelogin.
    const login = await deriveLoginKeys(PASSWORD, request.kdfSalt, request.kdfParams);
    expect(login.authKey).toBe(request.authKey); // server would verify this
    const vk = await unlockVault(login.kek, request.userId, request);
    expect(await decryptNote(vk, { userId: request.userId, noteId: 'n1', version: 1 }, note)).toEqual({
      title: 'hello',
      body: 'world',
    });
  });

  it('wrong password gives a different auth key and cannot unlock', async () => {
    const { request } = await prepareRegistration('a@b.c', PASSWORD, FAST_PARAMS);
    const login = await deriveLoginKeys(PASSWORD + '!', request.kdfSalt, request.kdfParams);
    expect(login.authKey).not.toBe(request.authKey);
    await expect(unlockVault(login.kek, request.userId, request)).rejects.toThrow(DecryptionError);
  });

  it('login refuses downgraded params from a malicious server', async () => {
    const { request } = await prepareRegistration('a@b.c', PASSWORD, FAST_PARAMS);
    await expect(deriveLoginKeys(PASSWORD, request.kdfSalt, { ...FAST_PARAMS, m: 64, t: 1 })).rejects.toThrow(
      CryptoInputError,
    );
    await expect(deriveLoginKeys(PASSWORD, 'AAAA', FAST_PARAMS)).rejects.toThrow(CryptoInputError);
  });

  it('password change: new password unlocks the same notes, old one does not', async () => {
    const { request, vaultKey } = await prepareRegistration('a@b.c', PASSWORD, FAST_PARAMS);
    const ctx = { userId: request.userId, noteId: 'n1', version: 3 };
    const note = await encryptNote(vaultKey, ctx, { title: 'keep', body: 'me' });

    const change = await preparePasswordChange({
      userId: request.userId,
      currentPassword: PASSWORD,
      currentKdfSalt: request.kdfSalt,
      currentKdfParams: request.kdfParams,
      current: request,
      newPassword: 'a completely new passphrase',
      newKdfParams: FAST_PARAMS,
    });
    expect(change.currentAuthKey).toBe(request.authKey);
    expect(change.newAuthKey).not.toBe(request.authKey);
    expect(change.newKdfSalt).not.toBe(request.kdfSalt);

    const newLogin = await deriveLoginKeys('a completely new passphrase', change.newKdfSalt, change.newKdfParams);
    expect(newLogin.authKey).toBe(change.newAuthKey);
    const vk = await unlockVault(newLogin.kek, request.userId, {
      wrappedVaultKey: change.newWrappedVaultKey,
      vaultKeyIv: change.newVaultKeyIv,
    });
    expect(await decryptNote(vk, ctx, note)).toEqual({ title: 'keep', body: 'me' });

    const oldLogin = await deriveLoginKeys(PASSWORD, request.kdfSalt, request.kdfParams);
    await expect(
      unlockVault(oldLogin.kek, request.userId, {
        wrappedVaultKey: change.newWrappedVaultKey,
        vaultKeyIv: change.newVaultKeyIv,
      }),
    ).rejects.toThrow(DecryptionError);
  });

  it('password change with the wrong current password fails before producing a request', async () => {
    const { request } = await prepareRegistration('a@b.c', PASSWORD, FAST_PARAMS);
    await expect(
      preparePasswordChange({
        userId: request.userId,
        currentPassword: 'nope-nope-nope',
        currentKdfSalt: request.kdfSalt,
        currentKdfParams: request.kdfParams,
        current: request,
        newPassword: 'whatever-whatever',
        newKdfParams: FAST_PARAMS,
      }),
    ).rejects.toThrow(DecryptionError);
  });
});
