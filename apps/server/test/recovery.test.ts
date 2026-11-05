import {
  decryptNote,
  deriveLoginKeys,
  deriveRecoveryLogin,
  encryptNote,
  prepareRecoveryReset,
  prepareRecoverySetup,
} from '@zk-notes/crypto';
import { randomBytes, randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { Client, FAST_PARAMS, fakeRegistration, realRegistration, registeredClient, useTestDb } from './helpers.js';

const { db, app: makeApp } = useTestDb();
const b64 = (n: number) => randomBytes(n).toString('base64');

function fakeSetup(currentAuthKey: string) {
  return {
    currentAuthKey,
    recoveryAuthKey: b64(32),
    recoveryWrappedVaultKey: b64(48),
    recoveryVaultKeyIv: b64(12),
  };
}

function fakeComplete(email: string, recoveryAuthKey: string) {
  return {
    email,
    recoveryAuthKey,
    newKdfSalt: b64(16),
    newKdfParams: FAST_PARAMS,
    newAuthKey: b64(32),
    newWrappedVaultKey: b64(48),
    newVaultKeyIv: b64(12),
  };
}

describe('recovery key management', () => {
  it('session bundle reports whether a recovery key exists', async () => {
    const app = makeApp();
    const { client, reg } = await registeredClient(app);
    expect((await client.req('get', '/api/auth/session')).body.hasRecoveryKey).toBe(false);
    expect((await client.req('post', '/api/auth/recovery-key', fakeSetup(reg.authKey))).status).toBe(200);
    expect((await client.req('get', '/api/auth/session')).body.hasRecoveryKey).toBe(true);
  });

  it('setting a recovery key requires the current password, a session and CSRF', async () => {
    const app = makeApp();
    const { client, reg } = await registeredClient(app);
    expect((await client.req('post', '/api/auth/recovery-key', fakeSetup(b64(32)))).status).toBe(401);

    const csrf = client.csrf;
    client.csrf = undefined;
    expect((await client.req('post', '/api/auth/recovery-key', fakeSetup(reg.authKey))).status).toBe(403);
    client.csrf = csrf;

    const anon = new Client(app);
    expect((await anon.req('post', '/api/auth/recovery-key', fakeSetup(reg.authKey))).status).toBe(401);
    const { rows } = await db.query('SELECT recovery_auth_hash FROM users WHERE id = $1', [reg.userId]);
    expect(rows[0].recovery_auth_hash).toBeNull();
  });

  it('stores only an Argon2id hash of the recovery auth key', async () => {
    const app = makeApp();
    const { client, reg } = await registeredClient(app);
    const setup = fakeSetup(reg.authKey);
    await client.req('post', '/api/auth/recovery-key', setup);
    const { rows } = await db.query('SELECT recovery_auth_hash FROM users WHERE id = $1', [reg.userId]);
    expect(rows[0].recovery_auth_hash).toMatch(/^\$argon2id\$/);
    expect(rows[0].recovery_auth_hash).not.toContain(setup.recoveryAuthKey);
  });

  it('replacing the recovery key invalidates the old one; removing it disables recovery', async () => {
    const app = makeApp();
    const { client, reg } = await registeredClient(app);
    const first = fakeSetup(reg.authKey);
    await client.req('post', '/api/auth/recovery-key', first);
    const second = fakeSetup(reg.authKey);
    await client.req('post', '/api/auth/recovery-key', second);

    const verify = (k: string) =>
      new Client(app).req('post', '/api/auth/recovery/verify', { email: reg.email, recoveryAuthKey: k });
    expect((await verify(first.recoveryAuthKey)).status).toBe(401);
    expect((await verify(second.recoveryAuthKey)).status).toBe(200);

    expect((await client.req('post', '/api/auth/recovery-key/remove', { currentAuthKey: b64(32) })).status).toBe(401);
    expect((await client.req('post', '/api/auth/recovery-key/remove', { currentAuthKey: reg.authKey })).status).toBe(200);
    expect((await verify(second.recoveryAuthKey)).status).toBe(401);
    expect((await client.req('get', '/api/auth/session')).body.hasRecoveryKey).toBe(false);
  });

  it('rejects malformed setup bodies', async () => {
    const { client, reg } = await registeredClient(makeApp());
    const bad = { ...fakeSetup(reg.authKey), recoveryWrappedVaultKey: b64(32) };
    expect((await client.req('post', '/api/auth/recovery-key', bad)).status).toBe(400);
    const extra = { ...fakeSetup(reg.authKey), recoveryKey: 'AAAAA-BBBBB' };
    expect((await client.req('post', '/api/auth/recovery-key', extra)).status).toBe(400);
  });
});

describe('account recovery', () => {
  it('verify returns the recovery wrap only for the right key; failures are indistinguishable', async () => {
    const app = makeApp();
    const { client, reg } = await registeredClient(app);
    const setup = fakeSetup(reg.authKey);
    await client.req('post', '/api/auth/recovery-key', setup);
    const { reg: noRecovery } = await registeredClient(app, fakeRegistration());

    const ok = await new Client(app).req('post', '/api/auth/recovery/verify', {
      email: reg.email,
      recoveryAuthKey: setup.recoveryAuthKey,
    });
    expect(ok.status).toBe(200);
    expect(ok.body).toEqual({
      userId: reg.userId,
      recoveryWrappedVaultKey: setup.recoveryWrappedVaultKey,
      recoveryVaultKeyIv: setup.recoveryVaultKeyIv,
    });
    expect(ok.headers['set-cookie']).toBeUndefined();

    const wrongKey = await new Client(app).req('post', '/api/auth/recovery/verify', { email: reg.email, recoveryAuthKey: b64(32) });
    const noKeySet = await new Client(app).req('post', '/api/auth/recovery/verify', { email: noRecovery.email, recoveryAuthKey: b64(32) });
    const noUser = await new Client(app).req('post', '/api/auth/recovery/verify', { email: 'ghost@example.com', recoveryAuthKey: b64(32) });
    for (const r of [wrongKey, noKeySet, noUser]) {
      expect(r.status).toBe(401);
      expect(r.body).toEqual({ error: 'invalid_credentials' });
    }
  });

  it('complete sets the new password, revokes every session, and signs in', async () => {
    const app = makeApp();
    const { client, reg } = await registeredClient(app);
    const setup = fakeSetup(reg.authKey);
    await client.req('post', '/api/auth/recovery-key', setup);

    const rescuer = new Client(app);
    const body = fakeComplete(reg.email, setup.recoveryAuthKey);
    const res = await rescuer.req('post', '/api/auth/recovery/complete', body);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      userId: reg.userId,
      kdfSalt: body.newKdfSalt,
      wrappedVaultKey: body.newWrappedVaultKey,
      vaultKeyIv: body.newVaultKeyIv,
      hasRecoveryKey: true,
    });
    expect(rescuer.cookie).toBeTruthy();

    // The old session is gone, the old password is dead, the new one works.
    expect((await client.req('get', '/api/auth/session')).status).toBe(401);
    expect((await new Client(app).req('post', '/api/auth/login', { email: reg.email, authKey: reg.authKey })).status).toBe(401);
    expect((await new Client(app).req('post', '/api/auth/login', { email: reg.email, authKey: body.newAuthKey })).status).toBe(200);
    // The recovery key itself stays valid.
    expect(
      (await new Client(app).req('post', '/api/auth/recovery/verify', { email: reg.email, recoveryAuthKey: setup.recoveryAuthKey })).status,
    ).toBe(200);
  });

  it('complete with a wrong recovery key changes nothing', async () => {
    const app = makeApp();
    const { client, reg } = await registeredClient(app);
    await client.req('post', '/api/auth/recovery-key', fakeSetup(reg.authKey));
    const res = await new Client(app).req('post', '/api/auth/recovery/complete', fakeComplete(reg.email, b64(32)));
    expect(res.status).toBe(401);
    expect((await client.req('get', '/api/auth/session')).status).toBe(200);
    expect((await new Client(app).req('post', '/api/auth/login', { email: reg.email, authKey: reg.authKey })).status).toBe(200);
  });

  it('rate-limits failed recovery attempts per account, without blocking normal login', async () => {
    const app = makeApp({ recoveryAccount: { windowMs: 60_000, limit: 3 } });
    const { client, reg } = await registeredClient(app);
    const setup = fakeSetup(reg.authKey);
    await client.req('post', '/api/auth/recovery-key', setup);
    const attempt = (k: string) => new Client(app).req('post', '/api/auth/recovery/verify', { email: reg.email, recoveryAuthKey: k });
    for (let i = 0; i < 3; i++) expect((await attempt(b64(32))).status).toBe(401);
    expect((await attempt(b64(32))).status).toBe(429);
    expect((await attempt(setup.recoveryAuthKey)).status).toBe(429);
    expect((await new Client(app).req('post', '/api/auth/login', { email: reg.email, authKey: reg.authKey })).status).toBe(200);
  });

  it('end-to-end with real crypto: forgot password → recovery key → notes still decrypt', async () => {
    const app = makeApp();
    const password = 'the password I will forget';
    const { request: reg, vaultKey } = await realRegistration('forgetful@example.com', password);
    const c = new Client(app);
    await c.req('post', '/api/auth/register', reg);

    const noteId = randomUUID();
    const enc = await encryptNote(vaultKey, { userId: reg.userId, noteId, version: 1 }, { title: 'keys', body: 'under the mat' });
    await c.req('post', '/api/notes', { id: noteId, ...enc });

    const { request: setup, recoveryKey } = await prepareRecoverySetup({
      userId: reg.userId,
      password,
      kdfSalt: reg.kdfSalt,
      kdfParams: reg.kdfParams,
      current: reg,
    });
    expect((await c.req('post', '/api/auth/recovery-key', setup)).status).toBe(200);

    // --- later, on a new device, password forgotten ---
    const d = new Client(app);
    const rec = await deriveRecoveryLogin(recoveryKey.toLowerCase().replace(/-/g, ' '));
    const verified = await d.req('post', '/api/auth/recovery/verify', { email: reg.email, recoveryAuthKey: rec.authKey });
    expect(verified.status).toBe(200);
    const { request: reset, vaultKey: recoveredVk } = await prepareRecoveryReset({
      userId: verified.body.userId,
      recoveryAuthKey: rec.authKey,
      recoveryKek: rec.kek,
      recoveryWrap: verified.body,
      newPassword: 'a new memorable passphrase',
      newKdfParams: FAST_PARAMS,
    });
    const done = await d.req('post', '/api/auth/recovery/complete', { email: reg.email, ...reset });
    expect(done.status).toBe(200);

    const note = (await d.req('get', '/api/notes')).body.notes[0];
    expect(await decryptNote(recoveredVk, { userId: reg.userId, noteId, version: note.version }, note)).toEqual({
      title: 'keys',
      body: 'under the mat',
    });

    // And a normal login with the new password works from scratch.
    const pre = await new Client(app).req('post', '/api/auth/prelogin', { email: reg.email });
    const login = await deriveLoginKeys('a new memorable passphrase', pre.body.kdfSalt, pre.body.kdfParams);
    expect((await new Client(app).req('post', '/api/auth/login', { email: reg.email, authKey: login.authKey })).status).toBe(200);
  });
});
