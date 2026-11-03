import { deriveLoginKeys, DEFAULT_KDF_PARAMS } from '@zk-notes/crypto';
import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { Client, FAST_PARAMS, fakeRegistration, realRegistration, registeredClient, useTestDb } from './helpers.js';

const { db, app: makeApp } = useTestDb();

describe('registration', () => {
  it('creates the user, starts a session, and stores only non-secret material', async () => {
    const app = makeApp();
    const { client, reg } = await registeredClient(app);
    expect(client.cookie).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(client.csrf).toBeTruthy();

    const { rows } = await db.query('SELECT * FROM users WHERE id = $1', [reg.userId]);
    const row = rows[0];
    expect(row.auth_hash).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    // The raw auth key must not appear anywhere in the row.
    const authKeyHex = Buffer.from(reg.authKey, 'base64').toString('hex');
    expect(JSON.stringify(row)).not.toContain(reg.authKey);
    expect(JSON.stringify(rows[0], (_k, v) => (Buffer.isBuffer(v) ? v.toString('hex') : v))).not.toContain(authKeyHex);
  });

  it('sets a hardened session cookie', async () => {
    const { client } = await registeredClient(makeApp());
    const c = client.lastSetCookie!;
    expect(c).toMatch(/^__Host-zkn_sid=/);
    expect(c).toMatch(/; HttpOnly/i);
    expect(c).toMatch(/; Secure/i);
    expect(c).toMatch(/; SameSite=Strict/i);
    expect(c).toMatch(/; Path=\//i);
    expect(c).not.toMatch(/Domain=/i);
  });

  it('rejects duplicate email or user id with a generic error', async () => {
    const app = makeApp();
    const { reg } = await registeredClient(app);
    const again = await new Client(app).req('post', '/api/auth/register', { ...fakeRegistration(reg.email) });
    expect(again.status).toBe(409);
    expect(again.body).toEqual({ error: 'registration_failed' });
    const sameId = await new Client(app).req('post', '/api/auth/register', { ...fakeRegistration(), userId: reg.userId });
    expect(sameId.status).toBe(409);
  });

  it.each([
    ['weak KDF memory', { kdfParams: { ...FAST_PARAMS, m: 1024 } }],
    ['weak KDF iterations', { kdfParams: { ...FAST_PARAMS, t: 1 } }],
    ['short auth key', { authKey: randomBytes(16).toString('base64') }],
    ['bad salt', { kdfSalt: 'not-base64!' }],
    ['bad wrapped key length', { wrappedVaultKey: randomBytes(32).toString('base64') }],
    ['invalid email', { email: 'nope' }],
    ['non-uuid user id', { userId: '1' }],
    ['unexpected field (e.g. a password)', { password: 'hunter2' }],
  ])('rejects %s', async (_n, patch) => {
    const res = await new Client(makeApp()).req('post', '/api/auth/register', { ...fakeRegistration(), ...patch });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'invalid_request' });
  });
});

describe('prelogin', () => {
  it('returns the stored salt and params for a known user', async () => {
    const app = makeApp();
    const { reg } = await registeredClient(app);
    const res = await new Client(app).req('post', '/api/auth/prelogin', { email: reg.email.toUpperCase() });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ kdfSalt: reg.kdfSalt, kdfParams: reg.kdfParams });
  });

  it('returns a stable fake salt for unknown users (no enumeration)', async () => {
    const app = makeApp();
    const a = await new Client(app).req('post', '/api/auth/prelogin', { email: 'ghost@example.com' });
    const b = await new Client(app).req('post', '/api/auth/prelogin', { email: 'ghost@example.com' });
    const c = await new Client(app).req('post', '/api/auth/prelogin', { email: 'other@example.com' });
    expect(a.status).toBe(200);
    expect(a.body.kdfParams).toEqual(DEFAULT_KDF_PARAMS);
    expect(Buffer.from(a.body.kdfSalt, 'base64')).toHaveLength(16);
    expect(a.body).toEqual(b.body);
    expect(c.body.kdfSalt).not.toBe(a.body.kdfSalt);
  });
});

describe('login', () => {
  it('end-to-end with real client crypto: register → prelogin → login → unlock bundle', async () => {
    const app = makeApp();
    const password = 'correct horse battery staple';
    const { request: reg } = await realRegistration('Real@Example.com', password);
    expect((await new Client(app).req('post', '/api/auth/register', reg)).status).toBe(201);

    const c = new Client(app);
    const pre = await c.req('post', '/api/auth/prelogin', { email: 'real@example.com' });
    const { authKey } = await deriveLoginKeys(password, pre.body.kdfSalt, pre.body.kdfParams);
    const res = await c.req('post', '/api/auth/login', { email: 'real@example.com', authKey });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      userId: reg.userId,
      wrappedVaultKey: reg.wrappedVaultKey,
      vaultKeyIv: reg.vaultKeyIv,
      kdfSalt: reg.kdfSalt,
    });
    expect(res.body).not.toHaveProperty('authHash');
    expect(JSON.stringify(res.body)).not.toContain('$argon2id$');
  });

  it('wrong auth key and unknown user both give the same 401', async () => {
    const app = makeApp();
    const { reg } = await registeredClient(app);
    const wrong = await new Client(app).req('post', '/api/auth/login', {
      email: reg.email,
      authKey: randomBytes(32).toString('base64'),
    });
    const ghost = await new Client(app).req('post', '/api/auth/login', {
      email: 'ghost@example.com',
      authKey: randomBytes(32).toString('base64'),
    });
    expect(wrong.status).toBe(401);
    expect(ghost.status).toBe(401);
    expect(wrong.body).toEqual(ghost.body);
    expect(wrong.headers['set-cookie']).toBeUndefined();
  });

  it('issues a fresh session token on login (session fixation defence)', async () => {
    const app = makeApp();
    const { client, reg } = await registeredClient(app);
    const before = client.cookie;
    const res = await client.req('post', '/api/auth/login', { email: reg.email, authKey: reg.authKey });
    expect(res.status).toBe(200);
    expect(client.cookie).not.toBe(before);
    // The old token is dead.
    const old = new Client(app);
    old.cookie = before;
    expect((await old.req('get', '/api/auth/session')).status).toBe(401);
  });
});

describe('session lifecycle', () => {
  it('GET /session returns the vault bundle and a CSRF token', async () => {
    const app = makeApp();
    const { client, reg } = await registeredClient(app);
    const csrf = client.csrf;
    const res = await client.req('get', '/api/auth/session');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ userId: reg.userId, email: reg.email, csrfToken: csrf });
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('rejects missing, malformed and unknown cookies', async () => {
    const app = makeApp();
    const c = new Client(app);
    expect((await c.req('get', '/api/auth/session')).status).toBe(401);
    c.cookie = 'garbage';
    expect((await c.req('get', '/api/auth/session')).status).toBe(401);
    c.cookie = randomBytes(32).toString('base64url');
    expect((await c.req('get', '/api/auth/session')).status).toBe(401);
  });

  it('stores only a hash of the session token', async () => {
    const { client } = await registeredClient(makeApp());
    const { rows } = await db.query('SELECT token_hash FROM sessions');
    expect(rows).toHaveLength(1);
    expect(rows[0].token_hash.toString('base64url')).not.toBe(client.cookie);
  });

  it('expires idle sessions', async () => {
    const app = makeApp();
    const { client } = await registeredClient(app);
    await db.query("UPDATE sessions SET last_seen_at = now() - interval '31 minutes'");
    expect((await client.req('get', '/api/auth/session')).status).toBe(401);
  });

  it('expires sessions at the absolute deadline even if active', async () => {
    const app = makeApp();
    const { client } = await registeredClient(app);
    await db.query("UPDATE sessions SET expires_at = now() - interval '1 second'");
    expect((await client.req('get', '/api/auth/session')).status).toBe(401);
  });

  it('logout revokes the session server-side and clears the cookie', async () => {
    const app = makeApp();
    const { client } = await registeredClient(app);
    const token = client.cookie;
    const res = await client.req('post', '/api/auth/logout');
    expect(res.status).toBe(204);
    expect(client.lastSetCookie).toMatch(/__Host-zkn_sid=;/);
    const replay = new Client(app);
    replay.cookie = token;
    expect((await replay.req('get', '/api/auth/session')).status).toBe(401);
  });
});

describe('password change', () => {
  function changeBody(currentAuthKey: string) {
    return {
      currentAuthKey,
      newKdfSalt: randomBytes(16).toString('base64'),
      newKdfParams: FAST_PARAMS,
      newAuthKey: randomBytes(32).toString('base64'),
      newWrappedVaultKey: randomBytes(48).toString('base64'),
      newVaultKeyIv: randomBytes(12).toString('base64'),
    };
  }

  it('requires the current auth key', async () => {
    const { client } = await registeredClient(makeApp());
    const res = await client.req('post', '/api/auth/change-password', changeBody(randomBytes(32).toString('base64')));
    expect(res.status).toBe(401);
  });

  it('updates credentials atomically and revokes all other sessions', async () => {
    const app = makeApp();
    const { client, reg } = await registeredClient(app);
    const other = new Client(app);
    await other.req('post', '/api/auth/login', { email: reg.email, authKey: reg.authKey });
    expect((await other.req('get', '/api/auth/session')).status).toBe(200);

    const body = changeBody(reg.authKey);
    const res = await client.req('post', '/api/auth/change-password', body);
    expect(res.status).toBe(200);

    expect((await other.req('get', '/api/auth/session')).status).toBe(401);
    const me = await client.req('get', '/api/auth/session');
    expect(me.status).toBe(200);
    expect(me.body).toMatchObject({
      kdfSalt: body.newKdfSalt,
      wrappedVaultKey: body.newWrappedVaultKey,
      vaultKeyIv: body.newVaultKeyIv,
    });

    const oldLogin = await new Client(app).req('post', '/api/auth/login', { email: reg.email, authKey: reg.authKey });
    expect(oldLogin.status).toBe(401);
    const newLogin = await new Client(app).req('post', '/api/auth/login', { email: reg.email, authKey: body.newAuthKey });
    expect(newLogin.status).toBe(200);
  });
});
