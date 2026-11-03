import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { Client, registeredClient, useTestDb } from './helpers.js';

const { db, app: makeApp } = useTestDb();
const W = 60_000;

describe('rate limiting', () => {
  it('locks an account after repeated failed logins, independent of IP; successes do not count', async () => {
    const app = makeApp({ loginAccount: { windowMs: W, limit: 3 } });
    const { reg } = await registeredClient(app);
    const bad = () =>
      new Client(app).req('post', '/api/auth/login', { email: reg.email, authKey: randomBytes(32).toString('base64') });

    // A success first: should not consume budget.
    expect((await new Client(app).req('post', '/api/auth/login', { email: reg.email, authKey: reg.authKey })).status).toBe(200);
    for (let i = 0; i < 3; i++) expect((await bad()).status).toBe(401);
    const blocked = await bad();
    expect(blocked.status).toBe(429);
    expect(blocked.body).toEqual({ error: 'rate_limited' });
    expect(blocked.headers['ratelimit-policy']).toBeDefined();
    // Even the right key is refused while locked (stops online guessing outright).
    expect((await new Client(app).req('post', '/api/auth/login', { email: reg.email, authKey: reg.authKey })).status).toBe(429);
  });

  it('limits prelogin/login per IP', async () => {
    const app = makeApp({ authIp: { windowMs: W, limit: 5 } });
    const statuses: number[] = [];
    for (let i = 0; i < 7; i++) {
      statuses.push((await new Client(app).req('post', '/api/auth/prelogin', { email: `x${i}@example.com` })).status);
    }
    expect(statuses.slice(0, 5)).toEqual([200, 200, 200, 200, 200]);
    expect(statuses.slice(5)).toEqual([429, 429]);
  });

  it('limits registrations per IP', async () => {
    const app = makeApp({ register: { windowMs: W, limit: 2 } });
    await registeredClient(app);
    await registeredClient(app);
    await expect(registeredClient(app)).rejects.toThrow(/429/);
  });

  it('state lives in Postgres (shared across app instances) and does not store emails', async () => {
    const limits = { loginAccount: { windowMs: W, limit: 2 } };
    const app1 = makeApp(limits);
    const app2 = makeApp(limits);
    const { reg } = await registeredClient(app1);
    const body = { email: reg.email, authKey: randomBytes(32).toString('base64') };
    await new Client(app1).req('post', '/api/auth/login', body);
    await new Client(app2).req('post', '/api/auth/login', body);
    expect((await new Client(app1).req('post', '/api/auth/login', body)).status).toBe(429);

    const { rows } = await db.query('SELECT key FROM rate_limits');
    expect(rows.map((r) => r.key).join(' ')).not.toContain(reg.email);
  });

  it('window resets after expiry', async () => {
    const app = makeApp({ authIp: { windowMs: W, limit: 1 } });
    expect((await new Client(app).req('post', '/api/auth/prelogin', { email: 'a@example.com' })).status).toBe(200);
    expect((await new Client(app).req('post', '/api/auth/prelogin', { email: 'a@example.com' })).status).toBe(429);
    await db.query("UPDATE rate_limits SET reset_at = now() - interval '1 second'");
    expect((await new Client(app).req('post', '/api/auth/prelogin', { email: 'a@example.com' })).status).toBe(200);
  });
});
