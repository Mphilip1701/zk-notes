import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { SESSION_COOKIE } from '../src/security/sessions.js';
import { Client, fakeNoteBlob, fakeRegistration, registeredClient, useTestDb } from './helpers.js';
import { randomUUID } from 'node:crypto';

const { app: makeApp } = useTestDb();

describe('CSRF and origin protections', () => {
  it('rejects state-changing requests with no Origin', async () => {
    const res = await request(makeApp()).post('/api/auth/register').send(fakeRegistration());
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'bad_origin' });
  });

  it('rejects a foreign Origin, even for login (login CSRF)', async () => {
    const res = await request(makeApp())
      .post('/api/auth/login')
      .set('Origin', 'https://evil.example')
      .send({ email: 'a@b.c', authKey: 'A'.repeat(43) + '=' });
    expect(res.status).toBe(403);
  });

  it('rejects cross-site requests via Fetch Metadata, even GETs', async () => {
    const app = makeApp();
    const { client } = await registeredClient(app);
    const res = await client.req('get', '/api/notes', undefined, { 'Sec-Fetch-Site': 'cross-site' });
    expect(res.status).toBe(403);
  });

  it('rejects non-JSON bodies (form posts cannot be forged without a preflight)', async () => {
    const res = await request(makeApp())
      .post('/api/auth/prelogin')
      .set('Origin', 'http://localhost:5173')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send('email=a@b.c');
    expect(res.status).toBe(415);
  });

  it('requires a valid CSRF token for authenticated mutations', async () => {
    const app = makeApp();
    const { client } = await registeredClient(app);
    const good = client.csrf!;

    client.csrf = undefined;
    expect((await client.req('post', '/api/notes', { id: randomUUID(), ...fakeNoteBlob() })).status).toBe(403);
    client.csrf = (good[0] === 'A' ? 'B' : 'A') + good.slice(1);
    expect((await client.req('post', '/api/notes', { id: randomUUID(), ...fakeNoteBlob() })).status).toBe(403);
    expect((await client.req('post', '/api/auth/logout')).status).toBe(403);

    client.csrf = good;
    expect((await client.req('post', '/api/notes', { id: randomUUID(), ...fakeNoteBlob() })).status).toBe(201);
  });

  it("another session's CSRF token is not accepted", async () => {
    const app = makeApp();
    const { client: a } = await registeredClient(app);
    const { client: b } = await registeredClient(app);
    a.csrf = b.csrf;
    const res = await a.req('post', '/api/notes', { id: randomUUID(), ...fakeNoteBlob() });
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'csrf_failed' });
  });

  it('reads (GET) do not need a CSRF token but do need the cookie', async () => {
    const app = makeApp();
    const { client } = await registeredClient(app);
    client.csrf = undefined;
    expect((await client.req('get', '/api/notes')).status).toBe(200);
    const anon = await request(app).get('/api/notes');
    expect(anon.status).toBe(401);
  });

  it('sends no CORS headers (same-origin only) and sets security headers', async () => {
    const res = await request(makeApp()).get('/api/health').set('Origin', 'https://evil.example');
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
    expect(res.headers['content-security-policy']).toContain("script-src 'self' 'wasm-unsafe-eval'");
    expect(res.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(res.headers['strict-transport-security']).toContain('max-age=');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['referrer-policy']).toBe('no-referrer');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  it('cookie name constant uses the __Host- prefix', () => {
    expect(SESSION_COOKIE.startsWith('__Host-')).toBe(true);
  });

  it('malformed JSON gets a generic 400', async () => {
    const res = await request(makeApp())
      .post('/api/auth/prelogin')
      .set('Origin', 'http://localhost:5173')
      .set('Content-Type', 'application/json')
      .send('{"email":');
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'invalid_json' });
  });

  it('a fresh unauthenticated client cannot register without the right origin header', async () => {
    const c = new Client(makeApp());
    const res = await c.req('post', '/api/auth/register', fakeRegistration(), { Origin: 'http://localhost:9999' });
    expect(res.status).toBe(403);
  });
});
