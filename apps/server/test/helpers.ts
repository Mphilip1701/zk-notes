import { MIN_KDF_PARAMS, prepareRegistration, type KdfParams, type RegistrationRequest } from '@zk-notes/crypto';
import { randomBytes, randomUUID } from 'node:crypto';
import type { Express } from 'express';
import request from 'supertest';
import { afterAll, beforeEach } from 'vitest';
import { createApp } from '../src/app.js';
import { loadConfig, type Config } from '../src/config.js';
import { createPool, type Db } from '../src/db/pool.js';
import type { RateLimitSettings } from '../src/middleware/rateLimit.js';
import { SESSION_COOKIE } from '../src/security/sessions.js';
import { TEST_DATABASE_URL } from './global-setup.js';

export const ORIGIN = 'http://localhost:5173';
export const FAST_PARAMS: KdfParams = { alg: 'argon2id', v: 1, ...MIN_KDF_PARAMS };

export function testConfig(overrides: Record<string, string> = {}): Config {
  return loadConfig({
    NODE_ENV: 'test',
    DATABASE_URL: TEST_DATABASE_URL,
    SERVER_SECRET: 'test-secret-'.padEnd(64, 'x'),
    ALLOWED_ORIGINS: ORIGIN,
    ...overrides,
  });
}

/** One pool per test file; tables truncated before each test. */
export function useTestDb(): { db: Db; app: (limits?: Partial<RateLimitSettings>) => Express; config: Config } {
  const config = testConfig();
  const db = createPool(config.databaseUrl);
  beforeEach(async () => {
    await db.query('TRUNCATE users, sessions, notes, rate_limits CASCADE');
  });
  afterAll(async () => {
    await db.end();
  });
  return { db, config, app: (limits) => createApp({ config, db, rateLimits: limits }) };
}

/**
 * Minimal browser-like client. supertest's cookie jar refuses Secure cookies
 * over plain HTTP, so the session cookie is tracked by hand.
 */
export class Client {
  cookie: string | undefined;
  csrf: string | undefined;
  lastSetCookie: string | undefined;

  constructor(private readonly app: Express) {}

  req(method: 'get' | 'post' | 'put' | 'delete', path: string, body?: unknown, headers: Record<string, string> = {}) {
    let r = request(this.app)[method](path).set('Origin', ORIGIN);
    if (this.cookie) r = r.set('Cookie', `${SESSION_COOKIE}=${this.cookie}`);
    if (this.csrf) r = r.set('X-CSRF-Token', this.csrf);
    for (const [k, v] of Object.entries(headers)) r = r.set(k, v);
    if (body !== undefined) r = r.send(body as object);
    return r.then((res) => {
      const set = ([] as string[]).concat(res.headers['set-cookie'] ?? []);
      const ours = set.find((c) => c.startsWith(`${SESSION_COOKIE}=`));
      if (ours) {
        this.lastSetCookie = ours;
        const value = ours.split(';')[0]!.slice(SESSION_COOKIE.length + 1);
        this.cookie = value || undefined;
      }
      if (typeof res.body?.csrfToken === 'string') this.csrf = res.body.csrfToken;
      return res;
    });
  }
}

/** A syntactically valid registration without paying for client-side Argon2. */
export function fakeRegistration(email = `u${randomUUID().slice(0, 8)}@example.com`): RegistrationRequest {
  return {
    userId: randomUUID(),
    email,
    kdfSalt: randomBytes(16).toString('base64'),
    kdfParams: { ...FAST_PARAMS },
    authKey: randomBytes(32).toString('base64'),
    wrappedVaultKey: randomBytes(48).toString('base64'),
    vaultKeyIv: randomBytes(12).toString('base64'),
  };
}

export async function registeredClient(app: Express, reg = fakeRegistration()) {
  const c = new Client(app);
  const res = await c.req('post', '/api/auth/register', reg);
  if (res.status !== 201) throw new Error(`register failed: ${res.status} ${JSON.stringify(res.body)}`);
  return { client: c, reg };
}

/** A real registration produced by the client crypto library. */
export async function realRegistration(email: string, password: string) {
  return prepareRegistration(email, password, FAST_PARAMS);
}

export function fakeNoteBlob() {
  return { ciphertext: randomBytes(256 + 16).toString('base64'), iv: randomBytes(12).toString('base64') };
}
