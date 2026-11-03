import { createHmac } from 'node:crypto';
import type { Request, RequestHandler } from 'express';
import { ipKeyGenerator, rateLimit } from 'express-rate-limit';
import type { Config } from '../config.js';
import type { Db } from '../db/pool.js';
import { PgRateLimitStore } from '../security/rateLimitStore.js';

export interface LimitRule {
  windowMs: number;
  limit: number;
}

export interface RateLimitSettings {
  /** All API traffic, per IP. */
  api: LimitRule;
  /** prelogin + login, per IP. */
  authIp: LimitRule;
  /** Failed logins per account (success does not count). */
  loginAccount: LimitRule;
  /** Registrations per IP. */
  register: LimitRule;
  /** Password changes per user. */
  changePassword: LimitRule;
}

const MIN = 60_000;
export const DEFAULT_RATE_LIMITS: RateLimitSettings = {
  api: { windowMs: 15 * MIN, limit: 1000 },
  authIp: { windowMs: 15 * MIN, limit: 40 },
  loginAccount: { windowMs: 15 * MIN, limit: 10 },
  register: { windowMs: 60 * MIN, limit: 5 },
  changePassword: { windowMs: 15 * MIN, limit: 5 },
};

export interface Limiters {
  api: RequestHandler;
  authIp: RequestHandler;
  loginAccount: RequestHandler;
  register: RequestHandler;
  changePassword: RequestHandler;
}

const ipKey = (req: Request) => ipKeyGenerator(req.ip ?? 'unknown');

export function createLimiters(db: Db, config: Config, settings: RateLimitSettings): Limiters {
  const make = (
    name: keyof RateLimitSettings,
    keyGenerator: (req: Request) => string,
    extra: { skipSuccessfulRequests?: boolean } = {},
  ) =>
    rateLimit({
      windowMs: settings[name].windowMs,
      limit: settings[name].limit,
      standardHeaders: 'draft-8',
      legacyHeaders: false,
      store: new PgRateLimitStore(db, name),
      keyGenerator,
      // Fail closed: if the store is unavailable, reject rather than allow unlimited guessing.
      passOnStoreError: false,
      handler: (_req, res) => {
        res.status(429).json({ error: 'rate_limited' });
      },
      ...extra,
    });

  // Keyed by an HMAC of the email so the rate_limits table does not store addresses.
  const accountKey = (req: Request) => {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    return createHmac('sha256', config.keys.rateLimit).update(email).digest('base64url');
  };

  return {
    api: make('api', ipKey),
    authIp: make('authIp', ipKey),
    loginAccount: make('loginAccount', accountKey, { skipSuccessfulRequests: true }),
    register: make('register', ipKey),
    changePassword: make('changePassword', (req) => req.auth?.userId ?? ipKey(req)),
  };
}
