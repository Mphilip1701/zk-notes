import { createHmac } from 'node:crypto';
import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  DATABASE_URL: z.string().min(1),
  /** >= 32 bytes of randomness, hex or base64. Used only as an HMAC key root. */
  SERVER_SECRET: z.string().min(43, 'SERVER_SECRET must be at least 32 random bytes (hex/base64)'),
  ALLOWED_ORIGINS: z.string().default('http://localhost:5173'),
  /** Express "trust proxy" value: 'false', 'true', a hop count, or a subnet list. */
  TRUST_PROXY: z.string().default('false'),
  SESSION_IDLE_MINUTES: z.coerce.number().int().positive().default(30),
  SESSION_ABSOLUTE_HOURS: z.coerce.number().int().positive().default(24 * 7),
  ARGON2_MAX_CONCURRENCY: z.coerce.number().int().positive().default(4),
  /** If set, serve the built web app from this directory (same-origin deployment). */
  STATIC_DIR: z.string().optional(),
});

export interface Config {
  env: 'development' | 'test' | 'production';
  port: number;
  databaseUrl: string;
  allowedOrigins: Set<string>;
  trustProxy: boolean | number | string;
  sessionIdleMs: number;
  sessionAbsoluteMs: number;
  argon2MaxConcurrency: number;
  staticDir: string | undefined;
  /** Independent subkeys of SERVER_SECRET, one per purpose. */
  keys: { preloginSalt: Buffer; csrf: Buffer; rateLimit: Buffer };
}

function subkey(secret: string, label: string): Buffer {
  return createHmac('sha256', secret).update(`zk-notes/server/${label}`).digest();
}

function parseTrustProxy(v: string): boolean | number | string {
  if (v === 'false') return false;
  if (v === 'true') return true;
  if (/^\d+$/.test(v)) return Number(v);
  return v;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = envSchema.safeParse(env);
  if (!parsed.success) {
    const msg = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`Invalid configuration: ${msg}`);
  }
  const e = parsed.data;
  const origins = new Set(
    e.ALLOWED_ORIGINS.split(',')
      .map((o) => o.trim())
      .filter(Boolean),
  );
  if (e.NODE_ENV === 'production') {
    for (const o of origins) {
      if (!o.startsWith('https://')) throw new Error(`ALLOWED_ORIGINS must be https in production: ${o}`);
    }
  }
  return {
    env: e.NODE_ENV,
    port: e.PORT,
    databaseUrl: e.DATABASE_URL,
    allowedOrigins: origins,
    trustProxy: parseTrustProxy(e.TRUST_PROXY),
    sessionIdleMs: e.SESSION_IDLE_MINUTES * 60_000,
    sessionAbsoluteMs: e.SESSION_ABSOLUTE_HOURS * 3_600_000,
    argon2MaxConcurrency: e.ARGON2_MAX_CONCURRENCY,
    staticDir: e.STATIC_DIR,
    keys: {
      preloginSalt: subkey(e.SERVER_SECRET, 'prelogin-salt'),
      csrf: subkey(e.SERVER_SECRET, 'csrf'),
      rateLimit: subkey(e.SERVER_SECRET, 'rate-limit-key'),
    },
  };
}
