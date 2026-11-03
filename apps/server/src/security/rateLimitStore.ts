import type { ClientRateLimitInfo, Options, Store } from 'express-rate-limit';
import type { Db } from '../db/pool.js';

/**
 * Postgres-backed fixed-window store for express-rate-limit, so limits hold
 * across multiple app instances and survive restarts.
 */
export class PgRateLimitStore implements Store {
  windowMs = 60_000;
  readonly localKeys = false;

  constructor(
    private readonly db: Db,
    readonly prefix: string,
  ) {}

  init(options: Options): void {
    this.windowMs = options.windowMs;
  }

  private k(key: string): string {
    return `${this.prefix}:${key}`;
  }

  async get(key: string): Promise<ClientRateLimitInfo | undefined> {
    const { rows } = await this.db.query<{ hits: number; reset_at: Date }>(
      'SELECT hits, reset_at FROM rate_limits WHERE key = $1 AND reset_at > now()',
      [this.k(key)],
    );
    const r = rows[0];
    return r ? { totalHits: r.hits, resetTime: r.reset_at } : undefined;
  }

  async increment(key: string): Promise<ClientRateLimitInfo> {
    const { rows } = await this.db.query<{ hits: number; reset_at: Date }>(
      `INSERT INTO rate_limits (key, hits, reset_at)
         VALUES ($1, 1, now() + make_interval(secs => $2))
       ON CONFLICT (key) DO UPDATE SET
         hits     = CASE WHEN rate_limits.reset_at <= now() THEN 1 ELSE rate_limits.hits + 1 END,
         reset_at = CASE WHEN rate_limits.reset_at <= now() THEN EXCLUDED.reset_at ELSE rate_limits.reset_at END
       RETURNING hits, reset_at`,
      [this.k(key), this.windowMs / 1000],
    );
    const r = rows[0]!;
    return { totalHits: r.hits, resetTime: r.reset_at };
  }

  async decrement(key: string): Promise<void> {
    await this.db.query('UPDATE rate_limits SET hits = GREATEST(hits - 1, 0) WHERE key = $1', [this.k(key)]);
  }

  async resetKey(key: string): Promise<void> {
    await this.db.query('DELETE FROM rate_limits WHERE key = $1', [this.k(key)]);
  }
}

export async function purgeRateLimits(db: Db): Promise<void> {
  await db.query('DELETE FROM rate_limits WHERE reset_at <= now()');
}
