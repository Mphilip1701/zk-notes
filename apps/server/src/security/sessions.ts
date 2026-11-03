import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Config } from '../config.js';
import type { Queryable } from '../db/pool.js';

export const SESSION_COOKIE = '__Host-zkn_sid';
/** Throttle last_seen_at writes to at most one per minute per session. */
const TOUCH_INTERVAL_MS = 60_000;

export interface SessionInfo {
  tokenHash: Buffer;
  userId: string;
}

export function hashToken(token: string): Buffer {
  return createHash('sha256').update(token, 'utf8').digest();
}

export class SessionStore {
  constructor(private readonly config: Config) {}

  /** Creates a session and returns the raw token (goes only into the cookie). */
  async create(db: Queryable, userId: string): Promise<{ token: string; tokenHash: Buffer; expiresAt: Date }> {
    const token = randomBytes(32).toString('base64url');
    const tokenHash = hashToken(token);
    const expiresAt = new Date(Date.now() + this.config.sessionAbsoluteMs);
    await db.query('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)', [
      tokenHash,
      userId,
      expiresAt,
    ]);
    return { token, tokenHash, expiresAt };
  }

  /** Validates absolute and idle expiry; slides the idle window. */
  async lookup(db: Queryable, token: string): Promise<SessionInfo | null> {
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
    const tokenHash = hashToken(token);
    const { rows } = await db.query<{ user_id: string; last_seen_at: Date }>(
      `SELECT user_id, last_seen_at FROM sessions
        WHERE token_hash = $1
          AND expires_at > now()
          AND last_seen_at > now() - make_interval(secs => $2)`,
      [tokenHash, this.config.sessionIdleMs / 1000],
    );
    const row = rows[0];
    if (!row) return null;
    if (Date.now() - row.last_seen_at.getTime() > TOUCH_INTERVAL_MS) {
      await db.query('UPDATE sessions SET last_seen_at = now() WHERE token_hash = $1', [tokenHash]);
    }
    return { tokenHash, userId: row.user_id };
  }

  async revoke(db: Queryable, tokenHash: Buffer): Promise<void> {
    await db.query('DELETE FROM sessions WHERE token_hash = $1', [tokenHash]);
  }

  async revokeAllForUser(db: Queryable, userId: string): Promise<void> {
    await db.query('DELETE FROM sessions WHERE user_id = $1', [userId]);
  }

  async purgeExpired(db: Queryable): Promise<void> {
    await db.query(
      `DELETE FROM sessions WHERE expires_at <= now() OR last_seen_at <= now() - make_interval(secs => $1)`,
      [this.config.sessionIdleMs / 1000],
    );
  }

  /**
   * CSRF token bound to the session: HMAC(csrfKey, tokenHash). Stateless, can be
   * re-issued on page reload, and useless without the matching session cookie.
   */
  csrfTokenFor(tokenHash: Buffer): string {
    return createHmac('sha256', this.config.keys.csrf).update(tokenHash).digest('base64url');
  }

  verifyCsrf(tokenHash: Buffer, presented: string | undefined): boolean {
    if (typeof presented !== 'string' || presented.length > 128) return false;
    const expected = Buffer.from(this.csrfTokenFor(tokenHash));
    const got = Buffer.from(presented);
    return got.length === expected.length && timingSafeEqual(got, expected);
  }
}
