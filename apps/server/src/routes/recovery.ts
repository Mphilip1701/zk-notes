import { Router } from 'express';
import type { Request } from 'express';
import type { Db } from '../db/pool.js';
import { withTransaction } from '../db/pool.js';
import { HttpError } from '../errors.js';
import { requireAuth, requireCsrf, setSessionCookie } from '../middleware/auth.js';
import type { Limiters } from '../middleware/rateLimit.js';
import type { AuthHasher } from '../security/authHash.js';
import type { SessionStore } from '../security/sessions.js';
import {
  recoveryCompleteSchema,
  recoveryRemoveSchema,
  recoverySetupSchema,
  recoveryVerifySchema,
} from '../validation.js';
import { USER_COLUMNS, vaultBundle, type UserRow } from './auth.js';

interface RecoveryRow {
  id: string;
  recovery_auth_hash: string | null;
  recovery_wrapped_vault_key: Buffer | null;
  recovery_vault_key_iv: Buffer | null;
}

/**
 * Recovery key endpoints. The server stores Argon2id(recovery auth key) and a
 * second wrap of the vault key; it never sees the recovery key or the vault key.
 */
export function recoveryRouter(deps: {
  db: Db;
  sessions: SessionStore;
  hasher: AuthHasher;
  limiters: Limiters;
}): Router {
  const { db, sessions, hasher, limiters } = deps;
  const r = Router();

  /** Re-authentication: the caller must prove the current password (auth key). */
  async function verifyCurrentPassword(req: Request, currentAuthKey: Buffer): Promise<string> {
    const userId = req.auth!.userId;
    const { rows } = await db.query<{ auth_hash: string }>('SELECT auth_hash FROM users WHERE id = $1', [userId]);
    const row = rows[0];
    if (!row || !(await hasher.verify(row.auth_hash, currentAuthKey))) {
      throw new HttpError(401, 'invalid_credentials');
    }
    return userId;
  }

  /**
   * Verify a recovery auth key for an email. Unknown accounts and accounts
   * without a recovery key take the same time and give the same error.
   */
  async function verifyRecovery(email: string, recoveryAuthKey: Buffer): Promise<RecoveryRow> {
    const { rows } = await db.query<RecoveryRow>(
      `SELECT id, recovery_auth_hash, recovery_wrapped_vault_key, recovery_vault_key_iv
         FROM users WHERE email = $1`,
      [email],
    );
    const row = rows[0];
    const ok = row?.recovery_auth_hash
      ? await hasher.verify(row.recovery_auth_hash, recoveryAuthKey)
      : await hasher.verifyDummy(recoveryAuthKey);
    if (!row || !ok) throw new HttpError(401, 'invalid_credentials');
    return row;
  }

  /** Create or replace the recovery key. Replacing it makes the old one useless. */
  r.post('/recovery-key', requireAuth, requireCsrf(sessions), limiters.changePassword, async (req, res) => {
    const body = recoverySetupSchema.parse(req.body);
    const userId = await verifyCurrentPassword(req, body.currentAuthKey);
    const hash = await hasher.hash(body.recoveryAuthKey);
    await db.query(
      `UPDATE users SET recovery_auth_hash = $1, recovery_wrapped_vault_key = $2, recovery_vault_key_iv = $3,
              recovery_updated_at = now(), updated_at = now()
        WHERE id = $4`,
      [hash, body.recoveryWrappedVaultKey, body.recoveryVaultKeyIv, userId],
    );
    res.json({ hasRecoveryKey: true });
  });

  r.post('/recovery-key/remove', requireAuth, requireCsrf(sessions), limiters.changePassword, async (req, res) => {
    const body = recoveryRemoveSchema.parse(req.body);
    const userId = await verifyCurrentPassword(req, body.currentAuthKey);
    await db.query(
      `UPDATE users SET recovery_auth_hash = NULL, recovery_wrapped_vault_key = NULL, recovery_vault_key_iv = NULL,
              recovery_updated_at = now(), updated_at = now()
        WHERE id = $1`,
      [userId],
    );
    res.json({ hasRecoveryKey: false });
  });

  /** Step 1: prove possession of the recovery key; receive the recovery-wrapped vault key. */
  r.post('/recovery/verify', limiters.authIp, limiters.recoveryAccount, async (req, res) => {
    const { email, recoveryAuthKey } = recoveryVerifySchema.parse(req.body);
    const row = await verifyRecovery(email, recoveryAuthKey);
    res.json({
      userId: row.id,
      recoveryWrappedVaultKey: row.recovery_wrapped_vault_key!.toString('base64'),
      recoveryVaultKeyIv: row.recovery_vault_key_iv!.toString('base64'),
    });
  });

  /**
   * Step 2: set a new password (the client re-wrapped the vault key under it).
   * The recovery key is re-verified, all sessions are revoked, and a new one starts.
   */
  r.post('/recovery/complete', limiters.authIp, limiters.recoveryAccount, async (req, res) => {
    const body = recoveryCompleteSchema.parse(req.body);
    const row = await verifyRecovery(body.email, body.recoveryAuthKey);
    const newHash = await hasher.hash(body.newAuthKey);
    const { session, user } = await withTransaction(db, async (c) => {
      // Guard against the recovery key being replaced between verification and now.
      const upd = await c.query(
        `UPDATE users SET kdf_salt = $1, kdf_params = $2, auth_hash = $3,
                wrapped_vault_key = $4, vault_key_iv = $5, updated_at = now()
          WHERE id = $6 AND recovery_auth_hash = $7`,
        [body.newKdfSalt, body.newKdfParams, newHash, body.newWrappedVaultKey, body.newVaultKeyIv, row.id, row.recovery_auth_hash],
      );
      if (upd.rowCount !== 1) throw new HttpError(409, 'recovery_key_changed');
      await sessions.revokeAllForUser(c, row.id);
      const session = await sessions.create(c, row.id);
      const { rows } = await c.query<UserRow>(`SELECT ${USER_COLUMNS} FROM users WHERE id = $1`, [row.id]);
      return { session, user: rows[0]! };
    });
    setSessionCookie(res, session.token, session.expiresAt);
    res.json({ ...vaultBundle(user), csrfToken: sessions.csrfTokenFor(session.tokenHash) });
  });

  return r;
}
