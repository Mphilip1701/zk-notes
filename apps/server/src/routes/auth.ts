import { DEFAULT_KDF_PARAMS } from '@zk-notes/crypto';
import { createHmac } from 'node:crypto';
import { Router } from 'express';
import type { Config } from '../config.js';
import { withTransaction, type Db } from '../db/pool.js';
import { HttpError } from '../errors.js';
import { clearSessionCookie, requireAuth, requireCsrf, setSessionCookie } from '../middleware/auth.js';
import type { Limiters } from '../middleware/rateLimit.js';
import type { AuthHasher } from '../security/authHash.js';
import type { SessionStore } from '../security/sessions.js';
import { changePasswordSchema, loginSchema, preloginSchema, registerSchema } from '../validation.js';

export interface UserRow {
  id: string;
  email: string;
  kdf_salt: Buffer;
  kdf_params: unknown;
  auth_hash: string;
  wrapped_vault_key: Buffer;
  vault_key_iv: Buffer;
  has_recovery: boolean;
}

/** Everything the client needs to (re)unlock its vault. None of it is secret. */
export function vaultBundle(u: UserRow) {
  return {
    userId: u.id,
    email: u.email,
    kdfSalt: u.kdf_salt.toString('base64'),
    kdfParams: u.kdf_params,
    wrappedVaultKey: u.wrapped_vault_key.toString('base64'),
    vaultKeyIv: u.vault_key_iv.toString('base64'),
    hasRecoveryKey: u.has_recovery,
  };
}

export const USER_COLUMNS =
  'id, email, kdf_salt, kdf_params, auth_hash, wrapped_vault_key, vault_key_iv, recovery_auth_hash IS NOT NULL AS has_recovery';

export function authRouter(deps: {
  db: Db;
  config: Config;
  sessions: SessionStore;
  hasher: AuthHasher;
  limiters: Limiters;
}): Router {
  const { db, config, sessions, hasher, limiters } = deps;
  const r = Router();

  async function findUserByEmail(email: string): Promise<UserRow | undefined> {
    const { rows } = await db.query<UserRow>(`SELECT ${USER_COLUMNS} FROM users WHERE email = $1`, [email]);
    return rows[0];
  }

  /**
   * Returns the salt + KDF params for an email. Unknown emails get a stable,
   * deterministic fake salt so this endpoint cannot be used to enumerate accounts.
   */
  r.post('/prelogin', limiters.authIp, async (req, res) => {
    const { email } = preloginSchema.parse(req.body);
    const user = await findUserByEmail(email);
    if (user) {
      res.json({ kdfSalt: user.kdf_salt.toString('base64'), kdfParams: user.kdf_params });
      return;
    }
    const fake = createHmac('sha256', config.keys.preloginSalt).update(email).digest().subarray(0, 16);
    res.json({ kdfSalt: fake.toString('base64'), kdfParams: DEFAULT_KDF_PARAMS });
  });

  r.post('/register', limiters.register, async (req, res) => {
    const body = registerSchema.parse(req.body);
    const authHash = await hasher.hash(body.authKey);
    const result = await withTransaction(db, async (c) => {
      const ins = await c.query(
        `INSERT INTO users (id, email, kdf_salt, kdf_params, auth_hash, wrapped_vault_key, vault_key_iv)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT DO NOTHING`,
        [body.userId, body.email, body.kdfSalt, body.kdfParams, authHash, body.wrappedVaultKey, body.vaultKeyIv],
      );
      if (ins.rowCount !== 1) return null;
      return sessions.create(c, body.userId);
    });
    if (!result) throw new HttpError(409, 'registration_failed');
    setSessionCookie(res, result.token, result.expiresAt);
    res.status(201).json({ userId: body.userId, email: body.email, csrfToken: sessions.csrfTokenFor(result.tokenHash) });
  });

  r.post('/login', limiters.authIp, limiters.loginAccount, async (req, res) => {
    const { email, authKey } = loginSchema.parse(req.body);
    const user = await findUserByEmail(email);
    const ok = user ? await hasher.verify(user.auth_hash, authKey) : await hasher.verifyDummy(authKey);
    if (!user || !ok) throw new HttpError(401, 'invalid_credentials');

    if (hasher.needsRehash(user.auth_hash)) {
      const fresh = await hasher.hash(authKey);
      await db.query('UPDATE users SET auth_hash = $1, updated_at = now() WHERE id = $2', [fresh, user.id]);
    }
    // Session fixation defence: always issue a new token; drop any presented one.
    if (req.auth) await sessions.revoke(db, req.auth.tokenHash);
    const s = await sessions.create(db, user.id);
    setSessionCookie(res, s.token, s.expiresAt);
    res.json({ ...vaultBundle(user), csrfToken: sessions.csrfTokenFor(s.tokenHash) });
  });

  /** Used after a page reload: the session survives, but keys must be re-derived from the password. */
  r.get('/session', requireAuth, async (req, res) => {
    const { rows } = await db.query<UserRow>(`SELECT ${USER_COLUMNS} FROM users WHERE id = $1`, [req.auth!.userId]);
    const user = rows[0];
    if (!user) throw new HttpError(401, 'unauthenticated');
    res.json({ ...vaultBundle(user), csrfToken: sessions.csrfTokenFor(req.auth!.tokenHash) });
  });

  r.post('/logout', requireAuth, requireCsrf(sessions), async (req, res) => {
    await sessions.revoke(db, req.auth!.tokenHash);
    clearSessionCookie(res);
    res.status(204).end();
  });

  r.post(
    '/change-password',
    requireAuth,
    requireCsrf(sessions),
    limiters.changePassword,
    async (req, res) => {
      const body = changePasswordSchema.parse(req.body);
      const userId = req.auth!.userId;
      const { rows } = await db.query<{ auth_hash: string }>('SELECT auth_hash FROM users WHERE id = $1', [userId]);
      const current = rows[0];
      if (!current || !(await hasher.verify(current.auth_hash, body.currentAuthKey))) {
        throw new HttpError(401, 'invalid_credentials');
      }
      const newHash = await hasher.hash(body.newAuthKey);
      const s = await withTransaction(db, async (c) => {
        await c.query(
          `UPDATE users SET kdf_salt = $1, kdf_params = $2, auth_hash = $3,
                  wrapped_vault_key = $4, vault_key_iv = $5, updated_at = now()
            WHERE id = $6`,
          [body.newKdfSalt, body.newKdfParams, newHash, body.newWrappedVaultKey, body.newVaultKeyIv, userId],
        );
        // Every existing session (other devices, and this one) is revoked.
        await sessions.revokeAllForUser(c, userId);
        return sessions.create(c, userId);
      });
      setSessionCookie(res, s.token, s.expiresAt);
      res.json({ csrfToken: sessions.csrfTokenFor(s.tokenHash) });
    },
  );

  return r;
}
