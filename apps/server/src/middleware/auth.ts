import { parseCookie } from 'cookie';
import type { CookieOptions, RequestHandler, Response } from 'express';
import type { Db } from '../db/pool.js';
import { HttpError } from '../errors.js';
import { SESSION_COOKIE, type SessionInfo, type SessionStore } from '../security/sessions.js';

declare module 'express-serve-static-core' {
  interface Request {
    auth?: SessionInfo;
  }
}

export const CSRF_HEADER = 'x-csrf-token';

function cookieOptions(expires?: Date): CookieOptions {
  // __Host- prefix requires Secure, Path=/ and no Domain. localhost counts as a
  // secure context in modern browsers, so this works in development too.
  return { httpOnly: true, secure: true, sameSite: 'strict', path: '/', ...(expires ? { expires } : {}) };
}

export function setSessionCookie(res: Response, token: string, expires: Date): void {
  res.cookie(SESSION_COOKIE, token, cookieOptions(expires));
}

export function clearSessionCookie(res: Response): void {
  res.clearCookie(SESSION_COOKIE, cookieOptions());
}

/** Attaches req.auth if a valid session cookie is present. Never rejects. */
export function loadSession(db: Db, sessions: SessionStore): RequestHandler {
  return async (req, _res, next) => {
    const header = req.headers.cookie;
    if (header) {
      const token = parseCookie(header)[SESSION_COOKIE];
      if (token) {
        const s = await sessions.lookup(db, token);
        if (s) req.auth = s;
      }
    }
    next();
  };
}

export const requireAuth: RequestHandler = (req, _res, next) => {
  if (!req.auth) return next(new HttpError(401, 'unauthenticated'));
  next();
};

/**
 * CSRF layer 2 (authenticated routes): session-bound token in a custom header.
 * A cross-site attacker can neither read the token nor set custom headers
 * without a CORS preflight, which this server never approves.
 */
export function requireCsrf(sessions: SessionStore): RequestHandler {
  return (req, _res, next) => {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
    if (!req.auth || !sessions.verifyCsrf(req.auth.tokenHash, req.get(CSRF_HEADER))) {
      return next(new HttpError(403, 'csrf_failed'));
    }
    next();
  };
}
