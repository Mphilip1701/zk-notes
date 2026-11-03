import express, { type Express } from 'express';
import path from 'node:path';
import type { Config } from './config.js';
import type { Db } from './db/pool.js';
import { HttpError, errorHandler } from './errors.js';
import { loadSession, requireAuth, requireCsrf } from './middleware/auth.js';
import { DEFAULT_RATE_LIMITS, createLimiters, type RateLimitSettings } from './middleware/rateLimit.js';
import { extraHeaders, noStore, originCheck, requireJson, securityHeaders } from './middleware/security.js';
import { authRouter } from './routes/auth.js';
import { notesRouter } from './routes/notes.js';
import { AuthHasher } from './security/authHash.js';
import { SessionStore } from './security/sessions.js';

export interface AppDeps {
  config: Config;
  db: Db;
  rateLimits?: Partial<RateLimitSettings>;
}

export function createApp({ config, db, rateLimits }: AppDeps): Express {
  const app = express();
  app.set('trust proxy', config.trustProxy);
  app.disable('x-powered-by');
  app.set('etag', false);

  const sessions = new SessionStore(config);
  const hasher = new AuthHasher(config.argon2MaxConcurrency);
  const limiters = createLimiters(db, config, { ...DEFAULT_RATE_LIMITS, ...rateLimits });

  app.use(securityHeaders(config.env === 'production'), extraHeaders);

  // No CORS middleware on purpose: the API is same-origin only.
  app.use(
    '/api',
    noStore,
    originCheck(config),
    limiters.api,
    requireJson,
    express.json({ limit: '1mb', strict: true }),
    loadSession(db, sessions),
  );
  app.get('/api/health', (_req, res) => {
    res.json({ ok: true });
  });
  app.use('/api/auth', authRouter({ db, config, sessions, hasher, limiters }));
  app.use('/api/notes', requireAuth, requireCsrf(sessions), notesRouter(db));
  app.use('/api', (_req, _res, next) => next(new HttpError(404, 'not_found')));

  if (config.staticDir) {
    const dir = path.resolve(config.staticDir);
    app.use(express.static(dir, { index: false, maxAge: '1h' }));
    // SPA fallback for client-side routes.
    app.get(/^\/(?!api\/).*/, (_req, res) => {
      res.setHeader('Cache-Control', 'no-cache');
      res.sendFile(path.join(dir, 'index.html'));
    });
  }

  app.use(errorHandler);
  return app;
}
