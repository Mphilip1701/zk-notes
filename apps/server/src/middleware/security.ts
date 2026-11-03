import type { RequestHandler } from 'express';
import helmet from 'helmet';
import type { Config } from '../config.js';
import { HttpError } from '../errors.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export function securityHeaders(production: boolean): RequestHandler {
  return helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        // 'wasm-unsafe-eval' is required to instantiate the Argon2 WASM module; no 'unsafe-eval'/'unsafe-inline'.
        scriptSrc: ["'self'", "'wasm-unsafe-eval'"],
        workerSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        fontSrc: ["'self'"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'none'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        // Only in production: on http://localhost it would break the dev setup.
        ...(production ? { upgradeInsecureRequests: [] } : {}),
      },
    },
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    referrerPolicy: { policy: 'no-referrer' },
    strictTransportSecurity: { maxAge: 63072000, includeSubDomains: true, preload: false },
  });
}

/** Extra headers helmet does not cover. */
export const extraHeaders: RequestHandler = (_req, res, next) => {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  next();
};

export const noStore: RequestHandler = (_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  next();
};

/**
 * CSRF layer 1 (applies to every API request, authenticated or not, so it also
 * covers login CSRF): state-changing requests must carry an allowed Origin, and
 * cross-site fetches are refused outright via Fetch Metadata.
 */
export function originCheck(config: Config): RequestHandler {
  return (req, _res, next) => {
    if (req.get('sec-fetch-site') === 'cross-site') return next(new HttpError(403, 'cross_site_request'));
    if (SAFE_METHODS.has(req.method)) return next();
    const origin = req.get('origin');
    if (!origin || !config.allowedOrigins.has(origin)) return next(new HttpError(403, 'bad_origin'));
    next();
  };
}

/** Bodies must be JSON: forces a CORS preflight for any cross-origin attempt. */
export const requireJson: RequestHandler = (req, _res, next) => {
  if (SAFE_METHODS.has(req.method)) return next();
  // Body-less requests (logout, DELETE) are fine; any body present must be JSON.
  const empty = req.headers['content-length'] === '0' || req.is('application/json') === null;
  if (!empty && !req.is('application/json')) return next(new HttpError(415, 'unsupported_media_type'));
  next();
};
