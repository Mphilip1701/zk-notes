import type { ErrorRequestHandler } from 'express';
import { ZodError } from 'zod';

export class HttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    public readonly extra?: Record<string, unknown>,
  ) {
    super(code);
  }
}

/** Generic, non-leaky error responses. Details go to the server log only. */
export const errorHandler: ErrorRequestHandler = (err, _req, res, _next) => {
  if (err instanceof HttpError) {
    res.status(err.status).json({ error: err.code, ...err.extra });
    return;
  }
  if (err instanceof ZodError) {
    res.status(400).json({ error: 'invalid_request' });
    return;
  }
  // body-parser errors (malformed JSON, too large)
  const status = (err as { status?: number }).status;
  if (status === 413) {
    res.status(413).json({ error: 'payload_too_large' });
    return;
  }
  if (status === 400 && (err as { type?: string }).type === 'entity.parse.failed') {
    res.status(400).json({ error: 'invalid_json' });
    return;
  }
  console.error('Unhandled error:', err instanceof Error ? err.stack : err);
  res.status(500).json({ error: 'internal_error' });
};
