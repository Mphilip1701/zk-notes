import { MAX_KDF_PARAMS, MAX_NOTE_PLAINTEXT, MIN_KDF_PARAMS, PAD_BLOCK } from '@zk-notes/crypto';
import { z } from 'zod';

const B64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

/** Strict base64 → Buffer with byte-length bounds. */
export function b64(opts: { exact?: number; min?: number; max?: number }) {
  const maxChars = Math.ceil(((opts.exact ?? opts.max ?? 1024) * 4) / 3) + 4;
  return z
    .string()
    .max(maxChars)
    .transform((s, ctx) => {
      if (s.length % 4 !== 0 || !B64_RE.test(s)) {
        ctx.addIssue({ code: 'custom', message: 'invalid base64' });
        return z.NEVER;
      }
      const buf = Buffer.from(s, 'base64');
      const bad =
        (opts.exact !== undefined && buf.length !== opts.exact) ||
        (opts.min !== undefined && buf.length < opts.min) ||
        (opts.max !== undefined && buf.length > opts.max);
      if (bad) {
        ctx.addIssue({ code: 'custom', message: 'wrong length' });
        return z.NEVER;
      }
      return buf;
    });
}

export const emailSchema = z.string().trim().toLowerCase().pipe(z.email().max(254));

/** Same floors/ceilings the client enforces; the server refuses to store weak params. */
export const kdfParamsSchema = z.strictObject({
  alg: z.literal('argon2id'),
  v: z.literal(1),
  m: z.number().int().min(MIN_KDF_PARAMS.m).max(MAX_KDF_PARAMS.m),
  t: z.number().int().min(MIN_KDF_PARAMS.t).max(MAX_KDF_PARAMS.t),
  p: z.number().int().min(MIN_KDF_PARAMS.p).max(MAX_KDF_PARAMS.p),
});

const authKey = b64({ exact: 32 });
const salt = b64({ exact: 16 });
const wrappedVaultKey = b64({ exact: 48 });
const iv = b64({ exact: 12 });

export const preloginSchema = z.strictObject({ email: emailSchema });

export const registerSchema = z.strictObject({
  userId: z.uuid(),
  email: emailSchema,
  kdfSalt: salt,
  kdfParams: kdfParamsSchema,
  authKey,
  wrappedVaultKey,
  vaultKeyIv: iv,
});

export const loginSchema = z.strictObject({ email: emailSchema, authKey });

export const changePasswordSchema = z.strictObject({
  currentAuthKey: authKey,
  newKdfSalt: salt,
  newKdfParams: kdfParamsSchema,
  newAuthKey: authKey,
  newWrappedVaultKey: wrappedVaultKey,
  newVaultKeyIv: iv,
});

export const recoverySetupSchema = z.strictObject({
  currentAuthKey: authKey,
  recoveryAuthKey: authKey,
  recoveryWrappedVaultKey: wrappedVaultKey,
  recoveryVaultKeyIv: iv,
});

export const recoveryRemoveSchema = z.strictObject({ currentAuthKey: authKey });

export const recoveryVerifySchema = z.strictObject({ email: emailSchema, recoveryAuthKey: authKey });

export const recoveryCompleteSchema = z.strictObject({
  email: emailSchema,
  recoveryAuthKey: authKey,
  newKdfSalt: salt,
  newKdfParams: kdfParamsSchema,
  newAuthKey: authKey,
  newWrappedVaultKey: wrappedVaultKey,
  newVaultKeyIv: iv,
});

/** Padded plaintext (>= one block) + 16-byte GCM tag; upper bound mirrors the client. */
const MAX_NOTE_CIPHERTEXT = Math.ceil((MAX_NOTE_PLAINTEXT + 4) / PAD_BLOCK) * PAD_BLOCK + 16;
const noteCiphertext = b64({ min: PAD_BLOCK + 16, max: MAX_NOTE_CIPHERTEXT });

export const noteIdSchema = z.uuid();

export const createNoteSchema = z.strictObject({ id: z.uuid(), ciphertext: noteCiphertext, iv });

export const updateNoteSchema = z.strictObject({
  ciphertext: noteCiphertext,
  iv,
  /** The new version; must be exactly current + 1 (optimistic concurrency). */
  version: z.number().int().min(2).max(2 ** 31 - 1),
});
