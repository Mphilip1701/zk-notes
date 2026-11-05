import type { WrappedVaultKeyWire } from './account.js';
import { deriveLoginKeys } from './account.js';
import {
  CryptoInputError,
  concatBytes,
  constantTimeEqual,
  fromBase64,
  randomBytes,
  toBase64,
  utf8Encode,
  wipe,
} from './encoding.js';
import { DEFAULT_KDF_PARAMS, KEY_LENGTH, assertKdfParamsAcceptable, type KdfParams } from './kdf.js';
import {
  LABEL_VAULT_KEY_RECOVERY_WRAP,
  deriveKeys,
  generateSalt,
  splitKey,
  unwrapVaultKey,
  wrapVaultKey,
  type DerivedKeys,
} from './keys.js';

/**
 * Recovery key: a second, independent way to unwrap the Vault Key.
 *
 *   RK  = 256 random bits, shown to the user once as Crockford base32 with a checksum
 *   RK ──HKDF(LABEL_RECOVERY_AUTH)──► RAK  (sent to the server, stored as Argon2id(RAK))
 *   RK ──HKDF(LABEL_RECOVERY_KEK)───► RKEK (never leaves the client)
 *   server stores AES-GCM(RKEK, VK, aad = LABEL_VAULT_KEY_RECOVERY_WRAP ‖ userId)
 *
 * RK has full 256-bit entropy, so no password-hardening KDF is needed. Holding
 * RK is equivalent to holding the master password: treat it like one.
 */

export const LABEL_RECOVERY_AUTH = 'zk-notes/v1/recovery-auth-key';
export const LABEL_RECOVERY_KEK = 'zk-notes/v1/recovery-key-encryption-key';
const LABEL_RECOVERY_CHECKSUM = 'zk-notes/v1/recovery-checksum';

export const RECOVERY_KEY_BYTES = KEY_LENGTH;
const CHECKSUM_BYTES = 2;
const GROUP = 5;

/** Crockford base32: no I, L, O or U, so it is hard to misread when copied by hand. */
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const DECODE: Record<string, number> = {};
for (let i = 0; i < ALPHABET.length; i++) DECODE[ALPHABET[i]!] = i;
// Common misreadings map to their intended digit.
DECODE.O = 0;
DECODE.I = 1;
DECODE.L = 1;

export function base32Encode(bytes: Uint8Array): string {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const b of bytes) {
    buffer = (buffer << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) out += ALPHABET[(buffer << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string, byteLength: number): Uint8Array<ArrayBuffer> {
  if (s.length !== Math.ceil((byteLength * 8) / 5)) throw new CryptoInputError('Invalid recovery key');
  const out = new Uint8Array(byteLength);
  let buffer = 0;
  let bits = 0;
  let i = 0;
  for (const ch of s) {
    const v = DECODE[ch];
    if (v === undefined) throw new CryptoInputError('Invalid recovery key');
    buffer = (buffer << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out[i++] = (buffer >>> (bits - 8)) & 0xff;
      bits -= 8;
    }
    buffer &= (1 << bits) - 1;
  }
  // Leftover bits must be zero padding (rejects non-canonical encodings).
  if (buffer !== 0) throw new CryptoInputError('Invalid recovery key');
  return out;
}

async function checksum(key: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const digest = await crypto.subtle.digest('SHA-256', concatBytes(utf8Encode(LABEL_RECOVERY_CHECKSUM), key));
  return new Uint8Array(digest).slice(0, CHECKSUM_BYTES);
}

/** Format raw key bytes for display: XXXXX-XXXXX-… (11 groups of 5). */
export async function formatRecoveryKey(raw: Uint8Array): Promise<string> {
  if (raw.length !== RECOVERY_KEY_BYTES) throw new CryptoInputError('Recovery key must be 32 bytes');
  const encoded = base32Encode(concatBytes(raw, await checksum(raw)));
  return encoded.match(new RegExp(`.{1,${GROUP}}`, 'g'))!.join('-');
}

/**
 * Parse user input. Tolerates lowercase, spaces, dashes and the O/0, I/L/1
 * confusions; rejects typos via the checksum (≈ 1 in 65 536 slip through).
 */
export async function parseRecoveryKey(input: string): Promise<Uint8Array<ArrayBuffer>> {
  if (typeof input !== 'string') throw new CryptoInputError('Invalid recovery key');
  const cleaned = input.toUpperCase().replace(/[\s-]/g, '');
  const bytes = base32Decode(cleaned, RECOVERY_KEY_BYTES + CHECKSUM_BYTES);
  const raw = bytes.slice(0, RECOVERY_KEY_BYTES);
  const sum = bytes.slice(RECOVERY_KEY_BYTES);
  if (!constantTimeEqual(sum, await checksum(raw))) {
    throw new CryptoInputError('Invalid recovery key (checksum mismatch: check for typos)');
  }
  return raw;
}

/** Recovery key → { authKey (RAK), kek (RKEK) }. Domain-separated from the password keys. */
export function deriveRecoveryKeys(raw: Uint8Array<ArrayBuffer>): Promise<DerivedKeys> {
  return splitKey(raw, LABEL_RECOVERY_AUTH, LABEL_RECOVERY_KEK);
}

export interface RecoveryWrapWire {
  recoveryWrappedVaultKey: string;
  recoveryVaultKeyIv: string;
}

export interface RecoverySetupRequest extends RecoveryWrapWire {
  /** Proves the user knows the current password (re-authentication). */
  currentAuthKey: string;
  recoveryAuthKey: string;
}

export interface RecoveryResetRequest {
  recoveryAuthKey: string;
  newKdfSalt: string;
  newKdfParams: KdfParams;
  newAuthKey: string;
  newWrappedVaultKey: string;
  newVaultKeyIv: string;
}

/**
 * Create (or replace) the recovery key. Needs the current password because the
 * in-memory VK is non-extractable: it must be re-unwrapped as extractable to wrap it again.
 */
export async function prepareRecoverySetup(args: {
  userId: string;
  password: string;
  kdfSalt: string;
  kdfParams: unknown;
  current: WrappedVaultKeyWire;
}): Promise<{ request: RecoverySetupRequest; recoveryKey: string }> {
  const login = await deriveLoginKeys(args.password, args.kdfSalt, args.kdfParams);
  const vk = await unwrapVaultKey(
    login.kek,
    { iv: fromBase64(args.current.vaultKeyIv), ciphertext: fromBase64(args.current.wrappedVaultKey) },
    args.userId,
    true,
  );
  const raw = randomBytes(RECOVERY_KEY_BYTES);
  try {
    const recoveryKey = await formatRecoveryKey(raw);
    const rk = await deriveRecoveryKeys(raw);
    const wrapped = await wrapVaultKey(rk.kek, vk, args.userId, LABEL_VAULT_KEY_RECOVERY_WRAP);
    const request: RecoverySetupRequest = {
      currentAuthKey: login.authKey,
      recoveryAuthKey: toBase64(rk.authKey),
      recoveryWrappedVaultKey: toBase64(wrapped.ciphertext),
      recoveryVaultKeyIv: toBase64(wrapped.iv),
    };
    wipe(rk.authKey);
    return { request, recoveryKey };
  } finally {
    wipe(raw);
  }
}

/** Step 1 of recovery: turn the typed recovery key into the auth key to send and the local KEK. */
export async function deriveRecoveryLogin(recoveryKey: string): Promise<{ authKey: string; kek: CryptoKey }> {
  const raw = await parseRecoveryKey(recoveryKey);
  try {
    const { authKey, kek } = await deriveRecoveryKeys(raw);
    const b64 = toBase64(authKey);
    wipe(authKey);
    return { authKey: b64, kek };
  } finally {
    wipe(raw);
  }
}

/**
 * Step 2 of recovery: unwrap the VK with the recovery KEK and re-wrap it under
 * a new password. Notes are untouched; the recovery key keeps working afterwards.
 */
export async function prepareRecoveryReset(args: {
  userId: string;
  recoveryAuthKey: string;
  recoveryKek: CryptoKey;
  recoveryWrap: RecoveryWrapWire;
  newPassword: string;
  newKdfParams?: KdfParams;
}): Promise<{ request: RecoveryResetRequest; vaultKey: CryptoKey }> {
  const params = args.newKdfParams ?? { ...DEFAULT_KDF_PARAMS };
  assertKdfParamsAcceptable(params);
  const vk = await unwrapVaultKey(
    args.recoveryKek,
    {
      iv: fromBase64(args.recoveryWrap.recoveryVaultKeyIv),
      ciphertext: fromBase64(args.recoveryWrap.recoveryWrappedVaultKey),
    },
    args.userId,
    true,
    LABEL_VAULT_KEY_RECOVERY_WRAP,
  );
  const salt = generateSalt();
  const fresh = await deriveKeys(args.newPassword, salt, params);
  const wrapped = await wrapVaultKey(fresh.kek, vk, args.userId);
  const vaultKey = await unwrapVaultKey(fresh.kek, wrapped, args.userId);
  const request: RecoveryResetRequest = {
    recoveryAuthKey: args.recoveryAuthKey,
    newKdfSalt: toBase64(salt),
    newKdfParams: params,
    newAuthKey: toBase64(fresh.authKey),
    newWrappedVaultKey: toBase64(wrapped.ciphertext),
    newVaultKeyIv: toBase64(wrapped.iv),
  };
  wipe(fresh.authKey);
  return { request, vaultKey };
}
