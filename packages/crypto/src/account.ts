import { CryptoInputError, fromBase64, toBase64, wipe } from './encoding.js';
import { DEFAULT_KDF_PARAMS, SALT_LENGTH, assertKdfParamsAcceptable, type KdfParams } from './kdf.js';
import { createVaultKey, deriveKeys, generateSalt, rewrapVaultKey, unwrapVaultKey } from './keys.js';

/**
 * High-level flows. Everything here returns base64 wire objects that map 1:1
 * onto the server API. Nothing in the returned wire objects is secret except
 * authKey, which is a password-equivalent for *authentication only*.
 */

export interface RegistrationRequest {
  userId: string;
  email: string;
  kdfSalt: string;
  kdfParams: KdfParams;
  authKey: string;
  wrappedVaultKey: string;
  vaultKeyIv: string;
}

export interface WrappedVaultKeyWire {
  wrappedVaultKey: string;
  vaultKeyIv: string;
}

export interface PasswordChangeRequest {
  currentAuthKey: string;
  newKdfSalt: string;
  newKdfParams: KdfParams;
  newAuthKey: string;
  newWrappedVaultKey: string;
  newVaultKeyIv: string;
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export async function prepareRegistration(
  email: string,
  password: string,
  params: KdfParams = { ...DEFAULT_KDF_PARAMS },
): Promise<{ request: RegistrationRequest; vaultKey: CryptoKey }> {
  assertKdfParamsAcceptable(params);
  const userId = crypto.randomUUID();
  const salt = generateSalt();
  const { authKey, kek } = await deriveKeys(password, salt, params);
  const { vaultKey, wrapped } = await createVaultKey(kek, userId);
  const request: RegistrationRequest = {
    userId,
    email: normalizeEmail(email),
    kdfSalt: toBase64(salt),
    kdfParams: params,
    authKey: toBase64(authKey),
    wrappedVaultKey: toBase64(wrapped.ciphertext),
    vaultKeyIv: toBase64(wrapped.iv),
  };
  wipe(authKey);
  return { request, vaultKey };
}

function decodeSalt(kdfSalt: string): Uint8Array<ArrayBuffer> {
  const salt = fromBase64(kdfSalt);
  if (salt.length !== SALT_LENGTH) throw new CryptoInputError('Bad salt length');
  return salt;
}

/** Login step: derive the auth key to send, and keep the KEK locally. */
export async function deriveLoginKeys(
  password: string,
  kdfSalt: string,
  kdfParams: unknown,
): Promise<{ authKey: string; kek: CryptoKey }> {
  assertKdfParamsAcceptable(kdfParams); // refuse server-supplied downgrades
  const { authKey, kek } = await deriveKeys(password, decodeSalt(kdfSalt), kdfParams);
  const b64 = toBase64(authKey);
  wipe(authKey);
  return { authKey: b64, kek };
}

export async function unlockVault(kek: CryptoKey, userId: string, wire: WrappedVaultKeyWire): Promise<CryptoKey> {
  return unwrapVaultKey(kek, { iv: fromBase64(wire.vaultKeyIv), ciphertext: fromBase64(wire.wrappedVaultKey) }, userId);
}

export async function preparePasswordChange(args: {
  userId: string;
  currentPassword: string;
  currentKdfSalt: string;
  currentKdfParams: unknown;
  current: WrappedVaultKeyWire;
  newPassword: string;
  newKdfParams?: KdfParams;
}): Promise<PasswordChangeRequest> {
  const newParams = args.newKdfParams ?? { ...DEFAULT_KDF_PARAMS };
  assertKdfParamsAcceptable(newParams);
  const old = await deriveLoginKeys(args.currentPassword, args.currentKdfSalt, args.currentKdfParams);
  const newSalt = generateSalt();
  const fresh = await deriveKeys(args.newPassword, newSalt, newParams);
  const rewrapped = await rewrapVaultKey(
    old.kek,
    fresh.kek,
    { iv: fromBase64(args.current.vaultKeyIv), ciphertext: fromBase64(args.current.wrappedVaultKey) },
    args.userId,
  );
  const req: PasswordChangeRequest = {
    currentAuthKey: old.authKey,
    newKdfSalt: toBase64(newSalt),
    newKdfParams: newParams,
    newAuthKey: toBase64(fresh.authKey),
    newWrappedVaultKey: toBase64(rewrapped.ciphertext),
    newVaultKeyIv: toBase64(rewrapped.iv),
  };
  wipe(fresh.authKey);
  return req;
}
