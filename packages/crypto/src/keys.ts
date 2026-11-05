import { IV_LENGTH, TAG_LENGTH, type Sealed } from './aead.js';
import { CryptoInputError, DecryptionError, encodeAad, randomBytes, utf8Encode, wipe } from './encoding.js';
import { KEY_LENGTH, SALT_LENGTH, deriveMasterKey, type KdfParams } from './kdf.js';

/**
 * Key hierarchy (v1):
 *
 *   password ──Argon2id(salt, params)──► MK  (never leaves this function)
 *   MK ──HKDF-SHA256(info=LABEL_AUTH)──► AK  (sent to server, server stores Argon2id(AK))
 *   MK ──HKDF-SHA256(info=LABEL_KEK)───► KEK (non-extractable, wraps VK)
 *   VK = 256 random bits, stored on server only as AES-GCM(KEK, VK, aad=userId)
 *   notes = AES-GCM(VK, payload, aad=userId‖noteId‖version)
 */

export const LABEL_AUTH = 'zk-notes/v1/auth-key';
export const LABEL_KEK = 'zk-notes/v1/key-encryption-key';
export const LABEL_VAULT_KEY_WRAP = 'zk-notes/v1/vault-key';
/** AAD label for the second VK wrap, under the recovery KEK (see recovery.ts). */
export const LABEL_VAULT_KEY_RECOVERY_WRAP = 'zk-notes/v1/vault-key-recovery';

const AES_GCM_256 = { name: 'AES-GCM', length: 256 } as const;

export interface DerivedKeys {
  /** 32 bytes. Safe to send to the server: it reveals nothing about the KEK. */
  authKey: Uint8Array<ArrayBuffer>;
  /** Non-extractable AES-256-GCM key usable only for wrapKey/unwrapKey. */
  kek: CryptoKey;
}

/**
 * Split 32 bytes of high-entropy key material into an auth key (sent to the
 * server) and a KEK (never leaves the client), via HKDF with distinct labels.
 */
export async function splitKey(
  ikm: Uint8Array<ArrayBuffer>,
  authLabel: string,
  kekLabel: string,
): Promise<DerivedKeys> {
  if (ikm.length !== KEY_LENGTH) throw new CryptoInputError('Key material must be 32 bytes');
  const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits', 'deriveKey']);
  const salt = new Uint8Array(0);
  const authBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: utf8Encode(authLabel) },
    base,
    KEY_LENGTH * 8,
  );
  const kek = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: utf8Encode(kekLabel) },
    base,
    AES_GCM_256,
    false,
    ['wrapKey', 'unwrapKey'],
  );
  return { authKey: new Uint8Array(authBits), kek };
}

/** Split MK into the auth key and the KEK. Exposed for domain-separation tests. */
export function splitMasterKey(mk: Uint8Array<ArrayBuffer>): Promise<DerivedKeys> {
  return splitKey(mk, LABEL_AUTH, LABEL_KEK);
}

/** password + salt + params → { authKey, kek }. The MK is wiped before returning. */
export async function deriveKeys(password: string, salt: Uint8Array, params: KdfParams): Promise<DerivedKeys> {
  const mk = await deriveMasterKey(password, salt, params);
  try {
    return await splitMasterKey(mk);
  } finally {
    wipe(mk);
  }
}

export function generateSalt(): Uint8Array<ArrayBuffer> {
  return randomBytes(SALT_LENGTH);
}

function vaultKeyAad(userId: string, label: string): Uint8Array<ArrayBuffer> {
  if (!userId) throw new CryptoInputError('userId required');
  return encodeAad(label, userId);
}

function assertWrapped(w: Sealed): void {
  if (w.iv.length !== IV_LENGTH) throw new CryptoInputError(`IV must be ${IV_LENGTH} bytes`);
  if (w.ciphertext.length !== KEY_LENGTH + TAG_LENGTH) throw new CryptoInputError('Wrapped key has wrong length');
}

/** Wrap an (extractable) VK under a KEK. `label` separates password wraps from recovery wraps. */
export async function wrapVaultKey(
  kek: CryptoKey,
  vk: CryptoKey,
  userId: string,
  label: string = LABEL_VAULT_KEY_WRAP,
): Promise<Sealed> {
  const iv = randomBytes(IV_LENGTH);
  const ct = await crypto.subtle.wrapKey('raw', vk, kek, {
    name: 'AES-GCM',
    iv,
    additionalData: vaultKeyAad(userId, label),
    tagLength: TAG_LENGTH * 8,
  });
  return { iv, ciphertext: new Uint8Array(ct) };
}

/**
 * Unwrap the Vault Key. By default the result is NON-extractable: page script
 * (including an XSS payload) can use it but cannot export its bytes.
 */
export async function unwrapVaultKey(
  kek: CryptoKey,
  wrapped: Sealed,
  userId: string,
  extractable = false,
  label: string = LABEL_VAULT_KEY_WRAP,
): Promise<CryptoKey> {
  assertWrapped(wrapped);
  try {
    return await crypto.subtle.unwrapKey(
      'raw',
      wrapped.ciphertext,
      kek,
      { name: 'AES-GCM', iv: wrapped.iv, additionalData: vaultKeyAad(userId, label), tagLength: TAG_LENGTH * 8 },
      AES_GCM_256,
      extractable,
      ['encrypt', 'decrypt'],
    );
  } catch {
    throw new DecryptionError('Could not unlock vault: wrong password or corrupted key');
  }
}

/** Generate a fresh random VK and wrap it. Returns a non-extractable working copy. */
export async function createVaultKey(
  kek: CryptoKey,
  userId: string,
): Promise<{ vaultKey: CryptoKey; wrapped: Sealed }> {
  const extractable = await crypto.subtle.generateKey(AES_GCM_256, true, ['encrypt', 'decrypt']);
  const wrapped = await wrapVaultKey(kek, extractable, userId);
  // Re-import as non-extractable via unwrap so no extractable copy survives.
  const vaultKey = await unwrapVaultKey(kek, wrapped, userId, false);
  return { vaultKey, wrapped };
}

/** Password change: re-wrap the same VK under a new KEK. Notes need no re-encryption. */
export async function rewrapVaultKey(
  oldKek: CryptoKey,
  newKek: CryptoKey,
  wrapped: Sealed,
  userId: string,
): Promise<Sealed> {
  const temp = await unwrapVaultKey(oldKek, wrapped, userId, true);
  return wrapVaultKey(newKek, temp, userId);
}
