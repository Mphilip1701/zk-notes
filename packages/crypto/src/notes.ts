import { open, seal } from './aead.js';
import {
  CryptoInputError,
  DecryptionError,
  concatBytes,
  encodeAad,
  fromBase64,
  toBase64,
  utf8Decode,
  utf8Encode,
} from './encoding.js';

export const LABEL_NOTE = 'zk-notes/v1/note';
/** Plaintexts are padded to a multiple of this to blur exact note lengths. */
export const PAD_BLOCK = 256;
export const MAX_NOTE_PLAINTEXT = 512 * 1024;

export interface NotePayload {
  title: string;
  body: string;
}

/** Context bound into the ciphertext as AAD. Any mismatch fails decryption. */
export interface NoteContext {
  userId: string;
  noteId: string;
  version: number;
}

/** Wire format: base64 strings, exactly what the server stores. */
export interface EncryptedNote {
  iv: string;
  ciphertext: string;
}

export function noteAad(ctx: NoteContext): Uint8Array<ArrayBuffer> {
  if (!ctx.userId || !ctx.noteId) throw new CryptoInputError('userId and noteId required');
  if (!Number.isSafeInteger(ctx.version) || ctx.version < 1) throw new CryptoInputError('version must be >= 1');
  return encodeAad(LABEL_NOTE, ctx.userId, ctx.noteId, ctx.version);
}

/** u32be(len) || json || zero padding up to a multiple of PAD_BLOCK. */
export function padPlaintext(data: Uint8Array): Uint8Array<ArrayBuffer> {
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, data.length, false);
  const unpadded = 4 + data.length;
  const total = Math.ceil(unpadded / PAD_BLOCK) * PAD_BLOCK;
  return concatBytes(len, data, new Uint8Array(total - unpadded));
}

export function unpadPlaintext(padded: Uint8Array): Uint8Array<ArrayBuffer> {
  if (padded.length < 4 || padded.length % PAD_BLOCK !== 0) throw new DecryptionError('Malformed note');
  const len = new DataView(padded.buffer, padded.byteOffset, 4).getUint32(0, false);
  if (len > padded.length - 4) throw new DecryptionError('Malformed note');
  for (let i = 4 + len; i < padded.length; i++) {
    if (padded[i] !== 0) throw new DecryptionError('Malformed note');
  }
  return padded.slice(4, 4 + len);
}

function validatePayload(p: unknown): NotePayload {
  if (typeof p !== 'object' || p === null) throw new DecryptionError('Malformed note');
  const { title, body } = p as Record<string, unknown>;
  if (typeof title !== 'string' || typeof body !== 'string') throw new DecryptionError('Malformed note');
  return { title, body };
}

export async function encryptNote(vaultKey: CryptoKey, ctx: NoteContext, payload: NotePayload): Promise<EncryptedNote> {
  const clean = { title: String(payload.title), body: String(payload.body) };
  const json = utf8Encode(JSON.stringify(clean));
  if (json.length > MAX_NOTE_PLAINTEXT) throw new CryptoInputError('Note too large');
  const sealed = await seal(vaultKey, padPlaintext(json), noteAad(ctx));
  return { iv: toBase64(sealed.iv), ciphertext: toBase64(sealed.ciphertext) };
}

export async function decryptNote(vaultKey: CryptoKey, ctx: NoteContext, enc: EncryptedNote): Promise<NotePayload> {
  let iv: Uint8Array<ArrayBuffer>;
  let ciphertext: Uint8Array<ArrayBuffer>;
  try {
    iv = fromBase64(enc.iv);
    ciphertext = fromBase64(enc.ciphertext);
  } catch {
    throw new DecryptionError('Malformed note');
  }
  const padded = await open(vaultKey, { iv, ciphertext }, noteAad(ctx));
  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8Decode(unpadPlaintext(padded)));
  } catch (e) {
    if (e instanceof DecryptionError) throw e;
    throw new DecryptionError('Malformed note');
  }
  return validatePayload(parsed);
}
