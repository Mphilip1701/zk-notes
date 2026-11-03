/**
 * Byte/encoding helpers. Pure functions, no dependencies, safe in browsers,
 * Web Workers and Node >= 20.
 */

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

export function utf8Encode(s: string): Uint8Array<ArrayBuffer> {
  return textEncoder.encode(s) as Uint8Array<ArrayBuffer>;
}

export function utf8Decode(b: Uint8Array): string {
  return textDecoder.decode(b);
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

const B64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

export function toBase64(bytes: Uint8Array): string {
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

/** Strict standard-alphabet base64 decoding. Throws on malformed input. */
export function fromBase64(s: string): Uint8Array<ArrayBuffer> {
  if (typeof s !== 'string' || s.length % 4 !== 0 || !B64_RE.test(s)) {
    throw new CryptoInputError('Invalid base64');
  }
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex: string): Uint8Array<ArrayBuffer> {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new CryptoInputError('Invalid hex');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(n);
  // getRandomValues is limited to 65536 bytes per call.
  for (let i = 0; i < n; i += 65536) {
    globalThis.crypto.getRandomValues(out.subarray(i, Math.min(n, i + 65536)));
  }
  return out;
}

/** Best-effort zeroisation (JS cannot guarantee no copies exist). */
export function wipe(b: Uint8Array | undefined | null): void {
  if (b) b.fill(0);
}

/** Constant-time comparison for equal-length byte arrays. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/**
 * Unambiguous encoding of a label plus fields for use as AEAD associated data:
 *   u32be(len(label)) || label || (u32be(len(field)) || field)*
 * Length-prefixing prevents "ab"+"c" colliding with "a"+"bc".
 */
export function encodeAad(label: string, ...fields: (string | number)[]): Uint8Array<ArrayBuffer> {
  const parts: Uint8Array[] = [];
  for (const f of [label, ...fields]) {
    const bytes = utf8Encode(String(f));
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, bytes.length, false);
    parts.push(len, bytes);
  }
  return concatBytes(...parts);
}

export class CryptoInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CryptoInputError';
  }
}

/** Thrown when authenticated decryption fails (wrong key, tampering, wrong context). */
export class DecryptionError extends Error {
  constructor(message = 'Decryption failed: wrong key or data was tampered with') {
    super(message);
    this.name = 'DecryptionError';
  }
}
