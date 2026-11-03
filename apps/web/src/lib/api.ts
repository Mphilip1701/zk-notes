import type { KdfParams, PasswordChangeRequest, RegistrationRequest } from '@zk-notes/crypto';

/** Thin same-origin JSON client. Holds the CSRF token in memory only. */

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly body: Record<string, unknown> = {},
  ) {
    super(code);
  }
}

let csrfToken: string | undefined;

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
  const res = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    cache: 'no-store',
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = res.status === 204 ? {} : await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, String(data.error ?? 'request_failed'), data);
  if (typeof data.csrfToken === 'string') csrfToken = data.csrfToken;
  return data as T;
}

export interface VaultBundle {
  userId: string;
  email: string;
  kdfSalt: string;
  kdfParams: KdfParams;
  wrappedVaultKey: string;
  vaultKeyIv: string;
}

export interface NoteWire {
  id: string;
  ciphertext: string;
  iv: string;
  version: number;
  createdAt: string;
  updatedAt: string;
}

export const api = {
  prelogin: (email: string) => call<{ kdfSalt: string; kdfParams: unknown }>('POST', '/api/auth/prelogin', { email }),
  register: (req: RegistrationRequest) => call<{ userId: string; email: string }>('POST', '/api/auth/register', req),
  login: (email: string, authKey: string) => call<VaultBundle>('POST', '/api/auth/login', { email, authKey }),
  session: () => call<VaultBundle>('GET', '/api/auth/session'),
  logout: async () => {
    try {
      await call('POST', '/api/auth/logout');
    } finally {
      csrfToken = undefined;
    }
  },
  changePassword: (req: PasswordChangeRequest) => call('POST', '/api/auth/change-password', req),
  listNotes: () => call<{ notes: NoteWire[] }>('GET', '/api/notes'),
  createNote: (id: string, enc: { iv: string; ciphertext: string }) =>
    call<NoteWire>('POST', '/api/notes', { id, ...enc }),
  updateNote: (id: string, version: number, enc: { iv: string; ciphertext: string }) =>
    call<NoteWire>('PUT', `/api/notes/${encodeURIComponent(id)}`, { version, ...enc }),
  deleteNote: (id: string) => call('DELETE', `/api/notes/${encodeURIComponent(id)}`),
};
