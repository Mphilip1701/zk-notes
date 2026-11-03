# ZK Notes

A zero-knowledge, end-to-end encrypted notes app. Notes are encrypted in the browser with AES-256-GCM under keys
derived from your master password. The server stores only ciphertext, IVs, salts and wrapped keys, and **cannot read
your notes**.

- **Frontend:** React + TypeScript (Vite). Argon2id runs in a Web Worker through hash-wasm (WASM).
- **Backend:** Node + Express + PostgreSQL
- **Crypto:** `packages/crypto`, shared by the browser and Node, and unit tested against published test vectors

See **[THREAT_MODEL.md](./THREAT_MODEL.md)** for the full security design, what it protects against, and what it doesn't.

## Key hierarchy

```
password ─Argon2id(64 MiB, t=3)─► MK ─HKDF("auth-key")─► AK ──► server stores Argon2id(AK)
                                     └HKDF("kek")──────► KEK ─wraps─► VK (random 256-bit) ─encrypts─► notes
```

- The password and MK never leave the client. The server never sees the KEK or VK; it only stores the VK wrapped.
- Logging in sends **AK** only. AK and KEK are independent HKDF outputs, so the server can authenticate you without
  being able to decrypt anything.
- Every ciphertext is bound by AAD to `userId`, `noteId` and `version`, so the server can't swap notes between users or
  notes, or relabel an old ciphertext as a newer version.
- Changing your password re-wraps the VK. Notes are not re-encrypted.

## Layout

```
packages/crypto   KDF, HKDF split, AES-GCM, VK wrap/unwrap, note encryption, high-level flows (+ tests)
apps/server       Express API: auth, sessions, CSRF, rate limiting, notes blob storage (+ integration tests)
apps/web          React client
```

## Getting started

Requires Node ≥ 20 and PostgreSQL 16 (or Docker).

```bash
npm install
```

```bash
docker compose up -d          # Postgres on 127.0.0.1:5432, plus the zknotes_test database
```

```bash
cp .env.example .env && sed -i "s/^SERVER_SECRET=.*/SERVER_SECRET=$(openssl rand -hex 32)/" .env
```

```bash
npm run build -w @zk-notes/crypto
```

**Development** uses two terminals. Vite proxies `/api` to the server, so the browser sees a single origin
(`http://localhost:5173`).

```bash
npm run dev:server
```

```bash
npm run dev:web
```

**Production-style** (single origin, strict CSP, the server serves the built client):

```bash
npm run build
```

```bash
cd apps/server && NODE_ENV=production ALLOWED_ORIGINS=https://notes.example.com STATIC_DIR=../web/dist npm start
```

Put the server behind a TLS-terminating proxy and set `TRUST_PROXY` to match (see THREAT_MODEL.md §8).

## Tests

```bash
npm test
```

This runs:
- **`packages/crypto`:** 67 unit tests, no database needed. They cover:
  - Argon2id reference vector, HKDF RFC 5869 vectors, AES-GCM known-answer vectors
  - tamper, wrong-key and AAD-mismatch detection, IV uniqueness
  - domain separation (AK cannot unwrap VK), non-extractability, KDF downgrade refusal
  - padding, and the full register / login / password-change flows
- **`apps/server`:** 49 integration tests against real Postgres (`TEST_DATABASE_URL`, default
  `postgres://zknotes:zknotes@localhost:5432/zknotes_test`). They cover:
  - cookie flags, session fixation, idle and absolute expiry, logout revocation
  - CSRF and Origin checks, enumeration resistance
  - per-account and per-IP rate limits (shared across instances)
  - note isolation between users, optimistic concurrency
  - an end-to-end check with the real crypto library that the database holds only ciphertext

## API

All endpoints are under `/api`, JSON only and same-origin only. Every state-changing request needs an allowed `Origin`
header. Authenticated state-changing requests also need `X-CSRF-Token`.

| Method | Path | Auth | Body → Response |
|---|---|---|---|
| POST | `/auth/prelogin` | – | `{email}` → `{kdfSalt, kdfParams}` (a decoy for unknown emails) |
| POST | `/auth/register` | – | `{userId, email, kdfSalt, kdfParams, authKey, wrappedVaultKey, vaultKeyIv}` → `{userId, email, csrfToken}` |
| POST | `/auth/login` | – | `{email, authKey}` → vault bundle + `csrfToken` |
| GET | `/auth/session` | cookie | → vault bundle + `csrfToken` (used to re-unlock after a reload) |
| POST | `/auth/logout` | cookie + CSRF | → 204 |
| POST | `/auth/change-password` | cookie + CSRF | `{currentAuthKey, newKdfSalt, newKdfParams, newAuthKey, newWrappedVaultKey, newVaultKeyIv}` → `{csrfToken}` |
| GET | `/notes` | cookie | → `{notes: [{id, ciphertext, iv, version, createdAt, updatedAt}]}` |
| POST | `/notes` | cookie + CSRF | `{id, ciphertext, iv}` → note (version 1) |
| PUT | `/notes/:id` | cookie + CSRF | `{ciphertext, iv, version}` → note. `version` must equal current + 1, otherwise 409 |
| DELETE | `/notes/:id` | cookie + CSRF | → 204 |
