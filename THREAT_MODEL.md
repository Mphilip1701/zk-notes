# Threat Model — ZK Notes

Status: v1 (key hierarchy `v: 1`). Scope: the web client (`apps/web`), the crypto library
(`packages/crypto`), the API server (`apps/server`) and its PostgreSQL database.

## 1. Security goals

| # | Goal |
|---|------|
| G1 | **Confidentiality of note contents** (titles and bodies) against everyone except the user, including the server operator and anyone who obtains the database. |
| G2 | **Integrity of notes**: the server cannot forge, modify, swap between notes/users, or relabel note ciphertexts without the client detecting it. |
| G3 | **The master password and encryption keys never leave the client.** |
| G4 | **Authentication does not reveal encryption keys**: what the server sees at login cannot decrypt anything. |
| G5 | **Account security** against online guessing, session theft, CSRF and session fixation. |
| G6 | **Resistance to offline brute force** when the database leaks, bounded by the strength of the user's password. |

Non-goals are listed in §7.

## 2. Assets

| Asset | Where it lives | Sensitivity |
|---|---|---|
| Master password | User's head; briefly in browser memory / KDF worker | Critical |
| Master Key (MK) | KDF worker memory only, wiped after use | Critical |
| Key-Encryption Key (KEK) | Browser memory, non-extractable `CryptoKey` | Critical |
| Vault Key (VK) | Browser memory, non-extractable `CryptoKey`; server stores it **wrapped** | Critical |
| Auth Key (AK) | Sent to the server over TLS at login; server stores `Argon2id(AK)` | High (it lets you log in, but not decrypt) |
| Recovery key (RK) | Wherever the user saved it (printout, password manager); briefly in browser memory | Critical: **equivalent to the master password** |
| Recovery auth key (RAK) | Sent to the server during recovery; server stores `Argon2id(RAK)` | High (it starts a recovery, but cannot decrypt) |
| Note plaintext | Browser memory only | Critical |
| Note ciphertext, IVs, salts, KDF params, wrapped VK | Server DB | Low (public by design) |
| Session token | `__Host-` HttpOnly cookie; DB stores SHA-256(token) | High |
| `SERVER_SECRET` | Server environment | Medium (CSRF tokens, prelogin decoys, rate-limit key hashing) |
| Metadata: email, note count, sizes, timestamps, IPs | Server DB / logs | Medium |

## 3. Adversaries

| ID | Adversary | Capabilities |
|---|---|---|
| A1 | **Network attacker** | Observes and modifies traffic. TLS is assumed in production; HSTS is set. |
| A2 | **Database thief** | Gets a full copy of the DB, including backups (SQL injection, stolen backup, insider). |
| A3 | **Honest-but-curious server** | Runs the code as written but reads everything it stores or receives. |
| A4 | **Malicious server (data layer)** | Like A3, and also returns arbitrary API responses: swaps, rolls back or forges ciphertext, and sends weak KDF params. It does **not** change the JavaScript it serves (see A5). |
| A5 | **Malicious server (code layer)** | Serves modified JavaScript. **Out of scope**: see §7.1. |
| A6 | **Malicious website** | A page in the user's browser that tries CSRF, login-CSRF, clickjacking or cross-origin reads. |
| A7 | **Online attacker** | Guesses passwords or auth keys against the API, and enumerates accounts. |
| A8 | **Other users** | Authenticated users who try to reach someone else's data (IDOR). |
| A9 | **Compromised endpoint / XSS** | Runs script in the app origin, or controls the device. Partially out of scope: see §7.2. |

## 4. Key hierarchy and protocol

```
password ──NFC──► Argon2id(salt₁₆, m=64 MiB, t=3, p=1) ──► MK (32 B)    [in the KDF worker]
MK ──HKDF-SHA256(info="zk-notes/v1/auth-key")──────────► AK (32 B)     → server
MK ──HKDF-SHA256(info="zk-notes/v1/key-encryption-key")► KEK            (non-extractable, wrap/unwrap only)
VK  = 256 random bits (client CSPRNG)                                    (non-extractable once unwrapped)
wrappedVK = AES-256-GCM(KEK, VK, iv₁₂, aad = len‖"zk-notes/v1/vault-key"‖len‖userId)
note      = AES-256-GCM(VK, pad₂₅₆(len‖JSON{title,body}), iv₁₂,
                        aad = len‖"zk-notes/v1/note"‖len‖userId‖len‖noteId‖len‖version)
server stores: Argon2id(AK; m=19 MiB, t=2, p=1, random salt)
```

- **Domain separation.** AK and KEK come from the same MK through HKDF with different `info` labels. Under HKDF's PRF assumption, AK reveals nothing about the KEK. This is G4.
- **Separate Vault Key.** Changing the password only re-wraps one 32-byte key, and KDF parameters can be raised later without re-encrypting any notes.
- **AAD binding.** Every ciphertext is bound to its owner, its note ID and its version. Length prefixes keep the encoding unambiguous. This covers G2 for swapping and relabelling.
- **Padding.** Plaintexts are padded to multiples of 256 bytes, which hides exact note lengths.
- **IVs.** Each encryption uses a fresh random 96-bit IV. The number of encryptions per VK stays far below the 2³² random-IV limit for GCM; 5,000 notes edited 10⁵ times each is about 2²⁹.
- **KDF parameter policy.** The client refuses parameters below m=19 MiB / t=2 or above m=1 GiB / t=20 / p=8. The server enforces the same limits when parameters are registered.
- **Login.**
  1. `prelogin(email)` returns `{salt, params}`. For unknown emails it returns a decoy salt, `HMAC(k, email)[:16]`, with the default params.
  2. The client derives AK and KEK in a Web Worker.
  3. `login(email, AK)` checks AK against the stored Argon2id hash.
  4. On success the server rotates the session and returns the wrapped VK, which the client unwraps locally.
- **Recovery key (optional).**
  ```
  RK   = 256 random bits (client CSPRNG), shown once as 11 groups of 5 Crockford-base32
         characters, with a 16-bit checksum: SHA-256("zk-notes/v1/recovery-checksum" ‖ RK)[:2]
  RK ──HKDF-SHA256(info="zk-notes/v1/recovery-auth-key")─────────────► RAK  → server stores Argon2id(RAK)
  RK ──HKDF-SHA256(info="zk-notes/v1/recovery-key-encryption-key")──► RKEK (non-extractable, never sent)
  recoveryWrappedVK = AES-256-GCM(RKEK, VK, aad = len‖"zk-notes/v1/vault-key-recovery"‖len‖userId)
  ```
  - RK already has full 256-bit entropy, so it needs no password-hardening KDF. HKDF is enough.
  - **Setup** requires the current password: the client must re-unwrap the VK as extractable in order to wrap it a second time, and the server checks the current AK before storing anything. Generating a new key replaces the old wrap and hash, so the old key stops working.
  - **Recovery:**
    1. `recovery/verify(email, RAK)` returns the recovery-wrapped VK.
    2. The client unwraps the VK with RKEK, picks a new salt and password, and wraps the VK under the new KEK.
    3. `recovery/complete` re-checks RAK, atomically replaces the password credentials, revokes **every** session, and starts a new one.
  - Notes are never re-encrypted, and the recovery key stays valid after it has been used.
- **Page reload.** The session cookie survives a reload but the keys do not. The client fetches the vault bundle and asks for the password again. The VK is unwrapped locally; no server check is involved.

## 5. Threats and mitigations

### 5.1 Confidentiality (G1, G3, G4)

| Threat | Adversary | Mitigation | Test coverage |
|---|---|---|---|
| Server reads notes | A3 | It only ever holds AES-GCM ciphertext. The VK only exists wrapped, under a KEK the server never receives. | `notes.test.ts` (server): DB holds no plaintext. E2E check. |
| Server learns the password from the login request | A3 | Only AK is sent. The password goes through Argon2id and HKDF on the client, and request bodies are validated with strict schemas, so unknown fields such as `password` are rejected. | `account.test.ts`, `auth.test.ts` "unexpected field" |
| Server uses AK to decrypt | A3/A4 | AK and KEK are independent HKDF outputs. Tests confirm AK cannot unwrap the VK. | `keys.test.ts` "knowing the auth key does not let you unwrap" |
| DB leak → offline guessing | A2 | Each guess costs one 64 MiB / t=3 Argon2id plus HKDF plus a GCM tag check against the wrapped VK, and per-user salts rule out precomputation. **Note:** for an attacker who already has the DB, the wrapped VK is a *cheaper* check than the server-side hash, so the server-side Argon2id adds no cost. Its job is to stop a leaked DB from yielding AKs that could be replayed to log in (and download ciphertext). How long a guessing attack takes depends entirely on how strong the password is (§7.3). | `kdf.test.ts`, server stores the `$argon2id$` hash |
| Malicious server downgrades KDF params to make guessing cheap | A4 | The client enforces minimums in `assertKdfParamsAcceptable` before deriving. | `kdf.test.ts` policy table, `account.test.ts` "refuses downgraded params" |
| Malicious server sends huge KDF params (DoS / out of memory) | A4 | The client enforces maximums. | `kdf.test.ts` |
| Eavesdropping in transit | A1 | TLS plus HSTS (2 years). The `Secure` cookie and the `__Host-` prefix mean the cookie is never sent over plain HTTP. Even with TLS broken, the attacker only sees ciphertext and AK. | `csrf.test.ts` headers |
| Key extraction by page script | A9 | KEK and VK are non-extractable `CryptoKey`s. The MK and the raw AK bytes are wiped after use, as far as JavaScript allows. | `keys.test.ts` non-extractable |
| Keys left in memory on an unattended device | A9 | Auto-lock after 15 minutes idle drops the keys. A manual **Lock** button does the same. Keys are never written to localStorage, sessionStorage or IndexedDB. | Manual / E2E |

### 5.2 Integrity (G2)

| Threat | Mitigation | Test |
|---|---|---|
| Ciphertext, IV or tag modified | The GCM tag check fails and the UI marks the note "Unreadable" instead of showing garbage. | `aead.test.ts`, `notes.test.ts` |
| Server swaps note A's ciphertext into note B, or between users | `noteId` and `userId` are in the AAD, so decryption fails. | `notes.test.ts` "context binding" |
| Server relabels an old ciphertext as a newer version | `version` is in the AAD. | `notes.test.ts` "relabelled as a newer version" |
| Server serves an old (version, ciphertext) pair as is (rollback) | **Only partially covered.** The client remembers the highest version it has seen this session and warns if the server returns a lower one. Detecting rollback across sessions or devices would need signed state; see §7.4. | Client logic |
| Server deletes notes, or returns an empty list | **Not prevented.** That is an availability issue (§7.5). | — |
| Wrapped VK swapped with another user's | The VK wrap's AAD contains `userId`. | `keys.test.ts` "bound to the user id" |
| Authentic but malformed plaintext (bug or old client) | Strict unpadding and payload schema checks raise `DecryptionError`. | `notes.test.ts` |
| Lost updates from concurrent edits | Optimistic concurrency: a write must set `version = current + 1`, otherwise the server returns 409. | `notes.test.ts` server CRUD |

### 5.3 Authentication and sessions (G5)

| Threat | Mitigation | Test |
|---|---|---|
| Online guessing of AK or password | Postgres-backed rate limits that hold across instances: **10 failed logins per account per 15 min** (successes don't count, and the key is an HMAC of the email), **40 auth requests per IP per 15 min**, 5 registrations per IP per hour, 5 password changes per user per 15 min. Limits fail closed if the store is down. AK is 256 bits of entropy, so guessing it directly is hopeless; guessing the *password* requires the client-side KDF for each attempt. | `rateLimit.test.ts` |
| CPU or memory exhaustion through login | Server-side Argon2 runs behind a semaphore (default 4 concurrent, 100 queued); beyond that it returns `503 server_busy`. JSON bodies are capped at 1 MB. Note count is capped per user. | Code review |
| Account enumeration via prelogin | Unknown emails get a deterministic decoy salt and the default params. | `auth.test.ts` "stable fake salt" |
| Account enumeration via login timing | Unknown users still go through an Argon2 verification against a dummy hash, and get the same 401 body as a wrong key. | `auth.test.ts` |
| Account enumeration via registration | **Residual risk:** registration returns 409 for an existing email. This is rate limited. Closing it fully needs email verification (§8). | — |
| Session token theft from a DB leak | Only SHA-256(token) is stored, and the tokens are 256-bit random. | `auth.test.ts` "stores only a hash" |
| Session theft by XSS | `HttpOnly` cookie. The strict CSP makes XSS harder. | E2E: `document.cookie` is empty |
| Session fixation | A new token is issued at login and register, and any token presented with the request is revoked. | `auth.test.ts` |
| Long-lived stolen session | 30-minute idle timeout and 7-day absolute lifetime, both enforced on the server. Logout deletes the server row. Password change revokes **all** sessions. | `auth.test.ts` |
| CSRF on authenticated actions | Three layers: (1) `SameSite=Strict`; (2) an Origin allowlist on every state-changing request, plus `Sec-Fetch-Site: cross-site` rejected outright; (3) a session-bound token, `HMAC(k, sessionHash)`, required in the `X-CSRF-Token` header and compared in constant time. Bodies must be `application/json`, which forces a CORS preflight that the server never approves (no CORS headers are sent). | `csrf.test.ts` |
| Login CSRF (logging the victim into the attacker's account) | The Origin check also applies to unauthenticated endpoints. | `csrf.test.ts` "even for login" |
| Clickjacking | `frame-ancestors 'none'` in the CSP. | `csrf.test.ts` |
| One user reaching another's notes (IDOR) | Every query is scoped by `user_id` from the session, and the notes primary key is `(user_id, id)`. | `notes.test.ts` "fully isolated" |
| SQL injection | Only parameterized queries are used. Every input is validated (UUIDs, strict base64, length bounds). | `notes.test.ts` path validation |

### 5.4 Recovery key

| Threat | Mitigation | Test |
|---|---|---|
| Server learns the recovery key | It only receives RAK and the recovery wrap. RAK and RKEK are independent HKDF outputs, and their labels differ from the password-derived keys'. | `recovery.test.ts` (crypto) "domain-separated" |
| DB leak → offline attack via the recovery wrap or `Argon2id(RAK)` | RK has 256 bits of entropy, so brute force is infeasible. Adding a recovery key does **not** weaken the account: the password wrap is still the weakest offline check. | — |
| Online guessing at `recovery/verify` or `recovery/complete` | 256-bit search space, plus **5 failed attempts per account per hour** (keyed by an HMAC of the email) and the per-IP auth limit. Failed recovery attempts do not lock normal login. | `recovery.test.ts` (server) rate limit |
| Account enumeration through recovery | Unknown accounts, accounts without a recovery key, and wrong keys all give the same 401 after the same Argon2id work (a dummy verification). | `recovery.test.ts` (server) "indistinguishable" |
| Someone with a hijacked session replaces or removes the recovery key (locking the user out, or planting their own) | Both actions require a valid session, a CSRF token **and** the current password's AK. | `recovery.test.ts` (server) "requires the current password" |
| Recovery wrap used as a password wrap, or transplanted to another user | Distinct AAD label, and `userId` is in the AAD. | `recovery.test.ts` (crypto) "not interchangeable" |
| Recovery key replaced partway through someone's recovery | `recovery/complete` updates the row only if the stored RAK hash is still the one that was verified; otherwise it returns 409. | Code review |
| A typo locks the user out, or wastes rate-limit budget | The checksum catches typos on the client before anything is sent (about 1 in 65,536 slip through). Input tolerates case, spaces, dashes, and O/0 and I/L/1 confusion. | `recovery.test.ts` (crypto) |
| **Stolen recovery key** | **Residual risk.** RK plus the email is a complete account takeover: the attacker can decrypt everything and set a new password. Mitigations: the UI shows the key only once and tells the user to store it offline; the user can replace or remove it at any time (doing so needs the password); recovery revokes every session, so the real user notices because they are signed out. | — |

### 5.5 Browser hardening

The CSP is: `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`, with `upgrade-insecure-requests` added in production.
- There is no `unsafe-inline` or `unsafe-eval`. `wasm-unsafe-eval` is needed to compile the Argon2 WebAssembly module, and it does not allow JavaScript `eval`.
- Other headers: COOP and CORP `same-origin`, `Referrer-Policy: no-referrer`, `nosniff`, a restrictive `Permissions-Policy`, and `Cache-Control: no-store` on all API responses.
- React escapes all rendered note content, and the code never uses `dangerouslySetInnerHTML`.

## 6. What the server can see (metadata)

Even with the encryption working as designed, the server can see:
- email address, account creation time, KDF parameters
- whether a recovery key is set up, when it was last changed, and when a recovery was used
- number of notes, when each was created and updated, and how many times each was edited (version)
- approximate note size, rounded up to 256 bytes
- client IP addresses, request timing, and the sessions in use

Note titles are encrypted together with the bodies, so they are hidden.

Also, a user with non-default KDF parameters can be told apart from a decoy at prelogin. That leaks one bit: "this account exists and has custom parameters".

## 7. Out of scope / residual risks

### 7.1 Malicious or compromised code delivery (A5)
A server, CDN or build pipeline that serves modified JavaScript can steal the password at the next login. **No browser-based end-to-end encryption design can prevent this.** Mitigations in place: a strict CSP, a same-origin deployment, and no third-party scripts. Possible future work: reproducible builds with published hashes, Subresource Integrity on a signed manifest, or shipping the client as a browser extension or desktop app.

### 7.2 Compromised endpoint or XSS (A9)
Malware, a malicious browser extension or a successful XSS can read plaintext and keystrokes while the vault is unlocked, and can use the non-extractable keys through Web Crypto (it just can't export them). Non-extractability and auto-lock limit how long such access lasts. They do not prevent it.

### 7.3 Weak master passwords
Everything above is only as strong as the password. The client requires at least 12 characters and recommends a passphrase of four or more random words. A low-entropy password *will* fall to offline guessing after a DB leak, whatever the KDF settings. Possible future work: a zxcvbn-style strength meter, and an optional second secret mixed into the KDF (as in 1Password's "Secret Key").

### 7.4 Rollback and freshness
The client detects rollback only within one session. A malicious server can show different devices different, consistent snapshots, or present an older version after a reload. Fixing this needs an authenticated, monotonic vault manifest (for example, a MAC over the `{noteId: version}` map, keyed from the VK, kept on the client).

### 7.5 Availability
The server can delete or withhold data. Users who need durability guarantees should export their notes or keep backups.

### 7.6 Account recovery depends on the user
There is no server-side password reset, and there can't be one: the server cannot decrypt anything. Recovery works only through the optional recovery key (§4, §5.4). If the user forgets the password **and** has no recovery key, or has lost it, the data is permanently lost. The app shows a persistent banner until a recovery key exists. The recovery key is as powerful as the password, so storing it badly creates a second way to lose the account.

### 7.7 Memory hygiene
JavaScript cannot guarantee that secrets are erased: strings are immutable and the garbage collector may copy them. The code wipes byte arrays where it can, keeps keys non-extractable, and never persists secrets, but memory forensics on an unlocked device is out of scope.

### 7.8 Side channels
Web Crypto AES-GCM is implemented natively and is presumed constant time. hash-wasm's Argon2id uses data-independent memory addressing in the first half-pass of the first pass (Argon2id's hybrid design). Network and timing side channels beyond the login timing equalization are out of scope.

### 7.9 Post-quantum
AES-256 and SHA-256 keep a comfortable margin against Grover-type attacks. No public-key cryptography is used, so the scheme isn't exposed to Shor-type attacks.

## 8. Operational requirements

- **TLS is mandatory in production.** Terminate it at a proxy, and set `TRUST_PROXY` correctly so rate limiting sees real client IPs. A wrong setting lets attackers spoof IPs through `X-Forwarded-For`, or puts every client in one bucket.
- **`SERVER_SECRET`:** at least 32 random bytes, kept in a secret manager. Rotating it invalidates CSRF tokens (users reload), changes the decoy salts, and resets account rate-limit keys. It cannot expose any note data.
- **`ALLOWED_ORIGINS`** must list exactly the HTTPS origins the app is served from. Production startup refuses non-HTTPS origins.
- **Database access:** least-privilege role, encrypted backups. A DB leak is still serious because of the metadata (§6) and the offline guessing it enables (§5.1).
- **Logs:** never log request bodies, which contain AK, wrapped keys and ciphertext. The default error handler logs stack traces only.
- **Dependencies:** pin and audit `hash-wasm`, `argon2`, `express` and `pg`. The crypto package has a single runtime dependency, hash-wasm.

## 9. Future hardening (not implemented)

1. A second factor (WebAuthn) gating login, independent of the KDF.
2. Email verification at registration, to close the enumeration gap.
3. A signed vault manifest for detecting rollback and deletion (§7.4).
4. Per-note keys wrapped by the VK, to support sharing.
5. Delivery integrity for the client code (§7.1).
6. Account deletion and data export endpoints.
7. Email notification when a recovery key is used or changed, so a stolen recovery key gets noticed sooner.
