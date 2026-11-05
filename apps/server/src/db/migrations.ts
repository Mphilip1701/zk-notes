/**
 * Ordered, append-only migrations. Never edit one that has shipped; add a new one.
 * The server stores ONLY: email, KDF salt + params, Argon2id(authKey),
 * the wrapped vault key + IV, and per-note ciphertext + IV + version.
 */
export const migrations: { id: string; sql: string }[] = [
  {
    id: '001_initial',
    sql: `
      CREATE TABLE users (
        id                uuid PRIMARY KEY,
        email             text NOT NULL UNIQUE CHECK (email = lower(email) AND length(email) <= 254),
        kdf_salt          bytea NOT NULL CHECK (octet_length(kdf_salt) = 16),
        kdf_params        jsonb NOT NULL,
        auth_hash         text NOT NULL,
        wrapped_vault_key bytea NOT NULL CHECK (octet_length(wrapped_vault_key) = 48),
        vault_key_iv      bytea NOT NULL CHECK (octet_length(vault_key_iv) = 12),
        created_at        timestamptz NOT NULL DEFAULT now(),
        updated_at        timestamptz NOT NULL DEFAULT now()
      );

      -- Only SHA-256(token) is stored, so a DB read does not yield usable session cookies.
      CREATE TABLE sessions (
        token_hash   bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
        user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at   timestamptz NOT NULL DEFAULT now(),
        last_seen_at timestamptz NOT NULL DEFAULT now(),
        expires_at   timestamptz NOT NULL
      );
      CREATE INDEX sessions_user_idx ON sessions (user_id);
      CREATE INDEX sessions_expires_idx ON sessions (expires_at);

      CREATE TABLE notes (
        user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        id         uuid NOT NULL,
        ciphertext bytea NOT NULL,
        iv         bytea NOT NULL CHECK (octet_length(iv) = 12),
        version    integer NOT NULL CHECK (version >= 1),
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY (user_id, id)
      );
      CREATE INDEX notes_user_updated_idx ON notes (user_id, updated_at DESC);

      CREATE UNLOGGED TABLE rate_limits (
        key      text PRIMARY KEY,
        hits     integer NOT NULL,
        reset_at timestamptz NOT NULL
      );
      CREATE INDEX rate_limits_reset_idx ON rate_limits (reset_at);
    `,
  },
  {
    id: '002_recovery_key',
    sql: `
      -- Optional second wrap of the vault key under a client-held recovery key.
      ALTER TABLE users
        ADD COLUMN recovery_auth_hash         text,
        ADD COLUMN recovery_wrapped_vault_key bytea CHECK (octet_length(recovery_wrapped_vault_key) = 48),
        ADD COLUMN recovery_vault_key_iv      bytea CHECK (octet_length(recovery_vault_key_iv) = 12),
        ADD COLUMN recovery_updated_at        timestamptz,
        ADD CONSTRAINT users_recovery_all_or_none CHECK (
          (recovery_auth_hash IS NULL) = (recovery_wrapped_vault_key IS NULL)
          AND (recovery_auth_hash IS NULL) = (recovery_vault_key_iv IS NULL)
        );
    `,
  },
];
