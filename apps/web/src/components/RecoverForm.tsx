import { deriveRecoveryLogin, normalizeEmail, parseRecoveryKey } from '@zk-notes/crypto';
import { useState, type FormEvent } from 'react';
import { ApiError, api, type VaultBundle } from '../lib/api';
import { describeError } from '../lib/errors';
import { kdf } from '../lib/kdfClient';
import { MIN_PASSWORD_LENGTH } from '../lib/policy';

/** "Forgot password?": recovery key + new password → re-wrap the vault key → signed in. */
export function RecoverForm(props: { onAuthenticated: (b: VaultBundle, vk: CryptoKey) => void; onCancel: () => void }) {
  const [email, setEmail] = useState('');
  const [recoveryKey, setRecoveryKey] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (password.length < MIN_PASSWORD_LENGTH) return setError(`Use at least ${MIN_PASSWORD_LENGTH} characters.`);
    if (password !== confirm) return setError('Passwords do not match.');
    try {
      await parseRecoveryKey(recoveryKey);
    } catch {
      return setError("That recovery key isn't valid. Check it for typos (dashes and capitals don't matter).");
    }
    const addr = normalizeEmail(email);
    try {
      setBusy('Checking recovery key…');
      const rec = await deriveRecoveryLogin(recoveryKey);
      const wrap = await api.recoveryVerify(addr, rec.authKey);
      setBusy('Deriving new keys…');
      const { request, vaultKey } = await kdf.recoveryReset({
        userId: wrap.userId,
        recoveryAuthKey: rec.authKey,
        recoveryKek: rec.kek,
        recoveryWrap: wrap,
        newPassword: password,
      });
      setBusy('Saving…');
      const bundle = await api.recoveryComplete(addr, request);
      props.onAuthenticated(bundle, vaultKey);
    } catch (err) {
      if (err instanceof ApiError && err.code === 'invalid_credentials') {
        setError("That recovery key doesn't match this account.");
      } else {
        setError(describeError(err));
      }
    } finally {
      setBusy(null);
      setPassword('');
      setConfirm('');
    }
  }

  return (
    <form className="card auth" onSubmit={submit}>
      <h1>Recover account</h1>
      <p className="muted small">
        Enter the recovery key you saved and choose a new master password. Your notes stay encrypted the whole time.
        All other devices will be signed out.
      </p>
      <label>
        Email
        <input type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} />
      </label>
      {/* Not wrapped in <label>: a wrapped textarea's contents would leak into its accessible name. */}
      <div className="field">
        <label htmlFor="recovery-key-input">Recovery key</label>
        <textarea
          id="recovery-key-input"
          className="recovery-input"
          required
          rows={2}
          spellCheck={false}
          autoComplete="off"
          placeholder="XXXXX-XXXXX-XXXXX-…"
          value={recoveryKey}
          onChange={(e) => setRecoveryKey(e.target.value)}
        />
      </div>
      <label>
        New master password
        <input type="password" autoComplete="new-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
      </label>
      <label>
        Confirm new password
        <input type="password" autoComplete="new-password" required value={confirm} onChange={(e) => setConfirm(e.target.value)} />
      </label>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <button className="primary" type="submit" disabled={busy !== null}>
        {busy ?? 'Recover account'}
      </button>
      <button type="button" className="link" onClick={props.onCancel}>
        Back to sign in
      </button>
    </form>
  );
}
