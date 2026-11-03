import { useState, type FormEvent } from 'react';
import { describeError } from '../lib/errors';

export function UnlockScreen(props: { email: string; onUnlock: (pw: string) => Promise<void>; onLogout: () => void }) {
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await props.onUnlock(password);
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
      setPassword('');
    }
  }

  return (
    <div className="center">
      <form className="card auth" onSubmit={submit}>
        <h1>🔒 Vault locked</h1>
        <p className="muted small">
          Signed in as <strong>{props.email}</strong>. Enter your master password to decrypt your notes on this
          device.
        </p>
        <input type="email" autoComplete="username" value={props.email} readOnly hidden />
        <label>
          Master password
          <input
            type="password"
            autoComplete="current-password"
            autoFocus
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <button className="primary" type="submit" disabled={busy}>
          {busy ? 'Deriving keys…' : 'Unlock'}
        </button>
        <button type="button" className="link" onClick={props.onLogout}>
          Sign out
        </button>
      </form>
    </div>
  );
}
