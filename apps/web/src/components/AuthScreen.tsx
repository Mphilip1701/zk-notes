import { normalizeEmail, unlockVault } from '@zk-notes/crypto';
import { useState, type FormEvent } from 'react';
import { api, type VaultBundle } from '../lib/api';
import { describeError } from '../lib/errors';
import { kdf } from '../lib/kdfClient';
import { MIN_PASSWORD_LENGTH } from '../lib/policy';
import { RecoverForm } from './RecoverForm';

export function AuthScreen({ onAuthenticated }: { onAuthenticated: (b: VaultBundle, vk: CryptoKey) => void }) {
  const [mode, setMode] = useState<'login' | 'register' | 'recover'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    const addr = normalizeEmail(email);
    try {
      if (mode === 'register') {
        if (password.length < MIN_PASSWORD_LENGTH) {
          setError(`Use at least ${MIN_PASSWORD_LENGTH} characters. A passphrase of 4+ random words is ideal.`);
          return;
        }
        if (password !== confirm) {
          setError('Passwords do not match.');
          return;
        }
        setBusy('Deriving keys…');
        const { request, vaultKey } = await kdf.register(addr, password);
        setBusy('Creating account…');
        await api.register(request);
        onAuthenticated(
          {
            userId: request.userId,
            email: request.email,
            kdfSalt: request.kdfSalt,
            kdfParams: request.kdfParams,
            wrappedVaultKey: request.wrappedVaultKey,
            vaultKeyIv: request.vaultKeyIv,
            hasRecoveryKey: false,
          },
          vaultKey,
        );
      } else {
        setBusy('Contacting server…');
        const pre = await api.prelogin(addr);
        setBusy('Deriving keys…');
        const { authKey, kek } = await kdf.derive(password, pre.kdfSalt, pre.kdfParams);
        setBusy('Signing in…');
        const bundle = await api.login(addr, authKey);
        const vaultKey = await unlockVault(kek, bundle.userId, bundle);
        onAuthenticated(bundle, vaultKey);
      }
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(null);
      setPassword('');
      setConfirm('');
    }
  }

  if (mode === 'recover') {
    return (
      <div className="center">
        <RecoverForm onAuthenticated={onAuthenticated} onCancel={() => setMode('login')} />
      </div>
    );
  }

  return (
    <div className="center">
      <form className="card auth" onSubmit={submit}>
        <h1>🔐 ZK Notes</h1>
        <p className="muted small">
          End-to-end encrypted. Your password never leaves this device, and the server cannot read your notes.
        </p>
        <div className="tabs" role="tablist">
          <button type="button" role="tab" aria-selected={mode === 'login'} onClick={() => setMode('login')}>
            Sign in
          </button>
          <button type="button" role="tab" aria-selected={mode === 'register'} onClick={() => setMode('register')}>
            Create account
          </button>
        </div>
        <label>
          Email
          <input type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} />
        </label>
        <label>
          Master password
          <input
            type="password"
            autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
            required
            minLength={mode === 'register' ? MIN_PASSWORD_LENGTH : undefined}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        {mode === 'register' && (
          <>
            <label>
              Confirm password
              <input
                type="password"
                autoComplete="new-password"
                required
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
              />
            </label>
            <p className="warning small">
              There is no password reset. After signing up, create a <strong>recovery key</strong>: without one, a
              forgotten master password means your notes cannot be recovered by anyone.
            </p>
          </>
        )}
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <button className="primary" type="submit" disabled={busy !== null}>
          {busy ?? (mode === 'login' ? 'Sign in' : 'Create account')}
        </button>
        {mode === 'login' && (
          <button type="button" className="link" onClick={() => setMode('recover')}>
            Forgot password? Use your recovery key
          </button>
        )}
      </form>
    </div>
  );
}
