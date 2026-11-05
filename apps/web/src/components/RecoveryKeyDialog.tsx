import { useState, type FormEvent } from 'react';
import { api, type VaultBundle } from '../lib/api';
import { describeError } from '../lib/errors';
import { kdf } from '../lib/kdfClient';

type Step = { kind: 'password'; action: 'create' | 'remove' } | { kind: 'show'; recoveryKey: string };

/**
 * Create, replace or remove the recovery key. The key is shown exactly once
 * and never sent to the server (only values derived from it are).
 */
export function RecoveryKeyDialog(props: {
  bundle: VaultBundle;
  onClose: () => void;
  onChanged: (b: VaultBundle) => void;
}) {
  const { bundle } = props;
  const [step, setStep] = useState<Step>({ kind: 'password', action: 'create' });
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);

  async function submitPassword(e: FormEvent) {
    e.preventDefault();
    if (step.kind !== 'password') return;
    setBusy(true);
    setError(null);
    try {
      if (step.action === 'create') {
        const { request, recoveryKey } = await kdf.recoverySetup({
          userId: bundle.userId,
          password,
          kdfSalt: bundle.kdfSalt,
          kdfParams: bundle.kdfParams,
          current: bundle,
        });
        await api.setRecoveryKey(request);
        props.onChanged({ ...bundle, hasRecoveryKey: true });
        setStep({ kind: 'show', recoveryKey });
      } else {
        const { authKey } = await kdf.derive(password, bundle.kdfSalt, bundle.kdfParams);
        await api.removeRecoveryKey(authKey);
        props.onChanged({ ...bundle, hasRecoveryKey: false });
        props.onClose();
      }
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
      setPassword('');
    }
  }

  async function copy(key: string) {
    try {
      await navigator.clipboard.writeText(key);
      setCopied(true);
    } catch {
      setError('Could not access the clipboard. Select the key and copy it manually.');
    }
  }

  function download(key: string) {
    const text = [
      'ZK Notes recovery key',
      '',
      `Account: ${bundle.email}`,
      `Created: ${new Date().toISOString().slice(0, 10)}`,
      '',
      key,
      '',
      'Use this on the sign-in screen ("Forgot password?") to set a new master password.',
      'Anyone with this key and your email can read your notes. Store it offline (print it,',
      'or keep it in a password manager), and never share it.',
      '',
    ].join('\n');
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = 'zk-notes-recovery-key.txt';
    a.click();
    URL.revokeObjectURL(url);
  }

  if (step.kind === 'show') {
    return (
      <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="rk-title">
        <div className="card auth wide">
          <h2 id="rk-title">Your recovery key</h2>
          <p className="warning small">
            This is the <strong>only time</strong> it will be shown. Anyone with this key can read your notes, so
            store it somewhere safe and offline: print it, or save it in a password manager.
          </p>
          <code className="recovery-key" aria-label="Recovery key">
            {/* One unbreakable span per group, so lines only wrap between groups. */}
            {step.recoveryKey.split('-').map((group, i) => (
              <span key={i} className="rk-group">
                {i > 0 ? '-' : ''}
                {group}
              </span>
            ))}
          </code>
          <div className="row">
            <button type="button" onClick={() => void copy(step.recoveryKey)}>
              {copied ? 'Copied ✓' : 'Copy'}
            </button>
            <button type="button" onClick={() => download(step.recoveryKey)}>
              Download .txt
            </button>
          </div>
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          <label className="checkbox">
            <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />I have saved my
            recovery key somewhere safe
          </label>
          <button className="primary" type="button" disabled={!saved} onClick={props.onClose}>
            Done
          </button>
        </div>
      </div>
    );
  }

  const removing = step.action === 'remove';
  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="rk-title">
      <form className="card auth" onSubmit={submitPassword}>
        <h2 id="rk-title">Recovery key</h2>
        {bundle.hasRecoveryKey ? (
          <p className="muted small">
            A recovery key is set up. You can generate a new one (the old key stops working) or remove it.
          </p>
        ) : (
          <p className="muted small">
            A recovery key lets you set a new master password if you forget yours. Without one, a forgotten password
            means your notes are lost for good.
          </p>
        )}
        {bundle.hasRecoveryKey && (
          <div className="tabs" role="tablist">
            <button
              type="button"
              role="tab"
              aria-selected={!removing}
              onClick={() => setStep({ kind: 'password', action: 'create' })}
            >
              Generate new key
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={removing}
              onClick={() => setStep({ kind: 'password', action: 'remove' })}
            >
              Remove key
            </button>
          </div>
        )}
        <label>
          Confirm with your master password
          <input
            type="password"
            autoComplete="current-password"
            autoFocus
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        {removing && (
          <p className="warning small">After removing it, a forgotten password can no longer be recovered.</p>
        )}
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <div className="row">
          <button type="button" onClick={props.onClose} disabled={busy}>
            Cancel
          </button>
          <button className={removing ? 'danger' : 'primary'} type="submit" disabled={busy}>
            {busy ? 'Working…' : removing ? 'Remove recovery key' : bundle.hasRecoveryKey ? 'Generate new key' : 'Create recovery key'}
          </button>
        </div>
      </form>
    </div>
  );
}
