import { useState, type FormEvent } from 'react';
import { api, type VaultBundle } from '../lib/api';
import { describeError } from '../lib/errors';
import { kdf } from '../lib/kdfClient';
import { MIN_PASSWORD_LENGTH } from './AuthScreen';

export function ChangePasswordDialog(props: {
  bundle: VaultBundle;
  onClose: () => void;
  onChanged: (b: VaultBundle) => void;
}) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (next.length < MIN_PASSWORD_LENGTH) return setError(`Use at least ${MIN_PASSWORD_LENGTH} characters.`);
    if (next !== confirm) return setError('New passwords do not match.');
    setBusy(true);
    try {
      const { bundle } = props;
      const req = await kdf.changePassword({
        userId: bundle.userId,
        currentPassword: current,
        currentKdfSalt: bundle.kdfSalt,
        currentKdfParams: bundle.kdfParams,
        current: bundle,
        newPassword: next,
      });
      await api.changePassword(req);
      props.onChanged({
        ...bundle,
        kdfSalt: req.newKdfSalt,
        kdfParams: req.newKdfParams,
        wrappedVaultKey: req.newWrappedVaultKey,
        vaultKeyIv: req.newVaultKeyIv,
      });
      props.onClose();
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
      setCurrent('');
      setNext('');
      setConfirm('');
    }
  }

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="cp-title">
      <form className="card auth" onSubmit={submit}>
        <h2 id="cp-title">Change master password</h2>
        <p className="muted small">
          Your vault key is re-wrapped under the new password. Notes are not re-encrypted. All other sessions are
          signed out.
        </p>
        <label>
          Current password
          <input type="password" autoComplete="current-password" required value={current} onChange={(e) => setCurrent(e.target.value)} />
        </label>
        <label>
          New password
          <input type="password" autoComplete="new-password" required value={next} onChange={(e) => setNext(e.target.value)} />
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
        <div className="row">
          <button type="button" onClick={props.onClose} disabled={busy}>
            Cancel
          </button>
          <button className="primary" type="submit" disabled={busy}>
            {busy ? 'Working…' : 'Change password'}
          </button>
        </div>
      </form>
    </div>
  );
}
