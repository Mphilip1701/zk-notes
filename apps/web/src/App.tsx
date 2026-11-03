import { unlockVault } from '@zk-notes/crypto';
import { useCallback, useEffect, useState } from 'react';
import { AuthScreen } from './components/AuthScreen';
import { NotesScreen } from './components/NotesScreen';
import { UnlockScreen } from './components/UnlockScreen';
import { ApiError, api, type VaultBundle } from './lib/api';
import { kdf } from './lib/kdfClient';

/**
 * State machine:
 *   loading → anonymous (no session) | locked (session, no key) → unlocked
 * The vault key lives only in React state (memory). Reload/lock drops it.
 */
export type AppState =
  | { kind: 'loading' }
  | { kind: 'anonymous' }
  | { kind: 'locked'; bundle: VaultBundle }
  | { kind: 'unlocked'; bundle: VaultBundle; vaultKey: CryptoKey };

export function App() {
  const [state, setState] = useState<AppState>({ kind: 'loading' });

  useEffect(() => {
    api
      .session()
      .then((bundle) => setState({ kind: 'locked', bundle }))
      .catch(() => setState({ kind: 'anonymous' }));
  }, []);

  const onAuthenticated = useCallback((bundle: VaultBundle, vaultKey: CryptoKey) => {
    setState({ kind: 'unlocked', bundle, vaultKey });
  }, []);

  const unlock = useCallback(async (bundle: VaultBundle, password: string) => {
    const { kek } = await kdf.derive(password, bundle.kdfSalt, bundle.kdfParams);
    const vaultKey = await unlockVault(kek, bundle.userId, bundle);
    setState({ kind: 'unlocked', bundle, vaultKey });
  }, []);

  const lock = useCallback(() => {
    setState((s) => (s.kind === 'unlocked' ? { kind: 'locked', bundle: s.bundle } : s));
  }, []);

  const logout = useCallback(async () => {
    await api.logout().catch(() => {});
    setState({ kind: 'anonymous' });
  }, []);

  const onSessionLost = useCallback((e: unknown) => {
    if (e instanceof ApiError && e.status === 401) setState({ kind: 'anonymous' });
  }, []);

  switch (state.kind) {
    case 'loading':
      return <div className="center muted">Loading…</div>;
    case 'anonymous':
      return <AuthScreen onAuthenticated={onAuthenticated} />;
    case 'locked':
      return (
        <UnlockScreen email={state.bundle.email} onUnlock={(pw) => unlock(state.bundle, pw)} onLogout={logout} />
      );
    case 'unlocked':
      return (
        <NotesScreen
          bundle={state.bundle}
          vaultKey={state.vaultKey}
          onLock={lock}
          onLogout={logout}
          onSessionLost={onSessionLost}
          onBundleChanged={(bundle) => setState({ kind: 'unlocked', bundle, vaultKey: state.vaultKey })}
        />
      );
  }
}
