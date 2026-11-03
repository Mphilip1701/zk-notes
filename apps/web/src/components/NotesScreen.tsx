import { decryptNote, encryptNote } from '@zk-notes/crypto';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ApiError, api, type NoteWire, type VaultBundle } from '../lib/api';
import { describeError } from '../lib/errors';
import { useIdle } from '../lib/useIdle';
import { ChangePasswordDialog } from './ChangePasswordDialog';

const AUTO_LOCK_MS = 15 * 60_000;

interface Note {
  id: string;
  version: number;
  updatedAt: string;
  title: string;
  body: string;
  /** Decryption failed: wrong key, tampering, or the server swapped/rolled back data. */
  broken?: boolean;
}

interface Props {
  bundle: VaultBundle;
  vaultKey: CryptoKey;
  onLock: () => void;
  onLogout: () => void;
  onSessionLost: (e: unknown) => void;
  onBundleChanged: (b: VaultBundle) => void;
}

export function NotesScreen({ bundle, vaultKey, onLock, onLogout, onSessionLost, onBundleChanged }: Props) {
  const userId = bundle.userId;
  const [notes, setNotes] = useState<Note[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [draft, setDraft] = useState({ title: '', body: '' });
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [showChangePw, setShowChangePw] = useState(false);
  /** Highest version seen per note this session: detects server-side rollback. */
  const seenVersions = useRef(new Map<string, number>());

  const selected = notes.find((n) => n.id === selectedId) ?? null;
  const dirty = !!selected && !selected.broken && (draft.title !== selected.title || draft.body !== selected.body);

  const decryptWire = useCallback(
    async (w: NoteWire): Promise<Note> => {
      try {
        const p = await decryptNote(vaultKey, { userId, noteId: w.id, version: w.version }, w);
        return { id: w.id, version: w.version, updatedAt: w.updatedAt, ...p };
      } catch {
        return { id: w.id, version: w.version, updatedAt: w.updatedAt, title: '⚠ Unreadable note', body: '', broken: true };
      }
    },
    [vaultKey, userId],
  );

  const fail = useCallback(
    (e: unknown) => {
      setError(describeError(e));
      onSessionLost(e);
    },
    [onSessionLost],
  );

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const { notes: wire } = await api.listNotes();
      const rolledBack = wire.filter((w) => (seenVersions.current.get(w.id) ?? 0) > w.version);
      if (rolledBack.length) {
        setError(`Warning: the server returned older versions of ${rolledBack.length} note(s) than seen before.`);
      }
      for (const w of wire) {
        seenVersions.current.set(w.id, Math.max(w.version, seenVersions.current.get(w.id) ?? 0));
      }
      setNotes(await Promise.all(wire.map(decryptWire)));
    } catch (e) {
      fail(e);
    } finally {
      setLoading(false);
    }
  }, [decryptWire, fail]);

  useEffect(() => {
    void load();
  }, [load]);

  function select(n: Note) {
    if (dirty && !window.confirm('Discard unsaved changes?')) return;
    setSelectedId(n.id);
    setDraft({ title: n.title, body: n.body });
    setStatus(null);
  }

  async function createNote() {
    if (dirty && !window.confirm('Discard unsaved changes?')) return;
    setError(null);
    const id = crypto.randomUUID();
    const payload = { title: 'Untitled', body: '' };
    try {
      const enc = await encryptNote(vaultKey, { userId, noteId: id, version: 1 }, payload);
      const w = await api.createNote(id, enc);
      seenVersions.current.set(id, 1);
      setNotes((ns) => [{ id, version: 1, updatedAt: w.updatedAt, ...payload }, ...ns]);
      setSelectedId(id);
      setDraft(payload);
    } catch (e) {
      fail(e);
    }
  }

  const save = useCallback(async () => {
    if (!selected || !dirty || saving) return;
    setSaving(true);
    setError(null);
    const version = selected.version + 1;
    try {
      const enc = await encryptNote(vaultKey, { userId, noteId: selected.id, version }, draft);
      const w = await api.updateNote(selected.id, version, enc);
      seenVersions.current.set(selected.id, version);
      setNotes((ns) =>
        [{ ...selected, ...draft, version, updatedAt: w.updatedAt }, ...ns.filter((n) => n.id !== selected.id)],
      );
      setStatus('Saved · encrypted');
    } catch (e) {
      fail(e);
      if (e instanceof ApiError && e.code === 'version_conflict') setStatus('Conflict: reload to see the latest');
    } finally {
      setSaving(false);
    }
  }, [selected, dirty, saving, vaultKey, userId, draft, fail]);

  async function remove() {
    if (!selected || !window.confirm(`Delete “${selected.title || 'Untitled'}”? This cannot be undone.`)) return;
    try {
      await api.deleteNote(selected.id);
      setNotes((ns) => ns.filter((n) => n.id !== selected.id));
      setSelectedId(null);
    } catch (e) {
      fail(e);
    }
  }

  // Ctrl/Cmd+S to save.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
        e.preventDefault();
        void save();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [save]);

  // Warn before leaving with unsaved changes.
  useEffect(() => {
    if (!dirty) return;
    const h = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener('beforeunload', h);
    return () => window.removeEventListener('beforeunload', h);
  }, [dirty]);

  // Auto-lock: drop the vault key from memory after inactivity (saving first).
  const saveRef = useRef(save);
  saveRef.current = save;
  useIdle(AUTO_LOCK_MS, () => {
    void saveRef.current().finally(onLock);
  });

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return notes;
    return notes.filter((n) => n.title.toLowerCase().includes(q) || n.body.toLowerCase().includes(q));
  }, [notes, query]);

  return (
    <div className="layout">
      <header className="topbar">
        <strong>🔐 ZK Notes</strong>
        <span className="muted small grow">{bundle.email}</span>
        <button onClick={() => setShowChangePw(true)}>Change password</button>
        <button onClick={onLock} title="Remove keys from memory">
          Lock
        </button>
        <button onClick={onLogout}>Sign out</button>
      </header>

      <aside className="sidebar">
        <div className="row">
          <input
            className="grow"
            type="search"
            placeholder="Search (local, decrypted)"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Search notes"
          />
          <button className="primary" onClick={createNote}>
            New
          </button>
        </div>
        {loading && <p className="muted small">Decrypting…</p>}
        {!loading && notes.length === 0 && <p className="muted small">No notes yet.</p>}
        <ul className="note-list">
          {filtered.map((n) => (
            <li key={n.id}>
              <button
                className={`note-item${n.id === selectedId ? ' active' : ''}${n.broken ? ' broken' : ''}`}
                onClick={() => select(n)}
              >
                <span className="note-title">{n.title || 'Untitled'}</span>
                <span className="muted small">{new Date(n.updatedAt).toLocaleString()}</span>
              </button>
            </li>
          ))}
        </ul>
      </aside>

      <main className="editor">
        {error && (
          <p className="error" role="alert">
            {error}{' '}
            <button className="link" onClick={() => setError(null)}>
              Dismiss
            </button>
          </p>
        )}
        {!selected && <p className="muted center-text">Select a note or create a new one.</p>}
        {selected?.broken && (
          <p className="error">
            This note failed integrity verification and cannot be decrypted. It may have been corrupted or tampered
            with on the server.
          </p>
        )}
        {selected && !selected.broken && (
          <>
            <input
              className="title-input"
              value={draft.title}
              onChange={(e) => setDraft((d) => ({ ...d, title: e.target.value }))}
              placeholder="Title"
              aria-label="Title"
            />
            <textarea
              className="body-input"
              value={draft.body}
              onChange={(e) => setDraft((d) => ({ ...d, body: e.target.value }))}
              placeholder="Write something…"
              aria-label="Note body"
            />
            <div className="row">
              <button className="primary" onClick={() => void save()} disabled={!dirty || saving}>
                {saving ? 'Encrypting…' : 'Save'}
              </button>
              <span className="muted small grow">{dirty ? 'Unsaved changes' : status}</span>
              {status?.startsWith('Conflict') && <button onClick={() => void load()}>Reload</button>}
              <button className="danger" onClick={remove}>
                Delete
              </button>
            </div>
          </>
        )}
        {selected?.broken && (
          <button className="danger" onClick={remove}>
            Delete
          </button>
        )}
      </main>

      {showChangePw && (
        <ChangePasswordDialog bundle={bundle} onClose={() => setShowChangePw(false)} onChanged={onBundleChanged} />
      )}
    </div>
  );
}
