import { decryptNote, encryptNote } from '@zk-notes/crypto';
import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { Client, fakeNoteBlob, realRegistration, registeredClient, useTestDb } from './helpers.js';

const { db, app: makeApp } = useTestDb();

describe('notes API', () => {
  it('CRUD with optimistic versioning', async () => {
    const { client } = await registeredClient(makeApp());
    const id = randomUUID();
    const v1 = fakeNoteBlob();
    const created = await client.req('post', '/api/notes', { id, ...v1 });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ id, version: 1, ciphertext: v1.ciphertext, iv: v1.iv });

    const v2 = fakeNoteBlob();
    const updated = await client.req('put', `/api/notes/${id}`, { ...v2, version: 2 });
    expect(updated.status).toBe(200);
    expect(updated.body.version).toBe(2);

    // Stale writer (thinks it is producing v2 again) is rejected.
    const stale = await client.req('put', `/api/notes/${id}`, { ...fakeNoteBlob(), version: 2 });
    expect(stale.status).toBe(409);
    expect(stale.body).toEqual({ error: 'version_conflict', currentVersion: 2 });
    // Skipping versions is rejected too.
    expect((await client.req('put', `/api/notes/${id}`, { ...fakeNoteBlob(), version: 4 })).status).toBe(409);

    const list = await client.req('get', '/api/notes');
    expect(list.body.notes).toHaveLength(1);
    expect(list.body.notes[0]).toMatchObject({ id, version: 2, ciphertext: v2.ciphertext });

    expect((await client.req('delete', `/api/notes/${id}`)).status).toBe(204);
    expect((await client.req('delete', `/api/notes/${id}`)).status).toBe(404);
    expect((await client.req('get', '/api/notes')).body.notes).toHaveLength(0);
  });

  it('duplicate note id is a conflict', async () => {
    const { client } = await registeredClient(makeApp());
    const id = randomUUID();
    await client.req('post', '/api/notes', { id, ...fakeNoteBlob() });
    expect((await client.req('post', '/api/notes', { id, ...fakeNoteBlob() })).status).toBe(409);
  });

  it('users are fully isolated from each other', async () => {
    const app = makeApp();
    const { client: alice } = await registeredClient(app);
    const { client: mallory } = await registeredClient(app);
    const id = randomUUID();
    await alice.req('post', '/api/notes', { id, ...fakeNoteBlob() });

    expect((await mallory.req('get', '/api/notes')).body.notes).toHaveLength(0);
    expect((await mallory.req('put', `/api/notes/${id}`, { ...fakeNoteBlob(), version: 2 })).status).toBe(404);
    expect((await mallory.req('delete', `/api/notes/${id}`)).status).toBe(404);
    // Mallory can reuse the same id in her own namespace without touching Alice's.
    expect((await mallory.req('post', '/api/notes', { id, ...fakeNoteBlob() })).status).toBe(201);
    expect((await alice.req('get', '/api/notes')).body.notes[0].version).toBe(1);
  });

  it.each([
    ['too-short ciphertext', { ciphertext: Buffer.alloc(10).toString('base64') }],
    ['bad IV', { iv: Buffer.alloc(16).toString('base64') }],
    ['non-base64', { ciphertext: '%%%%' }],
    ['plaintext field smuggled in', { title: 'leak' }],
  ])('rejects %s', async (_n, patch) => {
    const { client } = await registeredClient(makeApp());
    const res = await client.req('post', '/api/notes', { id: randomUUID(), ...fakeNoteBlob(), ...patch });
    expect(res.status).toBe(400);
  });

  it('rejects non-uuid ids in the path', async () => {
    const { client } = await registeredClient(makeApp());
    expect((await client.req('delete', '/api/notes/1%20OR%201=1')).status).toBe(400);
  });

  it('end-to-end: the server stores only ciphertext it cannot read', async () => {
    const app = makeApp();
    const { request: reg, vaultKey } = await realRegistration('e2e@example.com', 'a long enough password');
    const c = new Client(app);
    await c.req('post', '/api/auth/register', reg);

    const id = randomUUID();
    const secret = { title: 'Bank PIN', body: 'TOP-SECRET-1234' };
    const enc = await encryptNote(vaultKey, { userId: reg.userId, noteId: id, version: 1 }, secret);
    expect((await c.req('post', '/api/notes', { id, ...enc })).status).toBe(201);

    const { rows } = await db.query('SELECT ciphertext FROM notes WHERE id = $1', [id]);
    expect(rows[0].ciphertext.toString('latin1')).not.toContain('TOP-SECRET');
    expect(rows[0].ciphertext.toString('latin1')).not.toContain('Bank PIN');

    const fetched = (await c.req('get', '/api/notes')).body.notes[0];
    expect(await decryptNote(vaultKey, { userId: reg.userId, noteId: id, version: fetched.version }, fetched)).toEqual(
      secret,
    );
  });
});
