import { Router } from 'express';
import type { Db } from '../db/pool.js';
import { HttpError } from '../errors.js';
import { createNoteSchema, noteIdSchema, updateNoteSchema } from '../validation.js';

export const MAX_NOTES_PER_USER = 5000;

interface NoteRow {
  id: string;
  ciphertext: Buffer;
  iv: Buffer;
  version: number;
  created_at: Date;
  updated_at: Date;
}

function toWire(n: NoteRow) {
  return {
    id: n.id,
    ciphertext: n.ciphertext.toString('base64'),
    iv: n.iv.toString('base64'),
    version: n.version,
    createdAt: n.created_at.toISOString(),
    updatedAt: n.updated_at.toISOString(),
  };
}

/** Opaque blob storage. The server cannot read, search or validate note contents. */
export function notesRouter(db: Db): Router {
  const r = Router();

  r.get('/', async (req, res) => {
    const { rows } = await db.query<NoteRow>(
      'SELECT id, ciphertext, iv, version, created_at, updated_at FROM notes WHERE user_id = $1 ORDER BY updated_at DESC',
      [req.auth!.userId],
    );
    res.json({ notes: rows.map(toWire) });
  });

  r.post('/', async (req, res) => {
    const body = createNoteSchema.parse(req.body);
    const userId = req.auth!.userId;
    const { rows } = await db.query<NoteRow>(
      `INSERT INTO notes (user_id, id, ciphertext, iv, version)
       SELECT $1, $2, $3, $4, 1
        WHERE (SELECT count(*) FROM notes WHERE user_id = $1) < $5
       ON CONFLICT DO NOTHING
       RETURNING id, ciphertext, iv, version, created_at, updated_at`,
      [userId, body.id, body.ciphertext, body.iv, MAX_NOTES_PER_USER],
    );
    const row = rows[0];
    if (!row) {
      const exists = await db.query('SELECT 1 FROM notes WHERE user_id = $1 AND id = $2', [userId, body.id]);
      throw exists.rowCount ? new HttpError(409, 'note_exists') : new HttpError(403, 'note_limit_reached');
    }
    res.status(201).json(toWire(row));
  });

  r.put('/:id', async (req, res) => {
    const id = noteIdSchema.parse(req.params.id);
    const body = updateNoteSchema.parse(req.body);
    const userId = req.auth!.userId;
    // Optimistic concurrency: only succeeds if the stored version is exactly version - 1.
    const { rows } = await db.query<NoteRow>(
      `UPDATE notes SET ciphertext = $1, iv = $2, version = $3, updated_at = now()
        WHERE user_id = $4 AND id = $5 AND version = $3 - 1
        RETURNING id, ciphertext, iv, version, created_at, updated_at`,
      [body.ciphertext, body.iv, body.version, userId, id],
    );
    const row = rows[0];
    if (!row) {
      const cur = await db.query<{ version: number }>('SELECT version FROM notes WHERE user_id = $1 AND id = $2', [
        userId,
        id,
      ]);
      if (!cur.rows[0]) throw new HttpError(404, 'not_found');
      throw new HttpError(409, 'version_conflict', { currentVersion: cur.rows[0].version });
    }
    res.json(toWire(row));
  });

  r.delete('/:id', async (req, res) => {
    const id = noteIdSchema.parse(req.params.id);
    const del = await db.query('DELETE FROM notes WHERE user_id = $1 AND id = $2', [req.auth!.userId, id]);
    if (!del.rowCount) throw new HttpError(404, 'not_found');
    res.status(204).end();
  });

  return r;
}
